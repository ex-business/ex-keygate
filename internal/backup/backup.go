// Package backup 实现单管理域专用PostgreSQL的加密备份与独立签名检查点，不托管根私钥。
package backup

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"ex-keygate/internal/access"
	"ex-keygate/internal/auditarchive"
	"ex-keygate/internal/storage"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"
)

type Config struct {
	Environment         string `json:"environment"`
	DatabaseFile        string `json:"databaseFile"`
	Directory           string `json:"directory"`
	CheckpointDirectory string `json:"checkpointDirectory"`
	SigningKeyFile      string `json:"signingKeyFile"`
	PublicKeyFile       string `json:"publicKeyFile"`
	EncryptionKeyFile   string `json:"encryptionKeyFile"`
	PGDump              string `json:"pgDump"`
	PGRestore           string `json:"pgRestore"`
	PSQL                string `json:"psql"`
	BackupSeconds       int    `json:"backupSeconds"`
	CheckpointSeconds   int    `json:"checkpointSeconds"`
}
type Record struct {
	Kind         string                   `json:"kind"`
	ID           string                   `json:"id"`
	BackupID     string                   `json:"backupId"`
	CipherSHA256 string                   `json:"cipherSHA256"`
	State        storage.SafetyCheckpoint `json:"state"`
}
type Result struct {
	ID               string `json:"id"`
	CheckpointFile   string `json:"checkpointFile"`
	CheckpointSHA256 string `json:"checkpointSHA256"`
	BackupID         string `json:"backupId"`
}
type Runner struct {
	mu     sync.Mutex
	cfg    Config
	dsn    string
	key    []byte
	sign   ed25519.PrivateKey
	public ed25519.PublicKey
	db     *sql.DB
	store  *storage.Store
	locks  []*os.File
}

func hash(b []byte) string { v := sha256.Sum256(b); return hex.EncodeToString(v[:]) }
func id() string {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return ""
	}
	return hex.EncodeToString(b[:])
}
func privateDirectory(path string) error {
	info, e := os.Lstat(path)
	if e != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return ErrBackup
	}
	resolved, e := filepath.EvalSymlinks(path)
	if e != nil || resolved != path {
		return ErrBackup
	}
	return nil
}
func contains(parent, child string) bool {
	rel, e := filepath.Rel(parent, child)
	return e == nil && (rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)))
}
func Open(ctx context.Context, c Config, writer bool) (*Runner, error) {
	if !access.ValidID(c.Environment) || c.PGDump == "" || c.PGRestore == "" || c.PSQL == "" || c.BackupSeconds < 60 || c.BackupSeconds > 604800 || c.CheckpointSeconds < 10 || c.CheckpointSeconds > 3600 {
		return nil, ErrBackup
	}
	for _, p := range []*string{&c.Directory, &c.CheckpointDirectory, &c.DatabaseFile, &c.SigningKeyFile, &c.PublicKeyFile, &c.EncryptionKeyFile} {
		if !writer && (p == &c.DatabaseFile || p == &c.SigningKeyFile) {
			continue
		}
		if *p != "" {
			v, e := filepath.Abs(*p)
			if e != nil {
				return nil, ErrBackup
			}
			info, e := os.Lstat(v)
			if e != nil || info.Mode()&os.ModeSymlink != 0 {
				return nil, ErrBackup
			}
			real, e := filepath.EvalSymlinks(v)
			if e != nil {
				return nil, ErrBackup
			}
			*p = real
		}
	}
	if privateDirectory(c.Directory) != nil || privateDirectory(c.CheckpointDirectory) != nil || contains(c.Directory, c.CheckpointDirectory) || contains(c.CheckpointDirectory, c.Directory) {
		return nil, ErrBackup
	}
	paths := []string{c.PublicKeyFile, c.EncryptionKeyFile}
	if writer {
		paths = append(paths, c.SigningKeyFile, c.DatabaseFile)
	}
	for _, p := range paths {
		real, e := filepath.EvalSymlinks(p)
		if e != nil || real != p || contains(c.Directory, p) || contains(c.CheckpointDirectory, p) {
			return nil, ErrBackup
		}
	}
	r := &Runner{cfg: c}
	success := false
	defer func() {
		if !success {
			r.Close()
		}
	}()
	var e error
	if writer {
		raw, e := auditarchive.ReadPrivate(c.DatabaseFile, 16384)
		if e != nil {
			return nil, ErrBackup
		}
		r.dsn = strings.TrimSpace(string(raw))
		clear(raw)
		if _, _, e = pgEnv(r.dsn); e != nil {
			return nil, e
		}
	}
	r.key, e = auditarchive.ReadPrivate(c.EncryptionKeyFile, 32)
	if e != nil || len(r.key) != 32 {
		return nil, ErrBackup
	}
	r.public, e = auditarchive.ReadPrivate(c.PublicKeyFile, 32)
	if e != nil || len(r.public) != 32 {
		return nil, ErrBackup
	}
	// 固定公钥是公开材料，误用为加密密钥会使备份公开可解密，必须显式拒绝。
	if hmac.Equal(r.key, r.public) {
		return nil, ErrBackup
	}
	if writer {
		r.sign, e = auditarchive.ReadPrivate(c.SigningKeyFile, 64)
		if e != nil || len(r.sign) != 64 || !ed25519.PublicKey(r.public).Equal(r.sign.Public()) {
			return nil, ErrBackup
		}
		// 两个存储根分别排他，避免不同进程覆盖同一最新检查点；失败时由defer释放已取得的锁。
		for _, dir := range []string{c.Directory, c.CheckpointDirectory} {
			f, e := os.OpenFile(filepath.Join(dir, ".backup.lock"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if e != nil {
				return nil, ErrBackup
			}
			r.locks = append(r.locks, f)
			if _, e = f.WriteString(fmt.Sprint(os.Getpid())); e != nil {
				return nil, ErrBackup
			}
			if e = f.Sync(); e != nil {
				return nil, ErrBackup
			}
		}
		r.db, e = sql.Open("pgx", r.dsn)
		if e != nil {
			return nil, ErrBackup
		}
		if e = r.db.PingContext(ctx); e != nil {
			return nil, ErrBackup
		}
		r.store, _ = storage.New(r.db)
	}
	success = true
	return r, nil
}
func (r *Runner) Close() {
	for _, f := range r.locks {
		name := f.Name()
		f.Close()
		os.Remove(name)
	}
	r.locks = nil
	if r.db != nil {
		r.db.Close()
	}
	clear(r.key)
	clear(r.sign)
}
func (r *Runner) publish(record Record) (Result, error) {
	if !access.ValidID(record.ID) {
		return Result{}, ErrBackup
	}
	payload, e := json.Marshal(record)
	if e != nil {
		return Result{}, ErrBackup
	}
	raw, e := json.Marshal(auditarchive.Signed{Payload: payload, Signature: ed25519.Sign(r.sign, payload)})
	if e != nil {
		return Result{}, ErrBackup
	}
	path := filepath.Join(r.cfg.CheckpointDirectory, record.ID+".signed")
	if e = auditarchive.WriteOnce(path, raw); e != nil {
		return Result{}, ErrBackup
	}
	// 最新指针只在完整签名文件已持久化后原子推进；外部见证应保存日志中的摘要，不能信任备份自带的旧指针。
	f, e := os.CreateTemp(r.cfg.CheckpointDirectory, ".head-")
	if e != nil {
		return Result{}, ErrBackup
	}
	defer os.Remove(f.Name())
	if _, e = f.Write(raw); e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil || closeErr != nil {
		return Result{}, ErrBackup
	}
	if e = os.Rename(f.Name(), filepath.Join(r.cfg.CheckpointDirectory, "latest.signed")); e != nil {
		return Result{}, ErrBackup
	}
	d, e := os.Open(r.cfg.CheckpointDirectory)
	if e != nil {
		return Result{}, ErrBackup
	}
	e = d.Sync()
	d.Close()
	if e != nil {
		return Result{}, ErrBackup
	}
	return Result{record.ID, path, hash(raw), record.BackupID}, nil
}
func (r *Runner) Checkpoint(ctx context.Context) (Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.sign) != 64 {
		return Result{}, ErrBackup
	}
	var record Record
	e := r.store.WithBackupSnapshot(ctx, r.cfg.Environment, func(_ string, state storage.SafetyCheckpoint) error {
		record = Record{Kind: "keygate-backup-checkpoint-v1", ID: id(), State: state}
		return nil
	})
	if e != nil {
		return Result{}, e
	}
	return r.publish(record)
}
func (r *Runner) Backup(ctx context.Context) (Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.sign) != 64 {
		return Result{}, ErrBackup
	}
	backupID := id()
	if !access.ValidID(backupID) {
		return Result{}, ErrBackup
	}
	dir := filepath.Join(r.cfg.Directory, backupID)
	if e := os.Mkdir(dir, 0700); e != nil {
		return Result{}, ErrBackup
	}
	complete := false
	defer func() {
		if !complete {
			os.RemoveAll(dir)
		}
	}()
	var record Record
	e := r.store.WithBackupSnapshot(ctx, r.cfg.Environment, func(snapshot string, state storage.SafetyCheckpoint) error {
		f, e := os.OpenFile(filepath.Join(dir, "database.kgb"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return ErrBackup
		}
		h := sha256.New()
		e = dump(ctx, r.cfg.PGDump, r.dsn, snapshot, io.MultiWriter(f, h), r.key)
		if e == nil {
			e = f.Sync()
		}
		closeErr := f.Close()
		if e != nil || closeErr != nil {
			return ErrBackup
		}
		record = Record{Kind: "keygate-backup-checkpoint-v1", ID: id(), BackupID: backupID, CipherSHA256: hex.EncodeToString(h.Sum(nil)), State: state}
		// 备份内清单只作内容绑定，恢复的新鲜度必须由独立最新检查点和外部固定摘要提供。
		payload, _ := json.Marshal(record)
		raw, _ := json.Marshal(auditarchive.Signed{Payload: payload, Signature: ed25519.Sign(r.sign, payload)})
		if e = auditarchive.WriteOnce(filepath.Join(dir, "manifest.signed"), raw); e != nil {
			return e
		}
		return nil
	})
	if e != nil {
		return Result{}, e
	}
	complete = true
	return r.publishCompletedBackup(record, syncDirectory)
}
func (r *Runner) readRecord(path string) (Record, []byte, error) {
	raw, e := auditarchive.ReadPrivate(path, 1<<20)
	if e != nil {
		return Record{}, nil, ErrBackup
	}
	var signed auditarchive.Signed
	if json.Unmarshal(raw, &signed) != nil || !ed25519.Verify(r.public, signed.Payload, signed.Signature) {
		return Record{}, nil, ErrBackup
	}
	var v Record
	if json.Unmarshal(signed.Payload, &v) != nil || v.Kind != "keygate-backup-checkpoint-v1" || !access.ValidID(v.ID) || v.State.Environment != r.cfg.Environment || v.State.Kind != "keygate-state-v1" || !access.ValidID(v.State.ID) || v.State.CapturedAt.IsZero() {
		return Record{}, nil, ErrBackup
	}
	return v, raw, nil
}

// Restore 只进入显式确认的空目标库；先验证独立最新见证、备份签名及密文完整性，再还原并强制隔离，绝不启动认证。
func (r *Runner) Restore(ctx context.Context, backupID, latest, expectedHash, targetFile, confirm string) error {
	if !access.ValidID(backupID) || len(expectedHash) != 64 {
		return ErrBackup
	}
	if _, e := hex.DecodeString(expectedHash); e != nil {
		return ErrBackup
	}
	latestPath, e := filepath.EvalSymlinks(latest)
	if e != nil || contains(r.cfg.Directory, latestPath) {
		return ErrBackup
	}
	checkpoint, raw, e := r.readRecord(latestPath)
	if e != nil || hash(raw) != expectedHash {
		return ErrBackup
	}
	dir := filepath.Join(r.cfg.Directory, backupID)
	if privateDirectory(dir) != nil {
		return ErrBackup
	}
	record, _, e := r.readRecord(filepath.Join(dir, "manifest.signed"))
	if e != nil || record.BackupID != backupID || len(record.CipherSHA256) != 64 {
		return ErrBackup
	}
	if !reflect.DeepEqual(record.State.Tables, checkpoint.State.Tables) {
		return ErrBackup
	}
	path := filepath.Join(dir, "database.kgb")
	info, e := os.Lstat(path)
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return ErrBackup
	}
	f, e := os.Open(path)
	if e != nil {
		return ErrBackup
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(info, opened) {
		return ErrBackup
	}
	// 将密文复制到只持有私有句柄的临时文件，避免验签后原备份路径被替换；全程不落地明文。
	frozen, e := os.CreateTemp(r.cfg.CheckpointDirectory, ".restore-cipher-")
	if e != nil {
		return ErrBackup
	}
	defer frozen.Close()
	defer os.Remove(frozen.Name())
	if e = os.Remove(frozen.Name()); e != nil {
		return ErrBackup
	}
	h := sha256.New()
	if _, e = io.Copy(io.MultiWriter(frozen, h), f); e != nil || hex.EncodeToString(h.Sum(nil)) != record.CipherSHA256 {
		return ErrBackup
	}
	f.Close()
	f = frozen
	if _, e = f.Seek(0, 0); e != nil {
		return ErrBackup
	}
	// 先完整认证解密流再触碰目标，避免尾块损坏时子进程提前提交；明文只经丢弃流，不写磁盘。
	if e = decrypt(io.Discard, f, r.key); e != nil {
		return ErrBackup
	}
	if _, e = f.Seek(0, 0); e != nil {
		return ErrBackup
	}
	rawTarget, e := auditarchive.ReadPrivate(targetFile, 16384)
	if e != nil {
		return ErrBackup
	}
	target := strings.TrimSpace(string(rawTarget))
	clear(rawTarget)
	_, name, e := pgEnv(target)
	if e != nil || name != confirm || target == r.dsn {
		return ErrBackup
	}
	db, e := sql.Open("pgx", target)
	if e != nil {
		return ErrBackup
	}
	defer db.Close()
	var empty bool
	e = db.QueryRowContext(ctx, `SELECT NOT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname NOT IN ('public','information_schema') AND nspname NOT LIKE 'pg_%') AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public')`).Scan(&empty)
	if e != nil || !empty {
		return ErrBackup
	}
	postlude, e := storage.RestoreTransactionSQL(record.State, "restore-"+record.ID)
	if e != nil {
		return ErrBackup
	}
	if e = restore(ctx, r.cfg.PGRestore, r.cfg.PSQL, target, f, r.key, postlude); e != nil {
		return ErrBackup
	}
	return nil
}
func (r *Runner) Run(ctx context.Context, report func(string, Result, error)) {
	nextBackup := time.Time{}
	nextCheckpoint := time.Time{}
	timer := time.NewTicker(time.Second)
	defer timer.Stop()
	for ctx.Err() == nil {
		if !time.Now().Before(nextBackup) {
			job, cancel := context.WithTimeout(ctx, 30*time.Minute)
			v, e := r.Backup(job)
			cancel()
			report("backup", v, e)
			nextBackup = time.Now().Add(time.Duration(r.cfg.BackupSeconds) * time.Second)
			nextCheckpoint = time.Time{}
		}
		// 备份可能耗时，结束后立即保存新鲜状态，不把导出开始时的检查点误当成当前状态。
		if ctx.Err() == nil && !time.Now().Before(nextCheckpoint) {
			job, cancel := context.WithTimeout(ctx, time.Minute)
			v, e := r.Checkpoint(job)
			cancel()
			report("checkpoint", v, e)
			nextCheckpoint = time.Now().Add(time.Duration(r.cfg.CheckpointSeconds) * time.Second)
		}
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
	}
}

func syncDirectory(path string) error {
	d, e := os.Open(path)
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}

// 发布最新见证之前，备份根目录的新目录项必须确认持久化；同步失败只保留孤立完整备份，不推进见证。
func (r *Runner) publishCompletedBackup(record Record, sync func(string) error) (Result, error) {
	if e := sync(r.cfg.Directory); e != nil {
		return Result{}, ErrBackup
	}
	return r.publish(record)
}
