// keygate-ops 是受控离线运维入口；数据库及签名材料由本机环境/私有文件提供，不能部署为公开 HTTP。
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"ex-keygate/internal/auditarchive"
	"ex-keygate/internal/storage"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "运维操作失败：", e)
		os.Exit(1)
	}
}
func run() error {
	action := flag.String("action", "", "init-signing / archive / seal-archive / verify-archive")
	environment := flag.String("environment", "", "固定安全域")
	directory := flag.String("archive-dir", "", "独立归档目录（0700）")
	private := flag.String("signing-key", "", "独立 Ed25519 私钥文件（0600）")
	public := flag.String("public-key", "", "固定可信 Ed25519 公钥文件（0600）")
	checkpoint := flag.String("checkpoint", "", "归档目录之外的独立可信校验点文件")
	limit := flag.Int("limit", 1000, "每批上限 1..1000")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if *action == "init-signing" {
		pub, key, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return e
		}
		defer clear(key)
		if *private == "" || *public == "" || *private == *public {
			return errors.New("需要两个不同的私有文件路径")
		}
		if e = auditarchive.WriteOnce(*private, key); e != nil {
			return e
		}
		if e = auditarchive.WriteOnce(*public, pub); e != nil {
			return e
		}
		fmt.Println("签名密钥文件已创建；请独立保管并固定公钥")
		return nil
	}
	pub, e := auditarchive.ReadPrivate(*public, 32)
	if e != nil || len(pub) != 32 {
		return errors.New("可信公钥文件无效")
	}
	var key []byte
	if *action == "archive" || *action == "seal-archive" {
		key, e = auditarchive.ReadPrivate(*private, 64)
		if e != nil || len(key) != 64 {
			return errors.New("签名私钥文件无效")
		}
		defer clear(key)
		if !ed25519.PublicKey(pub).Equal(ed25519.PrivateKey(key).Public()) {
			return errors.New("归档签名身份不匹配")
		}
	}
	db, e := sql.Open("pgx", os.Getenv("KEYGATE_DATABASE_URL"))
	if e != nil {
		return errors.New("数据库配置无效")
	}
	defer db.Close()
	if e = db.PingContext(ctx); e != nil {
		return errors.New("数据库不可用")
	}
	store, e := storage.New(db)
	if e != nil {
		return e
	}
	switch *action {
	case "archive":
		n, e := store.ArchiveAuditBatch(ctx, *environment, auditarchive.Files{Dir: *directory, Key: key}, *limit)
		if e != nil {
			return e
		}
		fmt.Printf("已归档 %d 个事件\n", n)
		return nil
	case "seal-archive":
		if !externalPath(*directory, *checkpoint) {
			return errors.New("校验点必须位于归档目录之外")
		}
		before, e := store.AuditArchiveStatus(ctx, *environment)
		if e != nil {
			return e
		}
		if before.Pending != 0 {
			return errors.New("仍有未归档事件，不能签署完整清单")
		}
		inventory, e := auditarchive.VerifyInventory(*directory, *environment, pub, func(raw []byte) error { return store.CompareArchivedAudit(ctx, *environment, raw) })
		if e != nil {
			return e
		}
		after, e := store.AuditArchiveStatus(ctx, *environment)
		if e != nil {
			return e
		}
		if before != after || int64(inventory.Count) != after.Count {
			return errors.New("归档集合正在变化，稍后重新核对")
		}
		raw, e := json.Marshal(inventory)
		if e != nil {
			return e
		}
		signed, e := json.Marshal(auditarchive.Signed{Payload: raw, Signature: ed25519.Sign(key, raw)})
		if e != nil {
			return e
		}
		if e = auditarchive.WriteOnce(*checkpoint, signed); e != nil {
			return e
		}
		fmt.Printf("已生成独立签名清单，事件数 %d；需单独保管\n", inventory.Count)
		return nil
	case "verify-archive":
		raw, e := auditarchive.ReadPrivate(*checkpoint, 1<<20)
		if e != nil {
			return e
		}
		var signed auditarchive.Signed
		if json.Unmarshal(raw, &signed) != nil || !ed25519.Verify(pub, signed.Payload, signed.Signature) {
			return auditarchive.ErrIntegrity
		}
		var expected auditarchive.Inventory
		if json.Unmarshal(signed.Payload, &expected) != nil || expected.Version != "keygate-archive-v1" || expected.Environment != *environment {
			return auditarchive.ErrIntegrity
		}
		actual, e := auditarchive.VerifyInventory(*directory, *environment, pub, func(raw []byte) error { return store.CompareArchivedAudit(ctx, *environment, raw) })
		if e != nil {
			return e
		}
		if actual != expected {
			return auditarchive.ErrIntegrity
		}
		fmt.Println("独立清单、归档签名及数据库事件比对通过")
		return nil
	default:
		return errors.New("未知 action")
	}
}

// 路径独立性以真实父目录核验，不能通过符号链接把校验点放回归档目录。
func externalPath(dir, path string) bool {
	if path == "" {
		return false
	}
	a, e := filepath.EvalSymlinks(dir)
	if e != nil {
		return false
	}
	a, e = filepath.Abs(a)
	if e != nil {
		return false
	}
	parent, e := filepath.EvalSymlinks(filepath.Dir(path))
	if e != nil {
		return false
	}
	b, e := filepath.Abs(filepath.Join(parent, filepath.Base(path)))
	if e != nil {
		return false
	}
	rel, e := filepath.Rel(a, b)
	return e == nil && (rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)))
}
