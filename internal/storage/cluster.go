package storage

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"log/slog"
	"time"
)

var ErrFenced = errors.New("node is not authorized for current cluster generation")

const NodeLeaseDuration = 15 * time.Second

type NodePermit struct {
	ClusterID         string
	ConfigurationHash string
	NodeID            string
	Generation        uint64
	Incarnation       uint64
	secret            [32]byte
}

// ConfigureClusterOffline 是受控部署入口，必须在停服、核验共享配置后调用；不挂 HTTP，也不提供关闭集群绕过入口。
// 配置摘要应来自审核后的身份、根引用、插件及部署配置，不能由客户端决定。
func (s *Store) ConfigureClusterOffline(ctx context.Context, id, configuration, trace string) error {
	if !identifier.MatchString(id) || !validDigest(configuration) || !identifier.MatchString(trace) {
		return ErrInvalid
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var enabled bool
	if e = tx.QueryRowContext(ctx, `SELECT enabled FROM keygate.runtime_cluster WHERE singleton FOR UPDATE NOWAIT`).Scan(&enabled); e != nil {
		return e
	}
	if enabled {
		return ErrConflict
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.runtime_cluster SET enabled=true,cluster_id=$1,configuration_hash=$2 WHERE singleton`, id, configuration); e != nil {
		return e
	}
	if e = appendAudit(ctx, tx, Audit{trace, trace, "offline-bootstrap", "cluster_configure", id, "enabled"}); e != nil {
		return e
	}
	return tx.Commit()
}

// AcquireNode 多个不同 nodeID 可同时工作；同一 nodeID 只有一个有效实例，过期接管必须推进 incarnation。
// 租约以数据库时钟为准，提交不明时不给许可；重试使用新实例秘密且不能抢占仍有效的旧租约。
func (s *Store) AcquireNode(ctx context.Context, id, configuration, nodeID, trace string) (*Store, error) {
	if !identifier.MatchString(id) || !validDigest(configuration) || !identifier.MatchString(nodeID) || !identifier.MatchString(trace) {
		return nil, ErrInvalid
	}
	p := NodePermit{ClusterID: id, ConfigurationHash: configuration, NodeID: nodeID}
	if _, e := rand.Read(p.secret[:]); e != nil {
		return nil, e
	}
	hash := sha256.Sum256(p.secret[:])
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	var enabled bool
	var cluster, config string
	if e = tx.QueryRowContext(ctx, `SELECT enabled,cluster_id,configuration_hash,generation FROM keygate.runtime_cluster WHERE singleton FOR SHARE`).Scan(&enabled, &cluster, &config, &p.Generation); e != nil {
		return nil, e
	}
	if !enabled || cluster != id || config != configuration {
		return nil, ErrFenced
	}
	e = tx.QueryRowContext(ctx, `INSERT INTO keygate.runtime_nodes(node_id,instance_hash,cluster_generation,incarnation,expires_at) VALUES($1,$2,$3,1,clock_timestamp()+interval '15 seconds') ON CONFLICT(node_id) DO UPDATE SET instance_hash=EXCLUDED.instance_hash,cluster_generation=EXCLUDED.cluster_generation,incarnation=keygate.runtime_nodes.incarnation+1,expires_at=EXCLUDED.expires_at,drained=false WHERE keygate.runtime_nodes.expires_at<=clock_timestamp() OR keygate.runtime_nodes.drained OR keygate.runtime_nodes.cluster_generation<>EXCLUDED.cluster_generation RETURNING incarnation`, nodeID, hash[:], p.Generation).Scan(&p.Incarnation)
	if errors.Is(e, sql.ErrNoRows) {
		return nil, ErrFenced
	}
	if e != nil {
		return nil, e
	}
	if e = appendAudit(ctx, tx, Audit{trace, trace, nodeID, "node_acquire", id, "active"}); e != nil {
		return nil, e
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	slog.InfoContext(ctx, "节点已取得集群租约", "request_id", trace, "node_id", nodeID, "generation", p.Generation, "incarnation", p.Incarnation, "result", "active")
	return &Store{db: s.db, node: &p}, nil
}

// beginRuntime 在业务锁之前取得代次和节点共享行锁，接管或隔离必须等待已开始事务结束。
// 失去租约、配置不一致、只读库、数据库异常均拒绝；不依赖本机健康缓存来放行。
func (s *Store) beginRuntime(ctx context.Context) (*sql.Tx, error) {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	// 限制单条查询、锁等待和空闲事务，避免异常节点长期占有租约隔离锁。
	if _, e = tx.ExecContext(ctx, `SELECT set_config('statement_timeout','5000',true),set_config('lock_timeout','2000',true),set_config('idle_in_transaction_session_timeout','5000',true)`); e != nil {
		tx.Rollback()
		return nil, e
	}
	if e = s.checkRuntime(ctx, tx, false); e != nil {
		tx.Rollback()
		return nil, e
	}
	return tx, nil
}
func (s *Store) checkRuntime(ctx context.Context, tx *sql.Tx, exclusive bool) error {
	var recovery bool
	var readOnly string
	if e := tx.QueryRowContext(ctx, `SELECT pg_is_in_recovery(),current_setting('transaction_read_only')`).Scan(&recovery, &readOnly); e != nil {
		return e
	}
	if recovery || readOnly != "off" {
		return ErrFenced
	}
	var enabled bool
	var id, config string
	var generation uint64
	if e := tx.QueryRowContext(ctx, `SELECT enabled,cluster_id,configuration_hash,generation FROM keygate.runtime_cluster WHERE singleton FOR SHARE`).Scan(&enabled, &id, &config, &generation); e != nil {
		return e
	}
	if !enabled {
		if s.node != nil {
			return ErrFenced
		}
		return nil
	}
	p := s.node
	if p == nil || p.ClusterID != id || p.ConfigurationHash != config || p.Generation != generation {
		return ErrFenced
	}
	h := sha256.Sum256(p.secret[:])
	var live bool
	lock := " FOR SHARE"
	if exclusive {
		lock = " FOR UPDATE"
	}
	e := tx.QueryRowContext(ctx, `SELECT instance_hash=$2 AND cluster_generation=$3 AND incarnation=$4 AND NOT drained AND expires_at>clock_timestamp() FROM keygate.runtime_nodes WHERE node_id=$1`+lock, p.NodeID, h[:], p.Generation, p.Incarnation).Scan(&live)
	if errors.Is(e, sql.ErrNoRows) || e == nil && !live {
		return ErrFenced
	}
	return e
}

// RenewNode 只延长当前仍有效的实例；过期节点不能续活，必须重新申请并取得新代次。
func (s *Store) RenewNode(ctx context.Context) error {
	p := s.node
	if p == nil {
		return ErrFenced
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = s.checkRuntime(ctx, tx, true); e != nil {
		return e
	}
	h := sha256.Sum256(p.secret[:])
	result, e := tx.ExecContext(ctx, `UPDATE keygate.runtime_nodes SET expires_at=clock_timestamp()+interval '15 seconds' WHERE node_id=$1 AND instance_hash=$2 AND cluster_generation=$3 AND incarnation=$4 AND NOT drained AND expires_at>clock_timestamp()`, p.NodeID, h[:], p.Generation, p.Incarnation)
	if e != nil {
		return e
	}
	if e = oneResult(result); e != nil {
		return ErrFenced
	}
	return tx.Commit()
}

// DrainNode 先使本节点不能开始新事务；已持共享锁的事务完成后才提交摘流事实。
func (s *Store) DrainNode(ctx context.Context, trace string) error {
	if s.node == nil || !identifier.MatchString(trace) {
		return ErrInvalid
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = s.checkRuntime(ctx, tx, true); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.runtime_nodes SET drained=true,expires_at=clock_timestamp() WHERE node_id=$1`, s.node.NodeID); e != nil {
		return e
	}
	if e = appendAudit(ctx, tx, Audit{trace, trace, s.node.NodeID, "node_drain", s.node.ClusterID, "drained"}); e != nil {
		return e
	}
	return tx.Commit()
}

// FenceClusterOffline 用于数据库切换或恢复后的受控隔离；不负责证明旧数据库主库已经物理隔离。
// 调用方必须先完成旧主 fencing 和同步数据核验；代次只在当前权威库内有效，不能阻止独立旧库写入。
func (s *Store) FenceClusterOffline(ctx context.Context, trace string) error {
	if !identifier.MatchString(trace) {
		return ErrInvalid
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var id string
	if e = tx.QueryRowContext(ctx, `SELECT cluster_id FROM keygate.runtime_cluster WHERE singleton AND enabled FOR UPDATE NOWAIT`).Scan(&id); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.runtime_cluster SET generation=generation+1 WHERE singleton`); e != nil {
		return e
	}
	if e = appendAudit(ctx, tx, Audit{trace, trace, "offline-operator", "cluster_fence", id, "fenced"}); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) CheckReadiness(ctx context.Context) error {
	tx, e := s.beginRuntime(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	return tx.Commit()
}

// NodeIdentity 只返回非敏感诊断字段，实例秘密和其摘要不进入日志或 HTTP。
func (s *Store) NodeIdentity() (string, uint64, uint64) {
	if s.node == nil {
		return "", 0, 0
	}
	return s.node.NodeID, s.node.Generation, s.node.Incarnation
}
func ConfigurationDigest(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }

// RunNodeLease 仅续约现有实例，连接恢复后不会自动复活过期身份；失败状态变化时才记录日志。
func (s *Store) RunNodeLease(ctx context.Context) {
	if s.node == nil {
		return
	}
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	failed := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
			e := s.RenewNode(bounded)
			cancel()
			if e != nil && !failed {
				slog.WarnContext(ctx, "节点租约续约失败，权威事务将拒绝过期节点", "node_id", s.node.NodeID, "result", "unavailable")
				failed = true
			}
			if e == nil && failed {
				slog.InfoContext(ctx, "节点租约续约恢复", "node_id", s.node.NodeID, "result", "active")
				failed = false
			}
		}
	}
}

// RequiredRootIDs 仅供可信节点就绪探针检查根装配，不向 HTTP 暴露根清单或材料。
func (c *DevelopmentControl) RequiredRootIDs(ctx context.Context) ([]string, error) {
	tx, e := c.begin(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	if e = c.requireInternalProvider(ctx, tx); e != nil {
		return nil, e
	}
	rows, e := tx.QueryContext(ctx, `SELECT root_id FROM keygate.client_roots WHERE environment=$1 AND enabled ORDER BY root_id LIMIT 129`, c.environment)
	if e != nil {
		return nil, e
	}
	out := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return nil, e
		}
		out = append(out, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	if len(out) > 128 {
		return nil, ErrInvalid
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	return out, nil
}
