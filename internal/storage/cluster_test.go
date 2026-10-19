package storage

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"errors"
	"ex-keygate/internal/config"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func clusterFixture(t *testing.T) (*Store, string, string) {
	t.Helper()
	s, db := database(t)
	id := unique(t)
	digest := strings.Repeat("c", 64)
	if e := s.ConfigureClusterOffline(context.Background(), id, digest, unique(t)); e != nil {
		t.Fatal(e)
	}
	// 仅测试身份清理专用临时数据库；产品不提供关闭集群校验接口。
	t.Cleanup(func() {
		_, e := db.Exec(`DELETE FROM keygate.runtime_nodes; UPDATE keygate.runtime_cluster SET enabled=false,cluster_id='',configuration_hash='',generation=generation+1`)
		if e != nil {
			t.Error(e)
		}
	})
	return s, id, digest
}
func nodeStore(t *testing.T, s *Store, id, digest, node string) *Store {
	t.Helper()
	db, e := sql.Open("pgx", os.Getenv("KEYGATE_TEST_DATABASE_URL"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	raw, _ := New(db)
	out, e := raw.AcquireNode(context.Background(), id, digest, node, unique(t))
	if e != nil {
		t.Fatal(e)
	}
	return out
}
func TestClusterNodeFencingAndConfiguration(t *testing.T) {
	s, id, digest := clusterFixture(t)
	ctx := context.Background()
	a := nodeStore(t, s, id, digest, "node-a")
	b := nodeStore(t, s, id, digest, "node-b")
	if e := s.CheckReadiness(ctx); !errors.Is(e, ErrFenced) {
		t.Fatal("未登记实例绕过集群", e)
	}
	if _, e := s.AcquireNode(ctx, id, strings.Repeat("d", 64), "wrong-config", unique(t)); !errors.Is(e, ErrFenced) {
		t.Fatal("配置不一致仍加入", e)
	}
	if _, e := s.AcquireNode(ctx, id, digest, "node-a", unique(t)); !errors.Is(e, ErrFenced) {
		t.Fatal("相同节点抢占未过期实例", e)
	}
	if e := a.CheckReadiness(ctx); e != nil {
		t.Fatal(e)
	}
	if e := b.CheckReadiness(ctx); e != nil {
		t.Fatal(e)
	}
	if _, e := s.db.Exec(`UPDATE keygate.runtime_nodes SET expires_at=clock_timestamp()-interval '1 second' WHERE node_id='node-a'`); e != nil {
		t.Fatal(e)
	}
	if e := a.RenewNode(ctx); !errors.Is(e, ErrFenced) {
		t.Fatal("过期实例自动复活", e)
	}
	next := nodeStore(t, s, id, digest, "node-a")
	_, _, oldEpoch := a.NodeIdentity()
	_, _, newEpoch := next.NodeIdentity()
	if newEpoch <= oldEpoch {
		t.Fatal("接管未推进实例代次")
	}
	if e := a.CheckReadiness(ctx); !errors.Is(e, ErrFenced) {
		t.Fatal("旧实例仍可服务", e)
	}
	if e := next.DrainNode(ctx, unique(t)); e != nil {
		t.Fatal(e)
	}
	if e := next.CheckReadiness(ctx); !errors.Is(e, ErrFenced) {
		t.Fatal("摘流后仍就绪", e)
	}
	if e := b.CheckReadiness(ctx); e != nil {
		t.Fatal("单节点退出影响其他节点", e)
	}
	if e := s.FenceClusterOffline(ctx, unique(t)); e != nil {
		t.Fatal(e)
	}
	if e := b.CheckReadiness(ctx); !errors.Is(e, ErrFenced) {
		t.Fatal("全局代次未隔离旧节点", e)
	}
}
func TestClusterConcurrentRenewalsDoNotUpgradeSharedLocks(t *testing.T) {
	s, id, digest := clusterFixture(t)
	a := nodeStore(t, s, id, digest, "node-a")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	var failures atomic.Int64
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e := a.RenewNode(ctx); e != nil {
				failures.Add(1)
			}
		}()
	}
	wg.Wait()
	if failures.Load() != 0 {
		t.Fatal("并发续约失败或死锁", failures.Load())
	}
}
func TestClusterTakeoverWaitsForInFlightTransaction(t *testing.T) {
	s, id, digest := clusterFixture(t)
	a := nodeStore(t, s, id, digest, "node-a")
	ctx := context.Background()
	tx, e := a.beginRuntime(ctx)
	if e != nil {
		t.Fatal(e)
	}
	// 在共享节点锁仍被业务持有时，接管不能越过已开始的事务。
	bounded, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	if e = s.FenceClusterOffline(bounded, unique(t)); e == nil {
		t.Fatal("维护绕过活动事务")
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	if e = s.FenceClusterOffline(ctx, unique(t)); e != nil {
		t.Fatal(e)
	}
	if e = a.CheckReadiness(ctx); !errors.Is(e, ErrFenced) {
		t.Fatal(e)
	}
}
func TestClusterIndependentPoolsShareAuthenticationAndRevocation(t *testing.T) {
	f := newKeyFixture(t)
	ctx := context.Background()
	r := f.issue(t, 1)
	bundle, secret := f.claim(t, r)
	defer clear(secret)
	mac := hmac.New(sha256.New, secret)
	mac.Write(bundle.PossessionInput)
	if e := f.k.ConfirmPossession(ctx, r.ID, mac.Sum(nil), unique(t)); e != nil {
		t.Fatal(e)
	}
	f.operation(t, ActivateKey, 1, "")
	s := f.f.c.store
	id, digest := unique(t), strings.Repeat("e", 64)
	if e := s.ConfigureClusterOffline(ctx, id, digest, unique(t)); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		_, e := s.db.Exec(`DELETE FROM keygate.runtime_nodes; UPDATE keygate.runtime_cluster SET enabled=false,cluster_id='',configuration_hash='',generation=generation+1`)
		if e != nil {
			t.Error(e)
		}
	})
	a, b := nodeStore(t, s, id, digest, "node-a"), nodeStore(t, s, id, digest, "node-b")
	controls := []*DevelopmentControl{}
	keys := []*DevelopmentKeys{}
	for _, n := range []*Store{a, b} {
		c, e := NewDevelopmentControl(config.Test, f.f.c.environment, f.f.profile, n)
		if e != nil {
			t.Fatal(e)
		}
		controls = append(controls, c)
		keys = append(keys, &DevelopmentKeys{control: c, rootID: f.k.rootID, wrapper: f.k.wrapper, fingerprint: f.k.fingerprint})
	}
	body := []byte(`{"probe":true}`)
	request, _ := signedProbe(t, f, secret, body)
	var wg sync.WaitGroup
	var accepted atomic.Int64
	for _, k := range keys {
		wg.Add(1)
		go func(k *DevelopmentKeys) {
			defer wg.Done()
			if k.AuthenticateProbe(ctx, request, body, "keygate-probe") == nil {
				accepted.Add(1)
			}
		}(k)
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatal("跨节点重放", accepted.Load())
	}
	request, _ = signedProbe(t, f, secret, body)
	if e := keys[1].AuthenticateProbe(ctx, request, body, "keygate-probe"); e != nil {
		t.Fatal(e)
	}
	if e := controls[0].EmergencyDisableClient(ctx, f.f.tokens[0], "one", unique(t)); e != nil {
		t.Fatal(e)
	}
	request, _ = signedProbe(t, f, secret, body)
	if e := keys[1].AuthenticateProbe(ctx, request, body, "keygate-probe"); e == nil {
		t.Fatal("另一节点未立即看到停用")
	}
	if e := a.db.Close(); e != nil {
		t.Fatal(e)
	}
	if e := a.CheckReadiness(ctx); e == nil {
		t.Fatal("断开的节点继续放行")
	}
	if e := b.CheckReadiness(ctx); e != nil {
		t.Fatal("单节点断连影响另一连接池", e)
	}
}
