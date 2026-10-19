package storage

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

func submitClient(t *testing.T, f controlFixture, id string) ControlRequest {
	t.Helper()
	r, e := f.c.Submit(context.Background(), f.tokens[0], ControlOperation{Kind: CreateClient, ClientID: id, Name: "测试客户端", ProfileID: "backend", ProfileVersion: 1}, unique(t), unique(t))
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func approveControl(t *testing.T, f controlFixture, r ControlRequest) {
	t.Helper()
	for _, i := range []int{1, 2} {
		if _, e := f.c.Vote(context.Background(), f.tokens[i], r.ID, r.Digest, true, unique(t)); e != nil {
			t.Fatal(e)
		}
	}
}
func TestControlledClientApprovalAndExecution(t *testing.T) {
	f := newControlFixture(t)
	ctx := context.Background()
	r := submitClient(t, f, "one")
	if _, e := f.c.Vote(ctx, f.tokens[0], r.ID, r.Digest, true, unique(t)); !errors.Is(e, ErrDenied) {
		t.Fatal("self approval", e)
	}
	if _, e := f.c.Vote(ctx, f.tokens[3], r.ID, r.Digest, true, unique(t)); !errors.Is(e, ErrDenied) {
		t.Fatal("alias not in pool approved", e)
	}
	if _, e := f.c.Vote(ctx, f.tokens[1], r.ID, "wrong", true, unique(t)); !errors.Is(e, ErrConflict) {
		t.Fatal("wrong digest", e)
	}
	if e := f.c.ExecuteLocal(ctx, r.ID, r.Digest, unique(t)); !errors.Is(e, ErrDenied) {
		t.Fatal("unapproved execute", e)
	}
	var accepted atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := f.c.Vote(ctx, f.tokens[1], r.ID, r.Digest, true, unique(t)); e == nil {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatal("duplicate votes", accepted.Load())
	}
	if e := f.c.ExecuteLocal(ctx, r.ID, r.Digest, unique(t)); !errors.Is(e, ErrDenied) {
		t.Fatal("one vote execute", e)
	}
	if _, e := f.c.Vote(ctx, f.tokens[2], r.ID, r.Digest, true, unique(t)); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e := f.c.ExecuteLocal(ctx, r.ID, r.Digest, unique(t)); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	got, e := f.c.Client(ctx, f.tokens[0], "one")
	if e != nil || got.Name != "测试客户端" || got.Revision != 1 {
		t.Fatal(got, e)
	}
	var count int
	if e = f.db.QueryRow(`SELECT count(*) FROM keygate.control_executions WHERE environment=$1 AND request_id=$2`, f.c.environment, r.ID).Scan(&count); e != nil || count != 1 {
		t.Fatal("duplicate execution", count, e)
	}
}
func TestControlIdempotencyAndRevocation(t *testing.T) {
	f := newControlFixture(t)
	ctx := context.Background()
	op := ControlOperation{Kind: CreateClient, ClientID: "one", Name: "One", ProfileID: "backend", ProfileVersion: 1}
	key := unique(t)
	r, e := f.c.Submit(ctx, f.tokens[0], op, key, unique(t))
	if e != nil {
		t.Fatal(e)
	}
	same, e := f.c.Submit(ctx, f.tokens[0], op, key, unique(t))
	if e != nil || same.ID != r.ID {
		t.Fatal("idempotent request", e)
	}
	op.Name = "Changed"
	if _, e = f.c.Submit(ctx, f.tokens[0], op, key, unique(t)); !errors.Is(e, ErrConflict) {
		t.Fatal("idempotency parameter mismatch", e)
	}
	approveControl(t, f, r)
	if e = f.c.EmergencyDisablePrincipal(ctx, f.tokens[0], f.bootstrap.Principals[1].ID, unique(t)); e != nil {
		t.Fatal(e)
	}
	if e = f.c.ExecuteLocal(ctx, r.ID, r.Digest, unique(t)); !errors.Is(e, ErrDenied) {
		t.Fatal("revoked vote executed", e)
	}
	var exists bool
	_ = f.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM keygate.clients WHERE environment=$1 AND client_id='one')`, f.c.environment).Scan(&exists)
	if exists {
		t.Fatal("revoked operation changed target")
	}
}
func TestControlRejectionPolicyChangeAndTargetConflict(t *testing.T) {
	for _, scenario := range []string{"rejection", "policy", "target", "grant", "person"} {
		t.Run(scenario, func(t *testing.T) {
			f := newControlFixture(t)
			ctx := context.Background()
			r := submitClient(t, f, "one")
			if scenario == "rejection" {
				if _, e := f.c.Vote(ctx, f.tokens[1], r.ID, r.Digest, false, unique(t)); e != nil {
					t.Fatal(e)
				}
				if _, e := f.c.Vote(ctx, f.tokens[2], r.ID, r.Digest, true, unique(t)); !errors.Is(e, ErrConflict) {
					t.Fatal("rejected request resumed", e)
				}
				return
			}
			approveControl(t, f, r)
			switch scenario {
			case "policy":
				_, _ = f.db.Exec(`UPDATE keygate.control_policies SET version=version+1 WHERE environment=$1`, f.c.environment)
			case "target":
				_, _ = f.db.Exec(`INSERT INTO keygate.clients(environment,client_id,name,client_type,profile_id,profile_version,state) VALUES($1,'one','Existing','backend','backend',1,'enabled')`, f.c.environment)
			case "grant":
				_, _ = f.db.Exec(`UPDATE keygate.role_grants SET revision=revision+1 WHERE environment=$1 AND principal_id=$2`, f.c.environment, f.bootstrap.Principals[1].ID)
			case "person":
				_, _ = f.db.Exec(`UPDATE keygate.principals SET person_id='changed',revision=revision+1 WHERE environment=$1 AND principal_id=$2`, f.c.environment, f.bootstrap.Principals[1].ID)
			}
			if e := f.c.ExecuteLocal(ctx, r.ID, r.Digest, unique(t)); e == nil {
				t.Fatal("stale authority executed")
			}
		})
	}
}

func TestControlReadRevocationAndAuditRollback(t *testing.T) {
	f := newControlFixture(t)
	ctx := context.Background()
	r := submitClient(t, f, "one")
	approveControl(t, f, r)
	// 夹具使用随机十六进制 ID 构造仅针对本申请的故障约束，不影响其他并发测试的审计。
	constraint := "audit_fault_" + unique(t)
	if _, e := f.db.Exec(fmt.Sprintf("ALTER TABLE keygate.audit_events ADD CONSTRAINT %s CHECK(action <> 'control_execute' OR target_id <> '%s')", constraint, r.ID)); e != nil {
		t.Fatal(e)
	}
	defer f.db.Exec("ALTER TABLE keygate.audit_events DROP CONSTRAINT IF EXISTS " + constraint)
	if e := f.c.ExecuteLocal(ctx, r.ID, r.Digest, unique(t)); e == nil {
		t.Fatal("audit failure accepted")
	}
	var clients, executions int
	var executed bool
	if e := f.db.QueryRow(`SELECT (SELECT count(*) FROM keygate.clients WHERE environment=$1),(SELECT count(*) FROM keygate.control_executions WHERE environment=$1),executed FROM keygate.control_requests WHERE environment=$1 AND request_id=$2`, f.c.environment, r.ID).Scan(&clients, &executions, &executed); e != nil || clients != 0 || executions != 0 || executed {
		t.Fatal("partial execution survived audit failure", e)
	}
	if _, e := f.db.Exec("ALTER TABLE keygate.audit_events DROP CONSTRAINT " + constraint); e != nil {
		t.Fatal(e)
	}
	if e := f.c.ExecuteLocal(ctx, r.ID, r.Digest, unique(t)); e != nil {
		t.Fatal(e)
	}
	if _, e := f.db.Exec(`UPDATE keygate.role_grants SET enabled=false,revision=revision+1 WHERE environment=$1 AND principal_id=$2`, f.c.environment, f.bootstrap.Principals[0].ID); e != nil {
		t.Fatal(e)
	}
	if _, e := f.c.Request(ctx, f.tokens[0], r.ID); !errors.Is(e, ErrDenied) {
		t.Fatal("revoked applicant read request", e)
	}
}
