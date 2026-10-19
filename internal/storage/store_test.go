package storage

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"ex-keygate/internal/approval"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func database(t *testing.T) (*Store, *sql.DB) {
	t.Helper()
	dsn := os.Getenv("KEYGATE_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires disposable PostgreSQL: run scripts/test-postgres.py")
	}
	if !strings.Contains(dsn, "/keygate_test?") {
		t.Fatal("test database name must be keygate_test")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal("open database failed")
	}
	t.Cleanup(func() { db.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err = Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	s, _ := New(db)
	return s, db
}
func unique(t *testing.T) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("t%x", b)
}
func TestCrossNodeNonce(t *testing.T) {
	a, db := database(t)
	b, _ := New(db)
	scope := Scope{"test", unique(t), "key", 1}
	nonce := make([]byte, 32)
	rand.Read(nonce)
	var accepted atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := a
			if i%2 == 1 {
				s = b
			}
			ok, err := s.ConsumeNonce(context.Background(), scope, nonce, time.Now().Add(time.Minute))
			if err != nil {
				t.Error(err)
			}
			if ok {
				accepted.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatal("replay accepted", accepted.Load())
	}
	scope.ClientID = unique(t)
	ok, err := a.ConsumeNonce(context.Background(), scope, nonce, time.Now().Add(time.Minute))
	if err != nil || !ok {
		t.Fatal(err)
	}
	for _, until := range []time.Time{time.Now().Add(-time.Minute), time.Now().Add(time.Hour)} {
		ok, err = a.ConsumeNonce(context.Background(), Scope{"test", unique(t), "key", 1}, nonce, until)
		if err != nil || ok {
			t.Fatal("invalid expiry accepted", err)
		}
	}
}
func audit(root, event, action, result string) Audit {
	return Audit{event, "request", "actor", action, root, result}
}
func TestBudgetConcurrencyAndAuditRollback(t *testing.T) {
	s, db := database(t)
	root := unique(t)
	ctx := context.Background()
	if err := s.RegisterRootBudget(ctx, root, 3, audit(root, unique(t), "root_budget_register", "success")); err != nil {
		t.Fatal(err)
	}
	other, _ := New(db)
	var accepted atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			node := s
			if i%2 == 1 {
				node = other
			}
			err := node.ReserveWrappingUse(ctx, root, audit(root, fmt.Sprintf("%s-%d", root, i), "root_wrap_reserve", "reserved"))
			if err == nil {
				accepted.Add(1)
			} else if !errors.Is(err, ErrBudget) {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if accepted.Load() != 3 {
		t.Fatal("budget exceeded", accepted.Load())
	}
	root = unique(t)
	event := unique(t)
	if err := s.RegisterRootBudget(ctx, root, 2, audit(root, event, "root_budget_register", "success")); err != nil {
		t.Fatal(err)
	}
	if err := s.ReserveWrappingUse(ctx, root, audit(root, event, "root_wrap_reserve", "reserved")); err == nil {
		t.Fatal("duplicate audit accepted")
	}
	var used int64
	if err := db.QueryRow("SELECT used FROM keygate.root_budgets WHERE root_id=$1", root).Scan(&used); err != nil {
		t.Fatal(err)
	}
	if used != 0 {
		t.Fatal("usage survived audit rollback")
	}
}

func TestApprovalVotesAcrossNodes(t *testing.T) {
	s, db := database(t)
	other, _ := New(db)
	ctx := context.Background()
	id := unique(t)
	now := time.Now().Add(-time.Second)
	r, err := approval.New(id, "owner", approval.Operation{Kind: "rotate", Target: "client", TargetVersion: 1, Parameters: []byte(`{}`)}, approval.Policy{ID: "policy", Version: 1, Approvers: []string{"alice", "bob", "carol"}, Threshold: 2}, now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err = s.CreateApproval(ctx, r, Audit{unique(t), "request", "owner", "approval_create", id, "pending"}); err != nil {
		t.Fatal(err)
	}
	var accepted atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			node := s
			if i%2 == 1 {
				node = other
			}
			_, err := node.CastVote(ctx, id, r.Digest(), "alice", true, Audit{fmt.Sprintf("%s-%d", id, i), "request", "alice", "approval_vote", id, "accepted"})
			if err == nil {
				accepted.Add(1)
			} else if !errors.Is(err, approval.ErrDuplicate) {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatal("duplicate votes counted", accepted.Load())
	}
	if _, err = other.CastVote(ctx, id, "wrong", "bob", true, Audit{unique(t), "request", "bob", "approval_vote", id, "accepted"}); !errors.Is(err, approval.ErrConflict) {
		t.Fatal(err)
	}
	approved, err := other.CastVote(ctx, id, r.Digest(), "bob", true, Audit{unique(t), "request", "bob", "approval_vote", id, "accepted"})
	if err != nil || approved.State() != approval.Approved {
		t.Fatal(err)
	}
	got, err := s.Approval(ctx, id)
	if err != nil || got.State() != approval.Approved || len(got.Votes()) != 2 {
		t.Fatal("persistent decision wrong", err)
	}
}
func TestApprovalAuditFailureRollsBack(t *testing.T) {
	s, _ := database(t)
	ctx := context.Background()
	id := unique(t)
	event := unique(t)
	now := time.Now().Add(-time.Second)
	r, err := approval.New(id, "owner", approval.Operation{Kind: "rotate", Target: "client", TargetVersion: 1, Parameters: []byte(`{}`)}, approval.Policy{ID: "policy", Version: 1, Approvers: []string{"alice", "bob"}, Threshold: 2}, now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err = s.CreateApproval(ctx, r, Audit{event, "request", "owner", "approval_create", id, "pending"}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.CastVote(ctx, id, r.Digest(), "alice", true, Audit{event, "request", "alice", "approval_vote", id, "accepted"}); err == nil {
		t.Fatal("audit conflict accepted")
	}
	got, err := s.Approval(ctx, id)
	if err != nil || got.Revision() != 1 || len(got.Votes()) != 0 {
		t.Fatal("vote survived rollback", err)
	}
}
