package approval

import (
	"errors"
	"testing"
	"time"
)

func fixture(t *testing.T) (Request, time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	r, err := New("request-1", "owner", Operation{"rotate", "client-1", 4, []byte(`{"provider":"local"}`)}, Policy{"policy-1", 1, []string{"a", "b", "c"}, 2}, now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return r, now
}
func TestApprovalAndExecution(t *testing.T) {
	r, now := fixture(t)
	a, err := r.Vote("a", true, now)
	if err != nil || a.State() != Pending {
		t.Fatal(a, err)
	}
	b, err := a.Vote("b", true, now)
	if err != nil || b.State() != Approved {
		t.Fatal(b, err)
	}
	if r.Revision() != 1 || len(r.Votes()) != 0 || b.Digest() != r.Digest() {
		t.Fatal("snapshot mutated")
	}
	if _, err = b.Begin(3, 1, now); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	if _, err = b.Begin(4, 2, now); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	running, err := b.Begin(4, 1, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = running.Begin(4, 1, now); !errors.Is(err, ErrState) {
		t.Fatal(err)
	}
	if running.State() != Approved || running.Execution() != Executing {
		t.Fatal("approval decision lost")
	}
	unknown, err := running.Finish(Unknown)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = unknown.Begin(4, 1, now); !errors.Is(err, ErrState) {
		t.Fatal(err)
	}
}
func TestDeniedVotes(t *testing.T) {
	r, now := fixture(t)
	for _, actor := range []string{"owner", "stranger", ""} {
		if _, err := r.Vote(actor, true, now); !errors.Is(err, ErrForbidden) {
			t.Fatal(actor, err)
		}
	}
	a, _ := r.Vote("a", true, now)
	if _, err := a.Vote("a", true, now); !errors.Is(err, ErrDuplicate) {
		t.Fatal(err)
	}
	if _, err := r.Vote("a", true, now.Add(time.Hour)); !errors.Is(err, ErrExpired) {
		t.Fatal(err)
	}
	rejected, err := a.Vote("b", false, now)
	if err != nil || rejected.State() != Rejected {
		t.Fatal(err)
	}
	if _, err := rejected.Vote("c", true, now); !errors.Is(err, ErrState) {
		t.Fatal(err)
	}
	if _, err := r.Cancel("stranger", now); !errors.Is(err, ErrForbidden) {
		t.Fatal(err)
	}
	cancelled, err := r.Cancel("owner", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cancelled.Vote("a", true, now); !errors.Is(err, ErrState) {
		t.Fatal(err)
	}
}
func TestCopiesAndInvalidPolicy(t *testing.T) {
	r, now := fixture(t)
	op := r.Operation()
	op.Parameters[0] = 'x'
	if string(r.Operation().Parameters) != `{"provider":"local"}` {
		t.Fatal("operation alias")
	}
	for _, p := range []Policy{{"p", 1, []string{"a", "a"}, 2}, {"p", 1, []string{"owner", "a"}, 2}, {"p", 1, []string{"a"}, 1}} {
		if _, err := New("r", "owner", r.Operation(), p, now, now.Add(time.Hour)); !errors.Is(err, ErrInvalid) {
			t.Fatal(err)
		}
	}
	if _, err := (Request{}).Begin(0, 0, now); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
}

func TestDraftReplay(t *testing.T) {
	r, now := fixture(t)
	a, _ := r.Vote("a", true, now)
	approved, _ := a.Vote("b", true, now.Add(time.Second))
	restored, err := RestoreVotes(r.Draft(), approved.Votes())
	if err != nil || restored.State() != Approved || restored.Digest() != r.Digest() || restored.Revision() != approved.Revision() {
		t.Fatal("journal restore failed", err)
	}
	d := r.Draft()
	d.Policy.Approvers[0] = "intruder"
	if _, err = r.Vote("a", true, now); err != nil {
		t.Fatal("draft aliases policy")
	}
	if _, err = RestoreVotes(r.Draft(), []Vote{{"a", now.Add(time.Second), true}, {"b", now, true}}); !errors.Is(err, ErrInvalid) {
		t.Fatal("backdated journal accepted", err)
	}
	if _, err = RestoreVotes(r.Draft(), []Vote{{"a", now, true}, {"a", now, true}}); !errors.Is(err, ErrDuplicate) {
		t.Fatal(err)
	}
}

func TestVoteRejectsClockRollback(t *testing.T) {
	r, now := fixture(t)
	first, err := r.Vote("a", true, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = first.Vote("b", true, now); !errors.Is(err, ErrInvalid) {
		t.Fatal("backdated vote accepted", err)
	}
	if first.Revision() != 2 || len(first.Votes()) != 1 {
		t.Fatal("failed vote mutated state")
	}
}
