package keyservice

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"ex-keygate/internal/config"
	"ex-keygate/internal/keycrypto"
	"ex-keygate/internal/storage"
	"os"
	"strings"
	"testing"
)

func TestProductionSoftwareRejected(t *testing.T) {
	if _, err := NewDevelopment(config.Production, "root", make([]byte, 32), nil); !errors.Is(err, ErrDevelopmentOnly) {
		t.Fatal(err)
	}
}
func TestDurableBudgetBeforeEncryption(t *testing.T) {
	dsn := os.Getenv("KEYGATE_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	if !strings.Contains(dsn, "/keygate_test?") {
		t.Fatal("invalid test database")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal("open failed")
	}
	defer db.Close()
	ctx := context.Background()
	if err = storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	store, _ := storage.New(db)
	var id [16]byte
	rand.Read(id[:])
	root := "root-" + hex.EncodeToString(id[:])
	key, _ := keycrypto.Generate()
	p, err := NewDevelopment(config.Test, root, key, store)
	if err != nil {
		t.Fatal(err)
	}
	binding := keycrypto.Binding{Environment: "test", ClientID: "console", KeyID: "flow", Version: 1, Purpose: "login_pkce"}
	secret, _ := keycrypto.Generate()
	if _, err = p.Seal(ctx, binding, secret, "anonymous", "request"); !errors.Is(err, storage.ErrBudget) {
		t.Fatal("missing budget allowed encryption", err)
	}
	if err = store.RegisterRootBudget(ctx, root, 1, storage.Audit{EventID: root, RequestID: "request", ActorID: "bootstrap", Action: "root_budget_register", TargetID: root, Result: "success"}); err != nil {
		t.Fatal(err)
	}
	envelope, err := p.Seal(ctx, binding, secret, "anonymous", "request")
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := p.Open(ctx, binding, envelope)
	if err != nil || hex.EncodeToString(plaintext) != hex.EncodeToString(secret) {
		t.Fatal("roundtrip failed", err)
	}
	if _, err = p.Seal(ctx, binding, secret, "anonymous", "request"); !errors.Is(err, storage.ErrBudget) {
		t.Fatal("exhausted budget allowed encryption", err)
	}
}
