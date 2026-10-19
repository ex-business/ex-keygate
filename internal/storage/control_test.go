package storage

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"ex-keygate/internal/access"
	"ex-keygate/internal/client"
	"ex-keygate/internal/config"
)

type controlFixture struct {
	c         *DevelopmentControl
	db        *sql.DB
	bootstrap Bootstrap
	tokens    []string
	profile   string
}

func newControlFixture(t *testing.T) controlFixture {
	t.Helper()
	s, db := database(t)
	profile := strings.Repeat("a", 64)
	c, e := NewDevelopmentControl(config.Test, unique(t), profile, s)
	if e != nil {
		t.Fatal(e)
	}
	f := controlFixture{c: c, db: db, profile: profile}
	b := Bootstrap{Threshold: 2, EvidenceHash: strings.Repeat("b", 64), Profiles: []client.Profile{{ID: "backend", Version: 1, ClientType: client.Backend, Method: client.HMAC, Storage: client.ServerVault, ProviderID: "internal-software"}, {ID: "browser", Version: 1, ClientType: client.Browser, Method: client.FederatedSession, Storage: client.NoSecret, ProviderID: "oidc"}}}
	for i, subject := range []string{"owner", "alice", "bob", "alias", "viewer", "ungranted"} {
		person := subject
		if subject == "alias" {
			person = "alice"
		}
		p, e := access.NewPrincipal("https://issuer.example/"+c.environment, subject, person)
		if e != nil {
			t.Fatal(e)
		}
		b.Principals = append(b.Principals, p)
		roles := []access.Role{}
		switch i {
		case 0:
			roles = []access.Role{access.Requester, access.Viewer, access.EmergencyOperator}
		case 1, 2:
			roles = []access.Role{access.Approver}
		case 3:
			roles = []access.Role{access.Approver}
		case 4:
			roles = []access.Role{access.Viewer}
		}
		for _, r := range roles {
			g := access.Grant{PrincipalID: p.ID, Role: r}
			if i == 4 {
				g.ClientID = "one"
			}
			b.Grants = append(b.Grants, g)
		}
		token := make([]byte, 32)
		if _, e = rand.Read(token); e != nil {
			t.Fatal(e)
		}
		encoded := base64.RawURLEncoding.EncodeToString(token)
		hash := sha256.Sum256([]byte(encoded))
		if _, e = s.CreateSession(context.Background(), hash, profile, p.ID, time.Now().Add(-time.Second), Audit{unique(t), unique(t), p.ID, "session_create", hex.EncodeToString(hash[:]), "success"}); e != nil {
			t.Fatal(e)
		}
		f.tokens = append(f.tokens, encoded)
	}
	b.Approvers = []string{b.Principals[1].ID, b.Principals[2].ID}
	b.Witnesses = [2]string{b.Principals[0].ID, b.Principals[1].ID}
	f.bootstrap = b
	if e = c.BootstrapOffline(context.Background(), b, unique(t)); e != nil {
		t.Fatal(e)
	}
	return f
}
func TestControlBootstrapAndLivePermissions(t *testing.T) {
	f := newControlFixture(t)
	ctx := context.Background()
	c := f.c
	if e := c.BootstrapOffline(ctx, f.bootstrap, unique(t)); e == nil {
		t.Fatal("bootstrap reopened")
	}
	for _, token := range []string{"", strings.Repeat("a", 43), f.tokens[5]} {
		if _, e := c.Client(ctx, token, "one"); !errors.Is(e, ErrDenied) {
			t.Fatal("ungranted access", e)
		}
	}
	if _, e := c.Client(ctx, f.tokens[4], "two"); !errors.Is(e, ErrDenied) {
		t.Fatal("scope escaped", e)
	}
	other, _ := NewDevelopmentControl(config.Test, c.environment, strings.Repeat("c", 64), c.store)
	if _, e := other.Client(ctx, f.tokens[0], "one"); !errors.Is(e, ErrDenied) {
		t.Fatal("profile escaped", e)
	}
	if e := c.EmergencyDisablePrincipal(ctx, f.tokens[1], f.bootstrap.Principals[2].ID, unique(t)); !errors.Is(e, ErrDenied) {
		t.Fatal("approver gained emergency role", e)
	}
	if e := c.EmergencyDisablePrincipal(ctx, f.tokens[0], f.bootstrap.Principals[4].ID, unique(t)); e != nil {
		t.Fatal(e)
	}
	if _, e := c.Client(ctx, f.tokens[4], "one"); !errors.Is(e, ErrDenied) {
		t.Fatal("disabled principal retained access", e)
	}
	if _, e := NewDevelopmentControl(config.Production, c.environment, f.profile, c.store); e == nil {
		t.Fatal("production control enabled")
	}
}
func TestControlBootstrapAliasAndMigrationIntegrity(t *testing.T) {
	f := newControlFixture(t)
	ctx := context.Background()
	b := f.bootstrap
	b.Approvers = []string{b.Principals[1].ID, b.Principals[3].ID}
	other, _ := NewDevelopmentControl(config.Test, unique(t), f.profile, f.c.store)
	if e := other.BootstrapOffline(ctx, b, unique(t)); !errors.Is(e, ErrInvalid) {
		t.Fatal("same-person bootstrap votes", e)
	}
	var exists bool
	if e := f.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM keygate.security_domains WHERE environment=$1)`, other.environment).Scan(&exists); e != nil || exists {
		t.Fatal("invalid bootstrap persisted", e)
	}
	tx, e := f.db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	if _, e = tx.Exec(`UPDATE keygate.schema_migrations SET checksum='bad' WHERE version=1`); e != nil {
		t.Fatal(e)
	}
	if e = migrateControl(ctx, tx); e == nil {
		t.Fatal("changed migration accepted")
	}
}
