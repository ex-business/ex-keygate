package webauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"ex-keygate/internal/access"
	"ex-keygate/internal/client"
	"ex-keygate/internal/keycrypto"
	"ex-keygate/internal/mocksso"
	"ex-keygate/internal/storage"
)

// developmentFlow 仅在显式启用模拟流程后、启动 HTTP 服务前创建，运行中不切换权限域或根。
type developmentFlow struct {
	control             *storage.DevelopmentControl
	keys                *storage.DevelopmentKeys
	environment, rootID string
	limiter             requestLimiter
}
type requestLimiter struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
}

func (l *requestLimiter) allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if l.last.IsZero() {
		l.tokens = 256
	} else {
		l.tokens += now.Sub(l.last).Seconds() * 64
		if l.tokens > 256 {
			l.tokens = 256
		}
	}
	l.last = now
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}

// EnableSimulatedFlow 必须由开发启动命令显式调用；三个模拟账号不代表真实的三名人员或 MFA。
// 每次启动创建隔离的临时安全域和软件根，绝不根据“缺少管理员”重开已有域初始化。
func (s *Service) EnableSimulatedFlow(ctx context.Context) error {
	if s.flow != nil || !s.config.Identity.DevelopmentMode || s.config.Identity.ClientID != mocksso.ClientID || len(s.config.Identity.AllowedACR) != 1 || s.config.Identity.AllowedACR[0] != mocksso.SimulatedACR {
		return ErrConfig
	}
	environment := "demo-" + hexToken()
	control, e := storage.NewDevelopmentControl(s.config.Environment, environment, s.profile, s.store)
	if e != nil {
		return e
	}
	people := []access.Principal{}
	grants := []access.Grant{}
	for i, subject := range []string{"demo-requester", "demo-approver-1", "demo-approver-2"} {
		p, e := access.NewPrincipal(s.config.Identity.Issuer, subject, subject)
		if e != nil {
			return e
		}
		people = append(people, p)
		grants = append(grants, access.Grant{PrincipalID: p.ID, Role: access.Viewer})
		role := access.Approver
		if i == 0 {
			role = access.Requester
			grants = append(grants, access.Grant{PrincipalID: p.ID, Role: access.EmergencyOperator})
		}
		grants = append(grants, access.Grant{PrincipalID: p.ID, Role: role})
	}
	profiles := []client.Profile{}
	for _, kind := range []client.Type{client.Backend, client.Desktop, client.Mobile, client.Browser} {
		p := client.Profile{ID: string(kind), Version: 1, ClientType: kind, Method: client.FederatedSession, Storage: client.NoSecret, ProviderID: "oidc"}
		if kind == client.Backend {
			p.Method = client.HMAC
			p.Storage = client.ServerVault
			p.ProviderID = "internal-software"
		}
		profiles = append(profiles, p)
	}
	evidence := sha256.Sum256([]byte("SIMULATED OFFLINE CONFIRMATION ONLY:" + environment))
	b := storage.Bootstrap{Principals: people, Grants: grants, Profiles: profiles, Approvers: []string{people[1].ID, people[2].ID}, Threshold: 2, Witnesses: [2]string{people[0].ID, people[1].ID}, EvidenceHash: hex.EncodeToString(evidence[:])}
	if e = control.BootstrapOffline(ctx, b, "demo-bootstrap-"+hexToken()); e != nil {
		return errors.New("development control bootstrap failed")
	}
	material, e := keycrypto.Generate()
	if e != nil {
		return e
	}
	defer clear(material)
	root := "demo-client-root-" + hexToken()
	if e = s.store.RegisterRootBudget(ctx, root, 100000, audit("demo-budget-"+hexToken(), "offline-bootstrap", "root_budget_register", root, "success")); e != nil {
		return e
	}
	keys, e := storage.NewDevelopmentKeys(control, root, material, s.protector.RootID())
	if e != nil {
		return e
	}
	if e = keys.RegisterRootOffline(ctx, "demo-root-"+hexToken()); e != nil {
		return e
	}
	s.flow = &developmentFlow{control: control, keys: keys, environment: environment, rootID: root}
	s.logger.WarnContext(ctx, "已显式开启模拟密钥业务流程，仅供开发测试，模拟审批不代表真实多人授权", "environment", environment, "result", "enabled")
	return nil
}
