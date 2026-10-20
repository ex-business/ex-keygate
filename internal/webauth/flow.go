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
	mu                  sync.Mutex
	plugins             map[string]*pluginRuntime
	sealed              bool
	roots               map[string]*storage.DevelopmentKeys
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
	return s.enableSimulatedFlow(ctx, "demo-"+hexToken(), "", nil, nil)
}

// InitializePersistentSimulatedFlow 仅显式首次初始化；原域哨兵不可覆盖，材料必须先加密持久化。
func (s *Service) InitializePersistentSimulatedFlow(ctx context.Context, environment, rootID string, material []byte, persist func(string, []byte) error) error {
	if persist == nil || len(material) != 32 {
		return ErrConfig
	}
	return s.enableSimulatedFlow(ctx, environment, rootID, material, persist)
}
func (s *Service) enableSimulatedFlow(ctx context.Context, environment, root string, material []byte, persist func(string, []byte) error) error {
	if s.handlerStarted.Load() || s.flow != nil || !s.config.Identity.DevelopmentMode || s.config.Identity.ClientID != mocksso.ClientID || len(s.config.Identity.AllowedACR) != 1 || s.config.Identity.AllowedACR[0] != mocksso.SimulatedACR {
		return ErrConfig
	}
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
			grants = append(grants, access.Grant{PrincipalID: p.ID, Role: access.PolicyAdmin})
			grants = append(grants, access.Grant{PrincipalID: p.ID, Role: access.Auditor})
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
	if material == nil {
		material, e = keycrypto.Generate()
		if e != nil {
			return e
		}
		defer clear(material)
	}
	if root == "" {
		root = "demo-client-root-" + hexToken()
	}
	if persist != nil {
		if e = persist(root, material); e != nil {
			return e
		}
		control.SetRootPersistence(persist)
	}
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
	s.flow = &developmentFlow{control: control, keys: keys, environment: environment, rootID: root, roots: map[string]*storage.DevelopmentKeys{root: keys}}
	s.logger.WarnContext(ctx, "已显式开启模拟密钥业务流程，仅供开发测试，模拟审批不代表真实多人授权", "environment", environment, "result", "enabled")
	return nil
}

// 根集合仅保存进程内软件材料；新增根经批准写入后才对当前进程可见。
func (f *developmentFlow) keySnapshot() ([]*storage.DevelopmentKeys, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []*storage.DevelopmentKeys{}
	for _, k := range f.roots {
		out = append(out, k)
	}
	return out, f.rootID
}
func (f *developmentFlow) keyFor(root string) *storage.DevelopmentKeys {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.roots[root]
}

// ResumeQuarantinedSimulatedFlow 只恢复显式核验后的开发管理域；不重开 bootstrap，也不加载或猜测旧根。
// 空根集合使所有旧客户端认证拒绝，必须经新根和隔离换钥的独立多人审批才能恢复。
func (s *Service) ResumeQuarantinedSimulatedFlow(ctx context.Context, environment string) error {
	if s.handlerStarted.Load() || s.flow != nil || !s.config.Identity.DevelopmentMode || s.config.Identity.ClientID != mocksso.ClientID || len(s.config.Identity.AllowedACR) != 1 || s.config.Identity.AllowedACR[0] != mocksso.SimulatedACR {
		return ErrConfig
	}
	c, e := storage.NewDevelopmentControl(s.config.Environment, environment, s.profile, s.store)
	if e != nil {
		return e
	}
	if e = c.CheckQuarantinedOffline(ctx); e != nil {
		return e
	}
	s.flow = &developmentFlow{control: c, environment: environment, roots: map[string]*storage.DevelopmentKeys{}}
	s.logger.WarnContext(ctx, "已恢复隔离的开发管理域，旧根未加载，客户端须重新审批换钥", "environment", environment, "result", "quarantined")
	return nil
}

// RunLifecycleMaintenance 是显式开发启动的过期收尾循环，不自动执行需多人审批的业务申请。
// 单次有超时、空转不写审计/日志，多实例通过权威域锁串行，退出跟随服务上下文。
func (s *Service) RunLifecycleMaintenance(ctx context.Context) {
	if s.flow == nil {
		return
	}
	run := func() {
		task, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		trace := "maintenance-" + hexToken()
		n, e := s.flow.control.MaintainExpiredLifecycle(task, trace)
		if e != nil {
			if ctx.Err() == nil {
				s.logger.WarnContext(ctx, "过期生命周期收尾失败，认证仍按数据库期限拒绝", "request_id", trace, "environment", s.flow.environment, "result", "failed")
			}
			return
		}
		if n > 0 {
			s.logger.InfoContext(ctx, "过期生命周期已自动收尾", "request_id", trace, "environment", s.flow.environment, "changed", n, "result", "success")
		}
	}
	run()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}
