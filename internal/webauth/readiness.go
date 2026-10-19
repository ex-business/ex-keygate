package webauth

import (
	"context"
	"ex-keygate/internal/mocksso"
	"ex-keygate/internal/storage"
	"net/http"
	"time"
)

// DevelopmentRoot 只允许可信启动器在开发/测试时从受保护通道提供；不得作为管理 HTTP 的输入或持久化输出。
type DevelopmentRoot struct {
	ID       string
	Material []byte `json:"-"`
}

// AttachSimulatedNode 加入已有开发域，不创建管理员、根、预算或默认授权；启动器必须先装配同一身份与登录保护配置。
// 根材料经数据库指纹核对，缺根或错根立即拒绝；本方法不实现根分发，真实生产须接托管系统。
func (s *Service) AttachSimulatedNode(ctx context.Context, environment string, roots []DevelopmentRoot) error {
	if s.handlerStarted.Load() || s.flow != nil || !s.config.Identity.DevelopmentMode || s.config.Identity.ClientID != mocksso.ClientID || len(roots) == 0 || len(roots) > 128 {
		return ErrConfig
	}
	return s.attachAuthorizedNode(ctx, environment, roots)
}

// AttachOIDCManagement 只挂接受控离线初始化的安全域，不按 SSO 的 roles/groups 自动创建人员或授权。
// 当前仍限开发/测试软件根；真实身份接入不代表生产托管与基础设施验收已经通过。
func (s *Service) AttachOIDCManagement(ctx context.Context, environment string, roots []DevelopmentRoot) error {
	if s.handlerStarted.Load() || s.flow != nil || s.config.Identity.DevelopmentMode || len(roots) == 0 || len(roots) > 128 {
		return ErrConfig
	}
	return s.attachAuthorizedNode(ctx, environment, roots)
}
func (s *Service) attachAuthorizedNode(ctx context.Context, environment string, roots []DevelopmentRoot) error {
	c, e := storage.NewDevelopmentControl(s.config.Environment, environment, s.profile, s.store)
	if e != nil {
		return e
	}
	f := &developmentFlow{control: c, environment: environment, roots: map[string]*storage.DevelopmentKeys{}}
	for _, r := range roots {
		if f.roots[r.ID] != nil {
			return ErrConfig
		}
		k, e := storage.NewDevelopmentKeys(c, r.ID, r.Material, s.protector.RootID())
		if e != nil {
			return e
		}
		if e = k.CheckHealth(ctx); e != nil {
			return e
		}
		f.roots[r.ID] = k
	}
	// 多根场景不猜测新签发默认根；已有签发、领取和认证按权威记录选择根，后续新根仍经审批。
	if len(roots) == 1 {
		f.rootID = roots[0].ID
		f.keys = f.roots[f.rootID]
	}
	s.flow = f
	if e = s.checkBusinessReadiness(ctx); e != nil {
		s.flow = nil
		return e
	}
	s.logger.InfoContext(ctx, "节点已挂接已有授权域，未创建人员或重新初始化权限", "environment", environment, "result", "attached")
	return nil
}

// checkBusinessReadiness 检查权威库和本进程所需根，不能用存活检查或历史健康缓存代替认证就绪。
func (s *Service) checkBusinessReadiness(ctx context.Context) error {
	if s.flow == nil {
		return storage.ErrDenied
	}
	if e := s.store.CheckReadiness(ctx); e != nil {
		return e
	}
	required, e := s.flow.control.RequiredRootIDs(ctx)
	if e != nil {
		return e
	}
	if len(required) == 0 {
		return storage.ErrDenied
	}
	for _, id := range required {
		k := s.flow.keyFor(id)
		if k == nil {
			return storage.ErrDenied
		}
		if e = k.CheckHealth(ctx); e != nil {
			return e
		}
	}
	return nil
}
func (s *Service) readiness(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	w.Header().Set("Cache-Control", "no-store")
	if s.checkBusinessReadiness(ctx) != nil {
		businessJSON(w, 503, map[string]string{"status": "unavailable"})
		return
	}
	businessJSON(w, 200, map[string]string{"status": "ready"})
}
