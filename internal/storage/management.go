package storage

import (
	"context"
	"database/sql"
	"ex-keygate/internal/access"
	"ex-keygate/internal/client"
)

// Clients 每次根据当前 viewer 授权过滤；分页首期固定最多一百条，不返回其他范围的客户端。
func (c *DevelopmentControl) Clients(ctx context.Context, token string) ([]access.Client, error) {
	tx, e := c.begin(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	a, e := c.actor(ctx, tx, token, false)
	if e != nil {
		return nil, e
	}
	rows, e := tx.QueryContext(ctx, `SELECT c.environment,c.client_id,c.name,c.client_type,c.profile_id,c.profile_version,c.state,c.revision FROM keygate.clients c WHERE c.environment=$1 AND EXISTS(SELECT 1 FROM keygate.role_grants g WHERE g.environment=c.environment AND g.principal_id=$2 AND g.role='viewer' AND g.enabled AND (g.client_id='' OR g.client_id=c.client_id)) ORDER BY c.client_id LIMIT 100`, c.environment, a.id)
	if e != nil {
		return nil, e
	}
	out := []access.Client{}
	for rows.Next() {
		var item access.Client
		if e = rows.Scan(&item.Environment, &item.ID, &item.Name, &item.Type, &item.ProfileID, &item.ProfileVersion, &item.State, &item.Revision); e != nil {
			rows.Close()
			return nil, e
		}
		out = append(out, item)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	return out, nil
}

// Profiles 不可变配置属于环境信任信息，首期只向具备全域 viewer 的身份提供列表。
func (c *DevelopmentControl) Profiles(ctx context.Context, token string) ([]client.Profile, error) {
	tx, e := c.begin(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	a, e := c.actor(ctx, tx, token, false)
	if e != nil {
		return nil, e
	}
	if !c.has(ctx, tx, a.id, access.Viewer, "") {
		return nil, ErrDenied
	}
	rows, e := tx.QueryContext(ctx, `SELECT profile_id,version,client_type,method,storage,provider_id FROM keygate.auth_profiles WHERE environment=$1 AND enabled ORDER BY profile_id,version LIMIT 100`, c.environment)
	if e != nil {
		return nil, e
	}
	out := []client.Profile{}
	for rows.Next() {
		var p client.Profile
		if e = rows.Scan(&p.ID, &p.Version, &p.ClientType, &p.Method, &p.Storage, &p.ProviderID); e != nil {
			rows.Close()
			return nil, e
		}
		out = append(out, p)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	return out, nil
}

// Requests 只展示当前可读的最近一百条候选申请，权限撤销后不能继续读取旧快照。
func (c *DevelopmentControl) Requests(ctx context.Context, token string) ([]ControlRequest, error) {
	tx, e := c.begin(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	a, e := c.actor(ctx, tx, token, false)
	if e != nil {
		return nil, e
	}
	rows, e := tx.QueryContext(ctx, `SELECT request_id FROM keygate.control_requests WHERE environment=$1 ORDER BY expires_at DESC,request_id LIMIT 100`, c.environment)
	if e != nil {
		return nil, e
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return nil, e
		}
		ids = append(ids, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	out := []ControlRequest{}
	for _, id := range ids {
		r, m, e := c.loadRequest(ctx, tx, id)
		if e != nil {
			return nil, e
		}
		permitted := c.requestViewer(ctx, tx, a.id, m.Operation) || (a.id == m.Applicant.PrincipalID && c.has(ctx, tx, a.id, access.Requester, operationScope(m.Operation)))
		if !permitted {
			if _, e = c.currentMember(ctx, tx, m, a.id); e == nil {
				permitted = true
			}
		}
		if permitted {
			out = append(out, r)
		}
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	return out, nil
}

// executionActor 对来自浏览器的执行触发复查近期会话和原申请人资格；前端不获得执行器角色。
func (c *DevelopmentControl) executionActor(ctx context.Context, tx *sql.Tx, token string, m controlManifest) error {
	a, e := c.actor(ctx, tx, token, true)
	if e != nil {
		return e
	}
	if a.id != m.Applicant.PrincipalID {
		return ErrDenied
	}
	current, e := c.eligible(ctx, tx, a.id, access.Requester, operationScope(m.Operation))
	if e != nil {
		return e
	}
	if current != m.Applicant {
		return ErrDenied
	}
	return nil
}
