package storage

import (
	"context"
	"database/sql"
	"errors"
	"ex-keygate/internal/access"
	"ex-keygate/internal/mfa"
)

type ConsoleGrant struct {
	Role     access.Role `json:"role"`
	ClientID string      `json:"clientId"`
}
type ConsoleIdentity struct {
	PrincipalID string         `json:"principalId"`
	PersonID    string         `json:"personId"`
	Grants      []ConsoleGrant `json:"grants"`
	MFARequired bool           `json:"mfaRequired"`
	MFAVerified bool           `json:"mfaVerified"`
	Policy      *mfa.Policy    `json:"policy,omitempty"`
	Factors     []mfa.Factor   `json:"factors"`
}

// ConsoleIdentity 仅返回本人的角色范围和脱敏绑定说明；允许在MFA前展示验证入口，不返回地址、种子或他人资料。
func (c *DevelopmentControl) ConsoleIdentity(ctx context.Context, token string) (ConsoleIdentity, error) {
	tx, e := c.begin(ctx)
	if e != nil {
		return ConsoleIdentity{}, e
	}
	defer tx.Rollback()
	a, e := c.identityActor(ctx, tx, token, false)
	if e != nil {
		return ConsoleIdentity{}, e
	}
	out := ConsoleIdentity{PrincipalID: a.id, PersonID: a.person, Grants: []ConsoleGrant{}, Factors: []mfa.Factor{}}
	if e = tx.QueryRowContext(ctx, `SELECT native_mfa_required FROM keygate.security_domains WHERE environment=$1`, c.environment).Scan(&out.MFARequired); e != nil {
		return out, e
	}
	if out.MFARequired {
		e = c.requireNativeMFA(ctx, tx, token, a)
		if e != nil && !errors.Is(e, ErrDenied) {
			return out, e
		}
		out.MFAVerified = e == nil
	} else {
		out.MFAVerified = true
	}
	rows, e := tx.QueryContext(ctx, `SELECT role,client_id FROM keygate.role_grants WHERE environment=$1 AND principal_id=$2 AND enabled ORDER BY role,client_id`, c.environment, a.id)
	if e != nil {
		return out, e
	}
	for rows.Next() {
		var g ConsoleGrant
		if e = rows.Scan(&g.Role, &g.ClientID); e != nil {
			rows.Close()
			return out, e
		}
		out.Grants = append(out.Grants, g)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return out, e
	}
	policy, _, factors, e := c.mfaPolicy(ctx, tx, a.id)
	if e == nil {
		out.Policy = &policy
		out.Factors = factors
	} else if !errors.Is(e, ErrDenied) {
		return out, e
	}
	if e = tx.Commit(); e != nil {
		return ConsoleIdentity{}, e
	}
	return out, nil
}

type ConsolePerson struct {
	Account       *AccountInfo   `json:"account,omitempty"`
	Policy        *mfa.Policy    `json:"policy,omitempty"`
	Factors       []mfa.Factor   `json:"factors"`
	Revision      string         `json:"revision"`
	Issuer        string         `json:"issuer"`
	MFAConfigured bool           `json:"mfaConfigured"`
	PrincipalID   string         `json:"principalId"`
	PersonID      string         `json:"personId"`
	Enabled       bool           `json:"enabled"`
	Grants        []ConsoleGrant `json:"grants"`
}
type ConsoleSettings struct {
	Version    string          `json:"version"`
	M          int             `json:"m"`
	Sequential bool            `json:"sequential"`
	Approvers  []string        `json:"approvers"`
	People     []ConsolePerson `json:"people"`
}

// ConsoleSettings 组织人员及完整策略只向通过MFA且具有全域查看与策略管理/审计角色的身份开放；局部viewer不能用后台概览扩大授权范围。
func (c *DevelopmentControl) ConsoleSettings(ctx context.Context, token string) (ConsoleSettings, error) {
	tx, e := c.begin(ctx)
	if e != nil {
		return ConsoleSettings{}, e
	}
	defer tx.Rollback()
	a, e := c.actor(ctx, tx, token, false)
	if e != nil {
		return ConsoleSettings{}, e
	}
	if !c.has(ctx, tx, a.id, access.Viewer, "") || (!c.has(ctx, tx, a.id, access.PolicyAdmin, "") && !c.has(ctx, tx, a.id, access.Auditor, "")) {
		return ConsoleSettings{}, ErrDenied
	}
	out := ConsoleSettings{Approvers: []string{}, People: []ConsolePerson{}}
	if e = tx.QueryRowContext(ctx, `SELECT version::text,threshold,sequential FROM keygate.control_policies WHERE environment=$1`, c.environment).Scan(&out.Version, &out.M, &out.Sequential); e != nil {
		return out, e
	}
	rows, e := tx.QueryContext(ctx, `SELECT principal_id FROM keygate.control_policy_members WHERE environment=$1 ORDER BY ordinal,principal_id`, c.environment)
	if e != nil {
		return out, e
	}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return out, e
		}
		out.Approvers = append(out.Approvers, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return out, e
	}
	rows, e = tx.QueryContext(ctx, `SELECT p.principal_id,p.person_id,p.enabled,p.revision::text,p.issuer,EXISTS(SELECT 1 FROM keygate.mfa_policies m WHERE m.environment=p.environment AND m.principal_id=p.principal_id) FROM keygate.principals p WHERE environment=$1 ORDER BY person_id,principal_id LIMIT 128`, c.environment)
	if e != nil {
		return out, e
	}
	for rows.Next() {
		var p ConsolePerson
		if e = rows.Scan(&p.PrincipalID, &p.PersonID, &p.Enabled, &p.Revision, &p.Issuer, &p.MFAConfigured); e != nil {
			rows.Close()
			return out, e
		}
		p.Grants = []ConsoleGrant{}
		out.People = append(out.People, p)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return out, e
	}
	for i := range out.People {
		grants, e := consoleGrants(ctx, tx, c.environment, out.People[i].PrincipalID)
		if e != nil {
			return out, e
		}
		out.People[i].Grants = grants
		out.People[i].Account, e = c.accountInfo(ctx, tx, out.People[i].PrincipalID)
		if e != nil {
			return out, e
		}
		policy, _, factors, err := c.mfaPolicy(ctx, tx, out.People[i].PrincipalID)
		if err == nil {
			out.People[i].Policy = &policy
			out.People[i].Factors = factors
		} else if !errors.Is(err, ErrDenied) {
			return out, err
		}
	}
	if e = tx.Commit(); e != nil {
		return ConsoleSettings{}, e
	}
	return out, nil
}
func consoleGrants(ctx context.Context, tx *sql.Tx, environment, principal string) ([]ConsoleGrant, error) {
	rows, e := tx.QueryContext(ctx, `SELECT role,client_id FROM keygate.role_grants WHERE environment=$1 AND principal_id=$2 AND enabled ORDER BY role,client_id`, environment, principal)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []ConsoleGrant{}
	for rows.Next() {
		var g ConsoleGrant
		if e = rows.Scan(&g.Role, &g.ClientID); e != nil {
			return nil, e
		}
		out = append(out, g)
	}
	return out, rows.Err()
}
