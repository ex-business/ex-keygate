// Package access 定义本地授权模型；OIDC 身份与业务授权分别管理。
package access

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"ex-keygate/internal/identity"
	"net/url"
	"regexp"

	"ex-keygate/internal/client"
)

var ErrInvalid = errors.New("invalid access model")
var id = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)

func ValidID(s string) bool { return id.MatchString(s) }

type Role string

const (
	Viewer            Role = "viewer"
	Requester         Role = "requester"
	Approver          Role = "approver"
	PolicyAdmin       Role = "policy_admin"
	Auditor           Role = "auditor"
	EmergencyOperator Role = "emergency_operator"
)

func (r Role) Valid() bool {
	switch r {
	case Viewer, Requester, Approver, PolicyAdmin, Auditor, EmergencyOperator:
		return true
	}
	return false
}

type Principal struct {
	ID          string
	Issuer      string
	SubjectHash string
	PersonID    string
	Enabled     bool
	Revision    int64
}

// NewPrincipal 使用与 OIDC 验证器一致的 issuer/sub 摘要，不能用昵称或邮箱认领账号。
// personID 只能由离线核验或受控授权流程提供，不能由登录账号自行修改。
func NewPrincipal(issuer, subject, personID string) (Principal, error) {
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(issuer) > 2048 || len(subject) == 0 || len(subject) > 1024 || !ValidID(personID) {
		return Principal{}, ErrInvalid
	}
	sh := sha256.Sum256([]byte(subject))
	return Principal{identity.PrincipalID(issuer, subject), issuer, hex.EncodeToString(sh[:]), personID, true, 1}, nil
}
func (p Principal) Validate() error {
	if len(p.ID) != 69 || p.ID[:5] != "oidc-" || len(p.SubjectHash) != 64 || !ValidID(p.PersonID) || p.Revision != 1 || !p.Enabled {
		return ErrInvalid
	}
	for _, v := range []string{p.ID[5:], p.SubjectHash} {
		if _, err := hex.DecodeString(v); err != nil {
			return ErrInvalid
		}
	}
	u, e := url.Parse(p.Issuer)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return ErrInvalid
	}
	return nil
}

type Grant struct {
	PrincipalID string
	Role        Role
	// 空客户端表示本环境全部客户端；不是跨环境通配符。
	ClientID string
}

func (g Grant) Validate() error {
	if !ValidID(g.PrincipalID) || !g.Role.Valid() || (g.ClientID != "" && !ValidID(g.ClientID)) {
		return ErrInvalid
	}
	return nil
}

type Client struct {
	Environment    string      `json:"environment"`
	ID             string      `json:"id"`
	Name           string      `json:"name"`
	Type           client.Type `json:"type"`
	ProfileID      string      `json:"profileId"`
	ProfileVersion uint64      `json:"profileVersion,string"`
	State          string      `json:"state"`
	Revision       uint64      `json:"revision,string"`
}

// ValidateProfileV1 仅开放已有实现计划的组合，不把占位硬件能力当成可用认证。
func ValidateProfileV1(p client.Profile) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if p.Version > 9007199254740991 {
		return ErrInvalid
	}
	if p.ClientType == client.Backend && p.Method == client.HMAC && p.Storage == client.ServerVault && p.ProviderID == "internal-software" {
		return nil
	}
	if p.ClientType != client.Backend && p.Method == client.FederatedSession && p.Storage == client.NoSecret {
		return nil
	}
	return ErrInvalid
}
