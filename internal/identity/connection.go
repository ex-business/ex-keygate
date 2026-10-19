package identity

import (
	"ex-keygate/provider"
	"net/url"
	"time"
)

// Connection 只接受可信启动配置，不从 HTTP 参数或身份声明选择 issuer、端点或认证策略。
// 密钥通过独立私有文件提供，避免被连接元数据和诊断输出泄露。
type Connection struct {
	DevelopmentOnly       bool     `json:"developmentOnly"`
	Issuer                string   `json:"issuer"`
	JWKSURL               string   `json:"jwksUrl"`
	AuthorizationEndpoint string   `json:"authorizationEndpoint"`
	TokenEndpoint         string   `json:"tokenEndpoint"`
	ClientID              string   `json:"clientId"`
	RedirectURI           string   `json:"redirectUri"`
	CAFile                string   `json:"caFile,omitempty"`
	AllowedACR            []string `json:"allowedAcr"`
	RequiredAMR           []string `json:"requiredAmr,omitempty"`
	TokenAuthMethod       string   `json:"tokenAuthMethod,omitempty"`
	// Subjects 仅兼容现有模拟元数据，绝不从此字段创建人员或授予角色。
	Subjects []string `json:"subjects,omitempty"`
}

func ParseConnection(raw []byte) (Connection, error) {
	var c Connection
	if len(raw) == 0 || len(raw) > 16384 {
		return c, ErrConfig
	}
	if provider.DecodeStrict(raw, &c) != nil {
		return Connection{}, ErrConfig
	}

	if c.IdentityConfig().validate() != nil {
		return Connection{}, ErrConfig
	}
	issuer, _ := url.Parse(c.Issuer)
	for _, raw := range []string{c.AuthorizationEndpoint, c.TokenEndpoint} {
		u, e := url.Parse(raw)
		if e != nil || !secureURL(u) || u.ForceQuery || u.Host != issuer.Host {
			return Connection{}, ErrConfig
		}
	}
	callback, e := url.Parse(c.RedirectURI)
	if e != nil || !secureURL(callback) || callback.ForceQuery || callback.Path != "/auth/callback" {
		return Connection{}, ErrConfig
	}
	if c.TokenAuthMethod == "" {
		c.TokenAuthMethod = "none"
	}
	if c.TokenAuthMethod != "none" && c.TokenAuthMethod != "client_secret_basic" && c.TokenAuthMethod != "client_secret_post" {
		return Connection{}, ErrConfig
	}
	if !c.DevelopmentOnly && len(c.Subjects) > 0 {
		return Connection{}, ErrConfig
	}
	return c, nil
}
func (c Connection) IdentityConfig() Config {
	return Config{DevelopmentMode: c.DevelopmentOnly, Issuer: c.Issuer, JWKSURL: c.JWKSURL, ClientID: c.ClientID, AllowedACR: c.AllowedACR, RequiredAMR: c.RequiredAMR, MaxAuthAge: 5 * time.Minute}
}
