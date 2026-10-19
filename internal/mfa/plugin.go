package mfa

import (
	"context"
	"encoding/json"
	"time"
)

// Delivery 的目的地址只能取已核验绑定；插件失败保持未验证，不能降级为日志/页面回显验证码。
type Delivery struct {
	ID          string    `json:"id"`
	Method      Method    `json:"method"`
	Destination string    `json:"destination"`
	Code        string    `json:"code"`
	ExpiresAt   time.Time `json:"expiresAt"`
}
type DeliveryPlugin interface {
	Send(context.Context, Delivery) error
}
type HardwareChallenge struct {
	ID         string    `json:"id"`
	Nonce      string    `json:"nonce"`
	Credential string    `json:"credential"`
	Principal  string    `json:"principal"`
	Origin     string    `json:"origin"`
	ExpiresAt  time.Time `json:"expiresAt"`
}

// HardwarePlugin 必须验证实际持钥证明、challenge/Origin/凭据绑定及用户验证，不能相信客户端的成功标记。
// 具体WebAuthn/厂商协议由插件实现；KeyGate仅在服务端插件核验通过后计入该绑定项一次。
type HardwarePlugin interface {
	Begin(context.Context, HardwareChallenge) (json.RawMessage, error)
	Verify(context.Context, HardwareChallenge, json.RawMessage) error
}
type Plugins struct {
	Email    DeliveryPlugin
	SMS      DeliveryPlugin
	Hardware HardwarePlugin
}

func (p Plugins) Available(method Method) bool {
	switch method {
	case Email:
		return p.Email != nil
	case SMS:
		return p.SMS != nil
	case Hardware:
		return p.Hardware != nil
	case TOTP:
		return true
	}
	return false
}
