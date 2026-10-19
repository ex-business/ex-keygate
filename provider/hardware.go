package provider

import "context"

// ReservedHardware 保留硬件接口的类型契约；未接入设备和信任验证前始终拒绝，不能注册为已实现插件。
type ReservedHardware struct{}

func (ReservedHardware) Inspect(context.Context, string) (Device, error) {
	return Device{}, ErrUnsupported
}
func (ReservedHardware) Issue(context.Context, HardwareChallenge) ([]byte, error) {
	return nil, ErrUnsupported
}
func (ReservedHardware) VerifyChallenge(context.Context, HardwareChallenge, []byte) error {
	return ErrUnsupported
}

var _ DeviceInspector = ReservedHardware{}
var _ ChallengeIssuer = ReservedHardware{}
var _ ChallengeVerifier = ReservedHardware{}
