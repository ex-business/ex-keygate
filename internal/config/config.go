// Package config enforces deployment safety before the server starts listening.
package config

import "errors"

type Environment string

const (
	Development Environment = "development"
	Test        Environment = "test"
	Production  Environment = "production"
)

type RootMode string

const (
	Disabled            RootMode = "disabled"
	DevelopmentSoftware RootMode = "development_software"
	KMS                 RootMode = "kms"
	HSM                 RootMode = "hsm"
)

var (
	ErrInvalid             = errors.New("invalid deployment configuration")
	ErrProductionRoot      = errors.New("production requires an implemented KMS or HSM provider")
	ErrProviderUnavailable = errors.New("requested root provider is not implemented")
)

type Config struct {
	Environment Environment
	RootMode    RootMode
}

func Load(getenv func(string) string) (Config, error) {
	if getenv == nil {
		return Config{}, ErrInvalid
	}
	c := Config{Environment(getenv("KEYGATE_ENV")), RootMode(getenv("KEYGATE_ROOT_MODE"))}
	if c.Environment == "" {
		c.Environment = Development
	}
	if c.RootMode == "" {
		c.RootMode = Disabled
	}
	return c, c.Validate()
}
func (c Config) Validate() error {
	switch c.Environment {
	case Development, Test, Production:
	default:
		return ErrInvalid
	}
	switch c.RootMode {
	case Disabled, DevelopmentSoftware, KMS, HSM:
	default:
		return ErrInvalid
	}
	// No switch permits production to use a software root or silently run without
	// protection. KMS/HSM names alone do not prove an implementation is available.
	if c.Environment == Production && c.RootMode != KMS && c.RootMode != HSM {
		return ErrProductionRoot
	}
	if c.RootMode == KMS || c.RootMode == HSM {
		return ErrProviderUnavailable
	}
	return nil
}
