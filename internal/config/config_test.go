package config

import (
	"errors"
	"testing"
)

func TestDeploymentSafety(t *testing.T) {
	for _, environment := range []Environment{Development, Test} {
		for _, mode := range []RootMode{Disabled, DevelopmentSoftware} {
			if err := (Config{environment, mode}).Validate(); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, mode := range []RootMode{Disabled, DevelopmentSoftware} {
		if err := (Config{Production, mode}).Validate(); !errors.Is(err, ErrProductionRoot) {
			t.Fatal("unsafe production accepted", err)
		}
	}
	for _, environment := range []Environment{Development, Test, Production} {
		for _, mode := range []RootMode{KMS, HSM} {
			if err := (Config{environment, mode}).Validate(); !errors.Is(err, ErrProviderUnavailable) {
				t.Fatal("placeholder provider accepted", err)
			}
		}
	}
	for _, c := range []Config{{"unknown", Disabled}, {Development, "software"}, {"", Disabled}} {
		if !errors.Is(c.Validate(), ErrInvalid) {
			t.Fatal("unknown config accepted")
		}
	}
}
func TestEnvironmentLoading(t *testing.T) {
	c, err := Load(func(string) string { return "" })
	if err != nil || c.Environment != Development || c.RootMode != Disabled {
		t.Fatal("unsafe defaults", c, err)
	}
	values := map[string]string{"KEYGATE_ENV": "production", "KEYGATE_ROOT_MODE": "development_software"}
	if _, err = Load(func(k string) string { return values[k] }); !errors.Is(err, ErrProductionRoot) {
		t.Fatal(err)
	}
	if _, err = Load(nil); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
}
