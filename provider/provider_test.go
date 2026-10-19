package provider

import (
	"errors"
	"testing"
)

func TestCatalogIsolation(t *testing.T) {
	d := Descriptor{"local", "1", ProtocolVersion, Local, []Capability{Verify}}
	c, err := NewCatalog(d)
	if err != nil {
		t.Fatal(err)
	}
	d.Capabilities[0] = Create
	got, err := c.Require("local", Verify)
	if err != nil {
		t.Fatal(err)
	}
	got.Capabilities[0] = Create
	if _, err = c.Require("local", Verify); err != nil {
		t.Fatal("manifest was mutated")
	}
	for _, id := range []string{"local", "hardware", "missing"} {
		if _, err = c.Require(id, Disable); !errors.Is(err, ErrUnsupported) {
			t.Fatal(err)
		}
	}
	if _, err = NewCatalog(d, d); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	var nilCatalog *Catalog
	if _, err = nilCatalog.Require("local", Verify); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
}
func TestInvalidDescriptors(t *testing.T) {
	for _, d := range []Descriptor{
		{"bad/url", "1", ProtocolVersion, Local, nil},
		{"local", "1", "2", Local, nil},
		{"local", "1", ProtocolVersion, "unknown", nil},
		{"local", "1", ProtocolVersion, Local, []Capability{"unknown"}},
		{"local", "1", ProtocolVersion, Local, []Capability{Verify, Verify}},
	} {
		if d.Validate() == nil {
			t.Fatalf("accepted invalid descriptor: %+v", d)
		}
	}
}
