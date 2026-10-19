package manifest

import (
	"bytes"
	"testing"
)

func TestRestrictedJCS(t *testing.T) {
	got, e := Canonical(map[string]any{"z": "中文\u2028<>&\\\"\n", "a": []any{true, nil, 12}})
	want := []byte("{\"a\":[true,null,12],\"z\":\"中文\u2028<>&\\\\\\\"\\n\"}")
	if e != nil || !bytes.Equal(got, want) {
		t.Fatalf("canonical mismatch %q %v", got, e)
	}
	for _, v := range []any{map[string]any{"非ASCII": 1}, string([]byte{255}), 1.5, int64(9007199254740992)} {
		if _, e := Canonical(v); e == nil {
			t.Fatal("unsupported canonical value")
		}
	}
}
