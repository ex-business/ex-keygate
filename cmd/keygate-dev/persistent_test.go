package main

import (
	"encoding/json"
	"ex-keygate/internal/storage"
	"testing"
	"time"
)

func TestUpgradeCheckpointAcceptsCanonicalTimeAndRejectsAmbiguity(t *testing.T) {
	value := storage.SafetyCheckpoint{Kind: "keygate-state-v1", Environment: "deployment", ID: "checkpoint", CapturedAt: time.Now().UTC(), Tables: map[string]storage.TableCheckpoint{"principals": {Count: 3, Digest: "digest"}}}
	raw, e := json.Marshal(value)
	if e != nil {
		t.Fatal(e)
	}
	var parsed storage.SafetyCheckpoint
	if e = decodeUpgradeCheckpoint(raw, &parsed); e != nil || !value.CapturedAt.Equal(parsed.CapturedAt) {
		t.Fatal("规范运维检查点被拒绝", e)
	}
	for _, raw := range [][]byte{[]byte(`{"kind":"wrong","kind":"keygate-state-v1"}`), []byte(`{"kind":"keygate-state-v1","extra":true}`)} {
		if e = decodeUpgradeCheckpoint(raw, &parsed); e == nil {
			t.Fatal("歧义检查点被接受")
		}
	}
}
