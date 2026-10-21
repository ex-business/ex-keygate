package main

import (
	"encoding/json"
	"ex-keygate/internal/pluginmock"
	"ex-keygate/internal/storage"
	"ex-keygate/internal/trustnotify"
	"os"
	"path/filepath"
	"testing"
)

func TestAlertRouteDigestStableAcrossSnapshotPaths(t *testing.T) {
	_, ca, cert, key, e := pluginmock.DevelopmentTLS()
	if e != nil {
		t.Fatal(e)
	}
	defer clear(key)
	digests := []string{}
	for i := 0; i < 2; i++ {
		dir := t.TempDir()
		cfg := trustnotify.Config{URL: "https://localhost:19454/alerts", AllowedIPs: []string{"127.0.0.1"}, CAFile: filepath.Join(dir, "ca.pem"), CertificateFile: filepath.Join(dir, "client.pem"), KeyFile: filepath.Join(dir, "client.key")}
		for path, raw := range map[string][]byte{cfg.CAFile: ca, cfg.CertificateFile: cert, cfg.KeyFile: key} {
			if e = os.WriteFile(path, raw, 0600); e != nil {
				t.Fatal(e)
			}
		}
		payload := struct {
			Routes []struct {
				storage.AlertRoute
				Plugin trustnotify.Config `json:"plugin"`
			} `json:"routes"`
		}{Routes: []struct {
			storage.AlertRoute
			Plugin trustnotify.Config `json:"plugin"`
		}{{AlertRoute: storage.AlertRoute{ID: "operations", Channel: "email", Target: "oncall"}, Plugin: cfg}}}
		raw, _ := json.Marshal(payload)
		path := filepath.Join(dir, "config.json")
		if e = os.WriteFile(path, raw, 0600); e != nil {
			t.Fatal(e)
		}
		bindings, closeAll, e := loadAlertDelivery(path)
		if e != nil {
			t.Fatal(e)
		}
		digests = append(digests, bindings["operations"].Route.Digest)
		closeAll()
	}
	if digests[0] != digests[1] {
		t.Fatal("临时快照路径改变路由摘要")
	}
}
