package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDevelopmentDatabaseBoundary(t *testing.T) {
	good := "postgres://postgres:random@127.0.0.1:1234/keygate_dev?sslmode=disable"
	if !developmentDatabase(good) {
		t.Fatal("local disposable database refused")
	}
	for _, raw := range []string{"postgres://postgres:random@remote.example/keygate_dev?sslmode=disable", "postgres://postgres:random@127.0.0.1/business?sslmode=disable", good + "&host=remote.example", good + "&sslmode=disable", "postgres://postgres@127.0.0.1/keygate_dev?sslmode=disable"} {
		if developmentDatabase(raw) {
			t.Fatal("unsafe database accepted")
		}
	}
}
func TestPrivateDatabaseFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "database-url")
	if err := os.WriteFile(path, []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivate(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivate(path); err == nil {
		t.Fatal("public file accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivate(link); err == nil {
		t.Fatal("symlink accepted")
	}
}
