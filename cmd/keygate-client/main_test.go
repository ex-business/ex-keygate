package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateCredentialFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "recipient")
	if e := privateDirectory(dir); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "credential.key")
	if e := writeNew(path, map[string]string{"test": "fixture"}); e != nil {
		t.Fatal(e)
	}
	var out map[string]string
	if e := readPrivate(path, &out); e != nil || out["test"] != "fixture" {
		t.Fatal("private read", e)
	}
	if e := writeNew(path, map[string]string{"test": "overwrite"}); e == nil {
		t.Fatal("credential overwritten")
	}
	if e := os.Chmod(path, 0644); e != nil {
		t.Fatal(e)
	}
	if e := readPrivate(path, &out); e == nil {
		t.Fatal("public credential accepted")
	}
	if e := os.Chmod(path, 0600); e != nil {
		t.Fatal(e)
	}
	link := filepath.Join(dir, "link.key")
	if e := os.Symlink(path, link); e != nil {
		t.Fatal(e)
	}
	if e := readPrivate(link, &out); e == nil {
		t.Fatal("credential symlink followed")
	}
	if e := privateDirectory(link); e == nil {
		t.Fatal("symlink accepted as directory")
	}
}
