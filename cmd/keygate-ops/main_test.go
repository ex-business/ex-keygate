package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExternalCheckpointRejectsSymlinkBackIntoArchive(t *testing.T) {
	parent := t.TempDir()
	archive := filepath.Join(parent, "archive")
	outside := filepath.Join(parent, "independent")
	if e := os.Mkdir(archive, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(outside, 0700); e != nil {
		t.Fatal(e)
	}
	alias := filepath.Join(outside, "alias")
	if e := os.Symlink(archive, alias); e != nil {
		t.Fatal(e)
	}
	if externalPath(archive, filepath.Join(alias, "manifest")) {
		t.Fatal("符号链接使校验点落入归档目录")
	}
	if !externalPath(archive, filepath.Join(outside, "manifest")) {
		t.Fatal("独立真实目录被拒绝")
	}
}
