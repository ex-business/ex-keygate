package main

import (
	"flag"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func runWithArgs(t *testing.T, args ...string) error {
	t.Helper()
	oldArgs, oldFlags := os.Args, flag.CommandLine
	defer func() { os.Args = oldArgs; flag.CommandLine = oldFlags }()
	os.Args = append([]string{"mock-plugin"}, args...)
	flag.CommandLine = flag.NewFlagSet("mock-plugin", flag.ContinueOnError)
	t.Setenv("KEYGATE_ENV", "test")
	return run()
}
func TestOccupiedPortDoesNotReplaceCredentials(t *testing.T) {
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	_, port, e := net.SplitHostPort(listener.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	_ = os.Chmod(dir, 0700)
	path := filepath.Join(dir, "client.key")
	if e = os.WriteFile(path, []byte("existing-private-fixture"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = runWithArgs(t, "-port", port, "-output", dir); e == nil {
		t.Fatal("占用端口未拒绝")
	}
	raw, e := os.ReadFile(path)
	if e != nil || string(raw) != "existing-private-fixture" {
		t.Fatal("失败实例覆盖材料", e)
	}
}
func TestLockedDirectoryDoesNotReplaceCredentials(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0700)
	path := filepath.Join(dir, "client.key")
	_ = os.WriteFile(path, []byte("existing-private-fixture"), 0600)
	_ = os.WriteFile(filepath.Join(dir, ".instance.lock"), []byte("existing-instance"), 0600)
	if e := runWithArgs(t, "-port", "0", "-output", dir); e == nil {
		t.Fatal("目录排他锁被绕过")
	}
	raw, e := os.ReadFile(path)
	if e != nil || string(raw) != "existing-private-fixture" {
		t.Fatal("锁冲突仍覆盖材料", e)
	}
}
