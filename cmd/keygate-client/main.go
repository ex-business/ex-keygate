package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"ex-keygate/internal/recipient"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "开发客户端处理失败：", e)
		os.Exit(1)
	}
}
func run() error {
	action := flag.String("action", "", "init, claim, or probe")
	directory := flag.String("directory", "data/keygate-client", "Private recipient directory; use a separate directory per key version")
	origin := flag.String("origin", "https://localhost:18761", "Trusted loopback console origin")
	caFile := flag.String("ca-file", "data/dev-console/ca.pem", "Trusted console CA file")
	environment := flag.String("environment", "", "Environment returned by /api/config")
	client := flag.String("client", "", "Approved client ID")
	version := flag.Uint64("version", 1, "Approved key version")
	issue := flag.String("issue", "", "Approved issue request ID")
	flag.Parse()
	if *action != "init" && *action != "claim" && *action != "probe" {
		return errors.New("action must be init, claim, or probe")
	}
	if e := privateDirectory(*directory); e != nil {
		return e
	}
	identityPath := filepath.Join(*directory, "recipient.key")
	credentialPath := filepath.Join(*directory, "credential.key")
	if *action == "init" {
		identity, e := recipient.Generate()
		if e != nil {
			return e
		}
		defer clear(identity.Encryption)
		defer clear(identity.Signing)
		if e = writeNew(identityPath, identity); e != nil {
			return e
		}
		public, e := recipient.Public(identity)
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(public)
	}
	var identity recipient.Identity
	if e := readPrivate(identityPath, &identity); e != nil {
		return e
	}
	defer clear(identity.Encryption)
	defer clear(identity.Signing)
	ca, e := os.ReadFile(*caFile)
	if e != nil || len(ca) > 65536 {
		return errors.New("trusted CA file unavailable")
	}
	connection, e := recipient.New(*origin, ca, identity)
	if e != nil {
		return e
	}
	defer connection.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if *action == "claim" {
		if _, e = os.Lstat(credentialPath); !errors.Is(e, os.ErrNotExist) {
			return errors.New("credential file must not already exist")
		}
		credential, e := connection.Claim(ctx, recipient.Scope{Environment: *environment, ClientID: *client, IssueID: *issue, Version: *version})
		if e != nil {
			return e
		}
		defer clear(credential.Secret)
		// 先私有持久化再确认，避免服务端已确认但客户端崩溃丢失秘密；网络失败不自动重复领取。
		if e = writeNew(credentialPath, credential); e != nil {
			return e
		}
		if e = connection.Confirm(ctx, credential); e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"state": "staged", "clientId": credential.Scope.ClientID, "version": credential.Scope.Version, "credentialFile": credentialPath})
	}
	var credential recipient.Credential
	if e = readPrivate(credentialPath, &credential); e != nil {
		return e
	}
	defer clear(credential.Secret)
	status, e := connection.Probe(ctx, credential)
	if e != nil {
		return e
	}
	if e = json.NewEncoder(os.Stdout).Encode(map[string]any{"authenticated": status == 200, "httpStatus": status, "clientId": credential.Scope.ClientID, "version": credential.Scope.Version}); e != nil {
		return e
	}
	if status != 200 {
		return errors.New("client authentication rejected")
	}
	return nil
}
func privateDirectory(path string) error {
	if e := os.MkdirAll(path, 0700); e != nil {
		return e
	}
	info, e := os.Lstat(path)
	if e != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("recipient directory must be private and not a symlink")
	}
	return nil
}

// writeNew 永不覆盖已有凭据；失败也不删除或替换其他进程可能建立的文件。
func writeNew(path string, value any) error {
	raw, e := json.Marshal(value)
	if e != nil {
		return e
	}
	defer clear(raw)
	file, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return errors.New("private output file already exists or cannot be created")
	}
	defer file.Close()
	if _, e = file.Write(raw); e != nil {
		return e
	}
	if e = file.Sync(); e != nil {
		return e
	}
	if e = file.Close(); e != nil {
		return e
	}
	dir, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer dir.Close()
	return dir.Sync()
}

// readPrivate 验证打开前后为同一个私有普通文件，避免符号链接或替换路径读取秘密。
func readPrivate(path string, target any) error {
	before, e := os.Lstat(path)
	if e != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0077 != 0 {
		return errors.New("private credential file required")
	}
	file, e := os.Open(path)
	if e != nil {
		return errors.New("private credential unavailable")
	}
	defer file.Close()
	after, e := file.Stat()
	if e != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() || after.Mode().Perm()&0077 != 0 {
		return errors.New("private credential changed during open")
	}
	raw, e := io.ReadAll(io.LimitReader(file, 16385))
	if e != nil || len(raw) > 16384 {
		return errors.New("private credential invalid")
	}
	defer clear(raw)
	if e = json.Unmarshal(raw, target); e != nil {
		return errors.New("private credential invalid")
	}
	return nil
}
