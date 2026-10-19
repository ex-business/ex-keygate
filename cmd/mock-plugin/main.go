package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"ex-keygate/internal/pluginmock"
	"ex-keygate/provider"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

func main() {
	if e := run(); e != nil {
		slog.Error("模拟插件运行失败", "error", e)
		os.Exit(1)
	}
}
func run() error {
	port := flag.Int("port", 19444, "本机 TLS 端口")
	output := flag.String("output", "data/mock-plugin", "私有输出目录")
	flag.Parse()
	mode := os.Getenv("KEYGATE_ENV")
	if mode != "development" && mode != "test" {
		return errors.New("模拟插件要求显式开发或测试环境")
	}
	// 先占用监听端口，再取得输出目录排他权；失败实例不能覆盖运行中实例的证书。
	listener, e := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(*port)))
	if e != nil {
		return e
	}
	defer listener.Close()
	dir, e := filepath.Abs(*output)
	if e != nil {
		return e
	}
	if e = os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	info, e := os.Lstat(dir)
	if e != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("输出目录必须为私有真实目录")
	}
	lock, e := os.OpenFile(filepath.Join(dir, ".instance.lock"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return errors.New("模拟插件输出目录正在使用或遗留锁需人工核对")
	}
	defer os.Remove(lock.Name())
	if _, e = lock.WriteString(strconv.Itoa(os.Getpid())); e != nil {
		lock.Close()
		return e
	}
	if e = lock.Sync(); e != nil {
		lock.Close()
		return e
	}
	if e = lock.Close(); e != nil {
		return e
	}
	service, e := pluginmock.New()
	if e != nil {
		return e
	}
	serverCert, ca, client, clientKey, e := pluginmock.DevelopmentTLS()
	if e != nil {
		return e
	}
	defer clear(clientKey)
	for name, raw := range map[string][]byte{"ca.pem": ca, "client.pem": client, "client.key": clientKey} {
		if e = writePrivate(filepath.Join(dir, name), raw); e != nil {
			return e
		}
	}
	origin := "https://" + listener.Addr().String()
	payload, proof := service.Vector()
	metadata := struct {
		DevelopmentOnly bool                `json:"developmentOnly"`
		Descriptor      provider.Descriptor `json:"descriptor"`
		Endpoint        string              `json:"endpoint"`
		AllowedIPs      []string            `json:"allowedIPs"`
		CAFile          string              `json:"caFile"`
		ClientCertFile  string              `json:"clientCertFile"`
		ClientKeyFile   string              `json:"clientKeyFile"`
		Payload         []byte              `json:"payload"`
		Proof           []byte              `json:"proof"`
	}{true, pluginmock.Descriptor(), origin, []string{"127.0.0.1"}, filepath.Join(dir, "ca.pem"), filepath.Join(dir, "client.pem"), filepath.Join(dir, "client.key"), payload, proof}
	raw, e := json.MarshalIndent(metadata, "", "  ")
	if e != nil {
		return e
	}
	if e = writePrivate(filepath.Join(dir, "connection.json"), raw); e != nil {
		return e
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return errors.New("模拟信任根生成失败")
	}
	server := &http.Server{Handler: service.Handler(), TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-ctx.Done()
		bounded, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(bounded)
	}()
	slog.Warn("模拟第三方插件已启动，仅公开自检向量，不提供真实客户端认证", "endpoint", origin, "result", "development_only")
	e = server.Serve(tls.NewListener(listener, server.TLSConfig))
	stop()
	<-done
	if errors.Is(e, http.ErrServerClosed) {
		return nil
	}
	return e
}

// 私有证书采用完整临时文件原子替换，拒绝符号链接或公开权限的旧文件，避免跟随路径写出秘密。
func writePrivate(path string, raw []byte) error {
	if info, e := os.Lstat(path); e == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return errors.New("输出文件必须为私有普通文件")
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".plugin-")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if _, e = f.Write(raw); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = os.Rename(f.Name(), path); e != nil {
		return e
	}
	d, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
