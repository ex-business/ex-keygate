package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"ex-keygate/internal/mocksso"
)

func main() {
	if err := run(); err != nil {
		slog.Error("模拟 SSO 启动或运行失败", "error", err)
		os.Exit(1)
	}
}
func run() error {
	port := flag.Int("port", 19443, "Loopback TLS port; use 0 for a random port")
	directory := flag.String("output", "data/mock-sso", "Directory for public CA and non-secret connection metadata")
	redirect := flag.String("redirect", "https://127.0.0.1:18761/auth/callback", "Exact loopback HTTPS callback URI")
	flag.Parse()
	absolute, err := filepath.Abs(*directory)
	if err != nil {
		return err
	}
	*directory = absolute
	environment := os.Getenv("KEYGATE_ENV")
	if environment == "" {
		environment = "development"
	}
	// Refuse production before opening a listener or creating any files.
	if environment != "development" && environment != "test" {
		return mocksso.ErrConfig
	}
	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(*port)))
	if err != nil {
		return err
	}
	defer listener.Close()
	issuer := "https://" + listener.Addr().String()
	mock, err := mocksso.New(mocksso.Config{Environment: environment, Issuer: issuer, RedirectURI: *redirect})
	if err != nil {
		return err
	}
	certificate, ca, err := certificate()
	if err != nil {
		return err
	}
	if err = os.MkdirAll(*directory, 0700); err != nil {
		return err
	}
	info, err := os.Stat(*directory)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0077 != 0 {
		return errors.New("mock output directory must be private")
	}
	if err = os.WriteFile(filepath.Join(*directory, "ca.pem"), ca, 0600); err != nil {
		return err
	}
	metadata := map[string]any{"developmentOnly": true, "issuer": issuer, "jwksUrl": issuer + "/jwks", "authorizationEndpoint": issuer + "/authorize", "tokenEndpoint": issuer + "/token", "clientId": mocksso.ClientID, "redirectUri": *redirect, "allowedAcr": []string{mocksso.SimulatedACR}, "caFile": filepath.Join(*directory, "ca.pem"), "subjects": []string{"demo-requester", "demo-approver-1", "demo-approver-2"}}
	raw, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(*directory, "connection.json"), raw, 0600); err != nil {
		return err
	}
	server := &http.Server{Handler: mock.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			_ = server.Close()
		}
	}()
	slog.Info("开发模拟 SSO 已启动，无真实身份或多因素认证，禁止生产使用", "issuer", issuer, "config_file", filepath.Join(*directory, "connection.json"))
	err = server.Serve(tls.NewListener(listener, server.TLSConfig))
	stop()
	<-done
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
func certificate() (tls.Certificate, []byte, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "ExKeyGate Development CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(12 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leaf := &x509.Certificate{SerialNumber: new(big.Int).Add(serial, big.NewInt(1)), Subject: pkix.Name{CommonName: "ExKeyGate Mock SSO"}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &serverKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: serverKey}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), nil
}
