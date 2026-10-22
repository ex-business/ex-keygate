package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"strings"

	"ex-keygate/internal/passport"
	"ex-keygate/internal/webauth"
)

func configurePassport(service *webauth.Service) (*passport.Client, error) {
	endpoint := os.Getenv("KEYGATE_PASSPORT_URL")
	if endpoint == "" {
		for _, name := range []string{"KEYGATE_PASSPORT_EXECUTOR_ID", "KEYGATE_PASSPORT_SECRET_FILE", "KEYGATE_PASSPORT_CA_FILE", "KEYGATE_PASSPORT_CERT_FILE", "KEYGATE_PASSPORT_KEY_FILE", "KEYGATE_PASSPORT_LOOPBACK_HTTP"} {
			if os.Getenv(name) != "" {
				return nil, errors.New("Passport adapter URL required")
			}
		}
		return nil, nil
	}
	secret, e := readPrivate(os.Getenv("KEYGATE_PASSPORT_SECRET_FILE"))
	if e != nil {
		return nil, errors.New("Passport executor secret file unavailable")
	}
	defer clear(secret)
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}
	if caFile := os.Getenv("KEYGATE_PASSPORT_CA_FILE"); caFile != "" {
		raw, err := os.ReadFile(caFile)
		if err != nil {
			return nil, errors.New("Passport CA unavailable")
		}
		tlsConfig.RootCAs = x509.NewCertPool()
		if !tlsConfig.RootCAs.AppendCertsFromPEM(raw) {
			return nil, errors.New("Passport CA invalid")
		}
	}
	certFile, keyFile := os.Getenv("KEYGATE_PASSPORT_CERT_FILE"), os.Getenv("KEYGATE_PASSPORT_KEY_FILE")
	if certFile != "" || keyFile != "" {
		key, err := readPrivate(keyFile)
		if err != nil {
			return nil, errors.New("Passport mTLS key unavailable")
		}
		defer clear(key)
		cert, err := os.ReadFile(certFile)
		if err != nil {
			return nil, errors.New("Passport mTLS certificate unavailable")
		}
		pair, err := tls.X509KeyPair(cert, key)
		if err != nil {
			return nil, errors.New("Passport mTLS key pair invalid")
		}
		tlsConfig.Certificates = []tls.Certificate{pair}
	}
	p, e := passport.New(passport.Config{URL: endpoint, ClientID: os.Getenv("KEYGATE_PASSPORT_EXECUTOR_ID"), Secret: strings.TrimSuffix(string(secret), "\n"), TLS: tlsConfig, AllowLoopbackHTTP: os.Getenv("KEYGATE_PASSPORT_LOOPBACK_HTTP") == "1"})
	if e != nil {
		return nil, e
	}
	if e = service.ConfigurePassport(p); e != nil {
		p.Close()
		return nil, e
	}
	return p, nil
}
