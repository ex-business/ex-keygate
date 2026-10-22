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
	return configurePassportAdapter("KEYGATE_PASSPORT", service.ConfigurePassport)
}
func configurePassportJWT(service *webauth.Service) (*passport.Client, error) {
	return configurePassportAdapter("KEYGATE_PASSPORT_JWT", service.ConfigurePassportJWT)
}
func configurePassportAdapter(prefix string, configure func(*passport.Client) error) (*passport.Client, error) {
	endpoint := os.Getenv(prefix + "_URL")
	if endpoint == "" {
		for _, name := range []string{"_EXECUTOR_ID", "_SECRET_FILE", "_CA_FILE", "_CERT_FILE", "_KEY_FILE", "_LOOPBACK_HTTP"} {
			if os.Getenv(prefix+name) != "" {
				return nil, errors.New("Passport adapter URL required")
			}
		}
		return nil, nil
	}
	secret, e := readPrivate(os.Getenv(prefix + "_SECRET_FILE"))
	if e != nil {
		return nil, errors.New("Passport executor secret file unavailable")
	}
	defer clear(secret)
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}
	if caFile := os.Getenv(prefix + "_CA_FILE"); caFile != "" {
		raw, err := os.ReadFile(caFile)
		if err != nil {
			return nil, errors.New("Passport CA unavailable")
		}
		tlsConfig.RootCAs = x509.NewCertPool()
		if !tlsConfig.RootCAs.AppendCertsFromPEM(raw) {
			return nil, errors.New("Passport CA invalid")
		}
	}
	certFile, keyFile := os.Getenv(prefix+"_CERT_FILE"), os.Getenv(prefix+"_KEY_FILE")
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
	p, e := passport.New(passport.Config{URL: endpoint, ClientID: os.Getenv(prefix + "_EXECUTOR_ID"), Secret: strings.TrimSuffix(string(secret), "\n"), TLS: tlsConfig, AllowLoopbackHTTP: os.Getenv(prefix+"_LOOPBACK_HTTP") == "1"})
	if e != nil {
		return nil, e
	}
	if e = configure(p); e != nil {
		p.Close()
		return nil, e
	}
	return p, nil
}
