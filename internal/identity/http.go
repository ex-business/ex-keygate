package identity

import (
	"crypto/x509"
	"net/http"
)

// NewHTTPClient preserves the issuer network policy for authorization-code
// exchange as well as JWKS. Endpoints must still be fixed by trusted config.
func NewHTTPClient(roots *x509.CertPool) *http.Client {
	client := oidcHTTPClient()
	if roots != nil {
		client.Transport.(boundedTransport).base.(*http.Transport).TLSClientConfig.RootCAs = roots.Clone()
	}
	return client
}
