// Package passport implements the fixed Passport management protocol. It never
// accepts endpoints, credentials or an operation ID from a browser execution call.
package passport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var (
	ErrInvalid  = errors.New("invalid Passport adapter configuration or binding")
	ErrUnknown  = errors.New("Passport outcome unknown; query before any retry")
	ErrRejected = errors.New("Passport rejected the bound operation")
	ErrNotFound = errors.New("Passport operation not committed")
)
var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$`)

type Request struct {
	OperationID      string   `json:"operationId"`
	Operation        string   `json:"operation"`
	ClientID         string   `json:"clientId"`
	Audiences        []string `json:"audiences,omitempty"`
	ExpectedRevision int64    `json:"expectedRevision"`
}

func (r Request) Hash() string {
	raw, _ := json.Marshal(r)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}
func (r Request) Validate() error {
	if !idPattern.MatchString(r.OperationID) || !idPattern.MatchString(r.ClientID) || r.ExpectedRevision < 0 || r.ExpectedRevision > 9007199254740991 {
		return ErrInvalid
	}
	switch r.Operation {
	case "create":
		if r.ExpectedRevision != 0 || len(r.Audiences) == 0 || len(r.Audiences) > 32 {
			return ErrInvalid
		}
	case "rotate", "disable":
		if r.ExpectedRevision == 0 || len(r.Audiences) != 0 {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	for _, a := range r.Audiences {
		if a == "" || len(a) > 256 || strings.TrimSpace(a) != a {
			return ErrInvalid
		}
	}
	return nil
}

type Result struct {
	Kid            string `json:"kid,omitempty"`
	ApprovalDigest string `json:"approvalDigest,omitempty"`
	OperationID    string `json:"operationId"`
	Operation      string `json:"operation"`
	ClientID       string `json:"clientId,omitempty"`
	Revision       int64  `json:"revision"`
	Replayed       bool   `json:"replayed"`
	ClientSecret   string `json:"clientSecret,omitempty"`
	RequestHash    string `json:"requestHash,omitempty"`
}
type Config struct {
	URL, ClientID, Secret string
	TLS                   *tls.Config
	AllowLoopbackHTTP     bool
}
type Client struct {
	base, id, secret string
	http             *http.Client
}

func New(c Config) (*Client, error) {
	u, e := url.Parse(c.URL)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || !idPattern.MatchString(c.ClientID) || strings.Contains(c.ClientID, ":") || len(c.Secret) != 47 || !strings.HasPrefix(c.Secret, "epe_") {
		return nil, ErrInvalid
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || !c.AllowLoopbackHTTP || ip == nil || !ip.IsLoopback() {
			return nil, ErrInvalid
		}
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}
	if c.TLS != nil {
		tlsConfig = c.TLS.Clone()
		if tlsConfig.InsecureSkipVerify {
			return nil, ErrInvalid
		}
		tlsConfig.MinVersion = tls.VersionTLS13
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig, DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext, TLSHandshakeTimeout: 2 * time.Second, ResponseHeaderTimeout: 3 * time.Second, MaxIdleConns: 4, MaxConnsPerHost: 4}
	return &Client{strings.TrimRight(c.URL, "/"), c.ClientID, c.Secret, &http.Client{Transport: transport, Timeout: 4 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (c *Client) EndpointBinding() string {
	h := sha256.Sum256([]byte(c.base + "\x00" + c.id))
	return hex.EncodeToString(h[:])
}
func (c *Client) Close() { c.http.CloseIdleConnections() }
func (c *Client) exchange(ctx context.Context, method, path string, b any) (json.RawMessage, error) {
	var result json.RawMessage
	var body io.Reader
	if b != nil {
		raw, _ := json.Marshal(b)
		body = bytes.NewReader(raw)
	}
	req, e := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if e != nil {
		return result, ErrInvalid
	}
	req.SetBasicAuth(c.id, c.secret)
	req.Header.Set("Accept", "application/json")
	if b != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, e := c.http.Do(req)
	if e != nil {
		return result, ErrUnknown
	}
	defer response.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(response.Body, 32769))
	if e != nil || len(raw) > 32768 {
		return result, ErrUnknown
	}
	var envelope struct {
		Success bool            `json:"success"`
		Code    string          `json:"code"`
		Data    json.RawMessage `json:"data"`
	}
	if json.Unmarshal(raw, &envelope) != nil {
		return result, ErrUnknown
	}
	if method == "GET" && response.StatusCode == 404 && !envelope.Success && envelope.Code == "EXECUTOR_OPERATION_NOT_FOUND" {
		return result, ErrNotFound
	}
	if response.StatusCode == 400 || response.StatusCode == 401 || response.StatusCode == 403 || response.StatusCode == 409 {
		return result, ErrRejected
	}
	if response.StatusCode != 200 || !envelope.Success || envelope.Code != "OK" {
		return result, ErrUnknown
	}
	return envelope.Data, nil
}
func (c *Client) call(ctx context.Context, method, path string, b any) (Result, error) {
	raw, e := c.exchange(ctx, method, path, b)
	if e != nil {
		return Result{}, e
	}
	var out Result
	if json.Unmarshal(raw, &out) != nil {
		return Result{}, ErrUnknown
	}
	return out, nil
}
func validResult(b Request, r Result) bool {
	return r.OperationID == b.OperationID && r.Operation == b.Operation && r.ClientID == b.ClientID && r.Revision == b.ExpectedRevision+1
}
func (c *Client) Query(ctx context.Context, b Request) (Result, error) {
	if b.Validate() != nil {
		return Result{}, ErrInvalid
	}
	r, e := c.call(ctx, "GET", "/management/v1/introspection-clients/operations/"+url.PathEscape(b.OperationID), nil)
	if e != nil {
		return Result{}, e
	}
	if !validResult(b, r) || r.RequestHash != b.Hash() || r.ClientSecret != "" || !r.Replayed {
		return Result{}, ErrUnknown
	}
	return r, nil
}
func (c *Client) Execute(ctx context.Context, b Request) (Result, error) {
	if b.Validate() != nil {
		return Result{}, ErrInvalid
	}
	r, e := c.call(ctx, "POST", "/management/v1/introspection-clients/operations", &b)
	if e != nil {
		return Result{}, e
	}
	if !validResult(b, r) {
		return Result{}, ErrUnknown
	}
	if b.Operation == "disable" || r.Replayed {
		if r.ClientSecret != "" {
			return Result{}, ErrUnknown
		}
	} else if len(r.ClientSecret) != 47 || !strings.HasPrefix(r.ClientSecret, "epi_") {
		return Result{}, ErrUnknown
	}
	return r, nil
}
