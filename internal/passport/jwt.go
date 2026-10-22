package passport

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"
)

type JWTRequest struct {
	OperationID      string `json:"operationId"`
	ApprovalDigest   string `json:"approvalDigest"`
	Operation        string `json:"operation"`
	Kid              string `json:"kid"`
	ExpectedRevision int64  `json:"expectedRevision"`
	PublicKey        string `json:"publicKey,omitempty"`
	Reason           string `json:"reason"`
}

func (r JWTRequest) Hash() string {
	raw, _ := json.Marshal(r)
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:])
}
func (r JWTRequest) Validate() error {
	digest, e := hex.DecodeString(r.ApprovalDigest)
	if e != nil || len(digest) != 32 || strings.ToLower(r.ApprovalDigest) != r.ApprovalDigest || !idPattern.MatchString(r.OperationID) || !idPattern.MatchString(r.Kid) || r.ExpectedRevision < 1 || r.ExpectedRevision > 9007199254740991 || !utf8.ValidString(r.Reason) || len(strings.TrimSpace(r.Reason)) < 3 || len(r.Reason) > 500 || strings.ContainsFunc(r.Reason, unicode.IsControl) {
		return ErrInvalid
	}
	switch r.Operation {
	case "publish":
		public, e := base64.RawURLEncoding.Strict().DecodeString(r.PublicKey)
		if e != nil || len(public) != 32 || base64.RawURLEncoding.EncodeToString(public) != r.PublicKey {
			return ErrInvalid
		}
	case "activate", "retire", "revoke":
		if r.PublicKey != "" {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}
func validJWTResult(b JWTRequest, r Result) bool {
	return r.OperationID == b.OperationID && r.ApprovalDigest == b.ApprovalDigest && r.Operation == b.Operation && r.Kid == b.Kid && r.Revision == b.ExpectedRevision+1 && r.RequestHash == b.Hash() && r.ClientID == "" && r.ClientSecret == ""
}
func (c *Client) QueryJWT(ctx context.Context, b JWTRequest) (Result, error) {
	if b.Validate() != nil {
		return Result{}, ErrInvalid
	}
	r, e := c.call(ctx, "GET", "/management/v1/jwt-keys/operations/"+url.PathEscape(b.OperationID), nil)
	if e != nil {
		return Result{}, e
	}
	if !validJWTResult(b, r) || !r.Replayed {
		return Result{}, ErrUnknown
	}
	return r, nil
}
func (c *Client) ExecuteJWT(ctx context.Context, b JWTRequest) (Result, error) {
	if b.Validate() != nil {
		return Result{}, ErrInvalid
	}
	r, e := c.call(ctx, "POST", "/management/v1/jwt-keys/operations", &b)
	if e != nil {
		return Result{}, e
	}
	if !validJWTResult(b, r) {
		return Result{}, ErrUnknown
	}
	return r, nil
}

// JWTState contains public lifecycle metadata, never signing material.
type JWTState struct {
	Revision   int64         `json:"revision"`
	CurrentKid *string       `json:"currentKid"`
	Keys       []JWTKeyState `json:"keys"`
}
type JWTKeyState struct {
	Kid            string  `json:"kid"`
	State          string  `json:"state"`
	PublishedAt    string  `json:"publishedAt"`
	ActivatedAt    *string `json:"activatedAt,omitempty"`
	RetireAfter    *string `json:"retireAfter,omitempty"`
	MaxTokenExpiry string  `json:"maxTokenExpiry"`
}

func (c *Client) GetJWTState(ctx context.Context) (JWTState, error) {
	var out JWTState
	raw, e := c.exchange(ctx, "GET", "/management/v1/jwt-keys", nil)
	if e != nil {
		return out, e
	}
	if json.Unmarshal(raw, &out) != nil || out.Revision < 1 || out.Revision > 9007199254740991 || len(out.Keys) > 128 {
		return JWTState{}, ErrUnknown
	}
	if out.CurrentKid != nil && !idPattern.MatchString(*out.CurrentKid) {
		return JWTState{}, ErrUnknown
	}
	for _, k := range out.Keys {
		if !idPattern.MatchString(k.Kid) || (k.State != "staged" && k.State != "active" && k.State != "draining" && k.State != "retired" && k.State != "revoked") {
			return JWTState{}, ErrUnknown
		}
	}
	return out, nil
}
