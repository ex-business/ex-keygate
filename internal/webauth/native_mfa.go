package webauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"ex-keygate/internal/keycrypto"
	"ex-keygate/internal/mfa"
	"ex-keygate/internal/storage"
	"fmt"
	"math/big"
	"net/http"
	"time"
)

func (s *Service) mfaBinding(principal, scope, factor, purpose string) keycrypto.Binding {
	return keycrypto.Binding{Environment: s.flow.environment, ClientID: "native-mfa", KeyID: digestMFA(principal + "\x00" + scope + "\x00" + factor), Version: 1, Purpose: purpose}
}
func digestMFA(s string) string { h := sha256.Sum256([]byte(s)); return fmt.Sprintf("%x", h[:]) }
func (s *Service) mfaStateResponse(w http.ResponseWriter, state storage.MFAState) {
	available := map[mfa.Method]bool{}
	for _, rule := range state.Policy.Rules {
		available[rule.Method] = s.config.MFAPlugins.Available(rule.Method)
	}
	businessJSON(w, 200, map[string]any{"state": state, "available": available})
}
func (s *Service) nativeMFARoutes(handle func(string, http.HandlerFunc)) {
	handle("POST /api/mfa/challenges", func(w http.ResponseWriter, r *http.Request) {
		token, ok := s.businessSession(w, r, true)
		if !ok {
			return
		}
		var body struct {
			Purpose string `json:"purpose"`
		}
		if e := strictJSON(w, r, &body); e != nil {
			s.businessError(w, r, e)
			return
		}
		state, e := s.flow.control.StartMFA(r.Context(), token, body.Purpose, requestID(r))
		if e != nil {
			s.businessError(w, r, e)
			return
		}
		s.mfaStateResponse(w, state)
	})
	handle("GET /api/mfa/challenges/{challenge}", func(w http.ResponseWriter, r *http.Request) {
		token, ok := s.businessSession(w, r, false)
		if !ok {
			return
		}
		state, e := s.flow.control.MFAStatus(r.Context(), token, r.PathValue("challenge"))
		if e != nil {
			s.businessError(w, r, e)
			return
		}
		s.mfaStateResponse(w, state)
	})
	handle("POST /api/mfa/challenges/{challenge}/factors/{factor}", s.beginNativeFactor)
	handle("POST /api/mfa/challenges/{challenge}/factors/{factor}/verify", s.verifyNativeFactor)
}
func (s *Service) beginNativeFactor(w http.ResponseWriter, r *http.Request) {
	token, ok := s.businessSession(w, r, true)
	if !ok {
		return
	}
	var body struct{}
	if e := strictJSON(w, r, &body); e != nil {
		s.businessError(w, r, e)
		return
	}
	challenge, factor := r.PathValue("challenge"), r.PathValue("factor")
	state, e := s.flow.control.MFAStatus(r.Context(), token, challenge)
	if e != nil {
		s.businessError(w, r, e)
		return
	}
	var selected mfa.Factor
	for _, f := range state.Factors {
		if f.ID == factor {
			selected = f
			break
		}
	}
	if selected.ID == "" {
		fail(w, 400)
		return
	}
	if !s.config.MFAPlugins.Available(selected.Method) {
		fail(w, 503)
		return
	}
	session, e := s.store.Session(r.Context(), hash(token), s.profile)
	if e != nil {
		fail(w, 401)
		return
	}
	attempt, e := s.flow.control.BeginMFAFactor(r.Context(), token, challenge, factor, random(), nil, nil, requestID(r))
	if e != nil {
		s.businessError(w, r, e)
		return
	}
	var verifierCipher, digest []byte
	code := ""
	if !attempt.Existing && (selected.Method == mfa.Email || selected.Method == mfa.SMS) {
		key := make([]byte, 32)
		if _, e = rand.Read(key); e != nil {
			fail(w, 503)
			return
		}
		defer clear(key)
		value, e := rand.Int(rand.Reader, big.NewInt(100000000))
		if e != nil {
			fail(w, 503)
			return
		}
		code = fmt.Sprintf("%08d", value.Int64())
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(challenge + "\x00" + factor + "\x00" + code))
		digest = mac.Sum(nil)
		sealed, e := s.protector.Seal(r.Context(), s.mfaBinding(session.PrincipalID, challenge, factor, "mfa_code"), key, session.PrincipalID, requestID(r))
		if e != nil {
			fail(w, 503)
			return
		}
		verifierCipher, _ = json.Marshal(sealed)
		if e = s.flow.control.SaveMFACode(r.Context(), token, challenge, factor, attempt.ID, verifierCipher, digest, requestID(r)); e != nil {
			s.businessError(w, r, e)
			return
		}
	}
	var options json.RawMessage
	switch selected.Method {
	case mfa.Email, mfa.SMS:
		plugin := s.config.MFAPlugins.Email
		if selected.Method == mfa.SMS {
			plugin = s.config.MFAPlugins.SMS
		}
		if !attempt.Existing {
			e = plugin.Send(r.Context(), mfa.Delivery{ID: attempt.ID, Method: selected.Method, Destination: selected.Reference, Code: code, ExpiresAt: attempt.ExpiresAt})
		}
	case mfa.Hardware:
		options, e = s.config.MFAPlugins.Hardware.Begin(r.Context(), s.hardwareChallenge(attempt))
	}
	if e != nil {
		s.rejected(r, "mfa_plugin", "delivery_or_challenge_unavailable", attempt.ID)
		fail(w, 503)
		return
	}
	if !attempt.Existing {
		if e = s.flow.control.ReadyMFAFactor(r.Context(), token, challenge, factor, attempt.ID, requestID(r)); e != nil {
			s.businessError(w, r, e)
			return
		}
	}
	businessJSON(w, 201, map[string]any{"attemptId": attempt.ID, "expiresAt": attempt.ExpiresAt, "options": options})
}
func (s *Service) hardwareChallenge(a storage.MFAAttempt) mfa.HardwareChallenge {
	return mfa.HardwareChallenge{ID: a.ID, Nonce: a.Nonce, Credential: a.Factor.Reference, Principal: a.PrincipalID, Origin: s.origin, ExpiresAt: a.ExpiresAt}
}
func (s *Service) verifyNativeFactor(w http.ResponseWriter, r *http.Request) {
	token, ok := s.businessSession(w, r, true)
	if !ok {
		return
	}
	var body struct {
		Code  string          `json:"code"`
		Proof json.RawMessage `json:"proof"`
	}
	if e := strictJSON(w, r, &body); e != nil {
		s.businessError(w, r, e)
		return
	}
	if len(body.Code) > 8 || len(body.Proof) > 32768 {
		fail(w, 400)
		return
	}
	attempt, e := s.flow.control.ReserveMFAFactor(r.Context(), token, r.PathValue("challenge"), r.PathValue("factor"), requestID(r))
	if e != nil {
		s.businessError(w, r, e)
		return
	}
	verified := false
	counter := int64(-1)
	switch attempt.Factor.Method {
	case mfa.TOTP:
		var envelope keycrypto.Envelope
		if json.Unmarshal(attempt.Factor.SecretCipher, &envelope) == nil {
			secret, err := s.protector.Open(r.Context(), s.mfaBinding(attempt.PrincipalID, "enrollment", attempt.Factor.ID, "mfa_totp"), envelope)
			if err == nil {
				counter, err = mfa.TOTPCounter(secret, body.Code, time.Now(), attempt.LastCounter)
				verified = err == nil
				clear(secret)
			}
		}
	case mfa.Email, mfa.SMS:
		var envelope keycrypto.Envelope
		if json.Unmarshal(attempt.VerifierCipher, &envelope) == nil {
			key, err := s.protector.Open(r.Context(), s.mfaBinding(attempt.PrincipalID, attempt.ChallengeID, attempt.Factor.ID, "mfa_code"), envelope)
			if err == nil {
				mac := hmac.New(sha256.New, key)
				mac.Write([]byte(attempt.ChallengeID + "\x00" + attempt.Factor.ID + "\x00" + body.Code))
				verified = len(body.Code) == 8 && subtle.ConstantTimeCompare(mac.Sum(nil), attempt.CodeDigest) == 1
				clear(key)
			}
		}
	case mfa.Hardware:
		if s.config.MFAPlugins.Hardware != nil && len(body.Proof) > 0 {
			verified = s.config.MFAPlugins.Hardware.Verify(r.Context(), s.hardwareChallenge(attempt), body.Proof) == nil
		}
	}
	state, e := s.flow.control.CompleteMFAFactor(r.Context(), token, attempt, counter, verified, requestID(r))
	if e != nil {
		s.businessError(w, r, e)
		return
	}
	s.mfaStateResponse(w, state)
}

func validMFAPolicyHash(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == s
}
