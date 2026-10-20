package webauth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"ex-keygate/internal/keycrypto"
	"ex-keygate/internal/mfa"
	"ex-keygate/internal/password"
	"ex-keygate/internal/storage"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"time"
)

func setupHash(token string) (string, error) {
	raw, e := base64.RawURLEncoding.DecodeString(token)
	if e != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != token {
		return "", storage.ErrDenied
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:]), nil
}

// setupInput 交付码仅经固定同源JSON正文输入，不进入URL、Cookie或日志；不依赖已丢失的登录因子。
func (s *Service) setupInput(w http.ResponseWriter, r *http.Request, body any) bool {
	if len(r.Header.Values("Origin")) != 1 || r.Header.Get("Origin") != s.origin {
		fail(w, 403)
		return false
	}
	if e := strictJSON(w, r, body); e != nil {
		s.businessError(w, r, e)
		return false
	}
	return true
}
func (s *Service) accountRoutes(handle func(string, http.HandlerFunc)) {
	s.accountPages(handle)
	handle("GET /api/account/self", func(w http.ResponseWriter, r *http.Request) {
		token, ok := s.businessSession(w, r, false)
		if !ok {
			return
		}
		out, e := s.flow.control.OwnAccount(r.Context(), token)
		if e != nil {
			s.businessError(w, r, e)
			return
		}
		businessJSON(w, 200, map[string]any{"account": out})
	})
	handle("POST /api/account/password", func(w http.ResponseWriter, r *http.Request) {
		token, ok := s.businessSession(w, r, true)
		if !ok {
			return
		}
		var body struct {
			OldPassword string `json:"oldPassword"`
			NewPassword string `json:"newPassword"`
		}
		if strictJSON(w, r, &body) != nil || body.OldPassword == body.NewPassword {
			fail(w, 400)
			return
		}
		select {
		case s.passwordSlots <- struct{}{}:
			defer func() { <-s.passwordSlots }()
		default:
			fail(w, 429)
			return
		}
		snapshot, e := s.flow.control.PasswordChangeSnapshot(r.Context(), token)
		if e != nil {
			s.businessError(w, r, e)
			return
		}
		matched := password.Verify(snapshot.Hash, body.OldPassword)
		encoded, e := password.Hash(body.NewPassword)
		if e != nil {
			fail(w, 400)
			return
		}
		if e = s.flow.control.ChangeOwnPassword(r.Context(), token, snapshot, matched, encoded, requestID(r)); e != nil {
			s.businessError(w, r, e)
			return
		}
		s.logger.InfoContext(r.Context(), "本人密码已更新，旧会话已失效", "request_id", requestID(r), "principal_id", snapshot.Principal)
		w.WriteHeader(204)
	})
	handle("POST /api/account/setup/status", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Token string `json:"token"`
		}
		if !s.setupInput(w, r, &body) {
			return
		}
		h, e := setupHash(body.Token)
		if e != nil {
			fail(w, 403)
			return
		}
		out, e := s.flow.control.AccountSetupStatus(r.Context(), h)
		if e != nil {
			s.businessError(w, r, e)
			return
		}
		available := map[string]bool{}
		for _, method := range []mfa.Method{mfa.TOTP, mfa.Email, mfa.SMS, mfa.Hardware} {
			available[string(method)] = s.config.MFAPlugins.Available(method)
		}
		businessJSON(w, 200, map[string]any{"setup": out, "available": available})
	})
	handle("POST /api/account/setup/factors", s.prepareSetupFactor)
	handle("POST /api/account/setup/retry", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Token    string `json:"token"`
			FactorID string `json:"factorId"`
		}
		if !s.setupInput(w, r, &body) {
			return
		}
		h, e := setupHash(body.Token)
		if e != nil {
			fail(w, 403)
			return
		}
		attempt, _, e := s.flow.control.SetupFactorAttempt(r.Context(), h, body.FactorID, false)
		if e != nil {
			s.businessError(w, r, e)
			return
		}
		out, e := s.flow.control.AccountSetupStatus(r.Context(), h)
		if e != nil {
			s.businessError(w, r, e)
			return
		}
		if attempt.Factor.Method == mfa.TOTP {
			if e = s.flow.control.ReserveSetupDelivery(r.Context(), h, body.FactorID); e != nil {
				s.businessError(w, r, e)
				return
			}
			var envelope keycrypto.Envelope
			if json.Unmarshal(attempt.Factor.SecretCipher, &envelope) != nil {
				fail(w, 503)
				return
			}
			secret, e := s.protector.Open(r.Context(), s.mfaBinding(out.Target, "enrollment", body.FactorID, "mfa_totp"), envelope)
			if e != nil {
				fail(w, 503)
				return
			}
			defer clear(secret)
			seed := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
			businessJSON(w, 200, map[string]any{"seed": seed})
			return
		}
		options, e := s.deliverSetupFactor(r, h, out, attempt.Factor, attempt.Verifier)
		if e != nil {
			s.businessError(w, r, e)
			return
		}
		businessJSON(w, 200, map[string]any{"options": options})
	})
	handle("POST /api/account/setup/verify", s.verifySetupFactor)
	handle("POST /api/account/setup/complete", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Token       string `json:"token"`
			NewPassword string `json:"newPassword"`
		}
		if !s.setupInput(w, r, &body) {
			return
		}
		h, e := setupHash(body.Token)
		if e != nil {
			fail(w, 403)
			return
		}
		out, e := s.flow.control.AccountSetupStatus(r.Context(), h)
		if e != nil {
			s.businessError(w, r, e)
			return
		}
		encoded := ""
		if out.ResetPassword {
			select {
			case s.passwordSlots <- struct{}{}:
				defer func() { <-s.passwordSlots }()
			default:
				fail(w, 429)
				return
			}
			encoded, e = password.Hash(body.NewPassword)
			if e != nil {
				fail(w, 400)
				return
			}
		} else if body.NewPassword != "" {
			fail(w, 400)
			return
		}
		owner := ""
		if cookie, e := r.Cookie(sessionCookie); e == nil {
			owner = cookie.Value
		}
		if e = s.flow.control.CompleteAccountSetup(r.Context(), h, owner, encoded, requestID(r)); e != nil {
			s.businessError(w, r, e)
			return
		}
		s.logger.InfoContext(r.Context(), "验证器与账号设置完成，旧会话已失效", "request_id", requestID(r), "principal_id", out.Target, "setup_id", out.ID)
		w.WriteHeader(204)
	})
}
func (s *Service) prepareSetupFactor(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token     string     `json:"token"`
		Method    mfa.Method `json:"method"`
		Label     string     `json:"label"`
		Reference string     `json:"reference"`
	}
	if !s.setupInput(w, r, &body) {
		return
	}
	h, e := setupHash(body.Token)
	if e != nil {
		fail(w, 403)
		return
	}
	out, e := s.flow.control.AccountSetupStatus(r.Context(), h)
	if e != nil {
		s.businessError(w, r, e)
		return
	}
	if body.Method == mfa.Hardware {
		if _, ok := s.config.MFAPlugins.Hardware.(mfa.HardwareRegistrationPlugin); !ok {
			fail(w, 503)
			return
		}
	}
	if !s.config.MFAPlugins.Available(body.Method) {
		fail(w, 503)
		return
	}
	f := mfa.Factor{ID: "factor-" + hexToken(), Method: body.Method, Label: body.Label}
	var secret, verifier []byte
	seed := ""
	code := ""
	if f.Method == mfa.TOTP {
		if body.Reference != "" {
			fail(w, 400)
			return
		}
		secret = make([]byte, 32)
		if _, e = rand.Read(secret); e != nil {
			fail(w, 503)
			return
		}
		defer clear(secret)
		seed = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
		sum := sha256.Sum256(append([]byte("totp\x00"), secret...))
		f.Fingerprint = hex.EncodeToString(sum[:])
		f.SecretCipher = []byte("reserved")
	} else if f.Method == mfa.Hardware {
		if body.Reference != "" {
			fail(w, 400)
			return
		}
		f.Reference = random()
		sum := sha256.Sum256([]byte("hardware-pending\x00" + out.ID + f.ID))
		f.Fingerprint = hex.EncodeToString(sum[:])
	} else {
		f.Reference, e = enrollmentReference(f.Method, body.Reference)
		if e != nil {
			fail(w, 400)
			return
		}
		sum := sha256.Sum256([]byte(string(f.Method) + "\x00" + f.Reference))
		f.Fingerprint = hex.EncodeToString(sum[:])
		value, e := rand.Int(rand.Reader, big.NewInt(100000000))
		if e != nil {
			fail(w, 503)
			return
		}
		code = fmt.Sprintf("%08d", value.Int64())
	}
	// 数量与唯一指纹先占位，只有获胜请求可以消耗根包装预算；失败不得通过重建候选重置额度。
	if e = s.flow.control.AddSetupFactor(r.Context(), h, f, nil, requestID(r)); e != nil {
		s.businessError(w, r, e)
		return
	}
	if f.Method == mfa.TOTP {
		sealed, e := s.protector.Seal(r.Context(), s.mfaBinding(out.Target, "enrollment", f.ID, "mfa_totp"), secret, out.Target, requestID(r))
		if e != nil {
			fail(w, 503)
			return
		}
		f.SecretCipher, _ = json.Marshal(sealed)
	} else if f.Method != mfa.Hardware {
		sealed, e := s.protector.Seal(r.Context(), s.mfaBinding(out.Target, out.ID, f.ID, "mfa_code"), []byte(code), out.Target, requestID(r))
		if e != nil {
			fail(w, 503)
			return
		}
		verifier, _ = json.Marshal(sealed)
	}
	if e = s.flow.control.SaveSetupSecrets(r.Context(), h, f.ID, f.SecretCipher, verifier); e != nil {
		s.businessError(w, r, e)
		return
	}
	options, e := s.deliverSetupFactor(r, h, out, f, verifier)
	if e != nil {
		s.businessError(w, r, e)
		return
	}
	response := map[string]any{"factor": f, "options": options}
	if seed != "" {
		response["seed"] = seed
		response["uri"] = "otpauth://totp/" + url.PathEscape("ExKeyGate:"+out.PersonID) + "?secret=" + seed + "&issuer=ExKeyGate&algorithm=SHA1&digits=6&period=30"
	}
	businessJSON(w, 201, response)
}
func (s *Service) verifySetupFactor(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token    string          `json:"token"`
		FactorID string          `json:"factorId"`
		Code     string          `json:"code"`
		Proof    json.RawMessage `json:"proof,omitempty"`
	}
	if !s.setupInput(w, r, &body) {
		return
	}
	h, e := setupHash(body.Token)
	if e != nil {
		fail(w, 403)
		return
	}
	attempt, now, e := s.flow.control.SetupFactorAttempt(r.Context(), h, body.FactorID, true)
	if e != nil {
		s.businessError(w, r, e)
		return
	}
	if attempt.Factor.Method == mfa.Hardware {
		plugin, ok := s.config.MFAPlugins.Hardware.(mfa.HardwareRegistrationPlugin)
		if !ok {
			fail(w, 503)
			return
		}
		state, e := s.flow.control.AccountSetupStatus(r.Context(), h)
		if e != nil {
			s.businessError(w, r, e)
			return
		}
		credential, e := plugin.RegisterVerify(r.Context(), s.setupHardwareChallenge(attempt.SetupID, attempt.Target, attempt.Factor, state.ExpiresAt), body.Proof)
		if e != nil {
			s.businessError(w, r, storage.ErrDenied)
			return
		}
		reference, e := enrollmentReference(mfa.Hardware, credential)
		if e != nil {
			fail(w, 503)
			return
		}
		sum := sha256.Sum256([]byte("hardware\x00" + reference))
		if e = s.flow.control.CompleteSetupHardware(r.Context(), h, body.FactorID, reference, hex.EncodeToString(sum[:]), requestID(r)); e != nil {
			s.businessError(w, r, e)
			return
		}
		w.WriteHeader(204)
		return
	}
	var env keycrypto.Envelope
	binding := s.mfaBinding(attempt.Target, attempt.SetupID, attempt.Factor.ID, "mfa_code")
	cipher := attempt.Verifier
	if attempt.Factor.Method == mfa.TOTP {
		binding = s.mfaBinding(attempt.Target, "enrollment", attempt.Factor.ID, "mfa_totp")
		cipher = attempt.Factor.SecretCipher
	}
	if json.Unmarshal(cipher, &env) != nil {
		fail(w, 503)
		return
	}
	secret, e := s.protector.Open(r.Context(), binding, env)
	if e != nil {
		fail(w, 503)
		return
	}
	defer clear(secret)
	valid := false
	counter := int64(-1)
	if attempt.Factor.Method == mfa.TOTP {
		counter, e = mfa.TOTPCounter(secret, body.Code, now, attempt.LastCounter)
		valid = e == nil
	} else {
		valid = subtle.ConstantTimeCompare(secret, []byte(body.Code)) == 1
	}
	if e = s.flow.control.VerifySetupFactor(r.Context(), h, body.FactorID, counter, valid, requestID(r)); e != nil {
		s.businessError(w, r, e)
		return
	}
	w.WriteHeader(204)
}

func (s *Service) setupHardwareChallenge(id, target string, f mfa.Factor, expires time.Time) mfa.HardwareChallenge {
	return mfa.HardwareChallenge{ID: id + "-" + f.ID, Nonce: f.Reference, Principal: target, Origin: s.origin, ExpiresAt: expires}
}

// deliverSetupFactor 对外调用不持有数据库锁，重试复用同一候选、验证码与幂等键；失败不计已证明。
func (s *Service) deliverSetupFactor(r *http.Request, h string, out storage.AccountSetup, f mfa.Factor, verifier []byte) (json.RawMessage, error) {
	var options json.RawMessage
	if f.Method != mfa.TOTP {
		if e := s.flow.control.ReserveSetupDelivery(r.Context(), h, f.ID); e != nil {
			return nil, e
		}
	}
	if f.Method == mfa.Email || f.Method == mfa.SMS {
		var env keycrypto.Envelope
		if json.Unmarshal(verifier, &env) != nil {
			return nil, storage.ErrInvalid
		}
		raw, e := s.protector.Open(r.Context(), s.mfaBinding(out.Target, out.ID, f.ID, "mfa_code"), env)
		if e != nil {
			return nil, e
		}
		defer clear(raw)
		plugin := s.config.MFAPlugins.Email
		if f.Method == mfa.SMS {
			plugin = s.config.MFAPlugins.SMS
		}
		if plugin == nil {
			return nil, mfa.ErrPlugin
		}
		if e = plugin.Send(r.Context(), mfa.Delivery{ID: out.ID + "-" + f.ID, Method: f.Method, Destination: f.Reference, Code: string(raw), ExpiresAt: out.ExpiresAt}); e != nil {
			return nil, e
		}
	}
	if f.Method == mfa.Hardware {
		plugin, ok := s.config.MFAPlugins.Hardware.(mfa.HardwareRegistrationPlugin)
		if !ok {
			return nil, mfa.ErrPlugin
		}
		var e error
		options, e = plugin.RegisterBegin(r.Context(), s.setupHardwareChallenge(out.ID, out.Target, f, out.ExpiresAt))
		if e != nil {
			return nil, e
		}
	}
	return options, s.flow.control.SetupFactorReady(r.Context(), h, f.ID)
}
