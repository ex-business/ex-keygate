package webauth

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"ex-keygate/internal/identity"
	"ex-keygate/internal/mfa"
	"ex-keygate/internal/storage"
	"net/mail"
	"regexp"
	"strings"
)

// MFAEnrollmentPlan 只允许私有启动配置输入；既不挂HTTP，也不依据SSO自报角色或未核验地址初始化。
// TOTP种子只从操作员受控私有文件读入，立即加密后保存，不写日志或连接元数据。
type MFAEnrollmentPlan struct {
	WitnessSubjects  [2]string             `json:"witnessSubjects"`
	EvidenceHash     string                `json:"evidenceHash"`
	People           []MFAEnrollmentPerson `json:"people"`
	ApproverSubjects []string              `json:"approverSubjects"`
	M                int                   `json:"m"`
}
type MFAEnrollmentPerson struct {
	Subject string                `json:"subject"`
	Policy  mfa.Policy            `json:"policy"`
	Factors []MFAEnrollmentFactor `json:"factors"`
}
type MFAEnrollmentFactor struct {
	ID        string     `json:"id"`
	Method    mfa.Method `json:"method"`
	Label     string     `json:"label"`
	Reference string     `json:"reference"`
	TOTPSeed  string     `json:"totpSeed"`
}

var phoneNumber = regexp.MustCompile(`^\+[1-9][0-9]{7,14}$`)

func enrollmentReference(method mfa.Method, reference string) (string, error) {
	switch method {
	case mfa.Email:
		address, e := mail.ParseAddress(reference)
		if e != nil || address.Address != reference || strings.TrimSpace(reference) != reference {
			return "", mfa.ErrInvalid
		}
		for _, c := range reference {
			if c < 33 || c > 126 {
				return "", mfa.ErrInvalid
			}
		}
		return strings.ToLower(reference), nil
	case mfa.SMS:
		if !phoneNumber.MatchString(reference) {
			return "", mfa.ErrInvalid
		}
		return reference, nil
	case mfa.Hardware:
		if len(reference) == 0 || len(reference) > 2048 || strings.TrimSpace(reference) != reference {
			return "", mfa.ErrInvalid
		}
		return reference, nil
	}
	return "", mfa.ErrInvalid
}
func (s *Service) ProvisionNativeMFAOffline(ctx context.Context, plan MFAEnrollmentPlan) error {
	if s.handlerStarted.Load() || s.flow == nil || len(plan.People) == 0 || len(plan.People) > 128 {
		return ErrConfig
	}
	entries := []storage.MFAProvision{}
	for _, person := range plan.People {
		principal := identity.PrincipalID(s.config.Identity.Issuer, person.Subject)
		entry := storage.MFAProvision{PrincipalID: principal, Policy: person.Policy}
		for _, enrollment := range person.Factors {
			f := mfa.Factor{ID: enrollment.ID, Method: enrollment.Method, Label: enrollment.Label}
			var fingerprint []byte
			if f.Method == mfa.TOTP {
				if enrollment.Reference != "" {
					return mfa.ErrInvalid
				}
				secret, e := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(enrollment.TOTPSeed)
				if e != nil || len(secret) != 32 {
					clear(secret)
					return mfa.ErrInvalid
				}
				// 用途与人员、绑定项绑定，密文不能跨人员或设备搬移。
				envelope, e := s.protector.Seal(ctx, s.mfaBinding(principal, "enrollment", f.ID, "mfa_totp"), secret, principal, "mfa-provision-"+hexToken())
				sum := sha256.Sum256(append([]byte("totp\x00"), secret...))
				clear(secret)
				fingerprint = sum[:]
				if e != nil {
					return e
				}
				f.SecretCipher, _ = json.Marshal(envelope)
			} else {
				if enrollment.TOTPSeed != "" {
					return mfa.ErrInvalid
				}
				reference, e := enrollmentReference(f.Method, enrollment.Reference)
				if e != nil {
					return e
				}
				f.Reference = reference
				sum := sha256.Sum256([]byte(string(f.Method) + "\x00" + reference))
				fingerprint = sum[:]
			}
			f.Fingerprint = hex.EncodeToString(fingerprint)
			if f.Validate() != nil {
				return mfa.ErrInvalid
			}
			entry.Factors = append(entry.Factors, f)
		}
		entries = append(entries, entry)
	}
	witnesses := [2]string{identity.PrincipalID(s.config.Identity.Issuer, plan.WitnessSubjects[0]), identity.PrincipalID(s.config.Identity.Issuer, plan.WitnessSubjects[1])}
	if e := s.flow.control.ProvisionMFAOffline(ctx, entries, witnesses, plan.EvidenceHash, "mfa-provision-"+hexToken()); e != nil {
		return e
	}
	if len(plan.ApproverSubjects) > 0 {
		ids := []string{}
		for _, subject := range plan.ApproverSubjects {
			ids = append(ids, identity.PrincipalID(s.config.Identity.Issuer, subject))
		}
		if e := s.flow.control.ConfigureSequentialApprovalOffline(ctx, ids, plan.M, witnesses, plan.EvidenceHash, "mfa-sequence-"+hexToken()); e != nil {
			return e
		}
	}
	s.logger.InfoContext(ctx, "原生二次验证策略已配置，未配置人员拒绝管理操作", "environment", s.flow.environment, "people", len(entries), "result", "enabled")
	return nil
}
