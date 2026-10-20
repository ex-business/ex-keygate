package webauth

import (
	"encoding/json"
	"ex-keygate/internal/access"
	"ex-keygate/internal/storage"
	"strconv"
	"strings"
	"testing"
)

func TestOnlineGovernanceHTTP(t *testing.T) {
	a := setupFlow(t, true)
	owner := a.loginAs(t, "demo-requester")
	one := a.loginAs(t, "demo-approver-1")
	two := a.loginAs(t, "demo-approver-2")
	change := storage.GovernanceChange{Issuer: a.service.config.Identity.Issuer, Subject: "online-new-person", PersonID: "online-person", Enabled: true, Reason: "新人员身份关联核验", EvidenceHash: strings.Repeat("b", 64)}
	op := storage.ControlOperation{Kind: storage.CreatePrincipal, ClientID: "governance-management", Governance: &change}
	status, _ := a.business(t, one, "POST", "/api/requests", op)
	if status != 403 {
		t.Fatal("无治理权限登记人员", status)
	}
	r := a.submitOperation(t, owner, op)
	status, _ = a.business(t, owner, "POST", "/api/requests/"+r.ID+"/execute", map[string]string{"digest": r.Digest})
	if status != 403 {
		t.Fatal("未审批登记", status)
	}
	a.approveHTTP(t, []businessActor{one, two}, r)
	status, _ = a.business(t, owner, "POST", "/api/requests/"+r.ID+"/execute", map[string]string{"digest": r.Digest})
	if status != 200 {
		t.Fatal("登记执行失败", status)
	}
	status, raw := a.business(t, owner, "GET", "/api/console/settings", nil)
	var settings storage.ConsoleSettings
	if status != 200 || json.Unmarshal(raw, &settings) != nil {
		t.Fatal("人员目录", status)
	}
	p, _ := access.NewPrincipal(change.Issuer, change.Subject, change.PersonID)
	var registered *storage.ConsolePerson
	for i := range settings.People {
		if settings.People[i].PrincipalID == p.ID {
			registered = &settings.People[i]
		}
	}
	if registered == nil || len(registered.Grants) != 0 || registered.Revision != "1" || registered.MFAConfigured {
		t.Fatal("登记后隐式授权或配置MFA")
	}
	version, _ := strconv.ParseUint(settings.Version, 10, 64)
	op = storage.ControlOperation{Kind: storage.UpdateApprovalPolicy, ClientID: "governance-management", ExpectedRevision: version, Governance: &storage.GovernanceChange{M: 2, Approvers: []string{settings.Approvers[1], settings.Approvers[0]}, Reason: "调整审批人员先后顺序", EvidenceHash: strings.Repeat("c", 64)}}
	r = a.submitOperation(t, owner, op)
	a.approveHTTP(t, []businessActor{one, two}, r)
	status, _ = a.business(t, owner, "POST", "/api/requests/"+r.ID+"/execute", map[string]string{"digest": r.Digest})
	if status != 200 {
		t.Fatal("策略执行失败", status)
	}
	status, raw = a.business(t, owner, "GET", "/api/console/settings", nil)
	var updated storage.ConsoleSettings
	if status != 200 || json.Unmarshal(raw, &updated) != nil || updated.Version == settings.Version || updated.Approvers[0] != settings.Approvers[1] || !updated.Sequential {
		t.Fatal("在线策略未生效", status)
	}
}
