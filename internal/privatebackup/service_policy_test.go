package privatebackup

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/config"
)

func policyBackupPayload() Payload {
	payload := NewPayload("0.18.1")
	policy := config.DefaultServicePolicy("telegram", config.ServiceState{Sources: []string{"192.168.1.40/32"}})
	policy.Revision, policy.Enabled, policy.Mode = 7, true, "auto"
	policy.AllowedNodeIDs = []string{"node-" + strings.Repeat("a", 64)}
	policy.AllowedSourceIDs = []string{"feed-kort0881-ru-sni"}
	policy.TrustClasses = []string{"community"}
	payload.ServicePolicies = map[string]config.ServicePolicy{"telegram": policy}
	return payload
}

func TestPrivateBackupPreservesPolicyIntentOnlyInsideEncryption(t *testing.T) {
	payload := policyBackupPayload()
	if err := Seal(&payload); err != nil {
		t.Fatal(err)
	}
	envelope, err := Encrypt(payload, "policy-backup-password")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(envelope)
	if err != nil || strings.Contains(string(encoded), "feed-kort0881") || strings.Contains(string(encoded), "192.168.1.40") || strings.Contains(string(encoded), "service_policies") {
		t.Fatal("service policy authority escaped encrypted payload")
	}
	restored, err := Decrypt(envelope, "policy-backup-password")
	if err != nil || !reflect.DeepEqual(restored.ServicePolicies, payload.ServicePolicies) {
		t.Fatal("encryption round trip lost exact policy authority")
	}
	// Pausing belongs to typed restore, not archive creation: the copy must
	// preserve the user's original choices for a reviewable later opt-in.
	if !restored.ServicePolicies["telegram"].Enabled || restored.ServicePolicies["telegram"].Mode != "auto" {
		t.Fatal("export rewrote original policy settings")
	}
}

func TestPrivateBackupPolicyValidationAndLegacyDigestCompatibility(t *testing.T) {
	for _, mutate := range []func(*Payload){
		func(p *Payload) {
			policy := p.ServicePolicies["telegram"]
			policy.Revision = 0
			p.ServicePolicies["telegram"] = policy
		},
		func(p *Payload) {
			policy := p.ServicePolicies["telegram"]
			policy.ServiceID = "youtube"
			p.ServicePolicies["telegram"] = policy
		},
		func(p *Payload) {
			policy := p.ServicePolicies["telegram"]
			policy.Mode = "run-anything"
			p.ServicePolicies["telegram"] = policy
		},
		func(p *Payload) {
			policy := p.ServicePolicies["telegram"]
			policy.DeviceSources = []string{"127.0.0.1"}
			p.ServicePolicies["telegram"] = policy
		},
		func(p *Payload) {
			policy := p.ServicePolicies["telegram"]
			policy.PinnedNodeID = "node-" + strings.Repeat("b", 64)
			p.ServicePolicies["telegram"] = policy
		},
	} {
		payload := policyBackupPayload()
		mutate(&payload)
		if Seal(&payload) == nil {
			t.Fatal("invalid policy authority entered private archive")
		}
	}
	legacy := NewPayload("0.18.0")
	if err := Seal(&legacy); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(legacy)
	if strings.Contains(string(encoded), "service_policies") || legacy.Schema != 1 {
		t.Fatal("optional field changed legacy payload representation")
	}
	var decoded Payload
	if json.Unmarshal(encoded, &decoded) != nil || Validate(decoded) != nil || decoded.Digest != legacy.Digest {
		t.Fatal("older policy-free payload digest no longer validates")
	}
}
