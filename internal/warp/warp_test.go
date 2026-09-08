package warp

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/evidence"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

const validProfile = `[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 172.16.0.2/32, 2606:4700:110:8765::2/128
DNS = 1.1.1.1
MTU = 1280

[Peer]
PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = engage.cloudflareclient.com:2408
`

func TestValidateProfile(t *testing.T) {
	if err := ValidateProfile([]byte(validProfile)); err != nil {
		t.Fatal(err)
	}
	for _, replacement := range []struct{ old, new string }{
		{"PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "PrivateKey = bad"},
		{"Endpoint = engage.cloudflareclient.com:2408", "Endpoint = missing-port"},
		{"AllowedIPs = 0.0.0.0/0, ::/0", "AllowedIPs = nope"},
	} {
		if err := ValidateProfile([]byte(strings.Replace(validProfile, replacement.old, replacement.new, 1))); err == nil {
			t.Fatalf("expected rejection for %q", replacement.new)
		}
	}
}

func TestImportStagesCandidate(t *testing.T) {
	root := t.TempDir()
	configs := engineconfig.New(filepath.Join(root, "stage"), filepath.Join(root, "backups"))
	m := New(filepath.Join(root, "warp"), filepath.Join(root, "warp-backups"), configs)
	result, err := m.Import(validProfile)
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK || result.Source != "import" {
		t.Fatalf("unexpected result: %#v", result)
	}
	check, err := m.CheckCandidate()
	if err != nil {
		t.Fatal(err)
	}
	if !check.OK || check.Source != "staged" {
		t.Fatalf("unexpected check: %#v", check)
	}
}

func TestGenerateRequiresExplicitTermsAcceptanceBeforeRegistration(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "wgcf")
	if err := os.WriteFile(bin, []byte("not executed"), 0o755); err != nil {
		t.Fatal(err)
	}
	m := New(filepath.Join(root, "warp"), filepath.Join(root, "backups"), engineconfig.New(filepath.Join(root, "stage"), filepath.Join(root, "config-backups")))
	m.BinPaths = []string{bin}
	if _, err := m.Generate(context.Background(), false, false); !errors.Is(err, ErrTermsAcceptanceRequired) {
		t.Fatalf("generate error=%v", err)
	}
	if regularFile(filepath.Join(root, "warp", "wgcf-account.toml")) {
		t.Fatal("account was created without terms acceptance")
	}
}

func TestTransientRegistrationErrorClassification(t *testing.T) {
	for _, message := range []string{
		`Post "https://api.cloudflareclient.com/v0a1922/reg": net/http: TLS handshake timeout`,
		"dial tcp: i/o timeout",
		"read: connection reset by peer",
	} {
		if !transientRegistrationError(errors.New(message)) {
			t.Fatalf("transient error was not classified: %s", message)
		}
	}
	if transientRegistrationError(errors.New("invalid account format")) {
		t.Fatal("permanent error was classified as transient")
	}
}

func TestHealthPolicyRequiresConfirmedEvidenceAndThreshold(t *testing.T) {
	root := t.TempDir()
	m := New(filepath.Join(root, "warp"), filepath.Join(root, "backups"), nil)
	policy := HealthPolicy{Enabled: true, AcceptTOS: true, AutoGenerateCandidate: true, FailureThreshold: 3, MinFailedServices: 2, CooldownHours: 24, MaxRotationsPerDay: 1}
	if _, err := m.UpdateHealthPolicy(policy); err != nil {
		t.Fatal(err)
	}
	decision, err := m.ObserveHealth([]HealthEvidence{{ServiceID: "one", Status: "fail"}, {ServiceID: "two", Status: "fail"}})
	if err != nil {
		t.Fatal(err)
	}
	if decision.ShouldGenerate || decision.State.ConsecutiveFailedRounds != 0 || decision.State.RouteEvidenceConfirmed {
		t.Fatalf("unconfirmed evidence armed policy: %+v", decision)
	}

	confirmed := []HealthEvidence{{ServiceID: "one", Status: "fail", RouteConfirmed: true}, {ServiceID: "two", Status: "fail", RouteConfirmed: true}}
	for round := 1; round <= 3; round++ {
		decision, err = m.ObserveHealth(confirmed)
		if err != nil {
			t.Fatal(err)
		}
		if decision.State.ConsecutiveFailedRounds != round {
			t.Fatalf("round %d: %+v", round, decision)
		}
	}
	if !decision.ShouldGenerate || !decision.Eligible {
		t.Fatalf("threshold did not request candidate: %+v", decision)
	}
	if err := m.RecordRotation(); err != nil {
		t.Fatal(err)
	}
	if status := m.Health(); status.Eligible || status.State.ConsecutiveFailedRounds != 0 {
		t.Fatalf("rotation did not reset/cool down policy: %+v", status)
	}
}

func TestHealthPolicyRejectsExplicitRuntimeOnlySuccess(t *testing.T) {
	root := t.TempDir()
	m := New(filepath.Join(root, "warp"), filepath.Join(root, "backups"), nil)
	policy := HealthPolicy{Enabled: true, AcceptTOS: true, FailureThreshold: 3, MinFailedServices: 1, CooldownHours: 24, MaxRotationsPerDay: 1}
	if _, err := m.UpdateHealthPolicy(policy); err != nil {
		t.Fatal(err)
	}
	decision, err := m.ObserveHealth([]HealthEvidence{{ServiceID: "telegram", Status: "pass", RouteConfirmed: true, Level: evidence.Runtime}})
	if err != nil {
		t.Fatal(err)
	}
	if decision.State.RouteEvidenceConfirmed || len(decision.State.LastSuccessfulServices) != 0 {
		t.Fatalf("runtime-only response armed WARP health: %+v", decision.State)
	}
}

func TestHealthPolicyValidation(t *testing.T) {
	m := New(t.TempDir(), t.TempDir(), nil)
	if _, err := m.UpdateHealthPolicy(HealthPolicy{Enabled: true, AutoGenerateCandidate: true, FailureThreshold: 3, MinFailedServices: 2, CooldownHours: 24, MaxRotationsPerDay: 1}); err == nil {
		t.Fatal("expected terms requirement")
	}
	if _, err := m.UpdateHealthPolicy(HealthPolicy{Enabled: true, AcceptTOS: true, AutoApplyCandidate: true, FailureThreshold: 3, MinFailedServices: 2, CooldownHours: 24, MaxRotationsPerDay: 1}); err == nil {
		t.Fatal("expected automatic generation requirement")
	}
}

func TestRecordActivationState(t *testing.T) {
	m := New(t.TempDir(), t.TempDir(), nil)
	if err := m.RecordActivation(false, "handshake timeout"); err != nil {
		t.Fatal(err)
	}
	status := m.Health()
	if status.State.LastDecision != "fresh-profile-activation-failed" || status.State.LastActivationError != "handshake timeout" {
		t.Fatalf("unexpected failed activation state: %+v", status.State)
	}
	if err := m.RecordActivation(true, ""); err != nil {
		t.Fatal(err)
	}
	status = m.Health()
	if status.State.LastDecision != "fresh-profile-activated" || status.State.LastActivationError != "" {
		t.Fatalf("unexpected successful activation state: %+v", status.State)
	}
}
