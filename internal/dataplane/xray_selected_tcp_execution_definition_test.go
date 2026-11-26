package dataplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func xraySelectedTCPDefinitionFixture(t *testing.T) ExecutionXraySelectedTCPDefinition {
	t.Helper()
	x := newXrayOperationFixture(t, func(s *XraySelectedTCPRedirectSpec) {
		direct, err := CompileXraySelectedTCPLANPolicyRuntime(s.LAN.Generation, s.LAN.Ingress)
		if err != nil {
			t.Fatal(err)
		}
		s.LAN = direct
	})
	ctx := x.originalScope(t)
	if x.material.current(ctx, false) != nil {
		t.Fatal("original material changed")
	}
	compiled, err := CompileXraySelectedTCPRedirect(x.material.material.spec)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := PolicyEffectPlanDigest(compiled)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(x.material.material.config)
	return ExecutionXraySelectedTCPDefinition{Schema: 1, PlanID: x.scope.plan.PlanID, PlanDigest: x.scope.plan.Digest, NetworkProfile: x.scope.plan.NetworkProfileID,
		Match: x.material.material.spec.Clone(), Service: cloneXraySelectedTCPService(x.material.material.proof.service), Proof: x.material.material.ref,
		ConfigSHA256: hex.EncodeToString(hash[:]), EffectsSHA256: digest, Process: xraySelectedTCPProcessShape(),
		NetworkIdentity: netidentity.Identity{Version: 1, Kind: netidentity.ProcNetInode, BootID: "11111111-2222-3333-4444-555555555555", Inode: 42}}
}

func TestXraySelectedTCPExecutionDefinitionValidatesImmutableFullIntentOnly(t *testing.T) {
	d := xraySelectedTCPDefinitionFixture(t)
	compiled, err := d.validate()
	if err != nil {
		t.Fatal(err)
	}
	record := ExecutionResource{ID: "xr-" + strings.Repeat("a", 32), Kind: "xray-selected-tcp", State: "prepared", Phase: "planned", Generation: compiled.Generation, EffectsDigest: d.EffectsSHA256, XraySelectedTCP: &d}
	if err := validateXraySelectedTCPExecutionResource(record, false); err != nil {
		t.Fatal(err)
	}
	if err := validateXraySelectedTCPExecutionResource(record, true); err == nil {
		t.Fatal("planned definition became terminal proof")
	}
	mutations := []func(*ExecutionXraySelectedTCPDefinition){
		func(d *ExecutionXraySelectedTCPDefinition) { d.ConfigSHA256 = "" },
		func(d *ExecutionXraySelectedTCPDefinition) { d.EffectsSHA256 = strings.Repeat("f", 64) },
		func(d *ExecutionXraySelectedTCPDefinition) { d.Proof.NodeID = "node-foreign" },
		func(d *ExecutionXraySelectedTCPDefinition) { d.Service.CIDRs = d.Service.CIDRs[:0] },
		func(d *ExecutionXraySelectedTCPDefinition) { d.Proof.ServiceSHA256 = strings.Repeat("e", 64) },
		func(d *ExecutionXraySelectedTCPDefinition) { d.Process.ConfigSource = "named-path" },
		func(d *ExecutionXraySelectedTCPDefinition) { d.Process.EngineID = "sing-box" },
		func(d *ExecutionXraySelectedTCPDefinition) { d.Process.Version = "unknown" },
		func(d *ExecutionXraySelectedTCPDefinition) { d.Process.RouteProof = false },
		func(d *ExecutionXraySelectedTCPDefinition) {
			d.Match.Listener = netip.MustParseAddrPort("127.0.0.1:23456")
		},
		func(d *ExecutionXraySelectedTCPDefinition) { d.NetworkIdentity = netidentity.Identity{} },
	}
	for i, change := range mutations {
		changed := d.Clone()
		change(&changed)
		if _, err := changed.validate(); err == nil {
			t.Fatalf("accepted definition mutation %d", i)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := AcquireXraySelectedTCPExecutionResource(ctx, &XrayOperationMaterial{}, d.Match); err == nil {
		t.Fatal("definition issued native resource without original material/scope")
	}
}

func TestXraySelectedTCPExecutionDefinitionDeepCopyCannotRewriteOriginalSource(t *testing.T) {
	d := xraySelectedTCPDefinitionFixture(t)
	d.Service.Strategy = []string{"xray"}
	d.Service.Probes = []catalog.Probe{{ID: "main", Expect: catalog.ProbeExpectation{StatusCodes: []int{200}, RedirectHosts: []string{"service.example"}, BodyContains: []string{"expected"}}}}
	d.Service.Provenance = &catalog.Provenance{Provider: "original", SHA256: strings.Repeat("a", 64)}
	original := d.Clone()
	copy := d.Clone()
	copy.Match.LAN.Ingress[0].Sources[0] = "192.168.1.0/24"
	copy.Match.Destinations[0] = "8.8.8.0/24"
	copy.Service.Strategy[0] = "direct"
	copy.Service.Probes[0].Expect.StatusCodes[0] = 500
	copy.Service.Probes[0].Expect.RedirectHosts[0] = "foreign.example"
	copy.Service.Probes[0].Expect.BodyContains[0] = "changed"
	copy.Service.Provenance.Provider = "changed"
	if !reflect.DeepEqual(d, original) {
		t.Fatal("clone changed original held source")
	}
}

func TestXraySelectedTCPExecutionExpiredMetadataNeverRefreshesEligibility(t *testing.T) {
	d := xraySelectedTCPDefinitionFixture(t)
	d.Proof.CheckedAt = time.Now().Add(-2 * time.Hour)
	d.Proof.ExpiresAt = d.Proof.CheckedAt.Add(time.Hour)
	if _, err := d.validate(); err != nil {
		t.Fatal("historical journal intent lost exact cleanup comparison", err)
	}
	if d.eligible(time.Now()) {
		t.Fatal("expired journal proof refreshed eligibility")
	}
	if d.eligible(d.Proof.CheckedAt.Add(-time.Second)) {
		t.Fatal("future check accepted")
	}
}
