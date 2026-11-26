package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

func TestBootRetirementFirstXrayLANReportsOriginalScopeWithoutPublishing(t *testing.T) {
	for _, tc := range []struct {
		mode, expectedStage string
	}{
		{"same-boot", "first-xray-lan-same-boot"},
		{"changed-boot", "first-xray-lan-offline-unsupported"},
		{"unreadable-boot", "first-xray-lan-boot-unavailable"},
		{"mismatched-copy", "history-review"},
		{"different-cut", "history-review"},
		{"previous-plan", "history-review"},
		{"different-config", "history-review"},
		{"different-lan-snapshot", "history-review"},
		{"changed-during-boot-read", "history-review"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			definition := xraySelectedTCPDefinitionFixture(t)
			config := []byte(`{"test-fixture":"staged-node-secret"}`)
			definition.ConfigSHA256 = routeidentity.Hash(config)
			p := Plan{
				SchemaVersion: SchemaVersion, PlanID: definition.PlanID, Digest: definition.PlanDigest,
				State: "rollback-failed", LAN: CloneLANPolicyRuntime(definition.Match.LAN),
				Adapters: []string{NetworkPolicyAdapterID, "xray"}, NetworkProfileID: definition.NetworkProfile,
			}
			m := New(privateScopedXrayFixtureDir(t))
			xray := &ProxyTunnelAdapter{EngineID: "xray", StateRoot: filepath.Join(m.StateRoot, "xray")}
			if err := m.Register(xray); err != nil {
				t.Fatal(err)
			}
			root := filepath.Join(m.StateRoot, "transactions", p.PlanID)
			if err := m.prepareExecutionRoot(root); err != nil {
				t.Fatal(err)
			}
			if err := m.Record(p); err != nil {
				t.Fatal(err)
			}

			compiled, err := definition.validate()
			if err != nil {
				t.Fatal("invalid Xray definition fixture", err)
			}
			r := ExecutionResource{ID: "xr-" + strings.Repeat("a", 32), Kind: "xray-selected-tcp",
				Generation: compiled.Generation, EffectsDigest: definition.EffectsSHA256,
				State: "unused", Phase: "unused", XraySelectedTCP: &definition}
			now := time.Now().UTC().Format(time.RFC3339Nano)
			e := Execution{PlanID: p.PlanID, Digest: p.Digest, State: "rollback-failed",
				StartedAt: now, FinishedAt: now, Resources: []ExecutionResource{r}}
			for _, step := range [][3]string{
				{NetworkPolicyAdapterID, "snapshot", "passed"}, {"xray", "snapshot", "passed"},
				{NetworkPolicyAdapterID, "stage", "passed"}, {"xray", "stage", "passed"},
				{NetworkPolicyAdapterID, "validate", "passed"}, {"xray", "validate", "passed"},
				{"xray", "canary", "passed"}, {NetworkPolicyAdapterID, "activate", "failed"},
				{"xray", "rollback", "passed"}, {"xray", "verify-rollback", "passed"},
				{NetworkPolicyAdapterID, "rollback", "failed"}, {NetworkPolicyAdapterID, "verify-rollback", "failed"},
			} {
				e.Steps = append(e.Steps, ExecutionStep{Adapter: step[0], Phase: step[1], State: step[2], StartedAt: now, FinishedAt: now})
			}
			if tc.mode == "different-cut" {
				e.Steps[7].Adapter = "xray"
			}
			if err := validateExecutionResources(e, true); err != nil {
				t.Fatal("invalid typed fixture", err)
			}
			if err := m.writeExecution(root, e); err != nil {
				t.Fatal(err)
			}
			configPath := filepath.Join(root, "execution-resources", r.ID, definition.Process.ConfigName)
			if tc.mode == "different-config" {
				config = []byte(`{"test-fixture":"wrong-config"}`)
			}
			inactiveWrite(t, configPath, config)
			snapshot := []byte(`{"prior":null}`)
			if tc.mode == "different-lan-snapshot" {
				snapshot = []byte(`{"prior":{}}`)
			}
			inactiveWrite(t, filepath.Join(root, NetworkPolicyAdapterID, "snapshot.json"), snapshot)
			switch tc.mode {
			case "mismatched-copy":
				e.Steps[11].Detail = "different publication"
				altered, _ := json.Marshal(e)
				inactiveWrite(t, filepath.Join(root, "execution.json"), altered)
			case "previous-plan":
				earlier := p
				earlier.State = "committed"
				earlier.PlanID = "dp-1111111111111111"
				earlier.Digest = strings.Repeat("d", 64)
				image, _ := json.Marshal(earlier)
				inactiveWrite(t, filepath.Join(m.StateRoot, "latest-committed-plan.json"), image)
			}
			xray.bootIdentity = func() (string, error) {
				switch tc.mode {
				case "same-boot":
					return definition.NetworkIdentity.BootID, nil
				case "unreadable-boot":
					return "", errors.New("private boot diagnostic")
				case "changed-during-boot-read":
					inactiveWrite(t, configPath, []byte(`{"test-fixture":"changed-during-boot-read"}`))
				}
				return retirementNewBoot, nil
			}
			before := bootRetirementTree(t, m.StateRoot)
			fakeProof := proxyInactiveProof{
				interfaces: func() ([]net.Interface, error) {
					t.Fatal("preflight inspected an unrelated proxy runtime")
					return nil, nil
				},
				readlink: func(string) (string, error) { t.Fatal("preflight inspected an unrelated process"); return "", nil },
			}
			result, err := m.retireFailedRollbackAfterBoot(context.Background(), p.PlanID, p.Digest, strings.Repeat("c", 64),
				func(Plan) error { t.Fatal("preflight reached mutable recovery guard"); return nil }, bootRetirementOptions{proof: &fakeProof})
			if !errors.Is(err, ErrBootRetirement) || BootRetirementStage(err) != tc.expectedStage ||
				strings.Contains(err.Error(), "staged-node-secret") || strings.Contains(err.Error(), "private boot diagnostic") || result.State != "" {
				t.Fatalf("stage=%q err=%v result=%+v", BootRetirementStage(err), err, result)
			}
			if tc.mode == "changed-during-boot-read" {
				before[configPath] = []byte(`{"test-fixture":"changed-during-boot-read"}`)
			}
			if after := bootRetirementTree(t, m.StateRoot); !reflect.DeepEqual(before, after) {
				t.Fatal("read-only first-Apply refusal changed journal or runtime files")
			}
			if _, err := os.Stat(filepath.Join(m.StateRoot, "boot-retirements")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("preflight published retirement metadata")
			}
		})
	}
}
