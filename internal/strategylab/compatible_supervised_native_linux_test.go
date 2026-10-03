//go:build linux

package strategylab

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// This input is prepared by the installation owner from reviewed provenance.
// Tests verify these declared hashes; they never discover bytes and grant
// native trust to the discovered hashes. The isolated control is test-owned.
type compatibilityNativeReview struct {
	Schema       int    `json:"schema"`
	BinaryPath   string `json:"binary_path"`
	BinarySHA256 string `json:"binary_sha256"`
	Assets       []struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	} `json:"assets"`
	BaseArguments []string `json:"base_arguments"`
}

// Genuine CLI and Lua are opt-in and owned by the coordinator. This test does
// not create NFQUEUE, firewall rules, stock init hooks or activate any runtime.
// Run its compiled binary from a private reviewed directory, not go's /tmp
// build tree: the same binary becomes the protected dedicated helper.
func TestNFQWSNativeSupervisedCompatibility(t *testing.T) {
	reviewPath := os.Getenv("RAZVILKA_NFQWS_NATIVE_REVIEW")
	if reviewPath == "" {
		t.Skip("root-only genuine NFQWS binary/assets review required")
	}
	selected := os.Getenv("RAZVILKA_NFQWS_NATIVE_SUPERVISED_CASE")
	if selected != "normal" && selected != "lua-reject" {
		t.Fatal("select one reviewed genuine case: normal or lua-reject")
	}
	if err := compatibilityProtectedPath(reviewPath, false); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(reviewPath)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	_ = f.Close()
	if err != nil || len(data) > 64<<10 || compatibilityJSONUnique(data) != nil {
		t.Fatal("invalid bounded owner review")
	}
	var input compatibilityNativeReview
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&input) != nil || d.Decode(new(any)) != io.EOF || input.Schema != 1 {
		t.Fatal("invalid owner review shape")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	controlPath := filepath.Join(root, "isolated-control")
	ready, err := operationgate.InitializeSelfUpdateControl(context.Background(), controlPath)
	if err != nil {
		t.Fatal(err)
	}
	approval := CompatibilityApproval{BinaryPath: input.BinaryPath, BinarySHA256: input.BinarySHA256, BaseArguments: input.BaseArguments, ControlPath: controlPath, InstallationID: ready.InstallationID, Sequence: ready.Sequence}
	for _, asset := range input.Assets {
		approval.Assets = append(approval.Assets, CompatibilityApprovedAsset{Path: asset.Path, SHA256: asset.SHA256})
	}
	m, err := New(filepath.Join(root, "strategy-lab.json"))
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := m.AddCandidate("tcp-tls", "genuine compatibility", "--filter-tcp=443 --lua-desync=circular:fails=2:time=300 --lua-desync=fake:blob=tls_clienthello", "reviewed-native-fixture")
	if err != nil {
		t.Fatal(err)
	}
	provider, err := NewSupervisedCompatibilityProvider(m, approval)
	if err != nil {
		t.Fatal(err)
	}
	provider.helperPrefix = []string{"-test.run=^TestNFQWSSupervisedHelperEntry$", "--", "nfqws-compatibility-supervisor"}
	m.Validator = CompatibleValidator{Binary: approval.BinaryPath, BaseArguments: approval.BaseArguments, TrustedAssets: true, Timeout: 8 * time.Second, Provider: provider}
	checked, err := m.Validate(context.Background(), candidate.ID)
	if err != nil {
		t.Fatalf("native controller error: %v validation=%+v", err, checked.Validation)
	}
	if m.Snapshot().QuiescenceUnknown || checked.Validation.QuiescenceUnknown {
		t.Fatal("genuine terminal receipts were not acknowledged")
	}
	session := m.state.CompatibilitySession
	if session == nil || session.Active != "lua-init" || !compatibilityInvocationSucceeded(*session.DryRun) || session.LuaInit == nil || !session.LuaInit.Acknowledged || !session.LuaInit.Receipt.WaitECHILD || !session.LuaInit.Receipt.DirectReaped {
		t.Fatalf("both phase receipts required: %+v", session)
	}
	if selected == "normal" {
		if !checked.Validation.OK || !checked.Validation.Native || !checked.Validation.LuaChecked || checked.Validation.Code != "COMPATIBLE" || !compatibilityInvocationSucceeded(*session.LuaInit) {
			t.Fatalf("genuine native PASS required: %+v", checked.Validation)
		}
	} else if checked.Validation.OK || checked.Validation.Native || checked.Validation.LuaChecked || checked.Validation.Code != "COMPATIBILITY_REJECTED" || session.LuaInit.Receipt.ExitCode == 0 || session.LuaInit.Receipt.Cancelled {
		t.Fatalf("expected genuine known Lua rejection: %+v receipt=%+v", checked.Validation, session.LuaInit.Receipt)
	}
	reopened, err := New(m.Path)
	if err != nil || reopened.Snapshot().QuiescenceUnknown {
		t.Fatalf("acknowledged exact quiescence did not survive reload: %v", err)
	}
	t.Logf("genuine case=%s dry-helper=%d dry-direct=%d dry-reaped=%d lua-helper=%d lua-direct=%d lua-reaped=%d; both exact ECHILD receipts acknowledged", selected, session.DryRun.Receipt.PID, session.DryRun.Receipt.ChildPID, session.DryRun.Receipt.Reaped, session.LuaInit.Receipt.PID, session.LuaInit.Receipt.ChildPID, session.LuaInit.Receipt.Reaped)
}
