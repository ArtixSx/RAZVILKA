package dataplane

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

func addFirstStartCircularAssets(t *testing.T, f *firstStartFixture) {
	t.Helper()
	info := filepath.Join(f.owner.InfoDir, "nfqws2-keenetic.list")
	base := filepath.Dir(f.a.ConfigPath)
	if err := os.MkdirAll(filepath.Join(base, "blobs"), 0755); err != nil {
		t.Fatal(err)
	}
	writeStockText(t, info, readText(t, info)+"/opt/etc/nfqws2/lua/zapret-auto.lua.gz\n/opt/etc/nfqws2/blobs/tls_clienthello.bin\n")
	writeStockText(t, filepath.Join(base, "lua", "zapret-auto.lua.gz"), "modeled reviewed stock circular Lua\n")
	writeStockText(t, filepath.Join(base, "blobs", "tls_clienthello.bin"), "modeled reviewed stock ClientHello\n")
}

func TestNFQWSFirstStartRecipeChangesPlanDigestAndRejectsUnknown(t *testing.T) {
	input := Input{Revision: 1, Routes: []Route{{ServiceID: "selected", Resolved: "nfqws2", Domains: []string{"selected.example"}}}}
	before, err := BuildAt(input, time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}

	seen := map[string]bool{before.Digest: true}
	for _, recipe := range []engineconfig.NFQWSFirstStartRecipe{engineconfig.NFQWSFirstStartStockTLSCircular, engineconfig.NFQWSFirstStartStockTLSCircularAuto} {
		input.NFQWSFirstStartRecipe = recipe
		after, err := BuildAt(input, time.Unix(100, 0))
		if err != nil || seen[after.Digest] || before.PlanID == after.PlanID || after.NFQWSFirstStartRecipe != recipe {
			t.Fatal("recipe not bound to distinct plan", err)
		}
		seen[after.Digest] = true
	}
	input.NFQWSFirstStartRecipe = "foreign"
	if _, err := BuildAt(input, time.Unix(100, 0)); err == nil {
		t.Fatal("unknown recipe admitted")
	}
}

// Actual transaction/lease/native-review model, with explicit modeled kernel
// and process leaves. This is not evidence of Internet or LAN packet success.
func TestNFQWS2FirstStartRecipeHealthFailureRestoresPriorRecipe(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	recipes := []engineconfig.NFQWSFirstStartRecipe{"", engineconfig.NFQWSFirstStartStockTLSCircular, engineconfig.NFQWSFirstStartStockTLSCircularAuto}
	for _, priorRecipe := range recipes {
		for _, candidateRecipe := range recipes {
			if candidateRecipe == priorRecipe {
				continue
			}
			t.Run(string(priorRecipe)+"-to-"+string(candidateRecipe), func(t *testing.T) {
				f := newFirstStartFixture(t)
				addFirstStartCircularAssets(t, f)
				f.plan.NFQWSFirstStartRecipe = priorRecipe
				f.plan.PlanID = "dp-1111111111111111"
				f.apply(t)
				before, err := f.a.readLease()
				if err != nil {
					t.Fatal(err)
				}
				config := readBytes(t, f.a.ConfigPath)
				f.plan.PlanID = "dp-2222222222222222"
				f.plan.Digest = strings.Repeat("b", 64)
				f.plan.NFQWSFirstStartRecipe = candidateRecipe
				healthReached := false
				f.a.HealthProbe = func(context.Context, string) error {
					healthReached = true
					owner, _ := f.a.owner()
					got, err := engineconfig.NFQWSFirstStartConfigRecipe(readBytes(t, f.a.ConfigPath), owner)
					lease, leaseErr := f.a.readLease()
					if err != nil || leaseErr != nil || got != candidateRecipe || !f.running || !f.ownedRules || lease.FirstStart.Process.ArgumentsSHA256 == before.FirstStart.Process.ArgumentsSHA256 {
						t.Fatal("candidate did not reach health with its own exact running receipt", got, err, leaseErr)
					}
					return errors.New("modeled strict TLS health failure")
				}
				result, err := f.m.Apply(firstStartContext(t), f.plan, nil)
				if err == nil || !healthReached || result.State != "rolled-back" || !result.RollbackVerified {
					t.Fatal("cross-recipe rollback not verified", result.State, err)
				}
				after, err := f.a.readLease()
				if err != nil || !nfqws2RollbackLeaseEqual(after, before) || *after.FirstStart.Process == *before.FirstStart.Process || after.FirstStart.Process.ArgumentsSHA256 != before.FirstStart.Process.ArgumentsSHA256 {
					t.Fatal("prior runtime receipt not freshly restored", err)
				}
				if !bytes.Equal(config, readBytes(t, f.a.ConfigPath)) || !f.running || !f.ownedRules || f.a.firstStartReview != nil {
					t.Fatal("prior recipe/runtime not restored exactly")
				}
				f.assertWriterReleased(t)
			})
		}
	}
}

func TestNFQWS2FirstStartRecipeMissingAssetsRefusesBeforeStart(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	f := newFirstStartFixture(t)
	f.plan.NFQWSFirstStartRecipe = engineconfig.NFQWSFirstStartStockTLSCircularAuto
	result, err := f.m.Apply(firstStartContext(t), f.plan, nil)
	if err == nil || result.State == "committed" || f.running || f.ownedRules {
		t.Fatal("unreviewed recipe started", result.State, err)
	}
	for _, call := range f.calls {
		if firstStartRuntimeAction(call) {
			t.Fatal("missing asset reached lifecycle", call)
		}
	}
	f.assertWriterReleased(t)
}

func TestNFQWS2FirstStartRecipePriorRestartScopeRefusalCleansNewReceipt(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	f := newFirstStartFixture(t)
	addFirstStartCircularAssets(t, f)
	f.plan.PlanID = "dp-1111111111111111"
	f.apply(t)
	prior, err := f.a.readLease()
	if err != nil {
		t.Fatal(err)
	}
	f.plan.PlanID = "dp-2222222222222222"
	f.plan.Digest = strings.Repeat("b", 64)
	f.plan.NFQWSFirstStartRecipe = engineconfig.NFQWSFirstStartStockTLSCircularAuto
	f.a.HealthProbe = func(context.Context, string) error { return errors.New("modeled strict TLS failure") }
	revoked := false
	f.a.firstStartReceiptReady = func() {
		owner, _ := f.a.owner()
		recipe, err := engineconfig.NFQWSFirstStartConfigRecipe(readBytes(t, f.a.ConfigPath), owner)
		if err != nil {
			t.Fatal(err)
		}
		if recipe == "" {
			revoked = true
			f.policyFacts = []byte("nonempty policy")
		}
	}
	result, err := f.m.Apply(firstStartContext(t), f.plan, nil)
	if err == nil || !revoked || result.State != "rollback-failed" || result.RollbackVerified || f.running || f.ownedRules {
		t.Fatal("rejected prior restart left runtime or claimed restore", result.State, err)
	}
	current, err := f.a.readLease()
	if err != nil || current.FirstStart.Phase != nfqws2FirstStopped || *current.FirstStart.Process == *prior.FirstStart.Process {
		t.Fatal("new receipt not settled stopped", err)
	}
	result, err = f.m.RetryFailedRollback(firstStartContext(t), f.plan.PlanID, f.plan.Digest, func(Plan) error { return nil })
	if err == nil || result.RollbackVerified || f.running || f.ownedRules {
		t.Fatal("retry accepted a rejected new runtime", err)
	}
	f.assertWriterReleased(t)
}
