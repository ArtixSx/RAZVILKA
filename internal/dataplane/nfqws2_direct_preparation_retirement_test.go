package dataplane

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Phase model of native573 with the actual original writers. Snapshot, Stage
// and LAN Activate publish their real files; then the lost physical packet
// fence refuses NFQ Activate after activationAttempted and before any seal.
// Only the NFQ refusal itself and its never-started Rollback are modeled.
func (f *preEffectLANFixture) activateLANThenRefuseNFQ(t *testing.T) {
	t.Helper()
	f.snapshot(t, false)
	if err := f.e.gate.Stage(f.ctx, f.e.plan, f.root); err != nil {
		t.Fatal("original Stage", err)
	}
	if err := f.e.gate.Activate(f.ctx, f.e.plan, f.root); err != nil {
		t.Fatal("original LAN Activate", err)
	}
	if !f.e.lanActivationAttempted || f.e.neverActivatedLAN() {
		t.Fatal("phase model is not the LAN-activated 573 boundary")
	}
	f.e.mu.Lock()
	f.e.activationAttempted = true
	f.e.mu.Unlock()
	f.physical = errors.New("modeled notifications.route.tracked")
	f.e.retired = true
	if f.e.activationSeal != nil || f.e.resource != nil || f.e.prepared != nil || f.e.binding != nil || f.e.started || f.e.launchInvoked || f.e.material.issuedSelection != nil {
		t.Fatal("phase model manufactured an activation receipt")
	}
}

func directPreparationState(t *testing.T, f *preEffectLANFixture) (owner bool, status PolicyAdditionStatus) {
	t.Helper()
	_, err := os.Lstat(f.e.gate.ownerPath())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	status, inspectErr := f.e.gate.Binding.Inspect(f.ctx, f.e.plan.LAN, f.root)
	if inspectErr != nil && !errors.Is(inspectErr, os.ErrNotExist) {
		t.Fatal("original preparation unreadable", inspectErr)
	}
	return err == nil, status
}

func TestNFQWSDirectPreparationRetiresAfterLANActivateBeforeNFQSeal(t *testing.T) {
	f := newPreEffectLANFixture(t)
	f.activateLANThenRefuseNFQ(t)
	if owner, status := directPreparationState(t, f); !owner || !status.Complete || status.Removed {
		t.Fatal("LAN Activate did not publish its owner and preparation", owner, status)
	}
	if err := f.e.gate.Rollback(f.ctx, f.e.plan, f.root); err != nil {
		t.Fatal("573: the original metadata-only preparation cannot complete after the physical boundary is lost", err)
	}
	if ok, err := f.e.gate.VerifyRollback(f.ctx, f.e.plan, f.root); err != nil || !ok {
		t.Fatal("573: retired preparation not freshly verified", ok, err)
	}
	if owner, status := directPreparationState(t, f); owner || !status.Removed || status.Complete {
		t.Fatal("original owner/preparation not retired", owner, status)
	}
	if _, err := os.Stat(filepath.Join(f.root, "snapshot.json")); err != nil {
		t.Fatal("original Snapshot image removed", err)
	}
}
