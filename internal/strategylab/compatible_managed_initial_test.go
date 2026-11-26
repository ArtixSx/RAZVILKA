package strategylab

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func TestManagedCompatibilityInitialStateRejectsHistoryOrUnownedSlots(t *testing.T) {
	for _, change := range []string{"candidate", "selection", "receipt", "read-image", "unknown", "probe", "trusted"} {
		t.Run(change, func(t *testing.T) {
			m, err := New(filepath.Join(t.TempDir(), "strategy-lab.json"))
			if err != nil {
				t.Fatal(err)
			}
			m.Executor, m.Validator = nil, CompatibleValidator{}
			m.mu.Lock()
			if err := m.managedCompatibilityInitialStateLocked(nil); err != nil {
				t.Fatal("original closed model", err)
			}
			switch change {
			case "candidate":
				m.state.Candidates["declared"] = Candidate{}
			case "selection":
				m.state.Selections["declared"] = Selection{}
			case "receipt":
				m.state.PackReceipts = map[string]PackReceipt{"declared": {}}
			case "read-image":
				m.image.Exists = true
			case "unknown":
				m.compatibilityUnknown = true
			case "probe":
				m.Executor = &SystemProbeExecutor{}
			case "trusted":
				m.Validator = CompatibleValidator{TrustedAssets: true}
			}
			err = m.managedCompatibilityInitialStateLocked(nil)
			m.mu.Unlock()
			if err == nil {
				t.Fatal("non-initial model admitted source creation", change)
			}
		})
	}
}

func TestManagedCompatibilityInitialWriteRequiresActualControlAndSnapshotIsReadonly(t *testing.T) {
	m, err := New(filepath.Join(t.TempDir(), "strategy-lab.json"))
	if err != nil {
		t.Fatal(err)
	}
	m.Executor, m.Validator = nil, CompatibleValidator{}
	_ = m.Snapshot()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, control := range []*operationgate.ControlEpochReview{nil, {}} {
		if err := m.InitializeManagedCompatibilitySource(ctx, control); err == nil {
			t.Fatal("declared control wrote the initial source")
		}
	}
	if _, err := os.Lstat(m.Path); !os.IsNotExist(err) || m.image.Exists || len(m.state.Candidates) != 0 {
		t.Fatal("Snapshot/refused initializer wrote source or fabricated a candidate", err)
	}
}
