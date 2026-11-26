package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

func TestWGOriginalExecutionSyncFailureKeepsRenamedFDForCleanup(t *testing.T) {
	a, owner, ctx, _, _, _ := wgNetworkCommandOwnerFixture(t)
	t.Setenv("RAZVILKA_WG_COMMAND_CLI_MODEL", "1")
	t.Setenv("RAZVILKA_WG_COMMAND_TEST_MARKER", filepath.Join(t.TempDir(), "commands"))
	if _, err := a.run(ctx, a.IP, "link", "add", "rz-wg", "type", "wireguard"); err != nil {
		t.Fatal(err)
	}
	d := owner.scope.wgRecords
	old := d.infos
	d.syncDirectory = func(*ownedfs.Root) error { return errors.New("modeled post-rename directory sync failure") }
	owner.scope.execution.Error = "unknown after actual child mutation attempt"
	if err := owner.scope.manager.writeExecutionOwned(owner.scope.root, *owner.scope.execution, owner.scope); !errors.Is(err, ErrExecutionJournal) {
		t.Fatal("directory sync failure lost", err)
	}
	for i := range d.files {
		if d.files[i] == nil || os.SameFile(old[i], d.infos[i]) || d.ack[i] {
			t.Fatal("failed publication discarded own new FD or received ACK", i)
		}
	}
	if d.current(ctx, false) != nil || d.current(ctx, true) == nil {
		t.Fatal("unacknowledged original pair did not distinguish cleanup from forward")
	}
	if _, err := a.run(ctx, a.IP, "-j", "link", "show"); err == nil {
		t.Fatal("unacknowledged publication allowed forward child")
	}
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	cleanup, err := owner.cleanupContext(cleanup)
	if err != nil {
		t.Fatal("own failed publication blocked cleanup context", err)
	}
	if _, err := a.run(cleanup, a.IP, "-j", "link", "show"); err != nil {
		t.Fatal("own failed publication blocked actual cleanup read child", err)
	}
	d.syncDirectory = nil
	if err := owner.scope.manager.writeExecutionOwned(owner.scope.root, *owner.scope.execution, owner.scope); err != nil || d.current(cleanup, true) != nil {
		t.Fatal("original cleanup could not republish own pair", err)
	}
}

func TestWGOriginalExecutionHeldDirectoryMustMatchNamedAnchor(t *testing.T) {
	for _, index := range []int{0, 1} {
		t.Run([]string{"transaction", "manager"}[index], func(t *testing.T) {
			_, owner, ctx, _, _, _ := wgNetworkCommandOwnerFixture(t)
			d := owner.scope.wgRecords
			foreign, err := ownedfs.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer foreign.Close()
			name := []string{"execution.json", "latest-execution.json"}[index]
			file, err := foreign.WriteAtomicRetained(name, d.images[index], 0600)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			oldFile, oldInfo := d.files[index], d.infos[index]
			oldRoot := d.root
			if index == 0 {
				oldRoot = d.transactionRoot
				d.transactionRoot = foreign
			} else {
				d.root = foreign
			}
			d.files[index], d.infos[index] = file, nil
			d.infos[index], err = file.Stat()
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				d.files[index], d.infos[index] = oldFile, oldInfo
				if index == 0 {
					d.transactionRoot = oldRoot
				} else {
					d.root = oldRoot
				}
			}()
			// The path/anchor still name A; actual held root and authored FD are
			// B with identical canonical bytes. Only actual association rejects.
			if d.current(ctx, false) == nil || d.beforePublication() == nil {
				t.Fatal("foreign held directory acquired original named anchor")
			}
		})
	}
}

func TestWGOriginalExecutionReplacementRefusesActualChildStart(t *testing.T) {
	for _, slot := range []int{0, 1} {
		t.Run([]string{"transaction", "manager"}[slot], func(t *testing.T) {
			a, owner, ctx, _, _, _ := wgNetworkCommandOwnerFixture(t)
			if err := owner.scope.wgRecords.current(ctx, true); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(owner.scope.root, "execution.json")
			if slot == 1 {
				path = filepath.Join(owner.scope.managerRoot, "latest-execution.json")
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			saved := path + ".original"
			if err := os.Rename(path, saved); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = os.Remove(path); _ = os.Rename(saved, path) }()
			marker := filepath.Join(t.TempDir(), "started")
			t.Setenv("RAZVILKA_WG_COMMAND_CLI_MODEL", "1")
			t.Setenv("RAZVILKA_WG_COMMAND_TEST_MARKER", marker)
			if _, err := a.run(ctx, a.IP, "-j", "link", "show"); !errors.Is(err, ErrExecutionJournal) {
				t.Fatal("identical replacement supplied original writer authority", err)
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("foreign record reached real child Start", err)
			}
			if owner.scope.wgRecords.closed || !owner.scope.open {
				t.Fatal("refusal destroyed original owners")
			}
		})
	}
}

func TestWGOriginalUnknownMutationRetainsScopeAndFiles(t *testing.T) {
	a, owner, ctx, _, _, _ := wgNetworkCommandOwnerFixture(t)
	marker := filepath.Join(t.TempDir(), "started")
	t.Setenv("RAZVILKA_WG_COMMAND_CLI_MODEL", "1")
	t.Setenv("RAZVILKA_WG_COMMAND_TEST_MARKER", marker)
	// The actual child implements argv recording only. Starting its mutation
	// spelling is an explicit unknown-effect model, not a native WG proof.
	if _, err := a.run(ctx, a.IP, "link", "add", "rz-wg", "type", "wireguard"); err != nil {
		t.Fatal(err)
	}
	if !owner.mutationAttempted.Load() {
		t.Fatal("actual mutation attempt was not retained")
	}
	if err := owner.scope.close(); !errors.Is(err, ErrWGOperationOwner) {
		t.Fatal("unknown mutation closed original scope", err)
	}
	if !owner.scope.open || owner.scope.wgRecords.closed || owner.scope.wgRecords.current(ctx, true) != nil {
		t.Fatal("unknown close discarded original record FDs")
	}
}

func TestWGListSourceReviewDigestIgnoresOnlyNumericInspectionTime(t *testing.T) {
	f := newWGSourceReadFixture(t)
	t.Setenv("RAZVILKA_WG_COMMAND_TEST_OUTPUT", `[{"dst":"1.1.1.1","gateway":"192.0.2.1","dev":"eth0","prefsrc":"192.0.2.2","table":254,"flags":[]}]`)
	p, err := f.read.CaptureProfile(f.ctx, "server")
	if err != nil {
		t.Fatal(err)
	}
	service := catalog.Service{ID: "listed", Name: "Listed", Category: "fixture", Strategy: []string{"wireguard"}, CIDRs: []string{"1.1.1.0/24"}, ProbeURL: "https://1.1.1.1/"}
	first, err := ReviewWGListSourceMaterial(f.ctx, f.read, p, service)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := ReviewWGListSourceMaterial(f.ctx, f.read, p, service)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if first.wan.ResolvedAt.Equal(second.wan.ResolvedAt) {
		t.Fatal("fixture did not acquire distinct numeric inspection times")
	}
	if first.reference.SourceSHA256 != second.reference.SourceSHA256 {
		t.Fatal("fresh comparison changed immutable source intent")
	}
	t.Setenv("RAZVILKA_WG_COMMAND_TEST_OUTPUT", `[{"dst":"1.1.1.1","gateway":"192.0.2.3","dev":"eth0","prefsrc":"192.0.2.2","table":254,"flags":[]}]`)
	third, err := ReviewWGListSourceMaterial(f.ctx, f.read, p, service)
	if err != nil {
		t.Fatal(err)
	}
	defer third.Close()
	if third.reference.SourceSHA256 == first.reference.SourceSHA256 {
		t.Fatal("changed actual numeric WAN failed to invalidate intent digest")
	}
}
