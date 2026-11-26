package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func TestNFQWS2FirstStartOwnedRepair(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	for _, scenario := range []string{"owned-absent", "shared-owned-absent", "residual-hooks", "foreign-process", "pid-reused", "revoked", "no-review", "cancel-after-receipt"} {
		t.Run(scenario, func(t *testing.T) {
			f := newFirstStartFixture(t)
			if scenario == "shared-owned-absent" {
				f.plan.Routes = append(f.plan.Routes, Route{ServiceID: "second", ServiceName: "Second", Resolved: "nfqws2", Domains: []string{"second.example"}, ProbeURL: "https://second.example"})
			}
			f.apply(t)
			plan, ok, err := f.m.Committed()
			if err != nil || !ok {
				t.Fatal("read committed plan", err)
			}
			before, err := f.a.readLease()
			if err != nil {
				t.Fatal(err)
			}
			f.running, f.ownedRules = false, false
			f.a.inactivity = &NFQWSRuntimeInactiveSource{identity: netidentity.Identity{Version: 1, Kind: netidentity.ProcNetInode, BootID: f.boot, Inode: 1}}
			// Preserve the original closed configuration, stale PID file and
			// running overlay. Only the modelled daemon and graph went away.
			allowed := true
			ctx := f.bootContext(t, &allowed)
			switch scenario {
			case "residual-hooks":
				f.ownedRules = true
			case "foreign-process":
				f.foreign = true
			case "pid-reused":
				f.a.firstStartProcessRead = func(pid int) (components.NFQWSRuntimeProcessIdentity, error) {
					return components.NFQWSRuntimeProcessIdentity{PID: pid, Executable: "/bin/unrelated"}, nil
				}
			case "revoked":
				allowed = false
			case "no-review":
				ctx = firstStartContext(t)
			case "cancel-after-receipt":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				defer cancel()
				f.a.firstStartReceiptReady = cancel
			}
			start := len(f.calls)
			err = f.m.RepairCommittedNFQWS2FirstStart(ctx, plan)
			after, readErr := f.a.readLease()
			if readErr != nil {
				t.Fatal(readErr)
			}
			committed, found, planErr := f.m.Committed()
			if planErr != nil || !found || !reflect.DeepEqual(committed, plan) {
				t.Fatal("repair changed the committed plan", planErr)
			}
			switch scenario {
			case "owned-absent", "shared-owned-absent":
				if err != nil || !f.running || !f.ownedRules || after.FirstStart.Process == nil ||
					after.FirstStart.Process.PID == before.FirstStart.Process.PID || after.Transaction != before.Transaction {
					t.Fatal("same-boot repair did not restore the original plan with a new process", err)
				}
			case "cancel-after-receipt":
				if err == nil {
					t.Fatal("cancelled repair reported success")
				}
				f.assertStopped(t)
			default:
				if !errors.Is(err, ErrNFQWS2FirstStartRepairUnavailable) || !reflect.DeepEqual(before, after) {
					t.Fatal("unsafe restart was not refused before effects", err)
				}
				for _, call := range f.calls[start:] {
					if firstStartRuntimeAction(call) {
						t.Fatal("refused restart reached the owned runtime", call)
					}
				}
			}
			if f.a.firstStartReview != nil {
				t.Fatal("repair retained the component writer")
			}
		})
	}
}

func TestNFQWS2FirstStartOwnedRepairDistinguishesMissingPIDFromMissingProcessFields(t *testing.T) {
	root := t.TempDir()
	a := &NFQWS2Adapter{inactivity: &NFQWSRuntimeInactiveSource{platform: nfqws2InactivePlatform{procRoot: root}}}
	if err := a.firstStartRepairPIDAbsent(51); err != nil {
		t.Fatal("missing PID directory was not recognized", err)
	}
	if err := os.Mkdir(filepath.Join(root, "51"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := a.firstStartRepairPIDAbsent(51); !errors.Is(err, ErrNFQWSManagedProcessUnknown) {
		t.Fatal("existing PID without executable, stat or argv treated as absent", err)
	}
}
