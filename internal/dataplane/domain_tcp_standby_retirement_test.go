package dataplane

import (
	"context"
	"errors"
	"github.com/ArtixSx/razvilka/internal/dnscontrol"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Actual COMMON writer/borrow protocol, with explicitly modeled packet effects.
// These fixtures do not construct native standby retirement authority.
func TestDomainTCPStandbyRemoveBindsOriginalLoadedReceiptBeforeAnyDelete(t *testing.T) {
	for _, change := range []string{"", "receipt-ABA", "copied-token", "closed-token"} {
		t.Run(change, func(t *testing.T) {
			f := newPolicyEffectFixture(t)
			ctx := context.Background()
			if err := applyPolicyEffects(ctx, f.runtime, f.plan, f.root, f.options); err != nil {
				t.Fatal(err)
			}
			r := &domainTCPStandbyRetirement{owner: &domainTCPStandbyOwner{baseline: &syntheticBaselineExecutionResource{root: f.root}}}
			r.self = r
			r.open.Store(true)
			var err error
			r.receipt, err = observeNetworkPolicyEffects(ctx, f.plan, f.root, f.options)
			if err != nil {
				t.Fatal(err)
			}
			defer r.receipt.close()
			before := len(f.calls)
			switch change {
			case "receipt-ABA":
				raw, err := os.ReadFile(filepath.Join(f.root, policyAdditionFile))
				if err != nil {
					t.Fatal(err)
				}
				if err := r.receipt.owner.WriteAtomic(policyAdditionFile, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "copied-token":
				r = &domainTCPStandbyRetirement{self: r, owner: r.owner}
			case "closed-token":
				r.open.Store(false)
			}
			ctx = context.WithValue(ctx, domainTCPStandbyRetirementKey{}, r)
			err = removePolicyEffects(ctx, f.runtime, f.plan, f.root, f.options)
			if change == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || len(f.calls) != before {
				t.Fatal("foreign receipt/token admitted deletion", err, len(f.calls), before)
			}
		})
	}
}

// Actual retained publication/descriptor protocol only. cleaned is an explicit
// model input here, never a source of production packet cleanup authority.
func standbyRetirementPublicationModel(t *testing.T) (*domainTCPStandbyRetirement, *retainedXrayExecution, context.Context) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "private-original")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	execution := &Execution{PlanID: "dp-check-" + strings.Repeat("a", 32), ResourcePlanID: "dp-" + strings.Repeat("a", 16), Digest: strings.Repeat("a", 64), State: "resource-failed"}
	transaction := filepath.Join(root, "transactions", execution.PlanID)
	if err := os.MkdirAll(transaction, 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	m := &Manager{StateRoot: root}
	s := &executionResourceScope{manager: m, managerRoot: root, root: transaction, execution: execution, open: true, ctx: ctx, cancel: cancel, retained: true}
	var err error
	s.owned, s.anchor, err = openNetworkPolicyObservationRoot(transaction)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.owned.Close() })
	d := &xraySelectedTCPExecutionRecords{scope: s}
	d.root, d.anchor, err = openNetworkPolicyObservationRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	d.transactionRoot, d.transactionAnchor, err = openNetworkPolicyObservationRoot(transaction)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.close() })
	p := &XrayDomainTCPExecutionResource{scope: s, records: d}
	p.self = p
	s.xrayDomainTCP = map[string]*XrayDomainTCPExecutionResource{"original": p}
	if err := m.writeExecutionOwned(transaction, *execution, s); err != nil {
		t.Fatal(err)
	}
	original := &DomainTCPOriginalScope{}
	original.self = original
	owner := &domainTCPStandbyOwner{process: p, original: original, baseline: &syntheticBaselineExecutionResource{relative: "execution-resources/sb-model"}}
	owner.self = owner
	original.standbyOwner = owner
	if err := d.detachStandbyAlias(ctx, owner); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { owner.latest.Close() })
	retained := &retainedXrayExecution{scope: s, records: d, standby: owner, pending: true}
	retained.self = retained
	s.retainedXrayOwner, m.retainedXray = retained, retained

	// Actual local socket close/join accounting and original writer FDs only;
	// this model does not issue a native source/control/packet cleanup grant.
	dnsRoot := filepath.Join(root, "dns-model")
	if err := os.Mkdir(dnsRoot, 0700); err != nil {
		t.Fatal(err)
	}
	dnsFiles, err := ownedfs.Open(dnsRoot)
	if err != nil {
		t.Fatal(err)
	}
	ownerBytes := []byte("original model synthetic owner")
	ownerFile, err := dnsFiles.WriteAtomicRetained("owner.json", ownerBytes, 0600)
	if err != nil {
		t.Fatal(err)
	}
	ownerRecord, err := retainDomainTCPDNSOwnerRecord(dnsFiles, dnsRoot, ownerFile, ownerBytes, execution.PlanID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ownerFile.Close(); ownerRecord.directory.Close(); dnsFiles.Close() })
	if runtime.GOOS == "windows" {
		// Model only: Linux native tests execute actual RENAME_NOREPLACE+fsync.
		ownerRecord.rename = func(_ *os.File, from, to string) error {
			if _, err := os.Lstat(filepath.Join(dnsRoot, to)); !errors.Is(err, os.ErrNotExist) {
				return errors.New("model destination occupied")
			}
			return os.Rename(filepath.Join(dnsRoot, from), filepath.Join(dnsRoot, to))
		}
		ownerRecord.syncDirectory = func() error { return nil }
	}
	udp, tcp, err := listenScopedDNS(netip.MustParseAddrPort("127.0.0.1:0"))
	if err != nil {
		t.Fatal(err)
	}
	session := &scopedDNSSession{done: make(chan struct{}), resources: scopedDNSInactiveResources{udp: udp, tcp: tcp}}
	session.resources.cancelled.Store(true)
	udp.Close()
	tcp.Close()
	close(session.done)
	adapter := &ScopedDNSAdapter{StateRoot: dnsRoot, live: session}
	binding := &SyntheticDNSExecutionBinding{adapter: adapter, root: dnsRoot}
	binding.self = binding
	control := &operationgate.ControlEpochReview{}
	source := &dnscontrol.NetworkPolicyDNSSyntheticResolver{}
	session.synthetic = &scopedDNSSyntheticMode{binding: binding, source: source, control: control, ownerRecord: ownerRecord}
	scopedDNSInactivePublish(dnsRoot, session)
	t.Cleanup(func() { _ = scopedDNSInactiveRetire(dnsRoot, session) })
	p.material = &XrayDomainTCPOperationMaterial{binding: binding, session: session, control: control, dnsSource: source}

	r := &domainTCPStandbyRetirement{owner: owner, cleaned: true}
	r.self = r
	original.standbyRetirement = r
	return r, retained, ctx
}

func TestDomainTCPStandbyFinalizationRetryKeepsOriginalCustody(t *testing.T) {
	for _, kind := range []string{"partial-publication", "before-close", "actual-close-error"} {
		t.Run(kind, func(t *testing.T) {
			r, retained, ctx := standbyRetirementPublicationModel(t)
			witness := errors.New("original finalization fault")
			once := false
			switch kind {
			case "partial-publication":
				r.publishFault = func(i int) error {
					if i == 1 && !once {
						once = true
						return witness
					}
					return nil
				}
			case "before-close":
				r.closeFault = func(i int) error {
					if i == 5 && !once {
						once = true
						return witness
					}
					return nil
				}
			case "actual-close-error":
				r.closeFault = func(i int) error {
					if i == 5 && !once {
						once = true
						return r.owner.latest.Close()
					}
					return nil
				}
			}
			err := r.publishRemoved(ctx, retained)
			if err == nil {
				t.Fatal("fault masked")
			}
			s := retained.scope
			if !s.retained || s.retainedXrayOwner != retained || s.manager.retainedXrayOwner() != retained || r.owner.original.standbyOwner != r.owner {
				t.Fatal("failed finalization lost original custody")
			}
			if kind == "actual-close-error" {
				if r.closeErr == nil {
					t.Fatal("fixture did not reach original close error", err)
				}
				if err := r.publishRemoved(ctx, retained); err == nil {
					t.Fatal("uncertain original FD adopted on retry")
				}
				return
			}
			if !errors.Is(err, witness) {
				t.Fatal("original exception lost", err)
			}
			if err := r.publishRemoved(ctx, retained); err != nil {
				t.Fatal("same original finalization did not resume", err)
			}
			mode := r.owner.process.material.session.synthetic
			if _, err := scopedDNSInactiveEpoch(mode.binding.root); err != nil || mode.binding.adapter.live != nil {
				t.Fatal("completed original DNS lifecycle remains fenced", err)
			}
			if !r.finished || s.open || s.retained || s.manager.retainedXrayOwner() != nil || r.owner.original.standbyOwner != nil {
				t.Fatal("completed finalization retained active custody")
			}
		})
	}
}

func TestDomainTCPStandbyDNSOwnerRetirementRefusesChangedInputs(t *testing.T) {
	for _, change := range []string{"foreign-destination", "equal-image-replacement", "same-inode-mutation"} {
		t.Run(change, func(t *testing.T) {
			r, retained, ctx := standbyRetirementPublicationModel(t)
			record := r.owner.process.material.session.synthetic.ownerRecord
			ownerPath := filepath.Join(record.path, "owner.json")
			switch change {
			case "foreign-destination":
				if err := os.WriteFile(filepath.Join(record.path, record.destination), []byte("foreign retained history"), 0600); err != nil {
					t.Fatal(err)
				}
			case "equal-image-replacement":
				if err := record.root.WriteAtomic("owner.json", record.canonical, 0600); err != nil {
					t.Fatal(err)
				}
			case "same-inode-mutation":
				f, err := os.OpenFile(ownerPath, os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				_, e := f.WriteAt([]byte("X"), 0)
				ce := f.Close()
				if e != nil || ce != nil {
					t.Fatal(e, ce)
				}
				if err := os.Chtimes(ownerPath, record.info.ModTime(), record.info.ModTime()); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadFile(ownerPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := r.publishRemoved(ctx, retained); err == nil {
				t.Fatal("foreign original owner accepted")
			}
			after, err := os.ReadFile(ownerPath)
			if err != nil || string(after) != string(before) {
				t.Fatal("foreign source owner was changed", err)
			}
			if _, err := scopedDNSInactiveEpoch(record.path); err == nil || r.owner.process.material.binding.adapter.live == nil {
				t.Fatal("failed retirement lost DNS custody")
			}
		})
	}
}

func TestDomainTCPStandbyDNSOwnerUnknownRenameRetainsSameCursor(t *testing.T) {
	r, retained, ctx := standbyRetirementPublicationModel(t)
	record := r.owner.process.material.session.synthetic.ownerRecord
	originalRename := record.rename
	witness := errors.New("actual rename completed before acknowledgement failure")
	record.rename = func(dir *os.File, from, to string) error {
		if err := originalRename(dir, from, to); err != nil {
			return err
		}
		return witness
	}
	if err := r.publishRemoved(ctx, retained); !errors.Is(err, witness) {
		t.Fatal("rename exception lost", err)
	}
	if record.moved || !record.attempted || r.finished {
		t.Fatal("uncertain rename minted known lifecycle")
	}
	if _, err := scopedDNSInactiveEpoch(record.path); err == nil {
		t.Fatal("uncertain rename removed registry custody")
	}
	// Retry observes both original names and same held writer. No second rename.
	record.rename = func(*os.File, string, string) error { t.Fatal("uncertain rename replayed blindly"); return nil }
	if err := r.publishRemoved(ctx, retained); err != nil {
		t.Fatal(err)
	}
	if !r.finished {
		t.Fatal("original rename cursor did not finish")
	}
}

func TestDomainTCPStandbyDNSOwnerActualCloseFailureKeepsRegistry(t *testing.T) {
	r, retained, ctx := standbyRetirementPublicationModel(t)
	record := r.owner.process.material.session.synthetic.ownerRecord
	record.beforeClose = func(i int) {
		if i == 0 {
			_ = record.file.Close()
		}
	}
	if err := r.publishRemoved(ctx, retained); err == nil || record.closeErr == nil {
		t.Fatal("actual original close error erased", err)
	}
	if err := r.publishRemoved(ctx, retained); err == nil {
		t.Fatal("closed original FD adopted on retry")
	}
	if _, err := scopedDNSInactiveEpoch(record.path); err == nil || r.owner.process.material.binding.adapter.live == nil {
		t.Fatal("unknown close released registry")
	}
}

func TestDomainTCPStandbyDNSOwnerRetryRechecksBothNames(t *testing.T) {
	for _, change := range []string{"new-foreign-owner", "replaced-retired-history"} {
		t.Run(change, func(t *testing.T) {
			r, retained, ctx := standbyRetirementPublicationModel(t)
			record := r.owner.process.material.session.synthetic.ownerRecord
			witness := errors.New("original close cursor paused after owner move")
			once := false
			r.closeFault = func(i int) error {
				if i == 5 && !once {
					once = true
					return witness
				}
				return nil
			}
			if err := r.publishRemoved(ctx, retained); !errors.Is(err, witness) {
				t.Fatal("did not reach original post-move cut", err)
			}
			if !record.moved || record.closeIndex != 0 {
				t.Fatal("final DNS writer closed before retry boundary")
			}
			name := "owner.json"
			data := []byte("foreign new source owner")
			if change == "replaced-retired-history" {
				name = record.destination
				data = record.canonical
			}
			if err := record.root.WriteAtomic(name, data, 0600); err != nil {
				t.Fatal(err)
			}
			if err := r.publishRemoved(ctx, retained); err == nil {
				t.Fatal("cached owner-move bit bypassed fresh proof")
			}
			actual, err := os.ReadFile(filepath.Join(record.path, name))
			if err != nil || string(actual) != string(data) {
				t.Fatal("foreign input overwritten", err)
			}
			if _, err := scopedDNSInactiveEpoch(record.path); err == nil || r.owner.process.material.binding.adapter.live == nil || r.owner.process.scope.manager.retainedXrayOwner() != retained {
				t.Fatal("foreign retry inputs released original custody")
			}
		})
	}
}

func TestDomainTCPStandbyDNSOwnerDestinationRaceCannotOverwrite(t *testing.T) {
	r, retained, ctx := standbyRetirementPublicationModel(t)
	record := r.owner.process.material.session.synthetic.ownerRecord
	originalRename := record.rename
	foreign := []byte("foreign destination appeared at actual rename boundary")
	record.rename = func(dir *os.File, from, to string) error {
		if err := record.root.WriteAtomic(to, foreign, 0600); err != nil {
			return err
		}
		return originalRename(dir, from, to)
	}
	if err := r.publishRemoved(ctx, retained); err == nil {
		t.Fatal("destination race overwrote foreign history")
	}
	actual, err := os.ReadFile(filepath.Join(record.path, record.destination))
	if err != nil || string(actual) != string(foreign) {
		t.Fatal("foreign destination changed", err)
	}
	source, err := os.ReadFile(filepath.Join(record.path, "owner.json"))
	if err != nil || string(source) != string(record.canonical) {
		t.Fatal("original source lost on destination collision", err)
	}
	if _, err := scopedDNSInactiveEpoch(record.path); err == nil {
		t.Fatal("destination race released original lifecycle")
	}
}
