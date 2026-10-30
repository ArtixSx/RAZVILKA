package dataplane

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

type nfqws2RebootStopFixture struct {
	*nfqws2InactiveFixture
	manager       *Manager
	review        *RuntimeInactivitySourceReview
	plan          Plan
	instance      string
	runtimeCalls  int
	toolChecks    int
	afterRuntime  func()
	atSourceCheck func(int)
}

// Complete original-source model only: the real source association, files,
// lease, plan, process/queue/kernel predicates and original Deactivate execute.
// The existing private seams supply provider facts; this is not native proof.
func newNFQWS2RebootStopFixture(t *testing.T) *nfqws2RebootStopFixture {
	t.Helper()
	f := &nfqws2RebootStopFixture{nfqws2InactiveFixture: firstStartStoppedInactiveFixture(t)}
	f.manager = New(filepath.Dir(filepath.Dir(f.a.StateRoot)))
	if err := f.manager.Register(f.a); err != nil {
		t.Fatal(err)
	}
	if err := f.manager.Register(NewScopedDNSAdapter(context.Background(), nil, f.manager.StateRoot)); err != nil {
		t.Fatal(err)
	}
	f.a.inactivity, f.source.bound = nil, false
	f.source.inventory.reader.CheckTools = func(context.Context, backendInventoryScope) error {
		f.toolChecks++
		if f.atSourceCheck != nil {
			f.atSourceCheck(f.toolChecks)
		}
		return nil
	}
	f.source.frozen = *f.source.inventory
	ctx := nfqws2InactiveTestContext(t)
	settings := filepath.Join(filepath.Dir(f.manager.StateRoot), "dns", "state.json")
	if err := f.manager.bindRuntimeInactivitySources(ctx, f.source.provider, f.source.inventory, settings,
		func(context.Context, *NFQWS2Adapter, *BackendInventory) (*NFQWSRuntimeInactiveSource, error) {
			return f.source, nil
		}); err != nil {
		t.Fatal(err)
	}
	f.review = f.manager.runtimeSources
	f.plan = Plan{SchemaVersion: SchemaVersion, PlanID: "dp-aaaaaaaaaaaaaaaa", Digest: strings.Repeat("a", 64), State: "committed", Ready: true, RouteCount: 1,
		Adapters: []string{"nfqws2"}, Routes: []Route{{ServiceID: "selected", Selected: "nfqws2", Resolved: "nfqws2", Domains: []string{"selected.example"}}}}
	if err := f.manager.Record(f.plan); err != nil {
		t.Fatal(err)
	}
	lease, err := f.a.readLease()
	if err != nil {
		t.Fatal(err)
	}
	lease.Transaction, _ = f.a.firstStartTransaction(f.plan)
	lease.FirstStart.Phase = nfqws2FirstRunning
	lease.FirstStart.Process.BootID = "22345678-1234-1234-1234-123456789abc"
	if lease.FirstStart.Process.BootID == f.source.identity.BootID {
		t.Fatal("fixture must represent an earlier boot")
	}
	if err := os.MkdirAll(lease.Transaction, 0700); err != nil {
		t.Fatal(err)
	}
	for name, source := range map[string]string{"nfqws2.conf.staged": f.a.ConfigPath, "S51nfqws2.staged": f.a.InitPath} {
		if err := os.WriteFile(filepath.Join(lease.Transaction, name), readBytes(t, source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.a.writeLease(lease); err != nil {
		t.Fatal(err)
	}
	f.instance = nfqws2HookInstance(lease)
	f.a.firstStartObservation = func(c context.Context, full bool) error {
		if full {
			return f.verify(c)
		}
		f.runtimeCalls++
		return f.a.firstStartRuntimeAbsentWithSources(c, f.proof,
			func(c context.Context, use func(context.Context, netidentity.Identity) error) error {
				err := use(c, f.source.identity)
				if f.afterRuntime != nil {
					f.afterRuntime()
				}
				return err
			},
			func(c context.Context, identity netidentity.Identity) (BackendInventorySnapshot, error) {
				f.reads++
				return nfqwsDirectStockTestClone(f.image), c.Err()
			})
	}
	return f
}

func (f *nfqws2RebootStopFixture) admit(ctx context.Context) error {
	if err := sourceReviewModelCheck(ctx, f.review); err != nil {
		return err
	}
	review, err := f.review.reviewNFQWS2RebootStop(ctx, f.plan, f.instance)
	if err != nil {
		return err
	}
	if err := sourceReviewModelCheck(ctx, f.review); err != nil {
		return err
	}
	return review.current(ctx)
}

func (f *nfqws2RebootStopFixture) changeLease(t *testing.T, change func(*nfqws2Lease)) {
	t.Helper()
	lease, err := f.a.readLease()
	if err != nil {
		t.Fatal(err)
	}
	change(lease)
	if err := f.a.writeLease(lease); err != nil {
		t.Fatal(err)
	}
}

func TestNFQWS2RebootStopMissingOverlayAdmitsOnlyOriginalCleanup(t *testing.T) {
	f := newNFQWS2RebootStopFixture(t)
	ctx := nfqws2InactiveTestContext(t)
	transaction, _ := f.a.firstStartTransaction(f.plan)
	before, err := f.a.firstStartHookFiles(transaction)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(f.a.ConfigPath + ".run"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("regression requires the lost temporary overlay", err)
	}
	if err := f.verify(ctx); err == nil {
		t.Fatal("a running receipt became full inactivity before Stop")
	}
	if _, err := f.manager.ObserveCommittedNFQWS2Hooks(ctx, f.plan); err == nil {
		t.Fatal("missing overlay unexpectedly admitted the existing hook observer")
	}
	if err := f.admit(ctx); err != nil || f.runtimeCalls != 1 || f.reads != 2 {
		t.Fatal("exact old-boot source could not admit original Stop", err, f.runtimeCalls, f.reads)
	}
	after, err := f.a.firstStartHookFiles(transaction)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("admission rewrote metadata instead of proving runtime absence", err)
	}
	root, err := ownedfs.Open(f.manager.StateRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	j := &nfqws2BootHookWAL{root: root, path: f.manager.StateRoot, record: nfqws2CandidateHookRecord{
		Version: 1, PlanID: f.plan.PlanID, Digest: f.plan.Digest, Instance: f.instance, State: "uncertain",
		Effects: []nfqws2CandidateHookEffect{{Command: NFQWS2HookCommand{Family: 4, Args: []string{"-t", "mangle", "-N", "nfqws_post"}}, State: "unknown"}},
	}}
	if err := j.save(); err != nil {
		t.Fatal(err)
	}
	written := bytes.Clone(j.image)
	settle := func() error {
		return f.manager.settleNFQWS2BootHookStop(ctx, f.plan, j, func() error { return f.verify(ctx) })
	}
	if err := settle(); err == nil {
		t.Fatal("reboot admission replaced terminal full inactive verification")
	}
	if raw, _, err := readNFQWS2BootHookEvidence(root); err != nil || !bytes.Equal(raw, written) {
		t.Fatal("premature settlement changed uncertain evidence", err)
	}
	if err := f.a.Deactivate(ctx); err != nil {
		t.Fatal("original Deactivate did not settle the older receipt", err)
	}
	if err := settle(); err != nil {
		t.Fatal("fresh full inactive evidence refused original Stop", err)
	}
	lease, err := f.a.readLease()
	if err != nil || lease.FirstStart.Phase != nfqws2FirstStopped {
		t.Fatal("original Stop did not settle its receipt", err)
	}
	_, record, err := readNFQWS2BootHookJournal(root)
	if err != nil || record.State != "stopped" || record.Effects[0].State != "unknown" || record.Instance != f.instance {
		t.Fatal("Stop lost original uncertain history or instance", record, err)
	}
}

func TestNFQWS2RebootStopAllowsRetryAfterOriginalStoppedReceipt(t *testing.T) {
	f := newNFQWS2RebootStopFixture(t)
	ctx := nfqws2InactiveTestContext(t)
	f.changeLease(t, func(lease *nfqws2Lease) { lease.FirstStart.Phase = nfqws2FirstStopped })
	if err := os.WriteFile(f.a.firstStartPIDPath(), []byte("999\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.verify(ctx); err == nil {
		t.Fatal("a leftover PID file replaced full inactivity")
	}
	if err := f.admit(ctx); err != nil {
		t.Fatal("exact old-boot interrupted cleanup cannot retry", err)
	}
	if err := f.a.Deactivate(ctx); err != nil {
		t.Fatal("original cleanup retry failed", err)
	}
	if err := f.verify(ctx); err != nil {
		t.Fatal("retry did not reach full inactive state", err)
	}
}

func TestNFQWS2RebootStopCleansOnlyMatchingTemporaryFiles(t *testing.T) {
	f := newNFQWS2RebootStopFixture(t)
	ctx := nfqws2InactiveTestContext(t)
	for path, contents := range map[string]string{f.a.ConfigPath + ".run": nfqws2RouterRunFixture, f.a.firstStartPIDPath(): "999\n"} {
		if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.admit(ctx); err != nil {
		t.Fatal("exact previous-boot temporary files refused cleanup admission", err)
	}
	if err := f.a.Deactivate(ctx); err != nil {
		t.Fatal("original Stop could not remove its exact temporary files", err)
	}
	for _, path := range []string{f.a.ConfigPath + ".run", f.a.firstStartPIDPath()} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("temporary file remained after verified original Stop", err)
		}
	}
	if err := f.verify(ctx); err != nil {
		t.Fatal("temporary cleanup did not reach full inactivity", err)
	}
}

func TestNFQWS2RebootStopRejectsChangedBootInstanceAndPlan(t *testing.T) {
	for _, change := range []string{"current-boot", "malformed-boot", "different-old-boot", "pid-generation", "start-generation", "wrong-instance", "transaction", "starting", "retiring", "plan-routes", "plan-missing", "caller-plan", "mixed-adapter", "dns", "lan", "retiring-adapter", "suspended-dns", "network-profile", "domain-policy", "synthetic-dns", "network-route", "digest"} {
		t.Run(change, func(t *testing.T) {
			f := newNFQWS2RebootStopFixture(t)
			ctx := nfqws2InactiveTestContext(t)
			switch change {
			case "current-boot", "malformed-boot", "different-old-boot", "pid-generation", "start-generation", "transaction", "starting", "retiring":
				f.changeLease(t, func(lease *nfqws2Lease) {
					switch change {
					case "current-boot":
						lease.FirstStart.Process.BootID = f.source.identity.BootID
						f.instance = nfqws2HookInstance(lease)
					case "malformed-boot":
						lease.FirstStart.Process.BootID = "old-boot"
						f.instance = nfqws2HookInstance(lease)
					case "different-old-boot":
						lease.FirstStart.Process.BootID = "32345678-1234-1234-1234-123456789abc"
					case "pid-generation":
						lease.FirstStart.Process.PID++
					case "start-generation":
						lease.FirstStart.Process.Start = "124"
					case "transaction":
						lease.Transaction += "-other"
						f.instance = nfqws2HookInstance(lease)
					case "starting":
						lease.FirstStart.Phase, lease.FirstStart.Process = nfqws2FirstStarting, nil
					case "retiring":
						lease.FirstStart.Phase = nfqws2FirstRetiring
					}
				})
			case "wrong-instance":
				f.instance = strings.Repeat("b", 24)
			case "plan-routes":
				changed := f.plan
				changed.Routes = []Route{{ServiceID: "other", Selected: "nfqws2", Resolved: "nfqws2", Domains: []string{"other.example"}}}
				if err := f.manager.Record(changed); err != nil {
					t.Fatal(err)
				}
			case "plan-missing":
				for _, name := range []string{"latest-committed-plan.json", "latest-plan.json"} {
					if err := os.Remove(filepath.Join(f.manager.StateRoot, name)); err != nil {
						t.Fatal(err)
					}
				}
			case "caller-plan":
				f.plan.SiteExclusions = &SiteExclusions{Domains: []string{"changed.example"}}
			case "mixed-adapter", "dns", "lan", "retiring-adapter", "suspended-dns", "network-profile", "domain-policy", "synthetic-dns", "network-route", "digest":
				switch change {
				case "mixed-adapter":
					f.plan.Adapters = append(f.plan.Adapters, scopedDNSAdapterID)
				case "dns":
					f.plan.DNS = &ScopedDNSPlan{}
				case "lan":
					f.plan.LAN = &LANPolicyRuntimePlan{}
				case "retiring-adapter":
					f.plan.RetiringAdapters = []string{scopedDNSAdapterID}
				case "suspended-dns":
					f.plan.SuspendDNS = true
				case "network-profile":
					f.plan.NetworkProfileID = "changed"
				case "domain-policy":
					f.plan.DomainPolicy = &DomainPolicyRuntimePlan{}
				case "synthetic-dns":
					f.plan.SyntheticDNS = &SyntheticDNSTransportPlan{}
				case "network-route":
					f.plan.Routes[0].NetworkPolicyGeneration = "changed"
				case "digest":
					f.plan.Digest = strings.Repeat("b", 64)
				}
				if err := f.manager.Record(f.plan); err != nil {
					t.Fatal(err)
				}
			}
			before := readBytes(t, filepath.Join(f.a.StateRoot, nfqws2LeaseFile))
			if err := f.admit(ctx); err == nil {
				t.Fatal("changed historical owner admitted")
			}
			if f.runtimeCalls != 0 || !bytes.Equal(before, readBytes(t, filepath.Join(f.a.StateRoot, nfqws2LeaseFile))) {
				t.Fatal("invalid owner reached runtime proof or changed metadata", f.runtimeCalls)
			}
		})
	}
}

func TestNFQWS2RebootStopPreservesStockListOwnerProtection(t *testing.T) {
	f := newNFQWS2RebootStopFixture(t)
	lists := f.a.ownedListPaths()
	protected := f.proof.protected
	f.proof.protected = func(info os.FileInfo, directory, private bool) bool {
		if !directory && info != nil && (info.Name() == filepath.Base(lists[2]) || info.Name() == filepath.Base(lists[3])) {
			return false // Model the stock package UID, different from the owner.
		}
		return protected(info, directory, private)
	}
	f.source.platform = f.proof
	ctx := nfqws2InactiveTestContext(t)
	if err := f.admit(ctx); err == nil {
		t.Fatal("strict root-owner proof unexpectedly admitted stock list UID")
	}
	f.proof.foreignList = func(info os.FileInfo) bool { return protected(info, false, false) }
	f.source.platform = f.proof
	if err := f.admit(ctx); err != nil {
		t.Fatal("unchanged protected stock list owner blocked original Stop", err)
	}
	if err := os.WriteFile(lists[2], []byte("foreign\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.admit(ctx); err == nil {
		t.Fatal("foreign list UID allowance bypassed exact managed block ownership")
	}
}

func TestNFQWS2RebootStopLeavesProvenForeignQueuesUntouched(t *testing.T) {
	f := newNFQWS2RebootStopFixture(t)
	f.image = nfqwsDirectStockQueueFixture()
	for i := range f.image.Rows {
		row := &f.image.Rows[i]
		for j, token := range row.Tokens {
			if j > 0 && row.Tokens[j-1] == "--queue-num" {
				if token == "1104" {
					row.Tokens[j] = "64511"
				} else if token == "1106" {
					row.Tokens[j] = "64512"
				}
			}
		}
	}
	f.proof.queues = func(context.Context) ([]nfqwsScopedQueue, error) {
		return []nfqwsScopedQueue{{number: 64511, portID: 99, copyMode: 2, copyRange: 65531}, {number: 64512, portID: 100, copyMode: 2, copyRange: 65531}}, nil
	}
	f.proof.sockets = func(context.Context) (string, error) {
		return nfqws2InactiveTestSockets + "0 12 100 00000000 0 0 0 0 0 992\n", nil
	}
	before := nfqwsDirectStockTestClone(f.image)
	ctx := nfqws2InactiveTestContext(t)
	if err := f.admit(ctx); err != nil {
		t.Fatal("complete unchanged OUTPUT-only foreign queues blocked Stop", err)
	}
	if err := f.a.Deactivate(ctx); err != nil {
		t.Fatal("original Stop failed with independent foreign queues", err)
	}
	if !reflect.DeepEqual(before, f.image) {
		t.Fatal("Stop changed unrelated queue rows")
	}
}

func TestNFQWS2RebootStopRejectsForeignOrUnsettledFiles(t *testing.T) {
	for _, change := range []string{"config", "init", "list", "staged-config", "staged-init", "missing-stage", "run", "pid", "pending", "writer-lock", "symlink"} {
		t.Run(change, func(t *testing.T) {
			f := newNFQWS2RebootStopFixture(t)
			transaction, _ := f.a.firstStartTransaction(f.plan)
			path := map[string]string{"config": f.a.ConfigPath, "init": f.a.InitPath, "list": f.a.UserListPath,
				"staged-config": filepath.Join(transaction, "nfqws2.conf.staged"), "staged-init": filepath.Join(transaction, "S51nfqws2.staged"),
				"run": f.a.ConfigPath + ".run", "pid": f.a.firstStartPIDPath(), "pending": filepath.Join(f.a.StateRoot, ".pending"),
				"writer-lock": filepath.Join(f.a.StateRoot, ".state-"+nfqws2Hash([]byte(nfqws2LeaseFile))+".lock")}[change]
			switch change {
			case "missing-stage":
				if err := os.Remove(filepath.Join(transaction, "nfqws2.conf.staged")); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				path = f.a.ConfigPath + ".run"
				if err := os.Symlink(f.a.ConfigPath, path); err != nil {
					t.Skip("symlink not supported", err)
				}
			default:
				if err := os.WriteFile(path, []byte("foreign\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before := readBytes(t, filepath.Join(f.a.StateRoot, nfqws2LeaseFile))
			if err := f.admit(nfqws2InactiveTestContext(t)); err == nil || f.runtimeCalls != 0 {
				t.Fatal("foreign or unsettled file reached cleanup admission", err, f.runtimeCalls)
			}
			if !bytes.Equal(before, readBytes(t, filepath.Join(f.a.StateRoot, nfqws2LeaseFile))) {
				t.Fatal("refused files changed lease")
			}
		})
	}
}

func TestNFQWS2RebootStopRejectsMalformedAndMixedRouteScope(t *testing.T) {
	for _, change := range []string{"schema", "route-count", "mixed-direct", "mixed-vpn", "empty-service", "empty-domains", "cidrs", "sources", "source-refs", "ingress", "wireguard-revision", "network-policy-role"} {
		t.Run(change, func(t *testing.T) {
			f := newNFQWS2RebootStopFixture(t)
			switch change {
			case "schema":
				f.plan.SchemaVersion++
			case "route-count":
				f.plan.RouteCount++
			case "mixed-direct", "mixed-vpn":
				route := "direct"
				if change == "mixed-vpn" {
					route = "wireguard:other"
				}
				f.plan.Routes = append(f.plan.Routes, Route{ServiceID: "other", Resolved: route, Domains: []string{"other.example"}})
				f.plan.RouteCount = len(f.plan.Routes)
			case "empty-service":
				f.plan.Routes[0].ServiceID = ""
			case "empty-domains":
				f.plan.Routes[0].Domains = nil
			case "cidrs":
				f.plan.Routes[0].CIDRs = []string{"192.0.2.0/24"}
			case "sources":
				f.plan.Routes[0].Sources = []string{"192.0.2.1/32"}
			case "source-refs":
				f.plan.Routes[0].SourceRefs = []string{"client"}
			case "ingress":
				f.plan.Routes[0].Ingress = []string{"br0"}
			case "wireguard-revision":
				f.plan.Routes[0].WireGuardProfileRevision = "different"
			case "network-policy-role":
				f.plan.Routes[0].NetworkPolicyRole = "capture"
			}
			if err := f.manager.Record(f.plan); err != nil {
				t.Fatal(err)
			}
			before := readBytes(t, filepath.Join(f.a.StateRoot, nfqws2LeaseFile))
			if err := f.admit(nfqws2InactiveTestContext(t)); err == nil || f.runtimeCalls != 0 {
				t.Fatal("unclosed route scope admitted or reached absence observation", err, f.runtimeCalls)
			}
			if !bytes.Equal(before, readBytes(t, filepath.Join(f.a.StateRoot, nfqws2LeaseFile))) {
				t.Fatal("malformed route scope changed ownership metadata")
			}
		})
	}
}

func TestNFQWS2RebootStopRejectsChangedOriginalSourceAndContext(t *testing.T) {
	for _, change := range []string{"copy", "registry", "source", "provider", "collector", "active-owner", "root", "canceled", "unbounded"} {
		t.Run(change, func(t *testing.T) {
			f := newNFQWS2RebootStopFixture(t)
			ctx := nfqws2InactiveTestContext(t)
			switch change {
			case "copy":
				copy := *f.review
				f.review = &copy
			case "registry":
				f.manager.Adapters["nfqws2"] = NewNFQWS2Adapter()
			case "source":
				f.a.inactivity = nil
			case "provider":
				f.source.inventory.reader.Provider = netidentity.NewProcProvider()
			case "collector":
				f.source.inventory.review = strings.Repeat("b", 64)
			case "active-owner":
				f.a.activeProcess = &nfqws2ActiveOwner{}
			case "root":
				f.manager.StateRoot += "-replacement"
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "unbounded":
				ctx = context.Background()
			}
			if err := f.admit(ctx); err == nil || f.runtimeCalls != 0 {
				t.Fatal("unbound source or invalid context admitted", err, f.runtimeCalls)
			}
			if err := f.review.VerifyNFQWS2RebootStop(ctx, f.plan, f.instance); err == nil {
				t.Fatal("public API replaced the changed original owner")
			}
		})
	}
}

func TestNFQWS2RebootStopRequiresCompleteFreshRuntimeAbsence(t *testing.T) {
	for _, change := range []string{"live-nfqws", "unknown-process", "foreign-forward-queue", "owned-hook", "unattributed-queue", "incomplete-inventory", "unknown-sockets"} {
		t.Run(change, func(t *testing.T) {
			f := newNFQWS2RebootStopFixture(t)
			switch change {
			case "live-nfqws":
				f.process(t, 999, "nfqws2", 'S', 0, "nfqws2\x00--qnum=300\x00")
			case "unknown-process":
				f.process(t, 2, "unknown", 'S', 0, "")
			case "foreign-forward-queue":
				f.image.Rows = append(f.image.Rows, nfqwsDirectStockTestRow(4, "mangle", "-A", "FORWARD", "-j", "NFQUEUE", "--queue-num", "64511"))
			case "owned-hook":
				f.image.Rows = append(f.image.Rows, nfqwsDirectStockTestRow(4, "mangle", "-N", "nfqws_post"))
			case "unattributed-queue":
				f.proof.queues = func(context.Context) ([]nfqwsScopedQueue, error) {
					return []nfqwsScopedQueue{{number: 64512, portID: 99}}, nil
				}
			case "incomplete-inventory":
				f.image.Coverage.NativeNFTAllFamilies = false
			case "unknown-sockets":
				f.proof.sockets = func(context.Context) (string, error) { return "", nil }
			}
			before := readBytes(t, filepath.Join(f.a.StateRoot, nfqws2LeaseFile))
			if err := f.admit(nfqws2InactiveTestContext(t)); err == nil || f.runtimeCalls != 1 {
				t.Fatal("live or unknown runtime admitted", err, f.runtimeCalls)
			}
			if !bytes.Equal(before, readBytes(t, filepath.Join(f.a.StateRoot, nfqws2LeaseFile))) {
				t.Fatal("runtime refusal settled the stale lease")
			}
		})
	}
}

func TestNFQWS2RebootStopBookendsFilesPlanSourceAndCancellation(t *testing.T) {
	for _, change := range []string{"lease-replacement", "staged-file", "run-appeared", "pid-appeared", "parent-replacement", "plan", "source", "boot", "canceled", "closing-source-file", "closing-source-plan"} {
		t.Run(change, func(t *testing.T) {
			f := newNFQWS2RebootStopFixture(t)
			ctx, cancel := context.WithCancel(nfqws2InactiveTestContext(t))
			defer cancel()
			mutate := func() {
				switch change {
				case "lease-replacement":
					path := filepath.Join(f.a.StateRoot, nfqws2LeaseFile)
					raw := readBytes(t, path)
					if err := os.WriteFile(path+".replacement", raw, 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.Rename(path+".replacement", path); err != nil {
						t.Fatal(err)
					}
				case "staged-file":
					transaction, _ := f.a.firstStartTransaction(f.plan)
					if err := os.WriteFile(filepath.Join(transaction, "nfqws2.conf.staged"), []byte("changed\n"), 0600); err != nil {
						t.Fatal(err)
					}
				case "run-appeared", "pid-appeared", "closing-source-file":
					path := f.a.ConfigPath + ".run"
					if change == "pid-appeared" {
						path = f.a.firstStartPIDPath()
					}
					if err := os.WriteFile(path, []byte("999\n"), 0600); err != nil {
						t.Fatal(err)
					}
				case "parent-replacement":
					path := filepath.Dir(f.a.firstStartPIDPath())
					if err := os.Rename(path, path+".old"); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(path, 0700); err != nil {
						t.Fatal(err)
					}
				case "plan", "closing-source-plan":
					changed := f.plan
					changed.Routes = []Route{{ServiceID: "changed", Selected: "nfqws2", Resolved: "nfqws2", Domains: []string{"other.example"}}}
					if err := f.manager.Record(changed); err != nil {
						t.Fatal(err)
					}
				case "source":
					f.manager.runtimeSources = nil
				case "boot":
					f.source.identity.BootID = "32345678-1234-1234-1234-123456789abc"
				case "canceled":
					cancel()
				}
			}
			if strings.HasPrefix(change, "closing-source-") {
				f.atSourceCheck = func(calls int) {
					if calls == 2 {
						mutate()
					}
				}
			} else {
				f.afterRuntime = mutate
			}
			if err := f.admit(ctx); err == nil || f.runtimeCalls != 1 {
				t.Fatal("changed evidence inherited earlier runtime absence", err, f.runtimeCalls)
			}
		})
	}
}
