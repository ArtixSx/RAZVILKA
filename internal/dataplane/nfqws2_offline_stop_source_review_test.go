//go:build linux

package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// Real protected files, original source associations and the actual pending-WAL
// reader run here. Provider/tool/kernel/process inventories use the existing
// private models. No native command, router packet or real Stop is exercised.
type offlineStopSourceModel struct {
	f    *nfqws2InactiveFixture
	m    *Manager
	r    *RuntimeInactivitySourceReview
	plan Plan
	ctx  context.Context
}

func newOfflineStopSourceModel(t *testing.T) *offlineStopSourceModel {
	t.Helper()
	f := firstStartStoppedInactiveFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	plan, err := BuildAt(Input{Revision: 40,
		Routes:  []Route{{ServiceID: "video", Selected: "nfqws2", Resolved: "nfqws2", Domains: []string{"selected.example"}}},
		Engines: []Engine{{ID: "nfqws2", Installed: true, Configured: true, Activatable: true}},
		Host:    HostState{IPCommand: true, IPTables: true, IP6Tables: true, NFQueueTarget: true, NFQWS2Config: true, NFQWS2Init: true, OffloadState: "disabled"}}, time.Now().UTC().Add(-2*time.Second))
	if err != nil || !plan.Ready {
		t.Fatal("source plan unavailable", err)
	}
	plan.State = "committed"
	m := New(filepath.Dir(filepath.Dir(f.a.StateRoot)))
	transaction := filepath.Join(m.StateRoot, "transactions", plan.PlanID, "nfqws2")
	if err := os.MkdirAll(transaction, 0700); err != nil {
		t.Fatal(err)
	}
	for _, file := range []struct{ source, target string }{{f.a.ConfigPath, "nfqws2.conf.staged"}, {f.a.InitPath, "S51nfqws2.staged"}} {
		raw, err := os.ReadFile(file.source)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(transaction, file.target), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	lease, err := f.a.readLease()
	if err != nil {
		t.Fatal(err)
	}
	lease.Transaction, lease.FirstStart.Phase = transaction, nfqws2FirstRunning
	if err := f.a.writeLease(lease); err != nil {
		t.Fatal(err)
	}
	running := []byte("ISP_INTERFACE=\"eth3\"\nIPV6_ENABLED=0\nTCP_PORTS=443\nUDP_PORTS=\nPOLICY_NAME=\"nfqws\"\nPOLICY_EXCLUDE=0\nPOLICY_MARK=\"\"\nNFQUEUE_NUM=300\n")
	main, err := os.ReadFile(f.a.ConfigPath)
	if err != nil || engineconfig.NFQWSFirstStartRunningConfig(main, lease.Owner, running) != nil {
		t.Fatal("fixture overlay is outside the closed first-start format", err)
	}
	if err := os.WriteFile(f.a.ConfigPath+".run", running, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.a.firstStartPIDPath(), []byte("999\n"), 0600); err != nil {
		t.Fatal(err)
	}
	s := &offlineStopSourceModel{f: f, m: m, plan: plan, ctx: ctx}
	s.bind(t, f.source.identity)
	if err := s.m.Record(plan); err != nil {
		t.Fatal(err)
	}
	s.plan, _, err = s.m.Committed()
	if err != nil {
		t.Fatal(err)
	}
	// Keep the real complete absence predicate, substituting only the existing
	// private provider/inventory inputs, as in other first-start source tests.
	f.a.firstStartObservation = func(c context.Context, full bool) error {
		if full {
			return f.verify(c)
		}
		return f.a.firstStartRuntimeAbsentWithSources(c, f.proof,
			func(c context.Context, use func(context.Context, netidentity.Identity) error) error {
				return use(c, f.source.identity)
			},
			func(c context.Context, identity netidentity.Identity) (BackendInventorySnapshot, error) {
				f.reads++
				return nfqwsDirectStockTestClone(f.image), c.Err()
			})
	}
	return s
}

func (s *offlineStopSourceModel) bind(t *testing.T, identity netidentity.Identity) {
	t.Helper()
	// A new modeled startup owns a new source/provider/collector association.
	// The earlier receipt remains comparison data, including across reboot.
	previous := s.f.source
	s.f.a.inactivity = nil
	provider := netidentity.NewProcProvider()
	inventory := *previous.inventory
	inventory.reader.Provider = provider
	source := &NFQWSRuntimeInactiveSource{adapter: s.f.a, startup: *s.f.a, inventory: &inventory, frozen: inventory, provider: provider, identity: identity, platform: s.f.proof}
	source.self = source
	s.f.source = source
	s.f.image.Scope.Network = identity
	s.m = New(filepath.Dir(filepath.Dir(s.f.a.StateRoot)))
	s.m.Adapters["nfqws2"] = s.f.a
	if err := s.m.Register(NewScopedDNSAdapter(context.Background(), nil, s.m.StateRoot)); err != nil {
		t.Fatal(err)
	}
	settings := filepath.Join(s.m.StateRoot, "dns-state.json")
	if err := s.m.bindRuntimeInactivitySources(s.ctx, provider, &inventory, settings, func(context.Context, *NFQWS2Adapter, *BackendInventory) (*NFQWSRuntimeInactiveSource, error) {
		return source, nil
	}); err != nil {
		t.Fatal(err)
	}
	s.r = s.m.runtimeSources
}

func (s *offlineStopSourceModel) current(c context.Context) error {
	return sourceReviewModelCheck(c, s.r)
}

func (s *offlineStopSourceModel) inspect(t *testing.T) NFQWS2OfflineStopEvidence {
	t.Helper()
	evidence, err := s.r.inspectNFQWS2OfflineStop(s.ctx, s.plan, s.current)
	if err != nil {
		t.Fatal("original source inspection failed", err)
	}
	return evidence
}

func TestNFQWS2OfflineStopSourceInspectionAndCompactRoundtrip(t *testing.T) {
	s := newOfflineStopSourceModel(t)
	evidence := s.inspect(t)
	if !evidence.Matches(evidence, false) || evidence.Matches(evidence, true) || len(evidence.Files) != 11 || len(evidence.FileOwners) != 11 {
		t.Fatal("running source became stopped proof or lost its exact file bindings")
	}
	raw, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	var decoded NFQWS2OfflineStopEvidence
	if err := json.Unmarshal(raw, &decoded); err != nil || !reflect.DeepEqual(evidence, decoded) || !decoded.Matches(evidence, false) {
		t.Fatal("compact retained source did not survive decoding", err)
	}
	copy := *s.r
	if _, err := copy.inspectNFQWS2OfflineStop(s.ctx, s.plan, func(c context.Context) error { return sourceReviewModelCheck(c, &copy) }); err == nil {
		t.Fatal("copied source association was admitted")
	}
}

func TestNFQWS2OfflineStopSourceRejectsSameByteFileReplacement(t *testing.T) {
	for _, which := range []string{"main", "init", "list", "staged", "lease"} {
		t.Run(which, func(t *testing.T) {
			s := newOfflineStopSourceModel(t)
			original := s.inspect(t)
			path := s.f.a.ConfigPath
			switch which {
			case "init":
				path = s.f.a.InitPath
			case "list":
				path = s.f.a.UserListPath
			case "staged":
				path = filepath.Join(s.m.StateRoot, "transactions", s.plan.PlanID, "nfqws2", "nfqws2.conf.staged")
			case "lease":
				path = filepath.Join(s.f.a.StateRoot, nfqws2LeaseFile)
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path+".replacement", raw, info.Mode().Perm()); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(path+".replacement", path); err != nil {
				t.Fatal(err)
			}
			if observed := s.inspect(t); observed.Matches(original, false) {
				t.Fatal("identical bytes hid replacement of an original file")
			}
		})
	}
}

func TestNFQWS2OfflineStopSourceExactStoppedTransitionAndGeneration(t *testing.T) {
	s := newOfflineStopSourceModel(t)
	original := s.inspect(t)
	lease, err := s.f.a.readLease()
	if err != nil || s.f.a.recordFirstStartStopped(lease) != nil {
		t.Fatal("could not model exact original phase-only publication", err)
	}
	partial := s.inspect(t)
	if !partial.Matches(original, false) || partial.Matches(original, true) {
		t.Fatal("interrupted stopped metadata was lost or mistaken for complete cleanup")
	}
	for _, path := range []string{s.f.a.ConfigPath + ".run", s.f.a.firstStartPIDPath()} {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	stopped := s.inspect(t)
	if !stopped.Matches(original, true) || s.f.verify(s.ctx) != nil {
		t.Fatal("exact stopped generation and complete model absence were refused")
	}
	changed := stopped
	changed.Network.Inode++
	if changed.Matches(original, true) {
		t.Fatal("same-boot network replacement was accepted")
	}
	changed = stopped
	changed.Instance = "different-generation"
	if changed.Matches(original, true) {
		t.Fatal("another native generation matched retained Stop")
	}
	// Retained data still cannot certify absence after an independent process
	// appears. The actual complete process predicate must be run again.
	s.f.process(t, 999, "nfqws2", 'S', 0, "/opt/usr/bin/nfqws2\x00--qnum=300\x00")
	if !stopped.Matches(original, true) || s.f.verify(s.ctx) == nil {
		t.Fatal("retained comparison replaced fresh process observation")
	}
}

func (s *offlineStopSourceModel) pendingIntent(t *testing.T) ([]byte, NFQWS2OfflineStopIntent) {
	t.Helper()
	at := time.Now().UTC()
	before := config.Default()
	before.Revision, before.AppliedRevision = 42, s.plan.Revision
	before.SafeMode = true
	before.Services["video"] = config.ServiceState{Enabled: true, Route: "nfqws2", Mode: "nfqws2"}
	before.AppliedServices["video"] = before.Services["video"]
	resolved := map[string]string{"video": "nfqws2"}
	after, err := config.ReviewedNFQWS2StopImage(before, resolved, at)
	if err != nil {
		t.Fatal(err)
	}
	target, err := BuildAt(Input{Revision: after.Revision}, at)
	if err != nil {
		t.Fatal(err)
	}
	execution := Execution{PlanID: s.plan.PlanID, Digest: s.plan.Digest, State: "committed", StartedAt: at.Add(-time.Second).Format(time.RFC3339Nano), FinishedAt: at.Format(time.RFC3339Nano), Steps: []ExecutionStep{}}
	if err := s.m.writeExecution(filepath.Join(s.m.StateRoot, "transactions", s.plan.PlanID), execution); err != nil {
		t.Fatal(err)
	}
	source := s.inspect(t)
	boot := nfqws2CandidateHookRecord{Version: 1, State: "uncertain", PlanID: s.plan.PlanID, Digest: s.plan.Digest, Instance: source.Instance,
		Effects: []nfqws2CandidateHookEffect{{State: "unknown", Command: NFQWS2HookCommand{Family: 4, Args: []string{"-t", "mangle", "-N", "nfqws_post"}}}}}
	bootRaw, _ := json.Marshal(boot)
	if err := writeDataplaneJournal(filepath.Join(s.m.StateRoot, nfqws2BootHookJournal), bootRaw); err != nil {
		t.Fatal(err)
	}
	stoppedBoot, _, err := ReviewedNFQWS2BootHookStopImage(bootRaw, s.plan, source.Instance)
	if err != nil {
		t.Fatal(err)
	}
	root, err := ownedfs.Open(s.m.StateRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	info, err := root.RootInfo()
	if err != nil {
		t.Fatal(err)
	}
	owner, err := offlineStopDirectoryIdentity(info)
	if err != nil {
		t.Fatal(err)
	}
	beforeRaw, _ := json.MarshalIndent(before, "", "  ")
	afterRaw, _ := json.MarshalIndent(after, "", "  ")
	in := NFQWS2OfflineStopIntent{Version: 1, State: "pending", StateRoot: s.m.StateRoot, StateOwner: owner, ConfigPath: filepath.Join(s.m.StateRoot, "config.json"), ConfigOwner: owner, DNSPath: s.r.settings,
		AppliedAt: at, Plan: s.plan, Target: target, ConfigBefore: before, ConfigAfter: after, BeforeImage: restorejournal.Image{Exists: true, Data: beforeRaw}, AfterImage: restorejournal.Image{Exists: true, Data: afterRaw},
		Resolved: resolved, Source: source, Original: map[string]restorejournal.Image{}, HooksAfter: map[string]restorejournal.Image{"nfqws2-hooks-recovery.json": {}, nfqws2BootHookJournal: {Exists: true, Data: stoppedBoot}}}
	for _, name := range []string{"latest-plan.json", "latest-committed-plan.json", "latest-execution.json", "latest-recovery.json", "nfqws2-hooks-recovery.json", nfqws2BootHookJournal, filepath.Join("transactions", s.plan.PlanID, "execution.json")} {
		image, err := readEmptyStopImage(root, name)
		if err != nil {
			t.Fatal(err)
		}
		in.Original[name] = image
	}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeNFQWS2OfflineStopIntent(raw); err != nil {
		t.Fatal("retained pending intent is invalid", err)
	}
	if err := writeDataplaneJournal(filepath.Join(s.m.StateRoot, NFQWS2OfflineStopJournalName), raw); err != nil {
		t.Fatal(err)
	}
	return raw, in
}

func TestNFQWS2OfflineStopRetryReadsActualPendingIntentAndFreshAbsence(t *testing.T) {
	for _, which := range []string{"same-boot-running-metadata", "same-boot-stopped-metadata", "previous-boot", "live-process", "nonpending-intent", "nil-context", "unbounded-context", "cancelled-context", "missing-guard", "guard-refusal"} {
		t.Run(which, func(t *testing.T) {
			s := newOfflineStopSourceModel(t)
			originalWAL, intent := s.pendingIntent(t)
			want := true
			switch which {
			case "same-boot-running-metadata":
				for _, path := range []string{s.f.a.ConfigPath + ".run", s.f.a.firstStartPIDPath()} {
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
				}
			case "same-boot-stopped-metadata":
				lease, err := s.f.a.readLease()
				if err != nil || s.f.a.recordFirstStartStopped(lease) != nil {
					t.Fatal("phase publication failed", err)
				}
			case "previous-boot":
				identity := s.f.source.identity
				identity.BootID, identity.Inode = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", 54321
				s.bind(t, identity)
			case "live-process":
				s.f.process(t, 999, "nfqws2", 'S', 0, "/opt/usr/bin/nfqws2\x00--qnum=300\x00")
				want = false
			case "nonpending-intent":
				intent.State = "inactive"
				originalWAL, _ = json.Marshal(intent)
				if err := writeDataplaneJournal(filepath.Join(s.m.StateRoot, NFQWS2OfflineStopJournalName), originalWAL); err != nil {
					t.Fatal(err)
				}
				want = false
			case "nil-context", "unbounded-context", "cancelled-context", "missing-guard", "guard-refusal":
				want = false
			}
			filesBefore, err := s.f.a.firstStartHookFiles(filepath.Join(s.m.StateRoot, "transactions", s.plan.PlanID, "nfqws2"))
			if err != nil {
				t.Fatal(err)
			}
			ctx := WithReviewGuard(s.ctx, func(c context.Context) error { return c.Err() })
			switch which {
			case "nil-context":
				ctx = nil
			case "unbounded-context":
				ctx = WithReviewGuard(context.Background(), func(c context.Context) error { return c.Err() })
			case "cancelled-context":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			case "missing-guard":
				ctx = s.ctx
			case "guard-refusal":
				ctx = WithReviewGuard(s.ctx, func(context.Context) error { return ErrReviewChanged })
			}
			err = s.r.verifyNFQWS2OfflineStopRetry(ctx, s.current)
			if (err == nil) != want || want && s.f.reads == 0 {
				t.Fatal("retry did not require its pending intent and fresh complete model absence", err)
			}
			filesAfter, readErr := s.f.a.firstStartHookFiles(filepath.Join(s.m.StateRoot, "transactions", s.plan.PlanID, "nfqws2"))
			actualWAL, walErr := os.ReadFile(filepath.Join(s.m.StateRoot, NFQWS2OfflineStopJournalName))
			if readErr != nil || walErr != nil || !reflect.DeepEqual(filesBefore, filesAfter) || !bytes.Equal(actualWAL, originalWAL) {
				t.Fatal("read-only retry observation changed files or acknowledged uncertain history", errors.Join(readErr, walErr))
			}
		})
	}
}
