package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/usquediag"
)

func usqueHealthReceiptPlan(f *usqueLiveFixture) Plan {
	return Plan{NetworkProfileID: f.plan.NetworkProfileID, Routes: cloneNetworkPolicyRoutes(f.plan.Routes), LAN: CloneLANPolicyRuntime(f.plan.LAN)}
}

func usqueHealthReceiptWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func usqueHealthReceiptSelection(t *testing.T, f *usqueLiveFixture, candidate bool) (string, []string) {
	t.Helper()
	root, selection, evidence := f.a.StateRoot, "transport.json", "evidence.json"
	var roots []string
	if candidate {
		root, selection, evidence = t.TempDir(), "transport.staged.json", "evidence.staged.json"
		roots = []string{root}
	}
	data, _ := json.Marshal(f.transport)
	usqueHealthReceiptWrite(t, filepath.Join(root, selection), data)
	usqueHealthReceiptWrite(t, filepath.Join(root, evidence), []byte(`{"historical_canary":"leave unchanged"}`))
	f.a.ownedUSQUELiveIO = f.inspect
	return root, roots
}

func TestUSQUEHealthReceiptCandidateUsesSelectedHTTP2AndPersistsOriginalWholeProof(t *testing.T) {
	f := newUSQUELiveFixture(t, usqueTransport{HTTP2: true, SNI: "cloudflareclient.com"})
	root, roots := usqueHealthReceiptSelection(t, f, true)
	usqueHealthReceiptWrite(t, f.a.transportPath(), []byte(`{"http2":false}`))
	committedHistory := []byte(`{"old_committed_quic":"unchanged"}`)
	usqueHealthReceiptWrite(t, f.a.evidencePath(), committedHistory)
	var captured []byte
	f.ctx = context.WithValue(f.ctx, usqueLiveHealthCaptureKey{}, func(data []byte) {
		saved, err := os.ReadFile(filepath.Join(root, "evidence.staged.json"))
		if err != nil || !bytes.Equal(saved, data) {
			t.Fatal("capture preceded successful evidence write", err)
		}
		captured = data
	})
	if err := f.a.healthOwnedUSQUE(f.ctx, usqueHealthReceiptPlan(f), roots...); err != nil || f.probes != 1 || f.observed != 3 {
		t.Fatal("candidate live health failed", err, f.probes, f.observed)
	}
	expected, _ := json.Marshal(f.produced.CanaryEvidence())
	saved, err := os.ReadFile(filepath.Join(root, "evidence.staged.json"))
	if err != nil || !bytes.Equal(saved, expected) || !bytes.Equal(captured, expected) {
		t.Fatal("whole original receipt or timestamps/TTL changed", err)
	}
	f.produced.ReachableRoutes[0], f.produced.ConfirmedRoutes[0] = "caller-mutates", "caller-mutates"
	if !bytes.Equal(saved, captured) || bytes.Contains(captured, []byte("caller-mutates")) {
		t.Fatal("receipt aliases producer slices")
	}
	captured[0] = '['
	onDisk, _ := os.ReadFile(filepath.Join(root, "evidence.staged.json"))
	committed, _ := os.ReadFile(f.a.evidencePath())
	if !bytes.Equal(onDisk, expected) || !bytes.Equal(committed, committedHistory) {
		t.Fatal("capture aliases persisted evidence or wrote the committed root")
	}
	for _, spec := range f.processes.specs {
		if !reflect.DeepEqual(spec, f.a.engineProcessWithTransport(f.transport)) {
			t.Fatal("candidate borrowed committed QUIC process selection")
		}
	}
}

func TestUSQUEHealthReceiptStrictSelectionRefusesBeforeProducerOrWrite(t *testing.T) {
	for _, mode := range []string{"missing", "empty", "null", "array", "missing-http2", "null-http2", "string-http2", "duplicate", "unknown", "uppercase", "null-sni", "number-sni", "unsafe-sni", "empty-label", "trailing", "oversized", "directory", "empty-root", "relative-root", "unclean-root", "two-roots"} {
		t.Run(mode, func(t *testing.T) {
			f := newUSQUELiveFixture(t, usqueTransport{})
			root, roots := usqueHealthReceiptSelection(t, f, false)
			path := filepath.Join(root, "transport.json")
			bad := map[string]string{"empty": "", "null": "null", "array": "[]", "missing-http2": `{}`, "null-http2": `{"http2":null}`, "string-http2": `{"http2":"false"}`,
				"duplicate": `{"http2":false,"http2":true}`, "unknown": `{"http2":false,"fallback":true}`, "uppercase": `{"HTTP2":false}`,
				"null-sni": `{"http2":false,"sni":null}`, "number-sni": `{"http2":false,"sni":12}`, "unsafe-sni": `{"http2":false,"sni":"unsafe;command"}`,
				"empty-label": `{"http2":false,"sni":"a..example"}`, "trailing": `{"http2":false}{}`, "oversized": strings.Repeat(" ", 4097)}
			if data, ok := bad[mode]; ok {
				usqueHealthReceiptWrite(t, path, []byte(data))
			}
			switch mode {
			case "missing", "directory":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if mode == "directory" {
					if err := os.Mkdir(path, 0700); err != nil {
						t.Fatal(err)
					}
				}
			case "empty-root":
				roots = []string{""}
			case "relative-root":
				roots = []string{"relative"}
			case "unclean-root":
				roots = []string{root + string(filepath.Separator) + "."}
			case "two-roots":
				roots = []string{root, root}
			}
			// A usable old configuration/default may not fill a missing selection.
			f.a.UsqueConfig = filepath.Join(root, "preferred.conf")
			usqueHealthReceiptWrite(t, f.a.UsqueConfig, []byte("HTTP2_ENABLE=0\nSNI=cloudflareclient.com\n"))
			before := nodeRouterTransitReadbackTree(t, root)
			if _, err := f.a.usqueHealthTransport(roots...); err == nil {
				t.Fatal("malformed/ambiguous selection got a fallback")
			}
			if err := f.a.healthOwnedUSQUE(f.ctx, usqueHealthReceiptPlan(f), roots...); err == nil || f.probes != 0 || f.observed != 0 {
				t.Fatal("bad selection reached producer/observer", err, f.probes, f.observed)
			}
			if !reflect.DeepEqual(before, nodeRouterTransitReadbackTree(t, root)) {
				t.Fatal("selection refusal changed old evidence/state")
			}
		})
	}
}

func TestUSQUEHealthReceiptCommittedRequiresActionGuardAndDetachesProcessArgs(t *testing.T) {
	for _, mode := range []string{"positive", "nil-context", "missing-guard", "revoked", "canceled", "guard-cancels"} {
		t.Run(mode, func(t *testing.T) {
			f := newUSQUELiveFixture(t, usqueTransport{})
			root, roots := usqueHealthReceiptSelection(t, f, false)
			before := nodeRouterTransitReadbackTree(t, root)
			freshCalls := 0
			fresh := f.a.FreshProfile
			f.a.FreshProfile = func(ctx context.Context) (string, error) { freshCalls++; return fresh(ctx) }
			if mode == "positive" {
				f.a.Processes = usqueHealthReceiptProcessCallback{ProcessController: f.processes, running: func(spec ProcessSpec) bool {
					running := f.processes.Running(spec)
					// A controller receives its own argv slice, never the sealed
					// ProcessSpec used to construct the observer request/digest.
					spec.Args[0] = "caller-mutates"
					return running
				}}
			}
			switch mode {
			case "nil-context":
				f.ctx = nil
			case "missing-guard":
				f.ctx = context.Background()
			case "revoked":
				f.revoked = true
			case "canceled", "guard-cancels":
				ctx, cancel := context.WithCancel(f.ctx)
				defer cancel()
				f.ctx = ctx
				if mode == "canceled" {
					cancel()
				} else {
					f.ctx = WithReviewGuard(ctx, func(context.Context) error { cancel(); return nil })
				}
			}
			err := f.a.healthOwnedUSQUE(f.ctx, usqueHealthReceiptPlan(f), roots...)
			if mode == "positive" {
				expected, _ := json.Marshal(f.produced.CanaryEvidence())
				saved, readErr := os.ReadFile(f.a.evidencePath())
				if err != nil || readErr != nil || f.probes != 1 || f.observed != 3 || !bytes.Equal(saved, expected) {
					t.Fatal("committed live health replaced or lost proof", err, readErr)
				}
			} else if err == nil || freshCalls != 0 || f.probes != 0 || f.observed != 0 || !reflect.DeepEqual(before, nodeRouterTransitReadbackTree(t, root)) {
				t.Fatal("missing/revoked action authority reached callback or state", err, freshCalls)
			}
		})
	}
}

func TestUSQUEHealthReceiptCallbackDriftKeepsOldEvidence(t *testing.T) {
	for _, mode := range []string{"selection", "config", "spec", "Stop", "WAN", "review", "cancel", "final-identity", "final-selection", "final-config", "final-root", "final-WAN", "final-guard-cancels", "fresh-profile-revokes", "running-revokes"} {
		t.Run(mode, func(t *testing.T) {
			f := newUSQUELiveFixture(t, usqueTransport{HTTP2: true})
			root, roots := usqueHealthReceiptSelection(t, f, true)
			evidence := filepath.Join(root, "evidence.staged.json")
			before, _ := os.ReadFile(evidence)
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			f.ctx = ctx
			produce := f.inspect.produce
			f.inspect.produce = func(ctx context.Context, options usquediag.OwnedProbeOptions) (usquediag.OwnedRuntimeEvidence, error) {
				proof, err := produce(ctx, options)
				switch mode {
				case "selection":
					usqueHealthReceiptWrite(t, filepath.Join(root, "transport.staged.json"), []byte(`{"http2":false}`))
				case "config":
					usqueHealthReceiptWrite(t, f.a.engineConfigPath(), []byte(`{"endpoint_h2_v4":"162.159.198.3"}`))
				case "spec":
					f.a.SOCKSPort++
				case "Stop":
					f.processes.running = false
				case "WAN":
					f.profile = "wan-abcdef123456"
				case "review":
					f.revoked = true
				case "cancel":
					cancel()
				}
				return proof, err
			}
			observe := f.inspect.observe
			finalObserved := false
			f.inspect.observe = func(ctx context.Context, request usquediag.OwnedRuntimeRequest) (usquediag.OwnedRuntimeIdentity, error) {
				identity, err := observe(ctx, request)
				if f.observed == 3 {
					finalObserved = true
					switch mode {
					case "final-identity":
						identity.RuntimeID = "managed:usque:" + strings.Repeat("b", 64)
						usqueLiveBind(&identity)
					case "final-selection":
						usqueHealthReceiptWrite(t, filepath.Join(root, "transport.staged.json"), []byte(`{"http2":false}`))
					case "final-config":
						usqueHealthReceiptWrite(t, f.a.engineConfigPath(), []byte(`{"endpoint_h2_v4":"162.159.198.3"}`))
					case "final-root":
						f.a.StateRoot = filepath.Join(t.TempDir(), "foreign-root")
					case "final-WAN":
						f.profile = "wan-abcdef123456"
					}
				}
				return identity, err
			}
			if mode == "final-guard-cancels" {
				f.ctx = WithReviewGuard(f.ctx, func(context.Context) error {
					if finalObserved {
						cancel()
					}
					return nil
				})
			}
			if mode == "fresh-profile-revokes" {
				f.a.FreshProfile = func(context.Context) (string, error) { f.revoked = true; return f.profile, nil }
			}
			if mode == "running-revokes" {
				f.a.Processes = usqueHealthReceiptProcessCallback{ProcessController: f.processes, running: func(spec ProcessSpec) bool {
					f.revoked = true
					return f.processes.Running(spec)
				}}
			}
			f.a.ownedUSQUELiveIO = f.inspect
			captures := 0
			f.ctx = context.WithValue(f.ctx, usqueLiveHealthCaptureKey{}, func([]byte) { captures++ })
			if err := f.a.healthOwnedUSQUE(f.ctx, usqueHealthReceiptPlan(f), roots...); err == nil || captures != 0 {
				t.Fatal("drift acquired/persisted current health", err, captures)
			}
			after, _ := os.ReadFile(evidence)
			if !bytes.Equal(before, after) || f.probes > 1 {
				t.Fatal("drift replaced old receipt or replayed producer")
			}
		})
	}
}

type usqueHealthReceiptProcessCallback struct {
	ProcessController
	running func(ProcessSpec) bool
}

func (p usqueHealthReceiptProcessCallback) Running(spec ProcessSpec) bool { return p.running(spec) }

func TestUSQUEHealthReceiptRejectsNilOldAndForeignProof(t *testing.T) {
	for _, mode := range []string{"nil", "historical", "foreign", "grade"} {
		t.Run(mode, func(t *testing.T) {
			f := newUSQUELiveFixture(t, usqueTransport{})
			root, roots := usqueHealthReceiptSelection(t, f, false)
			before := nodeRouterTransitReadbackTree(t, root)
			produce := f.inspect.produce
			f.inspect.produce = func(ctx context.Context, options usquediag.OwnedProbeOptions) (usquediag.OwnedRuntimeEvidence, error) {
				proof, err := produce(ctx, options)
				switch mode {
				case "nil":
					return usquediag.OwnedRuntimeEvidence{}, nil
				case "historical":
					proof.CheckedAt = time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)
				case "foreign":
					proof.Identity.RuntimeID = "managed:usque:" + strings.Repeat("b", 64)
					usqueLiveBind(&proof.Identity)
				case "grade":
					proof.UDPForwarding = true
				}
				return proof, err
			}
			f.a.ownedUSQUELiveIO = f.inspect
			if err := f.a.healthOwnedUSQUE(f.ctx, usqueHealthReceiptPlan(f), roots...); err == nil || f.probes != 1 {
				t.Fatal("invalid proof got current evidence", err)
			}
			if !reflect.DeepEqual(before, nodeRouterTransitReadbackTree(t, root)) {
				t.Fatal("invalid proof altered saved history")
			}
		})
	}
}

func TestUSQUEHealthReceiptCommitUsesOnlyCapturedFreshProof(t *testing.T) {
	f := newUSQUELiveFixture(t, usqueTransport{HTTP2: true, SNI: "cloudflareclient.com"})
	root, roots := usqueHealthReceiptSelection(t, f, true)
	usqueHealthReceiptWrite(t, f.a.transportPath(), []byte(`{"http2":false}`))
	usqueHealthReceiptWrite(t, f.a.evidencePath(), []byte(`{"old_committed":"unchanged"}`))
	var captured []byte
	ctx := context.WithValue(f.ctx, usqueLiveHealthCaptureKey{}, func(data []byte) { captured = data })
	plan := usqueHealthReceiptPlan(f)
	if err := f.a.healthOwnedUSQUE(ctx, plan, roots...); err != nil {
		t.Fatal(err)
	}
	before := append([]byte(nil), captured...)
	usqueHealthReceiptWrite(t, filepath.Join(root, "evidence.staged.json"), []byte(`{"old_canary":"must not copy"}`))
	if err := f.a.commitOwnedUSQUEHealth(ctx, plan, root, captured); err != nil || f.probes != 1 || f.observed != 4 {
		t.Fatal("promotion replayed network or failed current readback", err, f.probes, f.observed)
	}
	saved, _ := os.ReadFile(f.a.evidencePath())
	selected, err := f.a.usqueHealthTransport()
	if err != nil || selected != f.transport || !bytes.Equal(saved, before) || !bytes.Equal(captured, before) {
		t.Fatal("promotion copied file history, refreshed TTL or mutated caller bytes", err)
	}
}

func TestUSQUEHealthReceiptCommitDriftKeepsCommittedHistory(t *testing.T) {
	for _, mode := range []string{"missing-capture", "unknown-capture", "duplicate-capture", "expired", "selection", "config", "spec", "WAN", "identity", "closing-selection", "review", "cancel", "foreign-service"} {
		t.Run(mode, func(t *testing.T) {
			f := newUSQUELiveFixture(t, usqueTransport{HTTP2: true})
			root, roots := usqueHealthReceiptSelection(t, f, true)
			usqueHealthReceiptWrite(t, f.a.transportPath(), []byte(`{"http2":false}`))
			usqueHealthReceiptWrite(t, f.a.evidencePath(), []byte(`{"old_committed":"unchanged"}`))
			var captured []byte
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			ctx = context.WithValue(ctx, usqueLiveHealthCaptureKey{}, func(data []byte) { captured = data })
			plan := usqueHealthReceiptPlan(f)
			if err := f.a.healthOwnedUSQUE(ctx, plan, roots...); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "missing-capture":
				captured = nil
			case "unknown-capture":
				captured = append([]byte(`{"unknown":true,`), captured[1:]...)
			case "duplicate-capture":
				captured = append([]byte(`{"transport":"HTTP/2",`), captured[1:]...)
			case "expired":
				var receipt usquediag.CanaryEvidence
				_ = json.Unmarshal(captured, &receipt)
				receipt.Owned.ValidUntil = time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)
				receipt = receipt.Owned.CanaryEvidence()
				captured, _ = json.Marshal(receipt)
			case "selection":
				usqueHealthReceiptWrite(t, filepath.Join(root, "transport.staged.json"), []byte(`{"http2":false}`))
			case "config":
				usqueHealthReceiptWrite(t, f.a.engineConfigPath(), []byte(`{"endpoint_h2_v4":"162.159.198.3"}`))
			case "spec":
				f.a.SOCKSPort++
			case "WAN":
				f.profile = "wan-abcdef123456"
			case "foreign-service":
				plan.Routes[0].ProbeService.ID = "foreign"
				plan.Routes[0].ServiceID = "foreign"
			}
			observe := f.inspect.observe
			f.inspect.observe = func(ctx context.Context, request usquediag.OwnedRuntimeRequest) (usquediag.OwnedRuntimeIdentity, error) {
				identity, err := observe(ctx, request)
				switch mode {
				case "identity":
					identity.RuntimeID = "managed:usque:" + strings.Repeat("b", 64)
					usqueLiveBind(&identity)
				case "closing-selection":
					usqueHealthReceiptWrite(t, filepath.Join(root, "transport.staged.json"), []byte(`{"http2":false}`))
				case "review":
					f.revoked = true
				case "cancel":
					cancel()
				}
				return identity, err
			}
			f.a.ownedUSQUELiveIO = f.inspect
			beforeTransport, _ := os.ReadFile(f.a.transportPath())
			beforeEvidence, _ := os.ReadFile(f.a.evidencePath())
			if err := f.a.commitOwnedUSQUEHealth(ctx, plan, root, captured); err == nil || f.probes != 1 {
				t.Fatal("stale/changed promotion got current evidence", err, f.probes)
			}
			afterTransport, _ := os.ReadFile(f.a.transportPath())
			afterEvidence, _ := os.ReadFile(f.a.evidencePath())
			if !bytes.Equal(beforeTransport, afterTransport) || !bytes.Equal(beforeEvidence, afterEvidence) {
				t.Fatal("promotion refusal changed committed selection/history")
			}
			if mode == "cancel" && !errors.Is(ctx.Err(), context.Canceled) {
				t.Fatal("cancellation fixture did not reach closing callback")
			}
		})
	}
}

func TestUSQUEHealthReceiptClosingWriteGuardCannotReturnSuccess(t *testing.T) {
	for _, action := range []string{"Health", "Commit"} {
		for _, mode := range []string{"review", "cancel"} {
			t.Run(action+"/"+mode, func(t *testing.T) {
				f := newUSQUELiveFixture(t, usqueTransport{})
				root, roots := usqueHealthReceiptSelection(t, f, action == "Commit")
				var captured []byte
				plan := usqueHealthReceiptPlan(f)
				if action == "Commit" {
					usqueHealthReceiptWrite(t, f.a.transportPath(), []byte(`{"http2":true}`))
					usqueHealthReceiptWrite(t, f.a.evidencePath(), []byte(`{"old_committed":"unchanged"}`))
					ctx := context.WithValue(f.ctx, usqueLiveHealthCaptureKey{}, func(data []byte) { captured = data })
					if err := f.a.healthOwnedUSQUE(ctx, plan, roots...); err != nil {
						t.Fatal(err)
					}
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				ctx = WithReviewGuard(ctx, func(context.Context) error {
					data, _ := os.ReadFile(f.a.evidencePath())
					if bytes.Contains(data, []byte(`"owned_runtime"`)) {
						if mode == "cancel" {
							cancel()
							return nil
						}
						return ErrReviewChanged
					}
					return nil
				})
				var err error
				if action == "Health" {
					err = f.a.healthOwnedUSQUE(ctx, plan)
				} else {
					err = f.a.commitOwnedUSQUEHealth(ctx, plan, root, captured)
				}
				want := ErrReviewChanged
				if mode == "cancel" {
					want = context.Canceled
				}
				data, _ := os.ReadFile(f.a.evidencePath())
				if !errors.Is(err, want) || !bytes.Contains(data, []byte(`"owned_runtime"`)) || f.probes != 1 {
					t.Fatal("action returned success after write-time authority loss or replayed producer", err, f.probes)
				}
			})
		}
	}
}
