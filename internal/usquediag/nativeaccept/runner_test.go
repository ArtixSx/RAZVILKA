package nativeaccept

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/routeidentity"
	"github.com/ArtixSx/razvilka/internal/systemprobe"
	"github.com/ArtixSx/razvilka/internal/usquediag"
)

const testExecutableSHA = "a3ad4dce52cc33825fd8bfab520bb2a03f80891b69920819aa391d6a42c6bf10"
const testPrivate = "TEST-ONLY-PRIVATE-DO-NOT-OUTPUT"

// Synthetic authority/identity exist ONLY in pure tests. No child, socket,
// passport, saved evidence, account registration or production observer runs.
type fixture struct {
	r                                                    Request
	io                                                   runnerIO
	events                                               []string
	account, read                                        []byte
	launch                                               Launch
	identity                                             usquediag.OwnedRuntimeIdentity
	proof                                                usquediag.OwnedRuntimeEvidence
	produced                                             bool
	acquires                                             int
	stopErr, verifyErr, releaseErr, startErr, acquireErr error
	stageErr, removeErr, closeErr                        error
	currentHook                                          func(context.Context) error
	startHook                                            func(context.Context, Launch) error
	probeHook                                            func(context.Context) error
	cleanupHook                                          func(context.Context)
	stage                                                *fixtureStage
}

type fixtureStage struct{ f *fixture }

func (s *fixtureStage) Path() string { return filepath.Join(s.f.r.WorkParent, "test-only-stage") }
func (s *fixtureStage) Verify(ctx context.Context) error {
	s.f.events = append(s.f.events, "stage-verify")
	return ctx.Err()
}
func (s *fixtureStage) RemoveSecret(ctx context.Context) error {
	s.f.events = append(s.f.events, "remove-secret")
	return errors.Join(s.f.removeErr, ctx.Err())
}
func (s *fixtureStage) Close() error {
	s.f.events = append(s.f.events, "close-stage")
	return s.f.closeErr
}

func newFixture(t *testing.T, mode string) *fixture {
	t.Helper()
	base := t.TempDir()
	f := &fixture{account: []byte(`{"private_key":"` + testPrivate + `","endpoint_pub_key":"TEST-ONLY-PEER","id":"TEST-ONLY-ID","access_token":"TEST-ONLY-TOKEN","endpoint_v4":"162.159.193.10","endpoint_h2_v4":"162.159.193.11"}`)}
	f.r = Request{Enabled: true, Transport: mode, Binary: filepath.Join(base, "usque"), BinarySHA256: testExecutableSHA,
		Account: filepath.Join(base, "account.json"), AccountSHA256: routeidentity.Hash(f.account), WorkParent: filepath.Join(base, "private"), SOCKSPort: 19080,
		Timeout: 20 * time.Second, CleanupTimeout: 5 * time.Second}
	now := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	f.stage = &fixtureStage{f}
	f.io = runnerIO{goos: "linux", goarch: "amd64", now: func() time.Time { return now },
		fresh: func(ctx context.Context) (systemprobe.WANProfile, error) {
			f.events = append(f.events, "fresh")
			return systemprobe.WANProfile{ID: "wan-123456789abc", WANInterface: "test-only-wan"}, ctx.Err()
		},
		load: func(ctx context.Context, r Request) ([]byte, error) {
			f.events = append(f.events, "load")
			f.read = append([]byte(nil), f.account...)
			return f.read, ctx.Err()
		},
		stage: func(ctx context.Context, r Request, account []byte) (stagedAssets, error) {
			f.events = append(f.events, "stage")
			if string(account) != string(f.account) {
				t.Fatal("account copy changed")
			}
			return f.stage, errors.Join(f.stageErr, ctx.Err())
		},
		produce: func(ctx context.Context, o usquediag.OwnedProbeOptions) (usquediag.OwnedRuntimeEvidence, error) {
			f.events = append(f.events, "produce")
			if !o.Enabled || o.Authority == nil || o.Runtime.Transport != mode || o.Runtime.SOCKSAddress != "127.0.0.1:19080" ||
				o.Network.SOCKSAddress != o.Runtime.SOCKSAddress || o.Network.Timeout > 20*time.Second || len(o.Network.Services) != 0 || o.Network.UDP != nil {
				t.Fatal("unexpected producer/options/fallback")
			}
			if err := o.Authority(ctx); err != nil {
				return usquediag.OwnedRuntimeEvidence{}, err
			}
			env, err := o.Runtime.Environment(ctx)
			if err != nil {
				return usquediag.OwnedRuntimeEvidence{}, err
			}
			f.identity = usquediag.OwnedRuntimeIdentity{RuntimeID: "managed:usque:" + routeidentity.Hash([]byte("test-only-child-birth")), BinarySHA256: testExecutableSHA,
				SessionSHA256: f.r.AccountSHA256, ArgsSHA256: routeidentity.Hash([]byte(strings.Join(append([]string{f.launch.Process.Binary}, f.launch.Process.Args...), "\x00") + "\x00")),
				EnvironmentID: env, Transport: mode, Endpoint: o.Runtime.Endpoint.String(), PeerObservation: "tcp-established-peer", SocketBinding: routeidentity.Hash([]byte("test-only-socket")),
				SourceCommit: "6aa03fc97d12848dce34eedbd187fb1077b5d1ea"}
			if mode == "QUIC" {
				f.identity.PeerObservation = "udp-unconnected-exclusive-config-inference"
			}
			i := f.identity
			binding, _ := json.Marshal([]string{"owned-usque-path-v1", i.RuntimeID, i.BinarySHA256, i.SessionSHA256, i.ArgsSHA256, i.EnvironmentID, i.Transport, i.Endpoint, i.PeerObservation, i.SocketBinding, i.SourceCommit})
			f.identity.BindingID = routeidentity.Hash(binding)
			f.proof = usquediag.OwnedRuntimeEvidence{Origin: "managed-usque-canary", CheckedAt: now.Format(time.RFC3339Nano), ValidUntil: now.Add(usquediag.MaxCanaryAge).Format(time.RFC3339Nano),
				Identity: f.identity, ProofBasis: "official-release-owned-path-inference", ProtocolPath: mode, Warp: "on", ServiceProofVersion: 1}
			f.produced = true
			if f.probeHook != nil {
				if err := f.probeHook(ctx); err != nil {
					return usquediag.OwnedRuntimeEvidence{}, err
				}
			}
			return f.proof, nil
		},
		observe: func(ctx context.Context, r usquediag.OwnedRuntimeRequest) (usquediag.OwnedRuntimeIdentity, error) {
			f.events = append(f.events, "independent-observe")
			before := len(f.events)
			env, err := r.Environment(ctx)
			if err != nil || env != f.identity.EnvironmentID || len(f.events) != before {
				t.Fatal("identity leaf retained external environment callback")
			}
			return f.identity, ctx.Err()
		}}
	return f
}

func (f *fixture) Acquire(ctx context.Context, a Acquisition) (Execution, error) {
	f.events = append(f.events, "acquire")
	f.acquires++
	if a.Request != f.r || a.Network.ID != "wan-123456789abc" {
		panic("acquisition binding changed")
	}
	return f, f.acquireErr
}
func (f *fixture) Current(ctx context.Context) error {
	f.events = append(f.events, "current")
	if f.currentHook != nil {
		return f.currentHook(ctx)
	}
	return ctx.Err()
}
func (f *fixture) Start(ctx context.Context, launch Launch) error {
	f.events = append(f.events, "start")
	f.launch = launch
	f.launch.Process.Args = append([]string(nil), launch.Process.Args...)
	if f.startHook != nil {
		return f.startHook(ctx, launch)
	}
	return f.startErr
}
func (f *fixture) StopAndJoin(ctx context.Context) error {
	f.events = append(f.events, "stop-join")
	if f.cleanupHook != nil {
		f.cleanupHook(ctx)
	}
	return errors.Join(f.stopErr, ctx.Err())
}
func (f *fixture) VerifySettled(ctx context.Context) error {
	f.events = append(f.events, "verify-settled")
	return errors.Join(f.verifyErr, ctx.Err())
}
func (f *fixture) Release(ctx context.Context) error {
	f.events = append(f.events, "release")
	return errors.Join(f.releaseErr, ctx.Err())
}

func has(f *fixture, event string) bool {
	for _, e := range f.events {
		if e == event {
			return true
		}
	}
	return false
}

func TestRunRefusesBeforeIO(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		change     func(*fixture)
		issuer     bool
	}{
		{"no-opt-in", "opt-in-required", func(f *fixture) { f.r.Enabled = false }, true},
		{"bad-budget", "arguments-invalid", func(f *fixture) { f.r.Timeout = 31 * time.Second }, true},
		{"mode-no-fallback", "arguments-invalid", func(f *fixture) { f.r.Transport = "auto" }, true},
		{"missing-issuer", "core-retained-issuer-unavailable", func(*fixture) {}, false},
		{"not-native", "native-linux-required", func(f *fixture) { f.io.goos = "windows" }, true},
		{"wrong-native-arch", "binary-not-audited-for-native-architecture", func(f *fixture) { f.io.goarch = "arm64" }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, "HTTP/2")
			tc.change(f)
			var issuer Issuer
			if tc.issuer {
				issuer = f
			}
			result := run(context.Background(), f.r, issuer, f.io)
			if result.Code != tc.code || len(f.events) != 0 {
				t.Fatalf("%+v, events %v", result, f.events)
			}
		})
	}
}

func TestRunSingleSelectedModeAndOriginalExpiry(t *testing.T) {
	for _, mode := range []string{"HTTP/2", "QUIC"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, mode)
			result := run(context.Background(), f.r, f, f.io)
			if result.Status != "passed" || result.ExitCode() != 0 || result.Settlement != "settled" || result.SecretCleanup != "removed" || result.Observation == nil ||
				result.Observation.OriginalExpiry != f.proof.ValidUntil || result.Observation.Negotiated || !result.Observation.ReadbackMatched || f.acquires != 1 {
				t.Fatalf("%+v, events %v", result, f.events)
			}
			want := processSpec(f.r, f.stage.Path())
			if !reflect.DeepEqual(f.launch.Process, want) || f.launch.ConfigSHA256 != f.r.AccountSHA256 || f.launch.BinarySHA256 != testExecutableSHA || f.launch.Transport != mode {
				t.Fatal("exact launch binding changed")
			}
			if !reflect.DeepEqual(f.launch.ProcessEnvironment, []string{"LANG=C", "HTTP_PROXY=", "HTTPS_PROXY=", "ALL_PROXY=", "http_proxy=", "https_proxy=", "all_proxy=", "NO_PROXY=", "no_proxy="}) {
				t.Fatal("ambient process environment adopted")
			}
			leaf := -1
			for i, event := range f.events {
				if event == "independent-observe" {
					leaf = i
				}
			}
			if leaf < 0 || !reflect.DeepEqual(f.events[leaf+1:], []string{"stop-join", "verify-settled", "remove-secret", "close-stage", "release"}) {
				t.Fatalf("external callback after identity leaf: %v", f.events)
			}
			for _, b := range f.read {
				if b != 0 {
					t.Fatal("private read buffer retained")
				}
			}
			if !strings.Contains(string(f.account), testPrivate) {
				t.Fatal("source account changed")
			}
		})
	}
}

func TestRunFreshCallbackCannotRevokeAndReturnMatchingNetwork(t *testing.T) {
	f := newFixture(t, "HTTP/2")
	base := f.io.fresh
	reads, revoked := 0, false
	f.io.fresh = func(ctx context.Context) (systemprobe.WANProfile, error) {
		reads++
		if reads == 2 {
			revoked = true
		}
		return base(ctx)
	}
	f.currentHook = func(context.Context) error {
		if revoked {
			return errors.New(testPrivate)
		}
		return nil
	}
	result := run(context.Background(), f.r, f, f.io)
	if result.Code != "core-current-refused" || has(f, "load") || has(f, "start") || result.Settlement != "settled" {
		t.Fatalf("%+v, %v", result, f.events)
	}
}

func TestRunParentDeadlineIsNeverWidened(t *testing.T) {
	f := newFixture(t, "HTTP/2")
	parent, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	expected, _ := parent.Deadline()
	f.currentHook = func(ctx context.Context) error {
		actual, ok := ctx.Deadline()
		if !ok || actual.After(expected) {
			t.Fatal("original parent deadline widened")
		}
		return ctx.Err()
	}
	result := run(parent, f.r, f, f.io)
	if result.Status != "passed" {
		t.Fatalf("%+v", result)
	}
}

func TestRunRevokedAuthorityAndIndependentReadback(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		change     func(*fixture)
	}{
		{"revoked-before-account", "core-current-refused", func(f *fixture) { f.currentHook = func(context.Context) error { return errors.New(testPrivate) } }},
		{"closing-authority-revoked", "closing-authority-refused", func(f *fixture) {
			f.currentHook = func(context.Context) error {
				if f.produced {
					return errors.New(testPrivate)
				}
				return nil
			}
		}},
		{"closing-callback-runtime-drift", "independent-readback-refused", func(f *fixture) {
			f.currentHook = func(context.Context) error {
				if f.produced {
					f.identity.SocketBinding = routeidentity.Hash([]byte("test-only-replaced-socket"))
				}
				return nil
			}
		}},
		{"expired-proof", "independent-readback-refused", func(f *fixture) {
			f.probeHook = func(context.Context) error { f.proof.ValidUntil = f.proof.CheckedAt; return nil }
		}},
		{"pre-action-proof", "independent-readback-refused", func(f *fixture) {
			f.probeHook = func(context.Context) error {
				f.proof.CheckedAt = f.io.now().Add(-time.Second).Format(time.RFC3339Nano)
				return nil
			}
		}},
		{"negotiation-overclaim", "independent-readback-refused", func(f *fixture) { f.probeHook = func(context.Context) error { f.proof.Negotiated = true; return nil } }},
		{"producer-failed", "owned-producer-refused", func(f *fixture) { f.probeHook = func(context.Context) error { return errors.New(testPrivate) } }},
		{"partial-start-error", "core-start-refused", func(f *fixture) { f.startErr = errors.New(testPrivate) }},
		{"partial-acquire-error", "core-acquisition-refused", func(f *fixture) { f.acquireErr = errors.New(testPrivate) }},
		{"partial-stage-error", "staging-failed", func(f *fixture) { f.stageErr = errors.New(testPrivate) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, "HTTP/2")
			tc.change(f)
			result := run(context.Background(), f.r, f, f.io)
			if result.Status != "failed" || result.Code != tc.code || result.Settlement != "settled" || result.Observation != nil || !has(f, "release") || f.acquires != 1 {
				t.Fatalf("%+v, %v", result, f.events)
			}
			if tc.name == "revoked-before-account" && has(f, "load") {
				t.Fatal("account read after revocation")
			}
			if has(f, "stage") && !has(f, "remove-secret") {
				t.Fatal("owned secret left after verified settlement")
			}
			encoded, _ := json.Marshal(result)
			if strings.Contains(string(encoded), testPrivate) || strings.Contains(string(encoded), f.r.Account) || strings.Contains(string(encoded), "access_token") {
				t.Fatal("private failure text leaked")
			}
		})
	}
}

func TestRunCleanupRequiresExactSettlement(t *testing.T) {
	for _, tc := range []struct {
		name, code      string
		change          func(*fixture)
		remove, release bool
	}{
		{"join-failed", "core-stop-join-unsettled", func(f *fixture) { f.stopErr = errors.New(testPrivate) }, false, false},
		{"ack-unverified", "core-settlement-unverified", func(f *fixture) { f.verifyErr = errors.New(testPrivate) }, false, false},
		{"secret-not-owned", "staged-secret-retained", func(f *fixture) { f.removeErr = errors.New(testPrivate) }, true, false},
		{"close-failed", "staged-descriptors-unsettled", func(f *fixture) { f.closeErr = errors.New(testPrivate) }, true, false},
		{"release-failed", "core-release-unsettled", func(f *fixture) { f.releaseErr = errors.New(testPrivate) }, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, "HTTP/2")
			tc.change(f)
			result := run(context.Background(), f.r, f, f.io)
			if result.Status != "failed" || result.Code != tc.code || has(f, "remove-secret") != tc.remove || has(f, "release") != tc.release || !has(f, "close-stage") {
				t.Fatalf("%+v, %v", result, f.events)
			}
			if !tc.remove && result.SecretCleanup != "retained" {
				t.Fatal("secret deleted before exact settlement")
			}
		})
	}
}

func TestRunCancellationKeepsOriginalBoundedCleanupGrant(t *testing.T) {
	type key struct{}
	parent, cancel := context.WithCancel(context.WithValue(context.Background(), key{}, "original-value"))
	defer cancel()
	f := newFixture(t, "HTTP/2")
	f.probeHook = func(ctx context.Context) error {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > f.r.Timeout || ctx.Value(key{}) != "original-value" {
			t.Fatal("check lost original bounded context")
		}
		cancel()
		return ctx.Err()
	}
	f.cleanupHook = func(ctx context.Context) {
		deadline, ok := ctx.Deadline()
		if ctx.Err() != nil || !ok || time.Until(deadline) > f.r.CleanupTimeout || ctx.Value(key{}) != "original-value" {
			t.Fatal("cleanup is not original bounded retained grant")
		}
	}
	result := run(parent, f.r, f, f.io)
	if result.Code != "owned-producer-refused" || result.Settlement != "settled" || result.SecretCleanup != "removed" || f.acquires != 1 {
		t.Fatalf("%+v, %v", result, f.events)
	}
}

func TestRunLaunchCannotRewriteExpectedArgs(t *testing.T) {
	f := newFixture(t, "HTTP/2")
	f.startHook = func(ctx context.Context, launch Launch) error {
		launch.Process.Args[len(launch.Process.Args)-1] = "--unapproved"
		// Simulate the actual child using mutated argv; local expected args must
		// remain frozen, so the independently observed identity cannot be adopted.
		f.launch.Process.Args = append([]string(nil), launch.Process.Args...)
		return nil
	}
	result := run(context.Background(), f.r, f, f.io)
	if result.Code != "independent-readback-refused" || result.Status != "failed" {
		t.Fatalf("%+v", result)
	}
}
