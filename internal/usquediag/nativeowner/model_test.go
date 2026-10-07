package nativeowner

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/routeidentity"
	"github.com/ArtixSx/razvilka/internal/systemprobe"
	"github.com/ArtixSx/razvilka/internal/usquediag/nativeaccept"
)

// Pure fixtures only: synthetic CORE authority, descriptors, child and receipts
// are never connected to production IO, serialized as grants or saved to disk.
type ownerFixture struct {
	ctx                                  context.Context
	cancel                               context.CancelFunc
	acquisition                          nativeaccept.Acquisition
	helper                               HelperAsset
	scope                                Scope
	launch                               nativeaccept.Launch
	events                               []string
	lease                                *ownerLease
	facts                                *ownerFacts
	session                              *ownerProcess
	prepareErr, acquireErr, errorCurrent error
	withStart                            func(func() error) error
	currentHook                          func()
}
type ownerPlatform struct{ f *ownerFixture }

func (p ownerPlatform) acquire(ctx context.Context, a nativeaccept.Acquisition, h HelperAsset) (scopeFacts, error) {
	p.f.events = append(p.f.events, "kernel-acquire")
	deadline, _ := ctx.Deadline()
	p.f.scope = Scope{Acquisition: a, Namespace: Namespace{Device: 1, Inode: 2}, Parent: components.NFQWSRuntimeProcessIdentity{PID: 100, BootID: "test-only-boot", Start: "1"}, Helper: h, Deadline: deadline}
	return p.f.facts, nil
}

type ownerFacts struct {
	f       *ownerFixture
	changed bool
}

func (f *ownerFacts) Scope() Scope { return f.f.scope }
func (f *ownerFacts) Current(context.Context) error {
	f.f.events = append(f.f.events, "kernel-current")
	if f.changed {
		return ErrOwned
	}
	return nil
}
func (f *ownerFacts) Prepare(ctx context.Context, l nativeaccept.Launch, c Control) (processSession, error) {
	f.f.events = append(f.f.events, "held-assets")
	f.f.session.launch = cloneLaunch(l)
	return f.f.session, f.f.prepareErr
}
func (f *ownerFacts) Close() error { f.f.events = append(f.f.events, "close-scope"); return nil }

type ownerLease struct {
	f                        *ownerFixture
	fences, releases, starts int
}

func (l *ownerLease) Current(ctx context.Context) error {
	l.f.events = append(l.f.events, "core-current")
	if l.f.currentHook != nil {
		l.f.currentHook()
	}
	return errors.Join(l.f.errorCurrent, ctx.Err(), l.f.ctx.Err())
}
func (l *ownerLease) WithStart(ctx context.Context, launch nativeaccept.Launch, begin func() error) error {
	l.f.events = append(l.f.events, "held-core-start")
	if l.f.withStart != nil {
		return l.f.withStart(begin)
	}
	return begin()
}
func (l *ownerLease) WithEffectStart(context.Context, string, func() error) error {
	panic("pure process fixture must not start a real helper")
}
func (l *ownerLease) Control(ctx context.Context) (Control, error) {
	return Control{Root: filepath.Join(l.f.acquisition.Request.WorkParent, "test-only-control"), TransactionID: strings.Repeat("a", 32), InstallationID: strings.Repeat("b", 32), Sequence: 1}, ctx.Err()
}
func (l *ownerLease) Release(ctx context.Context) error {
	l.f.events = append(l.f.events, "core-release")
	l.releases++
	return ctx.Err()
}
func (l *ownerLease) FenceUnsettled() { l.f.events = append(l.f.events, "core-fence"); l.fences++ }
func (l *ownerLease) WithCleanup(ctx context.Context, use func() error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return use()
}
func (f *ownerFixture) Acquire(ctx context.Context, s Scope) (OriginalLease, error) {
	f.events = append(f.events, "core-acquire")
	if s != f.scope {
		panic("actual scope changed")
	}
	return f.lease, f.acquireErr
}

type ownerProcess struct {
	f                                        *ownerFixture
	launch                                   nativeaccept.Launch
	starts                                   int
	startErr, stopErr, verifyErr, releaseErr error
	currentChanged                           bool
	startHook                                func()
	stopped, verified                        bool
}

func (p *ownerProcess) Start(ctx context.Context, lease OriginalLease) error {
	p.f.events = append(p.f.events, "actual-process-start")
	p.starts++
	if p.startHook != nil {
		p.startHook()
	}
	return errors.Join(p.startErr, ctx.Err())
}
func (p *ownerProcess) Current(ctx context.Context) error {
	p.f.events = append(p.f.events, "actual-process-leaf")
	if p.currentChanged {
		return ErrOwned
	}
	return ctx.Err()
}
func (p *ownerProcess) StopAndJoin(ctx context.Context) error {
	p.f.events = append(p.f.events, "exact-stop-join")
	p.stopped = p.stopErr == nil
	return errors.Join(p.stopErr, ctx.Err())
}
func (p *ownerProcess) VerifySettled(ctx context.Context) error {
	p.f.events = append(p.f.events, "exact-echild-ack-verify")
	if !p.stopped {
		return ErrOwned
	}
	p.verified = p.verifyErr == nil
	return errors.Join(p.verifyErr, ctx.Err())
}
func (p *ownerProcess) ReleaseAssets(ctx context.Context) error {
	p.f.events = append(p.f.events, "remove-owned-metadata-close-assets")
	if !p.verified {
		return ErrOwned
	}
	return errors.Join(p.releaseErr, ctx.Err())
}

func fixtureOwner(t *testing.T) *ownerFixture {
	t.Helper()
	base := t.TempDir()
	f := &ownerFixture{}
	f.ctx, f.cancel = context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(f.cancel)
	r := nativeaccept.Request{Enabled: true, Transport: "HTTP/2", Binary: filepath.Join(base, "usque"), BinarySHA256: "a3ad4dce52cc33825fd8bfab520bb2a03f80891b69920819aa391d6a42c6bf10", Account: filepath.Join(base, "existing-test-only-account"), AccountSHA256: strings.Repeat("c", 64), WorkParent: filepath.Join(base, "private"), SOCKSPort: 19080, Timeout: 20 * time.Second, CleanupTimeout: 5 * time.Second}
	f.acquisition = nativeaccept.Acquisition{Request: r, Network: systemprobe.WANProfile{ID: "wan-123456789abc", WANInterface: "test-only-wan"}}
	f.helper = HelperAsset{Path: filepath.Join(base, "test-only-supervisor"), SHA256: strings.Repeat("d", 64)}
	f.facts = &ownerFacts{f: f}
	f.lease = &ownerLease{f: f}
	f.session = &ownerProcess{f: f}
	dir := filepath.Join(r.WorkParent, "test-only-stage")
	f.launch = nativeaccept.Launch{BinarySHA256: r.BinarySHA256, ConfigSHA256: r.AccountSHA256, Endpoint: netip.MustParseAddrPort("162.159.193.11:443"), Transport: r.Transport, Environment: strings.Repeat("e", 64), ProcessEnvironment: []string{"LANG=C", "HTTP_PROXY=", "HTTPS_PROXY=", "ALL_PROXY=", "http_proxy=", "https_proxy=", "all_proxy=", "NO_PROXY=", "no_proxy="}}
	f.launch.Process.ID = "usque-canary"
	f.launch.Process.Binary = r.Binary
	f.launch.Process.Dir = dir
	f.launch.Process.RouteProof = true
	f.launch.Process.MatchArg = filepath.Join(dir, "engine.json")
	f.launch.Process.PIDPath = filepath.Join(dir, "engine.pid")
	f.launch.Process.LogPath = filepath.Join(dir, "engine.log")
	f.launch.Process.Args = []string{"-c", f.launch.Process.MatchArg, "socks", "-b", "127.0.0.1", "-p", "19080", "--always-reconnect", "-S", "--http2"}
	return f
}
func (f *ownerFixture) issuer() *issuer {
	return &issuer{original: f, helper: f.helper, platform: ownerPlatform{f}}
}
func (f *ownerFixture) execution(t *testing.T) nativeaccept.Execution {
	t.Helper()
	e, err := f.issuer().Acquire(f.ctx, f.acquisition)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestOwnerOriginalLeaseRequiredBeforeAnyIO(t *testing.T) {
	f := fixtureOwner(t)
	if owner, err := NewIssuer(nil, f.helper); err == nil || owner != nil {
		t.Fatal("missing original CORE lease became authority")
	}
	ctx, cancel := context.WithCancel(f.ctx)
	cancel()
	if e, err := f.issuer().Acquire(ctx, f.acquisition); err == nil || e != nil || len(f.events) != 0 {
		t.Fatal("canceled acquisition touched owner")
	}
	if e, err := f.issuer().Acquire(context.Background(), f.acquisition); err == nil || e != nil || len(f.events) != 0 {
		t.Fatal("unbounded acquisition touched owner")
	}
}

func TestOwnerOneUseFrozenLaunchAndVerifiedRelease(t *testing.T) {
	f := fixtureOwner(t)
	e := f.execution(t)
	if e.Start(f.ctx, f.launch) != nil {
		t.Fatal("original admitted start failed")
	}
	f.launch.Process.Args[0] = "TEST-ONLY-CHANGED"
	if f.session.launch.Process.Args[0] != "-c" {
		t.Fatal("held launch aliased caller")
	}
	if e.Start(f.ctx, f.launch) == nil || f.session.starts != 1 {
		t.Fatal("start replay admitted")
	}
	if e.Release(f.ctx) == nil || f.lease.releases != 0 {
		t.Fatal("release before settlement")
	}
	if e.StopAndJoin(f.ctx) != nil || e.VerifySettled(f.ctx) != nil || e.Release(f.ctx) != nil || f.lease.releases != 1 {
		t.Fatalf("settlement order %v", f.events)
	}
	if e.Current(f.ctx) == nil || e.Start(f.ctx, f.launch) == nil {
		t.Fatal("released execution renewed authority")
	}
}

func TestOwnerInvalidExactCommandNeverStarts(t *testing.T) {
	for _, change := range []func(*nativeaccept.Launch){func(l *nativeaccept.Launch) { l.Process.Args = append(l.Process.Args, "--register") }, func(l *nativeaccept.Launch) { l.Process.RouteProof = false }, func(l *nativeaccept.Launch) { l.ConfigSHA256 = strings.Repeat("f", 64) }, func(l *nativeaccept.Launch) {
		l.ProcessEnvironment = append(l.ProcessEnvironment, "HTTPS_PROXY=TEST-ONLY-PRIVATE")
	}, func(l *nativeaccept.Launch) { l.Transport = "QUIC" }} {
		f := fixtureOwner(t)
		e := f.execution(t)
		change(&f.launch)
		if e.Start(f.ctx, f.launch) == nil || f.session.starts != 0 {
			t.Fatal("unreviewed command started")
		}
		if e.Start(f.ctx, fixtureOwner(t).launch) == nil {
			t.Fatal("failed attempt renewed Start")
		}
	}
}

func TestOwnerRetainedBeginCannotReplayOrSwallowExceptionalOutcome(t *testing.T) {
	for _, mode := range []string{"no-begin", "swallowed-error", "twice-swallowed", "panic", "saved-late", "reentrant"} {
		t.Run(mode, func(t *testing.T) {
			f := fixtureOwner(t)
			e := f.execution(t)
			var saved func() error
			f.withStart = func(begin func() error) error {
				saved = begin
				switch mode {
				case "no-begin":
					return nil
				case "swallowed-error":
					f.session.startErr = ErrOwned
					_ = begin()
					return nil
				case "twice-swallowed":
					_ = begin()
					_ = begin()
					return nil
				case "panic":
					f.session.startHook = func() { panic("TEST-ONLY-PRIVATE") }
					return begin()
				case "reentrant":
					f.session.startHook = func() { _ = begin() }
					return begin()
				default:
					return begin()
				}
			}
			err := e.Start(f.ctx, f.launch)
			if mode == "saved-late" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("exceptional/swallowed start became success")
			}
			if saved == nil || saved() == nil || f.session.starts > 1 {
				t.Fatal("saved begin replayed")
			}
		})
	}
}

func TestOwnerClosingOriginalCallbackCannotReplaceFactsOrChild(t *testing.T) {
	for _, child := range []bool{false, true} {
		f := fixtureOwner(t)
		e := f.execution(t)
		if e.Start(f.ctx, f.launch) != nil {
			t.Fatal("start failed")
		}
		f.currentHook = func() {
			if child {
				f.session.currentChanged = true
			} else {
				f.facts.changed = true
			}
		}
		if e.Current(f.ctx) == nil {
			t.Fatal("closing original callback drift adopted")
		}
	}
}

func TestOwnerUnsettledChildRetainsOriginalFenceAndAssets(t *testing.T) {
	for _, failure := range []string{"stop", "echild-ack", "assets"} {
		t.Run(failure, func(t *testing.T) {
			f := fixtureOwner(t)
			e := f.execution(t)
			if e.Start(f.ctx, f.launch) != nil {
				t.Fatal("start failed")
			}
			switch failure {
			case "stop":
				f.session.stopErr = ErrOwned
			case "echild-ack":
				f.session.verifyErr = ErrOwned
			case "assets":
				f.session.releaseErr = ErrOwned
			}
			_ = e.StopAndJoin(f.ctx)
			_ = e.VerifySettled(f.ctx)
			if e.Release(f.ctx) == nil || f.lease.releases != 0 || f.lease.fences == 0 {
				t.Fatal("unknown child/asset outcome released original lease")
			}
			if e.Start(f.ctx, f.launch) == nil {
				t.Fatal("cleanup renewed start")
			}
		})
	}
}

func TestOwnerCleanupAfterOriginalCancelUsesSameObject(t *testing.T) {
	f := fixtureOwner(t)
	e := f.execution(t)
	if e.Start(f.ctx, f.launch) != nil {
		t.Fatal("start failed")
	}
	f.cancel()
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(f.ctx), time.Second)
	defer cancel()
	if e.Current(cleanup) == nil {
		t.Fatal("expired forward context renewed")
	}
	if e.StopAndJoin(cleanup) != nil || e.VerifySettled(cleanup) != nil || e.Release(cleanup) != nil || f.lease.releases != 1 {
		t.Fatalf("same original cleanup failed %v", f.events)
	}
}

func TestOwnerBoundedStopCannotOvertakeActualStart(t *testing.T) {
	f := fixtureOwner(t)
	e := f.execution(t)
	entered, finish := make(chan struct{}), make(chan struct{})
	f.session.startHook = func() { close(entered); <-finish }
	done := make(chan error, 1)
	go func() { done <- e.Start(f.ctx, f.launch) }()
	<-entered
	short, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if e.StopAndJoin(short) == nil {
		t.Fatal("Stop overtook original held Start")
	}
	close(finish)
	if <-done != nil {
		t.Fatal("start failed")
	}
	if f.lease.fences == 0 {
		t.Fatal("timed-out close did not retain fence")
	}
}

func TestOwnerTerminalRequiresExactKernelECHILDAndChild(t *testing.T) {
	f := fixtureOwner(t)
	_ = f.execution(t)
	control, _ := f.lease.Control(f.ctx)
	o := offer{Version: 1, Scope: f.scope, Launch: f.launch, Control: control}
	h := components.NFQWSSupervisionIdentity{PID: 200, Group: 200, BootID: f.scope.Parent.BootID, Start: "2"}
	c := components.NFQWSRuntimeProcessIdentity{PID: 201, ParentPID: 200, Group: 201, BootID: h.BootID, Start: "3", Executable: f.launch.Process.Binary, ArgumentsSHA256: components.NFQWSRuntimeArgumentsSHA256(f.launch.Process.Binary, f.launch.Process.Args)}
	r := components.NFQWSSupervisionReceipt{State: "reaped", PID: h.PID, Group: h.Group, BootID: h.BootID, Start: h.Start, ChildPID: c.PID, CommandSHA256: o.digest(), Started: true, DirectReaped: true, WaitECHILD: true, Reaped: 1, ExitCode: 125, Cancelled: true}
	if !terminalMatches(o, h, c, r) {
		t.Fatal("exact kernel fixture rejected")
	}
	for _, change := range []func(*components.NFQWSSupervisionReceipt){func(r *components.NFQWSSupervisionReceipt) { r.WaitECHILD = false }, func(r *components.NFQWSSupervisionReceipt) { r.DirectReaped = false }, func(r *components.NFQWSSupervisionReceipt) { r.CommandSHA256 = strings.Repeat("f", 64) }, func(r *components.NFQWSSupervisionReceipt) { r.ChildPID++ }, func(r *components.NFQWSSupervisionReceipt) { r.Reaped = 0 }} {
		bad := r
		change(&bad)
		if terminalMatches(o, h, c, bad) {
			t.Fatal("forged/partial terminal accepted")
		}
	}
	c.ParentPID++
	if terminalMatches(o, h, c, r) {
		t.Fatal("foreign child accepted")
	}
}

func TestOwnerWireRejectsDuplicateUnknownAndOversizedFrames(t *testing.T) {
	valid := frame{Version: 1, Kind: "permit", Binding: routeidentity.Hash([]byte("TEST-ONLY-BINDING"))}
	raw, _ := json.Marshal(valid)
	if _, err := decodeFrame(raw); err != nil {
		t.Fatal(err)
	}
	for _, raw := range [][]byte{[]byte(`{"Version":1,"Version":1,"Kind":"permit","Binding":"` + valid.Binding + `"}`), []byte(`{"Version":1,"Kind":"permit","Binding":"` + valid.Binding + `","Account":"TEST-ONLY-PRIVATE"}`), append(raw, []byte(" {}")...), []byte(strings.Repeat("x", frameLimit+1))} {
		if _, err := decodeFrame(raw); err == nil {
			t.Fatal("ambiguous/unbounded frame accepted")
		}
	}
}
