package nativeowner

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/routeidentity"
	"github.com/ArtixSx/razvilka/internal/systemprobe"
	"github.com/ArtixSx/razvilka/internal/usquediag/nativeaccept"
)

type platform interface {
	acquire(context.Context, nativeaccept.Acquisition, HelperAsset) (scopeFacts, error)
}
type scopeFacts interface {
	Scope() Scope
	Current(context.Context) error
	Prepare(context.Context, nativeaccept.Launch, Control) (processSession, error)
	Close() error
}
type processSession interface {
	Start(context.Context, OriginalLease) error
	Current(context.Context) error
	StopAndJoin(context.Context) error
	VerifySettled(context.Context) error
	ReleaseAssets(context.Context) error
}

type issuer struct {
	original OriginalFactory
	helper   HelperAsset
	platform platform
}

func (i *issuer) Acquire(ctx context.Context, a nativeaccept.Acquisition) (nativeaccept.Execution, error) {
	if ctx == nil || ctx.Err() != nil || nativeaccept.ValidateOwnerRequest(a.Request) != nil || !systemprobe.ValidWANProfileID(a.Network.ID) || a.Network.WANInterface == "" {
		return nil, ErrOwned
	}
	deadline, ok := ctx.Deadline()
	if !ok || !time.Now().Before(deadline) || deadline.After(time.Now().Add(30*time.Second)) {
		return nil, ErrOwned
	}
	facts, err := i.platform.acquire(ctx, a, i.helper)
	if err != nil {
		if facts != nil {
			_ = facts.Close()
		}
		return nil, ErrOwned
	}
	scope := facts.Scope()
	if scope.Acquisition != a || scope.Helper != i.helper || scope.Deadline != deadline || scope.Namespace.Inode == 0 || scope.Parent.PID <= 1 {
		_ = facts.Close()
		return nil, ErrOwned
	}
	original, err := i.original.Acquire(ctx, scope)
	if original == nil {
		_ = facts.Close()
		return nil, ErrOwned
	}
	e := &execution{scope: scope, facts: facts, original: original, gate: make(chan struct{}, 1)}
	e.gate <- struct{}{}
	if retained, ok := original.(interface{ retainExecution(*execution) }); ok {
		retained.retainExecution(e)
	}
	if err != nil || e.Current(ctx) != nil {
		return e, ErrOwned
	}
	return e, nil
}

type execution struct {
	mu                                        sync.Mutex
	gate                                      chan struct{}
	scope                                     Scope
	facts                                     scopeFacts
	original                                  OriginalLease
	session                                   processSession
	used, sealed, settled, verified, released bool
}

func (e *execution) lock(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrOwned
	}
	select {
	case <-ctx.Done():
		return ErrOwned
	case <-e.gate:
		return nil
	}
}
func (e *execution) unlock() { e.gate <- struct{}{} }

func (e *execution) Current(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrOwned
	}
	ctx, cancel := context.WithDeadline(ctx, e.scope.Deadline)
	defer cancel()
	e.mu.Lock()
	closed := e.sealed || e.released
	session := e.session
	e.mu.Unlock()
	if closed || e.original.Current(ctx) != nil || e.facts.Current(ctx) != nil || e.original.Current(ctx) != nil {
		return ErrOwned
	}
	// Actual facts are the closing leaf after external CORE callbacks.
	if e.facts.Current(ctx) != nil || session != nil && session.Current(ctx) != nil || ctx.Err() != nil {
		return ErrOwned
	}
	return nil
}

func (e *execution) Start(ctx context.Context, launch nativeaccept.Launch) (err error) {
	if ctx == nil {
		return ErrOwned
	}
	ctx, cancel := context.WithDeadline(ctx, e.scope.Deadline)
	defer cancel()
	if e.lock(ctx) != nil {
		return ErrOwned
	}
	defer e.unlock()
	e.mu.Lock()
	if e.used || e.sealed || e.released {
		e.mu.Unlock()
		return ErrOwned
	}
	e.used = true // consume before callbacks/IO, including partial/panic outcomes
	e.mu.Unlock()
	defer func() {
		if recover() != nil {
			err = ErrOwned
			e.original.FenceUnsettled()
		}
	}()
	launch = cloneLaunch(launch)
	if !launchMatches(e.scope, launch) || e.Current(ctx) != nil {
		return ErrOwned
	}
	control, err := e.original.Control(ctx)
	if err != nil || !controlShape(control) || e.Current(ctx) != nil {
		return ErrOwned
	}
	session, prepareErr := e.facts.Prepare(ctx, launch, control)
	e.mu.Lock()
	e.session = session
	e.mu.Unlock()
	if prepareErr != nil || session == nil {
		return ErrOwned
	}
	once := startOnce{open: true, begin: func() error { return session.Start(ctx, e.original) }}
	err = once.invoke(func(begin func() error) error { return e.original.WithStart(ctx, cloneLaunch(launch), begin) })
	if err != nil || e.Current(ctx) != nil {
		return ErrOwned
	}
	return nil
}

func (e *execution) StopAndJoin(ctx context.Context) error {
	if ctx == nil {
		return ErrOwned
	}
	ctx, cancel := context.WithTimeout(ctx, e.scope.Acquisition.Request.CleanupTimeout)
	defer cancel()
	if e.lock(ctx) != nil {
		e.original.FenceUnsettled()
		return ErrOwned
	}
	defer e.unlock()
	e.mu.Lock()
	e.sealed = true
	s := e.session
	released := e.released
	e.mu.Unlock()
	if released {
		return ErrOwned
	}
	if e.original.WithCleanup(ctx, func() error {
		if s != nil {
			return s.StopAndJoin(ctx)
		}
		return ctx.Err()
	}) != nil {
		e.original.FenceUnsettled()
		return ErrOwned
	}
	if ctx.Err() != nil {
		e.original.FenceUnsettled()
		return ErrOwned
	}
	e.mu.Lock()
	e.settled = true
	e.mu.Unlock()
	return nil
}

func (e *execution) VerifySettled(ctx context.Context) error {
	if ctx == nil {
		return ErrOwned
	}
	ctx, cancel := context.WithTimeout(ctx, e.scope.Acquisition.Request.CleanupTimeout)
	defer cancel()
	if e.lock(ctx) != nil {
		return ErrOwned
	}
	defer e.unlock()
	e.mu.Lock()
	allowed := e.sealed && e.settled && !e.released
	s := e.session
	e.mu.Unlock()
	if !allowed || ctx.Err() != nil || e.original.WithCleanup(ctx, func() error {
		if s != nil {
			return s.VerifySettled(ctx)
		}
		return nil
	}) != nil {
		e.original.FenceUnsettled()
		return ErrOwned
	}
	e.mu.Lock()
	e.verified = true
	e.mu.Unlock()
	return nil
}

func (e *execution) Release(ctx context.Context) error {
	if ctx == nil {
		return ErrOwned
	}
	ctx, cancel := context.WithTimeout(ctx, e.scope.Acquisition.Request.CleanupTimeout)
	defer cancel()
	if e.lock(ctx) != nil {
		return ErrOwned
	}
	defer e.unlock()
	e.mu.Lock()
	allowed := e.sealed && e.settled && e.verified && !e.released
	s := e.session
	e.mu.Unlock()
	if !allowed || e.original.WithCleanup(ctx, func() error {
		if s != nil && (s.VerifySettled(ctx) != nil || s.ReleaseAssets(ctx) != nil) {
			return ErrOwned
		}
		return e.facts.Close()
	}) != nil || ctx.Err() != nil {
		e.original.FenceUnsettled()
		return ErrOwned
	}
	if e.original.Release(ctx) != nil {
		e.original.FenceUnsettled()
		return ErrOwned
	}
	e.mu.Lock()
	e.released = true
	e.mu.Unlock()
	return nil
}

// Saved/reentrant/late begin and swallowed error/panic cannot create success.
type startOnce struct {
	mu                 sync.Mutex
	open, used, poison bool
	begin              func() error
	outcome            error
	done               chan struct{}
}

func (o *startOnce) run() (err error) {
	o.mu.Lock()
	if !o.open || o.begin == nil {
		o.mu.Unlock()
		return ErrOwned
	}
	if o.used {
		o.poison = true
		o.mu.Unlock()
		return ErrOwned
	}
	o.used = true
	o.outcome = ErrOwned
	o.done = make(chan struct{})
	o.mu.Unlock()
	completed := false
	defer func() {
		o.mu.Lock()
		defer o.mu.Unlock()
		if !completed || o.poison {
			err = errors.Join(err, ErrOwned)
		}
		if err == nil {
			o.outcome = nil
		} else {
			o.outcome = err
		}
		close(o.done)
	}()
	// A panic must retain the preset unknown outcome while still joining the
	// callback. The outer Start boundary converts the panic to a retained error.
	err = o.begin()
	completed = true
	return err
}
func (o *startOnce) invoke(action func(func() error) error) (err error) {
	defer func() {
		o.mu.Lock()
		o.open = false
		done := o.done
		o.mu.Unlock()
		if done != nil {
			<-done
		}
		o.mu.Lock()
		defer o.mu.Unlock()
		if o.poison {
			err = errors.Join(err, ErrOwned)
		}
		if !o.used {
			err = errors.Join(err, ErrOwned)
		} else {
			err = errors.Join(err, o.outcome)
		}
	}()
	return action(o.run)
}

func cloneLaunch(l nativeaccept.Launch) nativeaccept.Launch {
	l.Process.Args = append([]string(nil), l.Process.Args...)
	l.ProcessEnvironment = append([]string(nil), l.ProcessEnvironment...)
	return l
}
func hexShape(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func pathShape(s string) bool {
	return filepath.IsAbs(s) && filepath.Clean(s) == s && !strings.ContainsAny(s, "\x00\r\n") && len(s) <= 4096 && s != filepath.VolumeName(s)+string(filepath.Separator)
}
func assetShape(a HelperAsset) bool { return pathShape(a.Path) && hexShape(a.SHA256, 64) }
func controlShape(c Control) bool {
	return pathShape(c.Root) && hexShape(c.TransactionID, 32) && hexShape(c.InstallationID, 32) && c.Sequence > 0
}
func launchMatches(scope Scope, l nativeaccept.Launch) bool {
	r := scope.Acquisition.Request
	p := l.Process
	if nativeaccept.ValidateOwnerRequest(r) != nil || p.ID != "usque-canary" || !p.RouteProof || p.Binary != r.Binary || l.BinarySHA256 != r.BinarySHA256 || l.ConfigSHA256 != r.AccountSHA256 || l.Transport != r.Transport || !hexShape(l.Environment, 64) ||
		!pathShape(p.Dir) || filepath.Dir(p.Dir) != r.WorkParent || p.MatchArg != filepath.Join(p.Dir, "engine.json") || p.PIDPath != filepath.Join(p.Dir, "engine.pid") || p.LogPath != filepath.Join(p.Dir, "engine.log") || !l.Endpoint.IsValid() || l.Endpoint.Port() != 443 || !l.Endpoint.Addr().Is4() {
		return false
	}
	want := []string{"-c", p.MatchArg, "socks", "-b", "127.0.0.1", "-p", strconv.Itoa(int(r.SOCKSPort)), "--always-reconnect", "-S"}
	if r.Transport == "HTTP/2" {
		want = append(want, "--http2")
	}
	env := []string{"LANG=C", "HTTP_PROXY=", "HTTPS_PROXY=", "ALL_PROXY=", "http_proxy=", "https_proxy=", "all_proxy=", "NO_PROXY=", "no_proxy="}
	return reflect.DeepEqual(p.Args, want) && reflect.DeepEqual(l.ProcessEnvironment, env)
}

type offer struct {
	Version int
	Scope   Scope
	Launch  nativeaccept.Launch
	Control Control
}

func (o offer) digest() string {
	raw, err := json.Marshal(o)
	if err != nil {
		return ""
	}
	return routeidentity.Hash(raw)
}

func terminalMatches(o offer, helper components.NFQWSSupervisionIdentity, child components.NFQWSRuntimeProcessIdentity, r components.NFQWSSupervisionReceipt) bool {
	if helper.PID <= 1 || helper.Group != helper.PID || helper.BootID != o.Scope.Parent.BootID || !positive(helper.Start) || r.BootID != helper.BootID || r.Start != helper.Start || r.PID != helper.PID || r.Group != helper.Group || r.CommandSHA256 != o.digest() || !r.WaitECHILD {
		return false
	}
	if r.State == "not-started" {
		return !r.Started && !r.DirectReaped && r.ChildPID == 0 && r.Reaped == 0 && child.PID == 0 && r.ExitCode == 125
	}
	return r.State == "reaped" && r.Started && r.DirectReaped && r.Reaped >= 1 && r.ChildPID == child.PID && childMatches(o, helper, child)
}
func childMatches(o offer, h components.NFQWSSupervisionIdentity, c components.NFQWSRuntimeProcessIdentity) bool {
	return c.PID > 1 && c.ParentPID == h.PID && c.Group == c.PID && c.BootID == h.BootID && positive(c.Start) && c.Executable == o.Launch.Process.Binary && c.ArgumentsSHA256 == components.NFQWSRuntimeArgumentsSHA256(o.Launch.Process.Binary, o.Launch.Process.Args)
}
func positive(s string) bool {
	n, err := strconv.ParseUint(s, 10, 64)
	return err == nil && n > 0 && strconv.FormatUint(n, 10) == s
}
