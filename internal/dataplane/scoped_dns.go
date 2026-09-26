package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sync"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

// ScopedDNSAdapter participates in Manager.Apply, including its journal,
// health barrier and reverse rollback. It has no independent scheduler.
// Register only after the platform redirect and client acceptance tests pass.
type ScopedDNSAdapter struct {
	DNS          *dnscontrol.Manager
	StateRoot    string
	Runner       NFQWS2Runner
	IPTables     string
	FreshProfile func(context.Context) (string, error)
	// ScopeCheck must verify the exact gateway, ingress and every client.
	ScopeCheck  func(context.Context, ScopedDNSPlan) error
	HealthProbe func(context.Context, *dnscontrol.ScopedDNSResolver, Plan) error
	lifetime    context.Context
	mu          sync.Mutex
	live        *scopedDNSSession
	listen      func(netip.AddrPort) (*net.UDPConn, *net.TCPListener, error)
}

type scopedDNSSession struct {
	state    scopedDNSState
	resolver *dnscontrol.ScopedDNSResolver
	cancel   context.CancelFunc
	done     chan struct{}
}

type scopedDNSState struct {
	Network string         `json:"network"`
	DNS     *ScopedDNSPlan `json:"dns"`
	Routes  []Route        `json:"routes"`
}

type scopedDNSSnapshot struct {
	State  *scopedDNSState `json:"state"`
	Active bool            `json:"active"`
}

func NewScopedDNSAdapter(lifetime context.Context, manager *dnscontrol.Manager, stateRoot string) *ScopedDNSAdapter {
	return &ScopedDNSAdapter{DNS: manager, StateRoot: filepath.Join(stateRoot, scopedDNSAdapterID), Runner: nfqws2ExecRunner{}, IPTables: "iptables", FreshProfile: observeNetworkProfile, lifetime: lifetime}
}

func (a *ScopedDNSAdapter) ID() string { return scopedDNSAdapterID }

func (a *ScopedDNSAdapter) readState(path string) (*scopedDNSState, error) {
	var s scopedDNSState
	data, err := readScopedDNSFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if json.Unmarshal(data, &s) != nil || s.DNS == nil || validateScopedDNSPlan(s.DNS, s.Routes) != nil {
		return nil, errors.New("invalid scoped DNS ownership record")
	}
	return &s, nil
}

func readScopedDNSFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 128<<10 {
		return nil, errors.New("invalid scoped DNS record")
	}
	return os.ReadFile(path)
}

func writeScopedDNSFile(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(data) > 128<<10 {
		return errors.New("scoped DNS record too large")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return writeAtomic(path, data, 0600)
}

func (a *ScopedDNSAdapter) statePath() string { return filepath.Join(a.StateRoot, "owner.json") }

func (a *ScopedDNSAdapter) Snapshot(ctx context.Context, p Plan, root string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	state, err := a.readState(a.statePath())
	if err != nil {
		return err
	}
	if a.live != nil && (state == nil || !sameScopedDNSState(*state, a.live.state)) {
		return errors.New("scoped DNS runtime disagrees with ownership record")
	}
	active := a.live != nil && dnsSessionAlive(a.live)
	if state != nil {
		if !active {
			return errors.New("scoped DNS owner requires cleanup before applying")
		}
		if err := a.readbackRules(ctx, state.DNS, true); err != nil {
			return err
		}
	}
	return writeScopedDNSFile(filepath.Join(root, "snapshot.json"), scopedDNSSnapshot{state, active})
}

func (a *ScopedDNSAdapter) Stage(ctx context.Context, p Plan, root string) error {
	if err := a.validate(ctx, p); err != nil {
		return preflightRefusalError{err}
	}
	return writeScopedDNSFile(filepath.Join(root, "candidate.json"), scopedDNSState{p.NetworkProfileID, p.DNS, p.Routes})
}

func (a *ScopedDNSAdapter) Validate(ctx context.Context, p Plan, root string) error {
	s, err := a.readState(filepath.Join(root, "candidate.json"))
	if err != nil {
		return err
	}
	if s == nil || !sameScopedDNSState(*s, scopedDNSState{p.NetworkProfileID, p.DNS, p.Routes}) {
		return ErrReviewChanged
	}
	return a.validate(ctx, p)
}

func (a *ScopedDNSAdapter) validate(ctx context.Context, p Plan) error {
	if a.DNS == nil || a.lifetime == nil || a.ScopeCheck == nil || a.HealthProbe == nil || p.DNS == nil {
		return errors.New("scoped DNS executor is not configured")
	}
	if err := errors.Join(ctx.Err(), a.lifetime.Err(), validateScopedDNSPlan(p.DNS, p.Routes)); err != nil {
		return err
	}
	if err := a.ScopeCheck(ctx, *p.DNS); err != nil {
		return err
	}
	if err := verifyNetworkProfile(ctx, p.NetworkProfileID, a.FreshProfile); err != nil {
		return err
	}
	for _, b := range p.DNS.Bindings {
		identity, err := a.DNS.ScopedProfileIdentity(b.ProfileID)
		if err != nil || identity != b.ProfileDigest {
			return dnscontrol.ErrServiceDNSChanged
		}
	}
	return nil
}

func (a *ScopedDNSAdapter) Activate(ctx context.Context, p Plan, root string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.Validate(ctx, p, root); err != nil {
		return preflightRefusalError{err}
	}
	if err := a.stopLocked(ctx); err != nil {
		return err
	}
	return a.startLocked(ctx, scopedDNSState{p.NetworkProfileID, p.DNS, p.Routes})
}

func (a *ScopedDNSAdapter) startLocked(ctx context.Context, s scopedDNSState) error {
	// Own an immutable JSON-normalized copy; callers may reuse their input
	// slices, and omitted empty slices must compare equally after disk readback.
	encoded, err := json.Marshal(s)
	if err != nil {
		return err
	}
	var owned scopedDNSState
	if err := json.Unmarshal(encoded, &owned); err != nil {
		return err
	}
	s = owned
	if err := a.readbackRules(ctx, s.DNS, false); err != nil {
		return err
	}
	bindings := make([]dnscontrol.ClientDNSBinding, 0, len(s.DNS.Bindings))
	for _, b := range s.DNS.Bindings {
		bindings = append(bindings, dnscontrol.ClientDNSBinding{Client: netip.MustParseAddr(b.Client), Domain: b.Domain, ProfileID: b.ProfileID})
	}
	guard := func(c context.Context) error { return verifyNetworkProfile(c, s.Network, a.FreshProfile) }
	r, err := a.DNS.NewScopedDNSResolver(bindings, guard)
	if err != nil {
		return err
	}
	if err := r.UseLocalBaseline(netip.MustParseAddrPort("127.0.0.1:53")); err != nil {
		return err
	}
	endpoint := netip.MustParseAddrPort(s.DNS.Listener)
	listen := a.listen
	if listen == nil {
		listen = listenScopedDNS
	}
	u, t, err := listen(endpoint)
	if err != nil {
		return err
	}
	// Persist exact ownership BEFORE the first kernel change. If adding a later
	// rule fails, rollback can identify every partial mutation after a crash.
	if err := writeScopedDNSFile(a.statePath(), s); err != nil {
		_ = t.Close()
		_ = u.Close()
		return err
	}
	life, cancel := context.WithCancel(a.lifetime)
	session := &scopedDNSSession{s, r, cancel, make(chan struct{})}
	a.live = session
	go func() { defer close(session.done); _ = r.Serve(life, u, t) }()
	if err := a.changeRules(ctx, s.DNS, true); err != nil {
		return err
	}
	return a.readbackRules(ctx, s.DNS, true)
}

func listenScopedDNS(endpoint netip.AddrPort) (*net.UDPConn, *net.TCPListener, error) {
	u, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(endpoint))
	if err != nil {
		return nil, nil, err
	}
	actual := u.LocalAddr().(*net.UDPAddr).AddrPort()
	t, err := net.ListenTCP("tcp4", net.TCPAddrFromAddrPort(actual))
	if err != nil {
		_ = u.Close()
		return nil, nil, err
	}
	return u, t, nil
}

func dnsSessionAlive(s *scopedDNSSession) bool {
	if s == nil {
		return false
	}
	select {
	case <-s.done:
		return false
	default:
		return true
	}
}

func (a *ScopedDNSAdapter) Health(ctx context.Context, p Plan, root string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.validate(ctx, p); err != nil {
		return err
	}
	if !dnsSessionAlive(a.live) || !sameScopedDNSState(a.live.state, scopedDNSState{p.NetworkProfileID, p.DNS, p.Routes}) {
		return errors.New("scoped DNS listener is not serving the reviewed policy")
	}
	if err := a.readbackRules(ctx, p.DNS, true); err != nil {
		return err
	}
	if err := a.HealthProbe(ctx, a.live.resolver, p); err != nil {
		return err
	}
	return a.validate(ctx, p)
}

func (a *ScopedDNSAdapter) Commit(ctx context.Context, p Plan, root string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.validate(ctx, p); err != nil {
		return err
	}
	s, err := a.readState(a.statePath())
	if err != nil {
		return err
	}
	if !dnsSessionAlive(a.live) || s == nil || !sameScopedDNSState(*s, scopedDNSState{p.NetworkProfileID, p.DNS, p.Routes}) {
		return ErrReviewChanged
	}
	return a.readbackRules(ctx, p.DNS, true)
}

func sameScopedDNSState(left, right scopedDNSState) bool {
	l, errL := json.Marshal(left)
	r, errR := json.Marshal(right)
	return errL == nil && errR == nil && bytes.Equal(l, r)
}

// Readback only: this never issues an upstream query or repairs a rule.
func (a *ScopedDNSAdapter) observeOwnedRuntime(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	s, err := a.readState(a.statePath())
	if err != nil {
		return err
	}
	if s == nil || !dnsSessionAlive(a.live) || !sameScopedDNSState(*s, a.live.state) {
		return errors.New("scoped DNS runtime is unavailable")
	}
	if err := a.validate(ctx, Plan{DNS: s.DNS, Routes: s.Routes, NetworkProfileID: s.Network}); err != nil {
		return err
	}
	return a.readbackRules(ctx, s.DNS, true)
}

// Reconcile may restore the exact committed policy only under its original
// current network authority. Reboot/WAN changes require a newly reviewed plan;
// neither saved settings nor a listener PID authorize reusing old evidence.
func (a *ScopedDNSAdapter) Reconcile(ctx context.Context, p Plan) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.validate(ctx, p); err != nil {
		return err
	}
	s, err := a.readState(a.statePath())
	if err != nil {
		return err
	}
	wanted := scopedDNSState{p.NetworkProfileID, p.DNS, p.Routes}
	if s == nil || !sameScopedDNSState(*s, wanted) {
		return errors.New("scoped DNS committed ownership is unavailable")
	}
	if dnsSessionAlive(a.live) {
		if !sameScopedDNSState(a.live.state, wanted) {
			return ErrReviewChanged
		}
		return a.readbackRules(ctx, p.DNS, true)
	}
	if err := a.stopLocked(ctx); err != nil {
		return err
	}
	if err := a.startLocked(ctx, wanted); err != nil {
		return err
	}
	if err := a.HealthProbe(ctx, a.live.resolver, p); err != nil {
		return err
	}
	return a.validate(ctx, p)
}

func (a *ScopedDNSAdapter) stopLocked(ctx context.Context) error {
	s, err := a.readState(a.statePath())
	if err != nil {
		return err
	}
	// Remove redirects first so normal router DNS is restored before sockets
	// close. A failed cleanup retains both the listener and ownership record.
	if s != nil {
		if err := a.changeRules(ctx, s.DNS, false); err != nil {
			return err
		}
		if err := a.readbackRules(ctx, s.DNS, false); err != nil {
			return err
		}
	}
	if a.live != nil {
		a.live.cancel()
		select {
		case <-a.live.done:
			a.live = nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if s != nil {
		return os.Remove(a.statePath())
	}
	return ctx.Err()
}

func (a *ScopedDNSAdapter) Deactivate(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.stopLocked(ctx)
}

func (a *ScopedDNSAdapter) snapshot(root string) (scopedDNSSnapshot, error) {
	var s scopedDNSSnapshot
	data, err := readScopedDNSFile(filepath.Join(root, "snapshot.json"))
	if err != nil {
		return s, err
	}
	if json.Unmarshal(data, &s) != nil || s.State != nil && (s.State.DNS == nil || validateScopedDNSPlan(s.State.DNS, s.State.Routes) != nil) || s.Active != (s.State != nil) {
		return s, errors.New("invalid scoped DNS snapshot")
	}
	return s, nil
}

func (a *ScopedDNSAdapter) Rollback(ctx context.Context, p Plan, root string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	s, err := a.snapshot(root)
	if err != nil {
		return err
	}
	if err := a.stopLocked(ctx); err != nil {
		return err
	}
	if s.Active {
		// Restoring stale bindings would silently authorize a new network.
		if err := a.validate(ctx, Plan{DNS: s.State.DNS, NetworkProfileID: s.State.Network, Routes: s.State.Routes}); err != nil {
			return fmt.Errorf("previous scoped DNS policy is no longer eligible: %w", err)
		}
		return a.startLocked(ctx, *s.State)
	}
	return nil
}

func (a *ScopedDNSAdapter) VerifyRollback(ctx context.Context, p Plan, root string) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	s, err := a.snapshot(root)
	if err != nil {
		return false, err
	}
	current, err := a.readState(a.statePath())
	if err != nil {
		return false, err
	}
	if !reflect.DeepEqual(s.State, current) || s.Active != dnsSessionAlive(a.live) {
		return false, errors.New("scoped DNS rollback readback differs")
	}
	if s.Active {
		return true, a.readbackRules(ctx, s.State.DNS, true)
	}
	if p.DNS != nil {
		return true, a.readbackRules(ctx, p.DNS, false)
	}
	return true, nil
}
