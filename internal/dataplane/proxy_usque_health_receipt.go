package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/routeidentity"
	"github.com/ArtixSx/razvilka/internal/usquediag"
)

type usqueHealthReceiptRoot struct {
	root                 *ownedfs.Root
	path, selection, out string
	identity             os.FileInfo
}

// A selection is explicit persisted intent, never a preferred/config default.
// The caller of this context-free reader must first check the action's guard.
func (a *ProxyTunnelAdapter) usqueHealthTransport(roots ...string) (usqueTransport, error) {
	root, err := a.openUSQUEHealthReceiptRoot(roots...)
	if err != nil {
		return usqueTransport{}, err
	}
	defer root.root.Close()
	selected, err := root.readTransport()
	if err != nil {
		return usqueTransport{}, err
	}
	if err := root.check(); err != nil {
		return usqueTransport{}, err
	}
	return selected, nil
}

func (a *ProxyTunnelAdapter) openUSQUEHealthReceiptRoot(roots ...string) (*usqueHealthReceiptRoot, error) {
	if a == nil || a.ID() != "usque" || len(roots) > 1 {
		return nil, errOwnedUSQUELiveHealth
	}
	path, selection, out := a.StateRoot, "transport.json", "evidence.json"
	if len(roots) == 1 {
		path, selection, out = roots[0], "transport.staged.json", "evidence.staged.json"
	}
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errOwnedUSQUELiveHealth
	}
	identity, err := os.Lstat(path)
	if err != nil || !identity.IsDir() || identity.Mode()&os.ModeSymlink != 0 {
		return nil, errOwnedUSQUELiveHealth
	}
	root, err := ownedfs.Open(path)
	if err != nil {
		return nil, errOwnedUSQUELiveHealth
	}
	opened := &usqueHealthReceiptRoot{root: root, path: path, selection: selection, out: out, identity: identity}
	if err := opened.check(); err != nil {
		_ = root.Close()
		return nil, err
	}
	return opened, nil
}

func (r *usqueHealthReceiptRoot) check() error {
	current, err := os.Lstat(r.path)
	if err != nil || !current.IsDir() || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(r.identity, current) {
		return errOwnedUSQUELiveHealth
	}
	return nil
}

func (r *usqueHealthReceiptRoot) readTransport() (usqueTransport, error) {
	data, err := r.root.ReadLimited(r.selection, 4096)
	if err != nil {
		return usqueTransport{}, errOwnedUSQUELiveHealth
	}
	defer clear(data)
	decoder := json.NewDecoder(bytes.NewReader(data))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return usqueTransport{}, errOwnedUSQUELiveHealth
	}
	var selected usqueTransport
	seen := make(map[string]bool, 2)
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] || key != "http2" && key != "sni" {
			return usqueTransport{}, errOwnedUSQUELiveHealth
		}
		seen[key] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return usqueTransport{}, errOwnedUSQUELiveHealth
		}
		switch key {
		case "http2":
			if !bytes.Equal(value, []byte("true")) && !bytes.Equal(value, []byte("false")) {
				return usqueTransport{}, errOwnedUSQUELiveHealth
			}
			selected.HTTP2 = bytes.Equal(value, []byte("true"))
		case "sni":
			if bytes.Equal(value, []byte("null")) || json.Unmarshal(value, &selected.SNI) != nil || !usqueHealthSNI(selected.SNI) {
				return usqueTransport{}, errOwnedUSQUELiveHealth
			}
		}
	}
	end, err := decoder.Token()
	var trailing json.RawMessage
	if err != nil || end != json.Delim('}') || !seen["http2"] || decoder.Decode(&trailing) != io.EOF {
		return usqueTransport{}, errOwnedUSQUELiveHealth
	}
	return selected, nil
}

func usqueHealthSNI(value string) bool {
	if value == "" {
		return true
	}
	if !safeSNI.MatchString(value) {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
}

// Running has no error result. Retain callback authority failures independently
// so a transient failure cannot disappear when a later callback returns nil.
type usqueHealthProcesses struct {
	ProcessController
	ctx context.Context
	mu  sync.Mutex
	err error
}

func (p *usqueHealthProcesses) remember(err error) bool {
	if err == nil {
		return true
	}
	p.mu.Lock()
	p.err = errors.Join(p.err, err)
	p.mu.Unlock()
	return false
}

func (p *usqueHealthProcesses) Running(spec ProcessSpec) bool {
	if !p.remember(requireOwnedUSQUEReviewGuard(p.ctx)) {
		return false
	}
	spec.Args = append([]string(nil), spec.Args...)
	running := p.ProcessController.Running(spec)
	return p.remember(requireOwnedUSQUEReviewGuard(p.ctx)) && running
}

func (p *usqueHealthProcesses) failure() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

type usqueLiveHealthCaptureKey struct{}
type usqueLiveHealthPolicyKey struct{}

type usqueHealthReceiptAction struct {
	actual    *ProxyTunnelAdapter
	frozen    ProxyTunnelAdapter
	processes *usqueHealthProcesses
	inspect   usqueLiveHealthIO
}

func newUSQUEHealthReceiptAction(ctx context.Context, a *ProxyTunnelAdapter) (*usqueHealthReceiptAction, error) {
	if err := requireOwnedUSQUEReviewGuard(ctx); err != nil {
		return nil, err
	}
	if a == nil || a.ID() != "usque" || a.FreshProfile == nil || a.Processes == nil {
		return nil, errOwnedUSQUELiveHealth
	}
	frozen := *a
	fresh := frozen.FreshProfile
	frozen.FreshProfile = func(c context.Context) (string, error) {
		if err := requireOwnedUSQUEReviewGuard(c); err != nil {
			return "", err
		}
		profile, err := fresh(c)
		return profile, errors.Join(err, requireOwnedUSQUEReviewGuard(c))
	}
	processes := &usqueHealthProcesses{ProcessController: frozen.Processes, ctx: ctx}
	frozen.Processes = processes
	inspect := frozen.ownedUSQUELiveIO
	observe := inspect.observe
	if observe == nil {
		observe = usquediag.ObserveOwnedUSQUE
	}
	inspect.observe = func(c context.Context, request usquediag.OwnedRuntimeRequest) (usquediag.OwnedRuntimeIdentity, error) {
		if err := requireOwnedUSQUEReviewGuard(c); err != nil {
			return usquediag.OwnedRuntimeIdentity{}, err
		}
		identity, err := observe(c, request)
		return identity, errors.Join(err, requireOwnedUSQUEReviewGuard(c))
	}
	produce := inspect.produce
	if produce == nil {
		produce = usquediag.ProbeOwnedUSQUE
	}
	inspect.produce = func(c context.Context, options usquediag.OwnedProbeOptions) (usquediag.OwnedRuntimeEvidence, error) {
		if err := requireOwnedUSQUEReviewGuard(c); err != nil {
			return usquediag.OwnedRuntimeEvidence{}, err
		}
		proof, err := produce(c, options)
		return proof, errors.Join(err, requireOwnedUSQUEReviewGuard(c))
	}
	return &usqueHealthReceiptAction{actual: a, frozen: frozen, processes: processes, inspect: inspect}, nil
}

// The last observer is local-only. Full identity equality rejects a receipt
// from a Canary or an earlier active process even if its TTL remains valid.
func (action *usqueHealthReceiptAction) verify(ctx context.Context, plan Plan, root *usqueHealthReceiptRoot, selected usqueTransport, receipt usquediag.CanaryEvidence, started time.Time) error {
	if receipt.Owned == nil {
		return errOwnedUSQUELiveHealth
	}
	expected, err := json.Marshal(receipt.Owned.CanaryEvidence())
	actual, actualErr := json.Marshal(receipt)
	if err != nil || actualErr != nil || !bytes.Equal(expected, actual) {
		return errOwnedUSQUELiveHealth
	}
	if err := usqueHealthReceiptGrades(ctx, plan.RoutePlanFor("usque"), *receipt.Owned); err != nil {
		return err
	}
	if err := verifyNetworkProfile(ctx, plan.NetworkProfileID, action.frozen.FreshProfile); err != nil {
		return err
	}
	spec := action.frozen.engineProcessWithTransport(selected)
	spec.Args = append([]string(nil), spec.Args...)
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(action.frozen.SOCKSPort))
	protocol, err := ownedUSQUELiveTransport(spec, address)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(spec, action.actual.engineProcessWithTransport(selected)) {
		return errOwnedUSQUELiveHealth
	}
	if !action.processes.Running(spec) {
		return errors.Join(errOwnedUSQUELiveHealth, action.processes.failure())
	}
	runtimeIdentity, err := os.Lstat(spec.Dir)
	if err != nil || !runtimeIdentity.IsDir() || runtimeIdentity.Mode()&os.ModeSymlink != 0 {
		return errOwnedUSQUELiveHealth
	}
	runtime, err := ownedfs.Open(spec.Dir)
	if err != nil {
		return errOwnedUSQUELiveHealth
	}
	defer runtime.Close()
	config, err := runtime.ReadLimited("engine.json", 8<<20)
	if err != nil {
		return errOwnedUSQUELiveHealth
	}
	defer clear(config)
	endpoint, err := usquediag.SelectedOwnedUSQUEEndpoint(config, protocol)
	argsHash := routeidentity.Hash([]byte(strings.Join(append([]string{spec.Binary}, spec.Args...), "\x00") + "\x00"))
	if err != nil || receipt.Owned.Identity.Transport != protocol || receipt.Owned.Identity.Endpoint != endpoint.String() ||
		receipt.Owned.Identity.SessionSHA256 != routeidentity.Hash(config) || receipt.Owned.Identity.ArgsSHA256 != argsHash {
		return errOwnedUSQUELiveHealth
	}
	request := usquediag.OwnedRuntimeRequest{Root: spec.Dir, Binary: spec.Binary, SOCKSAddress: address,
		Transport: protocol, Endpoint: endpoint, Environment: usquediag.OwnedUSQUEEnvironment(action.frozen.FreshProfile)}
	current, err := action.inspect.observe(ctx, request)
	if err != nil || current != receipt.Owned.Identity {
		return errors.Join(errOwnedUSQUELiveHealth, err)
	}
	if err := verifyNetworkProfile(ctx, plan.NetworkProfileID, action.frozen.FreshProfile); err != nil {
		return err
	}
	if err := requireOwnedUSQUEReviewGuard(ctx); err != nil {
		return err
	}
	// Read actual policy last: a successful observer or WAN callback can still
	// change it. The remaining selection/config/TTL checks have no callbacks.
	if callback := ctx.Value(usqueLiveHealthPolicyKey{}); callback != nil {
		check, ok := callback.(func(context.Context) error)
		if !ok || check == nil {
			return errOwnedUSQUELiveHealth
		}
		if err := requireOwnedUSQUEReviewGuard(ctx); err != nil {
			return err
		}
		if err := errors.Join(check(ctx), requireOwnedUSQUEReviewGuard(ctx)); err != nil {
			return err
		}
	}
	// No callbacks intervene between these final reads and the anchored write.
	closing, err := root.readTransport()
	currentRuntimeRoot, runtimeRootErr := os.Lstat(spec.Dir)
	if err != nil || closing != selected || root.check() != nil || runtimeRootErr != nil || !os.SameFile(runtimeIdentity, currentRuntimeRoot) ||
		!currentRuntimeRoot.IsDir() || currentRuntimeRoot.Mode()&os.ModeSymlink != 0 || !reflect.DeepEqual(spec, action.actual.engineProcessWithTransport(selected)) {
		return errOwnedUSQUELiveHealth
	}
	closingConfig, err := runtime.ReadLimited("engine.json", 8<<20)
	if err != nil {
		return errOwnedUSQUELiveHealth
	}
	defer clear(closingConfig)
	closingEndpoint, err := usquediag.SelectedOwnedUSQUEEndpoint(closingConfig, protocol)
	environment, _ := json.Marshal([]string{"usque-environment-v1", plan.NetworkProfileID})
	checked, timeErr := time.Parse(time.RFC3339Nano, receipt.Owned.CheckedAt)
	if err != nil || closingEndpoint != endpoint || receipt.Owned.Identity.Transport != protocol || receipt.Owned.Identity.Endpoint != endpoint.String() ||
		receipt.Owned.Identity.SessionSHA256 != routeidentity.Hash(closingConfig) || receipt.Owned.Identity.ArgsSHA256 != argsHash ||
		receipt.Owned.Identity.EnvironmentID != routeidentity.Hash(environment) || timeErr != nil || !started.IsZero() && checked.Before(started) ||
		!usquediag.OwnedEvidenceFresh(*receipt.Owned, current, time.Now()) {
		return errOwnedUSQUELiveHealth
	}
	return ctx.Err()
}

func usqueHealthReceiptGrades(ctx context.Context, plan RoutePlan, proof usquediag.OwnedRuntimeEvidence) error {
	if len(plan.Routes) == 0 || len(plan.Routes) > 64 {
		return errOwnedUSQUELiveHealth
	}
	semantic := plan
	semantic.Routes = nil
	var services []catalog.Service
	for _, route := range plan.Routes {
		if route.Resolved != "usque" {
			return errOwnedUSQUELiveHealth
		}
		if route.NetworkPolicyRole == "default" {
			if _, err := plan.FrozenLAN(); err != nil {
				return err
			}
			continue
		}
		service, err := FrozenProbeService(route)
		if err != nil {
			return err
		}
		semantic.Routes = append(semantic.Routes, route)
		services = append(services, service)
	}
	probes, err := ownedUSQUECandidateServices(ctx, semantic, services)
	if err != nil || !ownedUSQUECandidateGrades(probes, proof) {
		return errors.Join(errOwnedUSQUELiveHealth, err)
	}
	return nil
}

// Health is a fresh producer action. The existing receipt is never used as
// authority or assigned new timestamps, and the opened evidence root is reused
// for the selected-transport readback and the single atomic receipt write.
func (a *ProxyTunnelAdapter) healthOwnedUSQUE(ctx context.Context, plan Plan, roots ...string) error {
	if err := requireOwnedUSQUEReviewGuard(ctx); err != nil {
		return err
	}
	if a == nil {
		return errOwnedUSQUELiveHealth
	}
	window, cancel := context.WithTimeout(ctx, min(a.timeout(), 30*time.Second))
	defer cancel()
	ctx = window
	action, err := newUSQUEHealthReceiptAction(ctx, a)
	if err != nil {
		return err
	}
	plan.Routes = cloneNetworkPolicyRoutes(plan.Routes)
	plan.LAN = CloneLANPolicyRuntime(plan.LAN)
	if err := verifyNetworkProfile(ctx, plan.NetworkProfileID, action.frozen.FreshProfile); err != nil {
		return err
	}
	if err := requireOwnedUSQUEReviewGuard(ctx); err != nil {
		return err
	}
	root, err := action.frozen.openUSQUEHealthReceiptRoot(roots...)
	if err != nil {
		return err
	}
	defer root.root.Close()
	selected, err := root.readTransport()
	if err != nil {
		return err
	}
	started := time.Now()
	receipt, err := action.frozen.probeOwnedUSQUELiveWith(ctx, plan.RoutePlanFor("usque"), selected, action.inspect)
	if err := errors.Join(err, action.processes.failure(), requireOwnedUSQUEReviewGuard(ctx)); err != nil {
		return err
	}
	if err := action.verify(ctx, plan, root, selected, receipt, started); err != nil {
		return err
	}
	data, err := json.Marshal(receipt)
	if err != nil || len(data) > 64<<10 {
		return errOwnedUSQUELiveHealth
	}
	defer clear(data)
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := root.root.WriteAtomic(root.out, data, 0600); err != nil {
		return err
	}
	if capture, ok := ctx.Value(usqueLiveHealthCaptureKey{}).(func([]byte)); ok && capture != nil {
		if err := requireOwnedUSQUEReviewGuard(ctx); err != nil {
			return err
		}
		capture(append([]byte(nil), data...))
		return requireOwnedUSQUEReviewGuard(ctx)
	}
	return requireOwnedUSQUEReviewGuard(ctx)
}

// captured is the private owned copy delivered by the preceding Health action,
// not a re-read of staged JSON. Promotion revalidates it without a new producer.
func (a *ProxyTunnelAdapter) commitOwnedUSQUEHealth(ctx context.Context, plan Plan, root string, captured []byte) error {
	if err := requireOwnedUSQUEReviewGuard(ctx); err != nil {
		return err
	}
	if a == nil || len(captured) == 0 || len(captured) > 64<<10 {
		return errOwnedUSQUELiveHealth
	}
	captured = append([]byte(nil), captured...)
	defer clear(captured)
	var receipt usquediag.CanaryEvidence
	if json.Unmarshal(captured, &receipt) != nil || receipt.Owned == nil {
		return errOwnedUSQUELiveHealth
	}
	canonical, err := json.Marshal(receipt)
	defer clear(canonical)
	if err != nil || !bytes.Equal(captured, canonical) {
		return errOwnedUSQUELiveHealth
	}
	window, cancel := context.WithTimeout(ctx, min(a.timeout(), 30*time.Second))
	defer cancel()
	ctx = window
	action, err := newUSQUEHealthReceiptAction(ctx, a)
	if err != nil {
		return err
	}
	plan.Routes = cloneNetworkPolicyRoutes(plan.Routes)
	plan.LAN = CloneLANPolicyRuntime(plan.LAN)
	if err := verifyNetworkProfile(ctx, plan.NetworkProfileID, action.frozen.FreshProfile); err != nil {
		return err
	}
	staged, err := action.frozen.openUSQUEHealthReceiptRoot(root)
	if err != nil {
		return err
	}
	defer staged.root.Close()
	selected, err := staged.readTransport()
	if err != nil {
		return err
	}
	committed, err := action.frozen.openUSQUEHealthReceiptRoot()
	if err != nil {
		return err
	}
	defer committed.root.Close()
	if err := action.verify(ctx, plan, staged, selected, receipt, time.Time{}); err != nil {
		return err
	}
	transport, err := json.Marshal(selected)
	if err != nil || committed.check() != nil || ctx.Err() != nil {
		return errors.Join(errOwnedUSQUELiveHealth, ctx.Err())
	}
	if err := committed.root.WriteAtomic(committed.selection, transport, 0600); err != nil {
		return err
	}
	if err := errors.Join(committed.check(), ctx.Err()); err != nil {
		return err
	}
	if err := committed.root.WriteAtomic(committed.out, captured, 0600); err != nil {
		return err
	}
	return requireOwnedUSQUEReviewGuard(ctx)
}
