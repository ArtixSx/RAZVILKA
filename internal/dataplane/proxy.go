package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
	xnetproxy "golang.org/x/net/proxy"
)

// ProxyTunnelAdapter runs an engine as an isolated loopback-only SOCKS5
// candidate. A second, RAZVILKA-owned sing-box process turns that SOCKS
// endpoint into a TUN interface. Only resolved service prefixes are sent to
// the interface by policy routing; neither process may replace the host's
// default route.
type ProxyTunnelAdapter struct {
	EngineID         string
	Configs          *engineconfig.Manager
	StateRoot        string
	Runner           NFQWS2Runner
	Processes        ProcessController
	Resolver         PrefixResolver
	Probe            func(context.Context, string) error
	SOCKSProbe       func(context.Context, string) error
	CanaryProbe      func(context.Context, string, string) error
	CanaryTraceProbe func(context.Context, string) (usqueCanaryEvidence, error)
	EngineBin        string
	SidecarBin       string
	PackageInit      string
	IP               string
	SOCKSPort        int
	Interface        string
	TunnelCIDR       string
	Table            int
	Priority         int
	Timeout          time.Duration
	UsqueConfig      string
}

type usqueTransport struct {
	HTTP2 bool   `json:"http2"`
	SNI   string `json:"sni,omitempty"`
}

type usqueCanaryEvidence struct {
	CheckedAt       string   `json:"checked_at"`
	Transport       string   `json:"transport"`
	Warp            string   `json:"warp"`
	Colo            string   `json:"colo,omitempty"`
	Loc             string   `json:"loc,omitempty"`
	EgressIP        string   `json:"egress_ip,omitempty"`
	ConfirmedRoutes []string `json:"confirmed_routes,omitempty"`
}

type proxySnapshot struct {
	ConfigPath          string      `json:"config_path"`
	Config              []byte      `json:"config,omitempty"`
	ConfigExisted       bool        `json:"config_existed"`
	ConfigDraft         bool        `json:"config_draft"`
	StagedConfig        []byte      `json:"staged_config,omitempty"`
	RuntimeEngine       []byte      `json:"runtime_engine,omitempty"`
	RuntimeEngineExists bool        `json:"runtime_engine_exists"`
	RuntimeSidecar      []byte      `json:"runtime_sidecar,omitempty"`
	RuntimeSideExists   bool        `json:"runtime_sidecar_exists"`
	Transport           []byte      `json:"transport,omitempty"`
	TransportExists     bool        `json:"transport_exists,omitempty"`
	Evidence            []byte      `json:"evidence,omitempty"`
	EvidenceExists      bool        `json:"evidence_exists,omitempty"`
	Policy              PolicyState `json:"policy"`
	PolicyExists        bool        `json:"policy_exists"`
	EngineWasRunning    bool        `json:"engine_was_running"`
	SidecarWasRunning   bool        `json:"sidecar_was_running"`
	PackageWasRunning   bool        `json:"package_was_running,omitempty"`
}

func NewProxyTunnelAdapter(id string, configs *engineconfig.Manager, stateRoot string) (*ProxyTunnelAdapter, error) {
	a := &ProxyTunnelAdapter{EngineID: id, Configs: configs, StateRoot: filepath.Join(stateRoot, id), Runner: nfqws2ExecRunner{}, Processes: OSProcessController{}, SOCKSProbe: probeSOCKS5, UsqueConfig: "/opt/etc/usque/usque.conf"}
	switch id {
	case "usque":
		a.SOCKSPort, a.Interface, a.TunnelCIDR, a.Table, a.Priority = 18080, "rz-usque", "172.31.20.1/30", 202, 20000
	case "sing-box":
		a.SOCKSPort, a.Interface, a.TunnelCIDR, a.Table, a.Priority = 18081, "rz-sing", "172.31.21.1/30", 203, 22000
	case "xray":
		a.SOCKSPort, a.Interface, a.TunnelCIDR, a.Table, a.Priority = 18082, "rz-xray", "172.31.22.1/30", 204, 24000
	default:
		return nil, fmt.Errorf("unsupported proxy tunnel engine %q", id)
	}
	a.Probe = func(ctx context.Context, rawURL string) error {
		return probeTunnelViaSOCKS(ctx, rawURL, net.JoinHostPort("127.0.0.1", strconv.Itoa(a.SOCKSPort)))
	}
	return a, nil
}

func (a *ProxyTunnelAdapter) ID() string { return a.EngineID }

func (a *ProxyTunnelAdapter) Snapshot(ctx context.Context, plan Plan, root string) error {
	if err := a.valid(); err != nil {
		return err
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	view, err := a.Configs.ReadExpert(a.ID(), "main")
	if err != nil {
		return err
	}
	live, liveExists, err := optionalFile(view.Path)
	if err != nil {
		return err
	}
	var draft []byte
	draftExists := planUsesEngineDraft(plan, a.ID(), "main") && view.Source == "staged"
	if draftExists {
		draft = []byte(view.Content)
	}
	engineRuntime, engineRuntimeExists, err := optionalFile(a.engineConfigPath())
	if err != nil {
		return err
	}
	sideRuntime, sideRuntimeExists, err := optionalFile(a.sidecarConfigPath())
	if err != nil {
		return err
	}
	transport, transportExists, err := optionalFile(a.transportPath())
	if err != nil {
		return err
	}
	evidence, evidenceExists, err := optionalFile(a.evidencePath())
	if err != nil {
		return err
	}
	policy, policyExists, err := a.loadPolicy()
	if err != nil {
		return err
	}
	packageWasRunning, err := a.packageRuntimeRunning(ctx)
	if err != nil {
		return err
	}
	snapshot := proxySnapshot{
		ConfigPath: view.Path, Config: live, ConfigExisted: liveExists, ConfigDraft: draftExists, StagedConfig: draft,
		RuntimeEngine: engineRuntime, RuntimeEngineExists: engineRuntimeExists, RuntimeSidecar: sideRuntime, RuntimeSideExists: sideRuntimeExists, Transport: transport, TransportExists: transportExists, Evidence: evidence, EvidenceExists: evidenceExists,
		Policy: policy, PolicyExists: policyExists, EngineWasRunning: a.Processes.Running(a.engineProcess()), SidecarWasRunning: a.Processes.Running(a.sidecarProcess()), PackageWasRunning: packageWasRunning,
	}
	data, _ := json.MarshalIndent(snapshot, "", "  ")
	return writeAtomic(filepath.Join(root, "snapshot.json"), data, 0o600)
}

func (a *ProxyTunnelAdapter) Stage(ctx context.Context, plan Plan, root string) error {
	snapshot, err := readProxySnapshot(root)
	if err != nil {
		return err
	}
	source := snapshot.Config
	if snapshot.ConfigDraft {
		source = snapshot.StagedConfig
	}
	if len(source) == 0 {
		return errors.New("engine configuration is empty")
	}
	candidate, endpoints, err := buildProxyCandidate(a.ID(), source, a.SOCKSPort)
	if err != nil {
		return err
	}
	prefixes, rules, err := resolvePolicyRules(ctx, plan, a.ID(), a.Resolver)
	if err != nil {
		return err
	}
	if len(prefixes) == 0 {
		return errors.New("proxy route has no destination prefixes")
	}
	if err := rejectEndpointOverlap(ctx, prefixes, endpoints, a.Resolver); err != nil {
		return err
	}
	schema, err := a.detectSidecarSchema(ctx)
	if err != nil {
		return err
	}
	sidecar, err := buildSOCKSTunnelConfigForSchema(a.Interface, a.TunnelCIDR, a.SOCKSPort, schema)
	if err != nil {
		return err
	}
	policy := PolicyState{Interface: a.Interface, Table: a.Table, PriorityBase: a.Priority, Prefixes: prefixes, Rules: rules}
	policyData, _ := json.MarshalIndent(policy, "", "  ")
	for _, item := range []struct {
		path string
		data []byte
	}{
		{filepath.Join(root, "engine.staged.json"), candidate},
		{filepath.Join(root, "sidecar.staged.json"), sidecar},
		{filepath.Join(root, "policy.staged.json"), policyData},
	} {
		if err := writeAtomic(item.path, item.data, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func (a *ProxyTunnelAdapter) Validate(ctx context.Context, _ Plan, root string) error {
	if err := a.valid(); err != nil {
		return err
	}
	engineCandidate := filepath.Join(root, "engine.staged.json")
	sidecarCandidate := filepath.Join(root, "sidecar.staged.json")
	if _, err := a.readStagedPolicy(root); err != nil {
		return err
	}
	if a.engineBinary() == "" {
		return fmt.Errorf("%s binary is not installed", a.ID())
	}
	if a.sidecarBinary() == "" {
		return errors.New("sing-box is required as the managed TUN sidecar")
	}
	if a.ID() != "usque" {
		var args []string
		if a.ID() == "sing-box" {
			args = []string{"check", "-c", engineCandidate}
		} else {
			args = []string{"run", "-test", "-config", engineCandidate}
		}
		if output, err := a.run(ctx, a.engineBinary(), args...); err != nil {
			return fmt.Errorf("%s native validation failed: %s", a.ID(), shortOutput(output, err))
		}
	}
	if output, err := a.run(ctx, a.sidecarBinary(), "check", "-c", sidecarCandidate); err != nil {
		return fmt.Errorf("sing-box TUN validation failed: %s", shortOutput(output, err))
	}
	return nil
}

// Canary starts only the staged proxy engine on an isolated loopback SOCKS
// port. It does not stop the working process, create a TUN interface or touch
// policy routing. The candidate is always removed before Activate can run.
func (a *ProxyTunnelAdapter) Canary(ctx context.Context, plan RoutePlan, root string) error {
	if err := a.valid(); err != nil {
		return err
	}
	staged, err := os.ReadFile(filepath.Join(root, "engine.staged.json"))
	if err != nil {
		return err
	}
	port, err := a.canaryPort()
	if err != nil {
		return err
	}
	candidate, _, err := buildProxyCandidate(a.ID(), staged, port)
	if err != nil {
		return err
	}
	canaryRoot := filepath.Join(root, "canary")
	if err := os.MkdirAll(canaryRoot, 0o700); err != nil {
		return err
	}
	configPath := filepath.Join(canaryRoot, "engine.json")
	if err := writeAtomic(configPath, candidate, 0o600); err != nil {
		return err
	}
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	transports := []usqueTransport{{}}
	if a.ID() == "usque" {
		preferred := a.preferredUsqueTransport()
		transports = []usqueTransport{preferred, {HTTP2: !preferred.HTTP2, SNI: preferred.SNI}}
	}
	failed := make([]string, 0, len(transports))
	for _, transport := range transports {
		spec := a.engineProcessAt(configPath, port, canaryRoot, a.ID()+"-canary", transport)
		evidence, err := a.runCanaryAttempt(ctx, plan, spec, address)
		if err != nil {
			if a.Processes.Running(spec) {
				return fmt.Errorf("isolated %s candidate could not be stopped after failed %s probe", a.ID(), usqueTransportName(transport))
			}
			failed = append(failed, usqueTransportName(transport)+": "+err.Error())
			continue
		}
		if a.ID() == "usque" {
			data, _ := json.MarshalIndent(transport, "", "  ")
			if err := writeAtomic(filepath.Join(root, "transport.staged.json"), data, 0o600); err != nil {
				return err
			}
			evidence.CheckedAt = time.Now().UTC().Format(time.RFC3339)
			evidence.Transport = usqueTransportName(transport)
			data, _ = json.MarshalIndent(evidence, "", "  ")
			if err := writeAtomic(filepath.Join(root, "evidence.staged.json"), data, 0o600); err != nil {
				return err
			}
		}
		return nil
	}
	return fmt.Errorf("%s candidate transports failed: %s", a.ID(), strings.Join(failed, "; "))
}

func (a *ProxyTunnelAdapter) runCanaryAttempt(ctx context.Context, plan RoutePlan, spec ProcessSpec, address string) (evidence usqueCanaryEvidence, resultErr error) {
	if err := a.Processes.Start(ctx, spec); err != nil {
		return evidence, fmt.Errorf("start isolated %s candidate: %w", a.ID(), err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), a.timeout())
		defer cancel()
		if err := a.Processes.Stop(cleanupCtx, spec); err != nil {
			if resultErr == nil {
				resultErr = fmt.Errorf("stop isolated %s candidate: %w", a.ID(), err)
			} else {
				resultErr = fmt.Errorf("%v; stop isolated %s candidate: %w", resultErr, a.ID(), err)
			}
		}
	}()
	if err := a.waitForSOCKSProcess(ctx, spec, address); err != nil {
		return evidence, err
	}
	if a.ID() == "usque" {
		traceProbe := a.CanaryTraceProbe
		if traceProbe == nil {
			traceProbe = probeCloudflareTraceViaSOCKS
		}
		probeCtx, cancel := context.WithTimeout(ctx, a.timeout())
		trace, err := traceProbe(probeCtx, address)
		cancel()
		if err != nil {
			return evidence, fmt.Errorf("candidate WARP trace failed: %w", err)
		}
		if trace.Warp != "on" && trace.Warp != "plus" {
			warpState := trace.Warp
			if warpState == "" {
				warpState = "unknown"
			}
			return evidence, fmt.Errorf("candidate Cloudflare trace reported warp=%s", warpState)
		}
		evidence = trace
	}
	probe := a.CanaryProbe
	if probe == nil {
		probe = probeTunnelViaSOCKS
	}
	probed := false
	for _, route := range plan.Routes {
		if strings.TrimSpace(route.ProbeURL) == "" {
			continue
		}
		probed = true
		probeCtx, cancel := context.WithTimeout(ctx, a.timeout())
		err := probe(probeCtx, route.ProbeURL, address)
		cancel()
		if err != nil {
			if a.ID() == "usque" {
				return evidence, fmt.Errorf("candidate service probe for %s failed after WARP was confirmed: %w", route.ServiceName, err)
			}
			return evidence, fmt.Errorf("candidate probe for %s failed: %w", route.ServiceName, err)
		}
		evidence.ConfirmedRoutes = append(evidence.ConfirmedRoutes, route.ServiceName)
	}
	if !probed && a.ID() != "usque" {
		probeCtx, cancel := context.WithTimeout(ctx, a.timeout())
		err := probe(probeCtx, "https://www.cloudflare.com/cdn-cgi/trace", address)
		cancel()
		if err != nil {
			return evidence, fmt.Errorf("candidate egress probe failed: %w", err)
		}
	}
	return evidence, nil
}

func (a *ProxyTunnelAdapter) Activate(ctx context.Context, _ Plan, root string) error {
	snapshot, err := readProxySnapshot(root)
	if err != nil {
		return err
	}
	desired, err := a.readStagedPolicy(root)
	if err != nil {
		return err
	}
	if old, exists, err := a.loadPolicy(); err != nil {
		return err
	} else if exists {
		if err := removePolicy(ctx, a.Runner, a.ip(), old); err != nil {
			return fmt.Errorf("remove previous %s policy: %w", a.ID(), err)
		}
	}
	if err := a.stopOwned(ctx); err != nil {
		return err
	}
	if snapshot.PackageWasRunning {
		if err := a.stopPackageRuntime(ctx); err != nil {
			return err
		}
	}
	engineCandidate, err := os.ReadFile(filepath.Join(root, "engine.staged.json"))
	if err != nil {
		return err
	}
	sideCandidate, err := os.ReadFile(filepath.Join(root, "sidecar.staged.json"))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(a.runtimeRoot(), 0o700); err != nil {
		return err
	}
	if err := writeAtomic(a.engineConfigPath(), engineCandidate, 0o600); err != nil {
		return err
	}
	if err := writeAtomic(a.sidecarConfigPath(), sideCandidate, 0o600); err != nil {
		return err
	}
	transport, err := a.stagedUsqueTransport(root)
	if err != nil {
		return err
	}
	if err := a.Processes.Start(ctx, a.engineProcessWithTransport(transport)); err != nil {
		return err
	}
	if err := a.waitForSOCKS(ctx); err != nil {
		return err
	}
	if err := a.Processes.Start(ctx, a.sidecarProcess()); err != nil {
		return err
	}
	if err := a.waitForInterface(ctx); err != nil {
		return err
	}
	if err := applyPolicy(ctx, a.Runner, a.ip(), desired); err != nil {
		return err
	}
	return nil
}

func (a *ProxyTunnelAdapter) Health(ctx context.Context, plan Plan, root string) error {
	state, err := a.readStagedPolicy(root)
	if err != nil {
		return err
	}
	return a.healthState(ctx, plan, state)
}

func (a *ProxyTunnelAdapter) healthState(ctx context.Context, plan Plan, state PolicyState) error {
	if !a.Processes.Running(a.engineProcess()) || !a.Processes.Running(a.sidecarProcess()) {
		return errors.New("managed proxy or TUN sidecar is not running")
	}
	if err := a.waitForSOCKS(ctx); err != nil {
		return err
	}
	if err := verifyPolicyEvidence(ctx, a.Runner, a.ip(), state); err != nil {
		return err
	}
	for _, route := range plan.Routes {
		if adapterID(route.Resolved) != a.ID() || strings.TrimSpace(route.ProbeURL) == "" || len(route.Sources) > 0 {
			continue
		}
		if err := a.Probe(ctx, route.ProbeURL); err != nil {
			return fmt.Errorf("%s probe for %s failed: %w", a.ID(), route.ServiceName, err)
		}
	}
	return nil
}

func (a *ProxyTunnelAdapter) Reconcile(ctx context.Context, plan Plan) error {
	state, exists, err := a.loadPolicy()
	if err != nil {
		return err
	}
	if !exists || !regularFile(a.engineConfigPath()) || !regularFile(a.sidecarConfigPath()) {
		return fmt.Errorf("committed %s runtime state is missing", a.ID())
	}
	// usque-keenetic starts its own nativetun process during installation and
	// boot. RAZVILKA owns a separate loopback SOCKS process and must not leave
	// both runtimes competing for the same Cloudflare session.
	if err := a.stopPackageRuntime(ctx); err != nil {
		return err
	}
	if err := a.healthState(ctx, plan, state); err == nil {
		return nil
	}
	_ = removePolicy(ctx, a.Runner, a.ip(), state)
	if err := a.stopOwned(ctx); err != nil {
		return err
	}
	if err := a.Processes.Start(ctx, a.engineProcess()); err != nil {
		return err
	}
	if err := a.waitForSOCKS(ctx); err != nil {
		_ = a.stopOwned(ctx)
		return err
	}
	if err := a.Processes.Start(ctx, a.sidecarProcess()); err != nil {
		_ = a.stopOwned(ctx)
		return err
	}
	if err := a.waitForInterface(ctx); err != nil {
		_ = a.stopOwned(ctx)
		return err
	}
	if err := applyPolicy(ctx, a.Runner, a.ip(), state); err != nil {
		_ = a.stopOwned(ctx)
		return err
	}
	if err := a.healthState(ctx, plan, state); err != nil {
		_ = removePolicy(ctx, a.Runner, a.ip(), state)
		_ = a.stopOwned(ctx)
		return err
	}
	return nil
}

func (a *ProxyTunnelAdapter) RefreshPolicy(ctx context.Context, plan Plan) (bool, error) {
	oldState, exists, err := a.loadPolicy()
	if err != nil || !exists {
		return false, err
	}
	prefixes, rules, err := resolvePolicyRules(ctx, plan, a.ID(), a.Resolver)
	if err != nil {
		return false, err
	}
	engineConfig, err := os.ReadFile(a.engineConfigPath())
	if err != nil {
		return false, err
	}
	var document map[string]any
	if err := json.Unmarshal(engineConfig, &document); err != nil {
		return false, err
	}
	if err := rejectEndpointOverlap(ctx, prefixes, collectEndpointHosts(document), a.Resolver); err != nil {
		return false, err
	}
	newState := PolicyState{Interface: a.Interface, Table: a.Table, PriorityBase: a.Priority, Prefixes: prefixes, Rules: rules}
	if samePolicy(oldState, newState) {
		return false, nil
	}
	if err := replacePolicy(ctx, a.Runner, a.ip(), oldState, newState); err != nil {
		return false, err
	}
	if err := a.healthState(ctx, plan, newState); err != nil {
		_ = replacePolicy(ctx, a.Runner, a.ip(), newState, oldState)
		return false, err
	}
	data, _ := json.MarshalIndent(newState, "", "  ")
	if err := writeAtomic(a.policyPath(), data, 0o600); err != nil {
		_ = replacePolicy(ctx, a.Runner, a.ip(), newState, oldState)
		return false, err
	}
	return true, nil
}

func (a *ProxyTunnelAdapter) Deactivate(ctx context.Context) error {
	owned := regularFile(a.policyPath()) || regularFile(a.engineConfigPath()) || regularFile(a.sidecarConfigPath()) || regularFile(a.transportPath()) || regularFile(a.engineProcess().PIDPath) || regularFile(a.sidecarProcess().PIDPath)
	if !owned {
		return nil
	}
	var firstErr error
	if state, exists, err := a.loadPolicy(); err != nil {
		firstErr = err
	} else if exists {
		if err := removePolicy(ctx, a.Runner, a.ip(), state); err != nil {
			firstErr = err
		}
	}
	if err := a.stopOwned(ctx); err != nil && firstErr == nil {
		firstErr = err
	}
	// A correctly stopped sing-box sidecar removes its TUN. Delete only the
	// exact adapter-owned interface if a crashed sidecar left it behind.
	if a.ip() != "" {
		if _, err := a.run(ctx, a.ip(), "link", "show", "dev", a.Interface); err == nil {
			if output, deleteErr := a.run(ctx, a.ip(), "link", "delete", "dev", a.Interface); deleteErr != nil && firstErr == nil {
				firstErr = fmt.Errorf("delete owned interface %s: %s", a.Interface, shortOutput(output, deleteErr))
			}
		}
	}
	for _, path := range []string{a.policyPath(), a.engineConfigPath(), a.sidecarConfigPath(), a.transportPath(), a.engineProcess().PIDPath, a.sidecarProcess().PIDPath} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (a *ProxyTunnelAdapter) Commit(_ context.Context, _ Plan, root string) error {
	snapshot, err := readProxySnapshot(root)
	if err != nil {
		return err
	}
	if snapshot.ConfigDraft {
		if err := installStagedBytes(snapshot.StagedConfig, snapshot.ConfigPath, 0o600); err != nil {
			return err
		}
		if err := a.Configs.Discard(a.ID(), "main"); err != nil {
			return err
		}
	}
	state, err := a.readStagedPolicy(root)
	if err != nil {
		return err
	}
	data, _ := json.MarshalIndent(state, "", "  ")
	if err := os.MkdirAll(a.StateRoot, 0o700); err != nil {
		return err
	}
	if err := writeAtomic(a.policyPath(), data, 0o600); err != nil {
		return err
	}
	if a.ID() == "usque" {
		transport, err := a.stagedUsqueTransport(root)
		if err != nil {
			return err
		}
		data, _ := json.MarshalIndent(transport, "", "  ")
		if err := writeAtomic(a.transportPath(), data, 0o600); err != nil {
			return err
		}
		evidence, err := os.ReadFile(filepath.Join(root, "evidence.staged.json"))
		if err != nil {
			return errors.New("validated USQUE canary evidence is missing")
		}
		if err := writeAtomic(a.evidencePath(), evidence, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func (a *ProxyTunnelAdapter) Rollback(ctx context.Context, _ Plan, root string) error {
	snapshot, err := readProxySnapshot(root)
	if err != nil {
		return err
	}
	var firstErr error
	if staged, readErr := a.readStagedPolicy(root); readErr == nil {
		if err := removePolicy(ctx, a.Runner, a.ip(), staged); err != nil {
			firstErr = err
		}
	}
	if err := a.stopOwned(ctx); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := restoreOptional(a.engineConfigPath(), snapshot.RuntimeEngine, snapshot.RuntimeEngineExists); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := restoreOptional(a.sidecarConfigPath(), snapshot.RuntimeSidecar, snapshot.RuntimeSideExists); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := restoreOptional(a.transportPath(), snapshot.Transport, snapshot.TransportExists); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := restoreOptional(a.evidencePath(), snapshot.Evidence, snapshot.EvidenceExists); err != nil && firstErr == nil {
		firstErr = err
	}
	if snapshot.EngineWasRunning {
		if err := a.Processes.Start(ctx, a.engineProcess()); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if snapshot.SidecarWasRunning {
		if err := a.Processes.Start(ctx, a.sidecarProcess()); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if snapshot.PolicyExists {
		if err := applyPolicy(ctx, a.Runner, a.ip(), snapshot.Policy); err != nil && firstErr == nil {
			firstErr = err
		}
		data, _ := json.MarshalIndent(snapshot.Policy, "", "  ")
		_ = os.MkdirAll(a.StateRoot, 0o700)
		_ = writeAtomic(a.policyPath(), data, 0o600)
	} else {
		_ = os.Remove(a.policyPath())
	}
	if err := restoreOptional(snapshot.ConfigPath, snapshot.Config, snapshot.ConfigExisted); err != nil && firstErr == nil {
		firstErr = err
	}
	if snapshot.ConfigDraft {
		if _, err := a.Configs.Stage(a.ID(), "main", string(snapshot.StagedConfig)); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if snapshot.PackageWasRunning {
		if err := a.startPackageRuntime(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (a *ProxyTunnelAdapter) valid() error {
	if a == nil || a.Configs == nil || a.StateRoot == "" || a.Runner == nil || a.Processes == nil || a.ID() == "" {
		return errors.New("proxy tunnel adapter is not configured")
	}
	if a.SOCKSPort < 1024 || a.SOCKSPort > 65535 || a.Table < 1 || a.Table > 252 || a.Priority < 1000 || a.Interface == "" {
		return errors.New("invalid proxy tunnel ownership settings")
	}
	return nil
}

func (a *ProxyTunnelAdapter) runtimeRoot() string { return filepath.Join(a.StateRoot, "runtime") }
func (a *ProxyTunnelAdapter) engineConfigPath() string {
	return filepath.Join(a.runtimeRoot(), "engine.json")
}
func (a *ProxyTunnelAdapter) sidecarConfigPath() string {
	return filepath.Join(a.runtimeRoot(), "sidecar.json")
}
func (a *ProxyTunnelAdapter) policyPath() string { return filepath.Join(a.StateRoot, "policy.json") }
func (a *ProxyTunnelAdapter) timeout() time.Duration {
	if a.Timeout <= 0 {
		return 25 * time.Second
	}
	return a.Timeout
}
func (a *ProxyTunnelAdapter) engineBinary() string {
	if a.EngineBin != "" {
		return a.EngineBin
	}
	switch a.ID() {
	case "usque":
		return findExecutable("/opt/bin/usque", "/opt/usr/bin/usque", "usque")
	case "sing-box":
		return findExecutable("/opt/bin/sing-box", "/opt/usr/bin/sing-box", "sing-box")
	case "xray":
		return findExecutable("/opt/bin/xray", "/opt/usr/bin/xray", "xray")
	}
	return ""
}
func (a *ProxyTunnelAdapter) sidecarBinary() string {
	if a.SidecarBin != "" {
		return a.SidecarBin
	}
	return findExecutable("/opt/bin/sing-box", "/opt/usr/bin/sing-box", "sing-box")
}
func (a *ProxyTunnelAdapter) ip() string {
	if a.IP != "" {
		return a.IP
	}
	return findExecutable("/opt/sbin/ip", "/opt/bin/ip", "ip")
}
func (a *ProxyTunnelAdapter) engineProcess() ProcessSpec {
	return a.engineProcessWithTransport(a.preferredUsqueTransport())
}

func (a *ProxyTunnelAdapter) engineProcessWithTransport(transport usqueTransport) ProcessSpec {
	return a.engineProcessAt(a.engineConfigPath(), a.SOCKSPort, a.runtimeRoot(), a.ID()+"-engine", transport)
}

func (a *ProxyTunnelAdapter) engineProcessAt(config string, port int, root, processID string, transport usqueTransport) ProcessSpec {
	args := []string{}
	switch a.ID() {
	case "usque":
		// Keep upstream USQUE's default MASQUE transport (QUIC/UDP 443). Hardware
		// tests showed that a TCP socket to the HTTP/2 endpoint can succeed while
		// actual tunneled requests still stall. A separate connectivity check
		// reports TCP/443 as a fallback without mistaking it for a working tunnel.
		args = []string{"-c", config, "socks", "-b", "127.0.0.1", "-p", strconv.Itoa(port), "--always-reconnect", "-S"}
		if transport.SNI != "" {
			args = append(args, "-s", transport.SNI)
		}
		if transport.HTTP2 {
			args = append(args, "--http2")
		}
	case "sing-box":
		args = []string{"run", "-c", config}
	case "xray":
		args = []string{"run", "-config", config}
	}
	return ProcessSpec{ID: processID, Binary: a.engineBinary(), Args: args, Dir: root, PIDPath: filepath.Join(root, "engine.pid"), LogPath: filepath.Join(root, "engine.log"), MatchArg: config}
}

func (a *ProxyTunnelAdapter) transportPath() string {
	return filepath.Join(a.StateRoot, "transport.json")
}

func (a *ProxyTunnelAdapter) evidencePath() string {
	return filepath.Join(a.StateRoot, "evidence.json")
}

func (a *ProxyTunnelAdapter) preferredUsqueTransport() usqueTransport {
	if a.ID() != "usque" {
		return usqueTransport{}
	}
	if data, exists, _ := optionalFile(a.transportPath()); exists {
		var transport usqueTransport
		if json.Unmarshal(data, &transport) == nil {
			return transport
		}
	}
	data, err := os.ReadFile(a.UsqueConfig)
	if err != nil {
		return usqueTransport{}
	}
	return parseUsqueTransport(string(data))
}

func (a *ProxyTunnelAdapter) stagedUsqueTransport(root string) (usqueTransport, error) {
	if a.ID() != "usque" {
		return usqueTransport{}, nil
	}
	data, err := os.ReadFile(filepath.Join(root, "transport.staged.json"))
	if err != nil {
		return usqueTransport{}, errors.New("validated USQUE transport selection is missing")
	}
	var transport usqueTransport
	if err := json.Unmarshal(data, &transport); err != nil {
		return usqueTransport{}, errors.New("validated USQUE transport selection is invalid")
	}
	return transport, nil
}

var safeSNI = regexp.MustCompile(`(?i)^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)

func parseUsqueTransport(content string) usqueTransport {
	transport := usqueTransport{}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
		switch key {
		case "HTTP2_ENABLE":
			transport.HTTP2 = value == "1"
		case "SNI":
			if safeSNI.MatchString(value) {
				transport.SNI = value
			}
		}
	}
	return transport
}

func usqueTransportName(transport usqueTransport) string {
	if transport.HTTP2 {
		return "HTTP/2"
	}
	return "QUIC"
}

func (a *ProxyTunnelAdapter) canaryPort() (int, error) {
	port := a.SOCKSPort + 1000
	if port > 65535 {
		port = a.SOCKSPort - 1000
	}
	if port < 1024 || port > 65535 || port == a.SOCKSPort {
		return 0, errors.New("no safe loopback port is available for proxy canary")
	}
	return port, nil
}

func (a *ProxyTunnelAdapter) packageInitPath() string {
	if a.ID() != "usque" {
		return ""
	}
	if a.PackageInit != "" {
		return a.PackageInit
	}
	const path = "/opt/etc/init.d/S51usque"
	if regularFile(path) {
		return path
	}
	return ""
}

func (a *ProxyTunnelAdapter) packageRuntimeRunning(ctx context.Context) (bool, error) {
	init := a.packageInitPath()
	if init == "" {
		return false, nil
	}
	output, err := a.run(ctx, init, "status")
	if err != nil {
		// The Entware init script may return non-zero for the normal stopped
		// state. Its bounded status output is still authoritative.
		if strings.Contains(strings.ToLower(string(output)), " is stopped") {
			return false, nil
		}
		return false, fmt.Errorf("inspect package %s runtime: %s", a.ID(), shortOutput(output, err))
	}
	return strings.Contains(strings.ToLower(string(output)), " is running"), nil
}

func (a *ProxyTunnelAdapter) stopPackageRuntime(ctx context.Context) error {
	running, err := a.packageRuntimeRunning(ctx)
	if err != nil || !running {
		return err
	}
	init := a.packageInitPath()
	if output, err := a.run(ctx, init, "stop"); err != nil {
		return fmt.Errorf("stop package %s runtime: %s", a.ID(), shortOutput(output, err))
	}
	return nil
}

func (a *ProxyTunnelAdapter) startPackageRuntime(ctx context.Context) error {
	init := a.packageInitPath()
	if init == "" {
		return nil
	}
	if output, err := a.run(ctx, init, "start"); err != nil {
		return fmt.Errorf("restore package %s runtime: %s", a.ID(), shortOutput(output, err))
	}
	return nil
}
func (a *ProxyTunnelAdapter) sidecarProcess() ProcessSpec {
	config := a.sidecarConfigPath()
	return ProcessSpec{ID: a.ID() + "-tun", Binary: a.sidecarBinary(), Args: []string{"run", "-c", config}, Dir: a.runtimeRoot(), PIDPath: filepath.Join(a.runtimeRoot(), "sidecar.pid"), LogPath: filepath.Join(a.runtimeRoot(), "sidecar.log"), MatchArg: config}
}
func (a *ProxyTunnelAdapter) stopOwned(ctx context.Context) error {
	var firstErr error
	if err := a.Processes.Stop(ctx, a.sidecarProcess()); err != nil {
		firstErr = err
	}
	if err := a.Processes.Stop(ctx, a.engineProcess()); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}
func (a *ProxyTunnelAdapter) run(parent context.Context, name string, args ...string) ([]byte, error) {
	if a.Runner == nil || name == "" {
		return nil, errors.New("proxy command runner is unavailable")
	}
	ctx, cancel := context.WithTimeout(parent, a.timeout())
	defer cancel()
	output, err := a.Runner.Run(ctx, name, args...)
	if ctx.Err() == context.DeadlineExceeded {
		return output, errors.New("proxy command timed out")
	}
	return output, err
}
func (a *ProxyTunnelAdapter) waitForSOCKS(ctx context.Context) error {
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(a.SOCKSPort))
	return a.waitForSOCKSProcess(ctx, a.engineProcess(), address)
}

func (a *ProxyTunnelAdapter) waitForSOCKSProcess(ctx context.Context, spec ProcessSpec, address string) error {
	deadline := time.Now().Add(a.timeout())
	probe := a.SOCKSProbe
	if probe == nil {
		probe = probeSOCKS5
	}
	for {
		if !a.Processes.Running(spec) {
			return errors.New("proxy engine exited before SOCKS became ready")
		}
		if err := probe(ctx, address); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("SOCKS endpoint %s did not become ready", address)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}
func (a *ProxyTunnelAdapter) waitForInterface(ctx context.Context) error {
	deadline := time.Now().Add(a.timeout())
	for {
		if !a.Processes.Running(a.sidecarProcess()) {
			return errors.New("TUN sidecar exited before interface became ready")
		}
		if _, err := a.run(ctx, a.ip(), "link", "show", "dev", a.Interface); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("TUN interface %s did not become ready", a.Interface)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}
func (a *ProxyTunnelAdapter) loadPolicy() (PolicyState, bool, error) {
	data, exists, err := optionalFile(a.policyPath())
	if err != nil || !exists {
		return PolicyState{}, exists, err
	}
	var state PolicyState
	if err := json.Unmarshal(data, &state); err != nil {
		return PolicyState{}, true, err
	}
	return state, true, nil
}
func (a *ProxyTunnelAdapter) readStagedPolicy(root string) (PolicyState, error) {
	data, err := os.ReadFile(filepath.Join(root, "policy.staged.json"))
	if err != nil {
		return PolicyState{}, err
	}
	var state PolicyState
	if err := json.Unmarshal(data, &state); err != nil {
		return PolicyState{}, err
	}
	if state.Interface != a.Interface || state.Table != a.Table || state.PriorityBase != a.Priority || len(state.Prefixes) == 0 || len(effectivePolicyRules(state)) > maxPolicyPrefixes {
		return PolicyState{}, errors.New("invalid staged proxy policy ownership")
	}
	return state, nil
}

func readProxySnapshot(root string) (proxySnapshot, error) {
	data, err := os.ReadFile(filepath.Join(root, "snapshot.json"))
	if err != nil {
		return proxySnapshot{}, err
	}
	var snapshot proxySnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return proxySnapshot{}, err
	}
	if snapshot.ConfigPath == "" {
		return proxySnapshot{}, errors.New("invalid proxy snapshot")
	}
	return snapshot, nil
}

func buildProxyCandidate(engineID string, source []byte, port int) ([]byte, []string, error) {
	var document map[string]any
	if err := json.Unmarshal(source, &document); err != nil {
		return nil, nil, fmt.Errorf("invalid %s JSON: %w", engineID, err)
	}
	if len(document) == 0 {
		return nil, nil, fmt.Errorf("%s configuration is empty", engineID)
	}
	endpoints := collectEndpointHosts(document)
	switch engineID {
	case "usque":
		for _, key := range []string{"private_key", "endpoint_pub_key", "id", "access_token"} {
			if strings.TrimSpace(fmt.Sprint(document[key])) == "" || fmt.Sprint(document[key]) == "<nil>" {
				return nil, nil, fmt.Errorf("usque configuration is missing %s", key)
			}
		}
	case "sing-box":
		if _, ok := document["outbounds"].([]any); !ok {
			return nil, nil, errors.New("sing-box configuration has no outbounds")
		}
		document["inbounds"] = []any{map[string]any{"type": "socks", "tag": "rz-engine-in", "listen": "127.0.0.1", "listen_port": port}}
		delete(document, "services")
		delete(document, "experimental")
	case "xray":
		if _, ok := document["outbounds"].([]any); !ok {
			return nil, nil, errors.New("Xray configuration has no outbounds")
		}
		document["inbounds"] = []any{map[string]any{"tag": "rz-engine-in", "listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": map[string]any{"udp": true}}}
	default:
		return nil, nil, fmt.Errorf("unsupported proxy engine %q", engineID)
	}
	data, err := json.MarshalIndent(document, "", "  ")
	return data, endpoints, err
}

func buildSOCKSTunnelConfig(iface, cidr string, port int) ([]byte, error) {
	return buildSOCKSTunnelConfigForSchema(iface, cidr, port, singBoxSidecarSchema{modernAddress: true})
}

type singBoxSidecarSchema struct {
	modernAddress bool
	dnsMode       bool
}

var singBoxVersionPattern = regexp.MustCompile(`(?i)(?:sing-box\s+version\s+|v)(\d+)\.(\d+)(?:\.\d+)?`)

func (a *ProxyTunnelAdapter) detectSidecarSchema(ctx context.Context) (singBoxSidecarSchema, error) {
	binary := a.sidecarBinary()
	if binary == "" {
		return singBoxSidecarSchema{}, errors.New("sing-box is required as the managed TUN sidecar")
	}
	output, err := a.run(ctx, binary, "version")
	if err != nil {
		return singBoxSidecarSchema{}, fmt.Errorf("detect sing-box sidecar version: %s", shortOutput(output, err))
	}
	match := singBoxVersionPattern.FindStringSubmatch(string(output))
	if len(match) != 3 {
		return singBoxSidecarSchema{}, fmt.Errorf("sing-box sidecar version is not recognizable: %s", shortOutput(output, nil))
	}
	major, _ := strconv.Atoi(match[1])
	minor, _ := strconv.Atoi(match[2])
	if major < 1 || (major == 1 && minor < 8) {
		return singBoxSidecarSchema{}, fmt.Errorf("sing-box %d.%d is too old for the managed TUN sidecar; version 1.8 or newer is required", major, minor)
	}
	return singBoxSidecarSchema{modernAddress: major > 1 || minor >= 10, dnsMode: major > 1 || minor >= 14}, nil
}

func buildSOCKSTunnelConfigForSchema(iface, cidr string, port int, schema singBoxSidecarSchema) ([]byte, error) {
	if iface == "" || port < 1024 || port > 65535 {
		return nil, errors.New("invalid SOCKS tunnel settings")
	}
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() > 30 {
		return nil, errors.New("invalid SOCKS tunnel IPv4 prefix")
	}
	inbound := map[string]any{
		"type": "tun", "tag": "rz-tun-in", "interface_name": iface, "mtu": 1280,
		"auto_route": false, "strict_route": false, "stack": "system",
	}
	if schema.modernAddress {
		inbound["address"] = []string{prefix.String()}
	} else {
		inbound["inet4_address"] = []string{prefix.String()}
	}
	// sing-box 1.14 made TUN DNS handling explicit and defaults to hijack.
	// RAZVILKA owns policy routing, not the router DNS plane, so opt out on
	// versions that understand the field while keeping older schemas valid.
	if schema.dnsMode {
		inbound["dns_mode"] = "disabled"
	}
	document := map[string]any{
		"log":       map[string]any{"level": "warn", "timestamp": true},
		"inbounds":  []any{inbound},
		"outbounds": []any{map[string]any{"type": "socks", "tag": "rz-socks-out", "server": "127.0.0.1", "server_port": port, "version": "5"}},
		"route":     map[string]any{"final": "rz-socks-out", "auto_detect_interface": true},
	}
	return json.MarshalIndent(document, "", "  ")
}

func collectEndpointHosts(value any) []string {
	seen := map[string]bool{}
	var walk func(any, string)
	walk = func(current any, key string) {
		switch item := current.(type) {
		case map[string]any:
			for childKey, child := range item {
				walk(child, strings.ToLower(childKey))
			}
		case []any:
			for _, child := range item {
				walk(child, key)
			}
		case string:
			switch key {
			case "server", "address", "endpoint", "endpoint_v4", "endpoint_v6", "endpoint_h2_v4", "endpoint_h2_v6":
				host := strings.Trim(strings.TrimSpace(item), "[]")
				if split, _, err := net.SplitHostPort(host); err == nil {
					host = strings.Trim(split, "[]")
				}
				if host != "" && host != "127.0.0.1" && host != "::1" {
					seen[host] = true
				}
			}
		}
	}
	walk(value, "")
	out := make([]string, 0, len(seen))
	for host := range seen {
		out = append(out, host)
	}
	return sortedUnique(out)
}

func rejectEndpointOverlap(ctx context.Context, prefixes, hosts []string, resolver PrefixResolver) error {
	if resolver == nil {
		resolver = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	parsed := make([]netip.Prefix, 0, len(prefixes))
	for _, value := range prefixes {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return err
		}
		parsed = append(parsed, prefix)
	}
	for _, host := range hosts {
		addresses := []netip.Addr{}
		if address, err := netip.ParseAddr(host); err == nil {
			addresses = append(addresses, address)
		} else if resolved, err := resolver(ctx, host); err == nil {
			addresses = append(addresses, resolved...)
		}
		for _, address := range addresses {
			address = address.Unmap()
			for _, prefix := range parsed {
				if prefix.Contains(address) {
					return fmt.Errorf("proxy endpoint %s overlaps selected service prefix %s; refusing self-tunnel loop", address, prefix)
				}
			}
		}
	}
	return nil
}

func probeSOCKS5(ctx context.Context, address string) error {
	dialer := net.Dialer{Timeout: 2 * time.Second}
	connection, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := connection.Write([]byte{5, 1, 0}); err != nil {
		return err
	}
	reply := make([]byte, 2)
	if _, err := connection.Read(reply); err != nil {
		return err
	}
	if reply[0] != 5 || reply[1] != 0 {
		return fmt.Errorf("unexpected SOCKS5 greeting %v", reply)
	}
	return nil
}

// probeTunnelViaSOCKS proves that the candidate proxy can carry an actual
// service request. Policy rules are validated independently, so this probe
// must not depend on the host resolver choosing IPv4 or IPv6 for the temporary
// TUN interface.
func probeTunnelViaSOCKS(ctx context.Context, rawURL, address string) error {
	response, cleanup, err := socksHTTPGet(ctx, rawURL, address)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, err = strictServiceResponse(rawURL, response)
	return err
}

func probeCloudflareTraceViaSOCKS(ctx context.Context, address string) (usqueCanaryEvidence, error) {
	response, cleanup, err := socksHTTPGet(ctx, "https://www.cloudflare.com/cdn-cgi/trace", address)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		return usqueCanaryEvidence{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return usqueCanaryEvidence{}, fmt.Errorf("Cloudflare trace returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 16*1024))
	if err != nil {
		return usqueCanaryEvidence{}, err
	}
	return parseCloudflareTrace(string(body))
}

func parseCloudflareTrace(body string) (usqueCanaryEvidence, error) {
	values := map[string]string{}
	for _, line := range strings.Split(body, "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), "=", 2)
		if len(parts) == 2 {
			values[strings.ToLower(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	evidence := usqueCanaryEvidence{Warp: strings.ToLower(values["warp"])}
	if value := strings.ToUpper(values["colo"]); regexp.MustCompile(`^[A-Z0-9]{3}$`).MatchString(value) {
		evidence.Colo = value
	}
	if value := strings.ToUpper(values["loc"]); regexp.MustCompile(`^[A-Z]{2}$`).MatchString(value) {
		evidence.Loc = value
	}
	if value := values["ip"]; net.ParseIP(value) != nil {
		evidence.EgressIP = value
	}
	if evidence.Warp == "" {
		return usqueCanaryEvidence{}, errors.New("Cloudflare trace did not include WARP state")
	}
	return evidence, nil
}

func socksHTTPGet(ctx context.Context, rawURL, address string) (*http.Response, func(), error) {
	dialer, err := xnetproxy.SOCKS5("tcp", address, nil, &net.Dialer{Timeout: 5 * time.Second})
	if err != nil {
		return nil, nil, err
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, target string) (net.Conn, error) {
			return dialer.(xnetproxy.ContextDialer).DialContext(ctx, network, target)
		},
		ForceAttemptHTTP2: true,
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		transport.CloseIdleConnections()
		return nil, nil, err
	}
	request.Header.Set("User-Agent", "RAZVILKA-Proxy-Health/1")
	response, err := serviceProbeClient(&http.Client{Transport: transport, Timeout: 15 * time.Second}, rawURL).Do(request)
	if err != nil {
		transport.CloseIdleConnections()
		return nil, nil, err
	}
	return response, transport.CloseIdleConnections, nil
}
