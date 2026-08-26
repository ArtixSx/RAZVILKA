package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/warp"
)

type WARPWireGuardAdapter struct {
	EngineID          string
	Configs           *engineconfig.Manager
	StateRoot         string
	RuntimeConfigPath string
	Interface         string
	Table             int
	PriorityBase      int
	WGQuick           string
	WG                string
	IP                string
	Runner            NFQWS2Runner
	Resolver          PrefixResolver
	HealthProbe       func(context.Context, string) error
	Timeout           time.Duration
	HandshakeTimeout  time.Duration
	FallbackPorts     []int
}

type warpWGSelection struct {
	Endpoint string `json:"endpoint"`
}

type WARPHandshakeError struct {
	Ports []int
}

func (e WARPHandshakeError) Error() string {
	ports := make([]string, 0, len(e.Ports))
	for _, port := range e.Ports {
		ports = append(ports, strconv.Itoa(port))
	}
	if len(ports) == 0 {
		return "WARP WireGuard handshake was not confirmed"
	}
	return "WARP WireGuard handshake was not confirmed on UDP ports " + strings.Join(ports, ", ")
}

type warpWGSnapshot struct {
	ProfilePath        string      `json:"profile_path"`
	ProfileExisted     bool        `json:"profile_existed"`
	Profile            []byte      `json:"profile,omitempty"`
	ProfileDraft       bool        `json:"profile_draft"`
	StagedProfile      []byte      `json:"staged_profile,omitempty"`
	RuntimeExisted     bool        `json:"runtime_existed"`
	RuntimeConfig      []byte      `json:"runtime_config,omitempty"`
	InterfaceWasActive bool        `json:"interface_was_active"`
	StateExisted       bool        `json:"state_existed"`
	State              PolicyState `json:"state"`
}

func NewWARPWireGuardAdapter(configs *engineconfig.Manager, stateRoot string) *WARPWireGuardAdapter {
	runtimeRoot := filepath.Join(stateRoot, "runtime", "warp-wg")
	return &WARPWireGuardAdapter{
		EngineID: "warp-wg", Configs: configs, StateRoot: runtimeRoot, RuntimeConfigPath: filepath.Join(runtimeRoot, "rz-warp.conf"),
		Interface: "rz-warp", Table: 201, PriorityBase: 18100, Runner: nfqws2ExecRunner{}, Timeout: 25 * time.Second,
	}
}

func NewAmneziaWGAdapter(configs *engineconfig.Manager, stateRoot string) *WARPWireGuardAdapter {
	runtimeRoot := filepath.Join(stateRoot, "runtime", "amneziawg")
	return &WARPWireGuardAdapter{
		EngineID: "amneziawg", Configs: configs, StateRoot: runtimeRoot, RuntimeConfigPath: filepath.Join(runtimeRoot, "rz-awg.conf"),
		Interface: "rz-awg", Table: 205, PriorityBase: 26000, Runner: nfqws2ExecRunner{}, Timeout: 25 * time.Second,
	}
}

func (a *WARPWireGuardAdapter) ID() string {
	if a.EngineID == "" {
		return "warp-wg"
	}
	return a.EngineID
}

func (a *WARPWireGuardAdapter) Snapshot(ctx context.Context, plan Plan, root string) error {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	if a.Configs == nil {
		return errors.New("WARP config manager is unavailable")
	}
	content, err := a.Configs.ReadExpert(a.ID(), "main")
	if err != nil {
		return err
	}
	snapshot := warpWGSnapshot{ProfilePath: content.Path, ProfileDraft: planUsesEngineDraft(plan, a.ID(), "main") && content.Source == "staged"}
	snapshot.Profile, snapshot.ProfileExisted, err = optionalFile(content.Path)
	if err != nil {
		return err
	}
	if snapshot.ProfileDraft {
		snapshot.StagedProfile = []byte(content.Content)
	}
	snapshot.RuntimeConfig, snapshot.RuntimeExisted, err = optionalFile(a.RuntimeConfigPath)
	if err != nil {
		return err
	}
	snapshot.State, snapshot.StateExisted, err = a.loadPolicyState()
	if err != nil {
		return err
	}
	snapshot.InterfaceWasActive = a.interfaceActive(ctx)
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(root, "snapshot.json"), data, 0o600)
}

func (a *WARPWireGuardAdapter) Stage(ctx context.Context, plan Plan, root string) error {
	snapshot, err := readWarpWGSnapshot(root)
	if err != nil {
		return err
	}
	profile := snapshot.Profile
	if snapshot.ProfileDraft {
		profile = snapshot.StagedProfile
	}
	if len(profile) == 0 {
		return errors.New("WARP WireGuard profile is missing")
	}
	profileText := string(profile)
	if err := warp.ValidateProfile(profile); err != nil {
		return err
	}
	if a.ID() == "amneziawg" {
		if err := validateAmneziaProfile(profileText); err != nil {
			return err
		}
	}
	runtimeProfile, err := sanitizeWGQuickProfile(profileText)
	if err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(root, "rz-warp.conf.staged"), []byte(runtimeProfile), 0o600); err != nil {
		return err
	}
	prefixes, rules, err := resolvePolicyRules(ctx, plan, a.ID(), a.Resolver)
	if err != nil {
		return err
	}
	prefixes, err = excludeWGEndpoint(ctx, prefixes, profileText, a.Resolver)
	if err != nil {
		return err
	}
	if len(prefixes) == 0 {
		return errors.New("WARP policy has no service prefixes after endpoint exclusion")
	}
	state := PolicyState{Interface: a.interfaceName(), Table: a.table(), PriorityBase: a.priorityBase(), Prefixes: prefixes, Rules: rules}
	data, _ := json.MarshalIndent(state, "", "  ")
	return writeAtomic(filepath.Join(root, "policy.staged.json"), data, 0o600)
}

func (a *WARPWireGuardAdapter) Validate(ctx context.Context, _ Plan, root string) error {
	for _, path := range []string{filepath.Join(root, "rz-warp.conf.staged"), filepath.Join(root, "policy.staged.json")} {
		if !regularFile(path) {
			return fmt.Errorf("WARP transaction file is missing: %s", path)
		}
	}
	if err := warp.ValidateProfile(mustRead(filepath.Join(root, "rz-warp.conf.staged"))); err != nil {
		return err
	}
	if a.ID() == "amneziawg" {
		if err := validateAmneziaProfile(string(mustRead(filepath.Join(root, "rz-warp.conf.staged")))); err != nil {
			return err
		}
	}
	if a.wg() == "" || a.ip() == "" {
		return errors.New("wg and ip are required for WARP WireGuard")
	}
	snapshot, err := readWarpWGSnapshot(root)
	if err != nil {
		return err
	}
	if snapshot.InterfaceWasActive && !snapshot.StateExisted {
		return fmt.Errorf("interface %s already exists without RAZVILKA ownership state", a.interfaceName())
	}
	if _, err := a.readStagedPolicy(root); err != nil {
		return err
	}
	return ctx.Err()
}

func (a *WARPWireGuardAdapter) Activate(ctx context.Context, _ Plan, root string) error {
	snapshot, err := readWarpWGSnapshot(root)
	if err != nil {
		return err
	}
	if snapshot.StateExisted {
		if err := removePolicy(ctx, a.Runner, a.ip(), snapshot.State); err != nil {
			return fmt.Errorf("remove previous WARP policy: %w", err)
		}
	}
	if snapshot.InterfaceWasActive {
		if err := a.stopInterface(ctx); err != nil {
			return fmt.Errorf("stop previous WARP interface: %w", err)
		}
	}
	if err := installStaged(filepath.Join(root, "rz-warp.conf.staged"), a.RuntimeConfigPath); err != nil {
		return err
	}
	if err := a.startInterface(ctx); err != nil {
		return fmt.Errorf("start WARP interface: %w", err)
	}
	state, err := a.readStagedPolicy(root)
	if err != nil {
		return err
	}
	if err := applyPolicy(ctx, a.Runner, a.ip(), state); err != nil {
		return err
	}
	return nil
}

func (a *WARPWireGuardAdapter) Health(ctx context.Context, plan Plan, root string) error {
	state, err := a.readStagedPolicy(root)
	if err != nil {
		return err
	}
	return a.healthState(ctx, plan, state, root)
}

func (a *WARPWireGuardAdapter) healthState(ctx context.Context, plan Plan, state PolicyState, transactionRoot string) error {
	if !a.interfaceActive(ctx) {
		return fmt.Errorf("WARP interface %s is not active", state.Interface)
	}
	if err := verifyPolicyEvidence(ctx, a.Runner, a.ip(), state); err != nil {
		return err
	}
	// Confirm the tunnel itself before attributing a timeout to the selected
	// service. This produces an actionable handshake error instead of making
	// every unreachable endpoint look like a service-specific failure.
	if err := a.confirmHandshake(ctx, state.Interface); err != nil {
		if a.ID() != "warp-wg" || transactionRoot == "" {
			return err
		}
		ports, portErr := a.warpEndpointPorts()
		if portErr != nil {
			return portErr
		}
		attempted := []int{ports[0]}
		connected := false
		for _, port := range ports[1:] {
			attempted = append(attempted, port)
			endpoint, switchErr := a.switchEndpointPort(ctx, port)
			if switchErr != nil {
				continue
			}
			if handshakeErr := a.confirmHandshake(ctx, state.Interface); handshakeErr != nil {
				continue
			}
			selection, _ := json.Marshal(warpWGSelection{Endpoint: endpoint})
			if writeErr := writeAtomic(filepath.Join(transactionRoot, "selected-endpoint.json"), selection, 0o600); writeErr != nil {
				return writeErr
			}
			connected = true
			break
		}
		if !connected {
			return WARPHandshakeError{Ports: attempted}
		}
	}
	probe := a.HealthProbe
	if probe == nil {
		probe = defaultTunnelProbe
	}
	for _, route := range plan.Routes {
		if adapterID(route.Resolved) != a.ID() || route.ProbeURL == "" || len(route.Sources) > 0 {
			continue
		}
		probeCtx, cancel := context.WithTimeout(ctx, a.timeout())
		err := probe(probeCtx, route.ProbeURL)
		cancel()
		if err != nil {
			return fmt.Errorf("%s WARP health probe: %w", route.ServiceName, err)
		}
	}
	return nil
}

func (a *WARPWireGuardAdapter) Reconcile(ctx context.Context, plan Plan) error {
	state, exists, err := a.loadPolicyState()
	if err != nil {
		return err
	}
	if !exists || !regularFile(a.RuntimeConfigPath) {
		return fmt.Errorf("committed %s runtime state is missing", a.ID())
	}
	if a.interfaceActive(ctx) {
		if err := a.healthState(ctx, plan, state, ""); err == nil {
			return nil
		}
	}
	_ = removePolicy(ctx, a.Runner, a.ip(), state)
	if a.interfaceActive(ctx) {
		if err := a.stopInterface(ctx); err != nil {
			return fmt.Errorf("stop stale %s interface: %w", a.ID(), err)
		}
	}
	if err := a.startInterface(ctx); err != nil {
		return fmt.Errorf("recover %s interface: %w", a.ID(), err)
	}
	if err := applyPolicy(ctx, a.Runner, a.ip(), state); err != nil {
		_ = a.stopInterface(ctx)
		return err
	}
	if err := a.healthState(ctx, plan, state, ""); err != nil {
		_ = removePolicy(ctx, a.Runner, a.ip(), state)
		_ = a.stopInterface(ctx)
		return err
	}
	return nil
}

func (a *WARPWireGuardAdapter) RefreshPolicy(ctx context.Context, plan Plan) (bool, error) {
	oldState, exists, err := a.loadPolicyState()
	if err != nil || !exists {
		return false, err
	}
	prefixes, rules, err := resolvePolicyRules(ctx, plan, a.ID(), a.Resolver)
	if err != nil {
		return false, err
	}
	profile, err := os.ReadFile(a.RuntimeConfigPath)
	if err != nil {
		return false, err
	}
	if prefixes, err = excludeWGEndpoint(ctx, prefixes, string(profile), a.Resolver); err != nil {
		return false, err
	}
	newState := PolicyState{Interface: a.interfaceName(), Table: a.table(), PriorityBase: a.priorityBase(), Prefixes: prefixes, Rules: rules}
	if samePolicy(oldState, newState) {
		return false, nil
	}
	if err := replacePolicy(ctx, a.Runner, a.ip(), oldState, newState); err != nil {
		return false, err
	}
	if err := a.healthState(ctx, plan, newState, ""); err != nil {
		_ = replacePolicy(ctx, a.Runner, a.ip(), newState, oldState)
		return false, err
	}
	data, _ := json.MarshalIndent(newState, "", "  ")
	if err := writeAtomic(a.statePath(), data, 0o600); err != nil {
		_ = replacePolicy(ctx, a.Runner, a.ip(), newState, oldState)
		return false, err
	}
	return true, nil
}

func (a *WARPWireGuardAdapter) Deactivate(ctx context.Context) error {
	var firstErr error
	if state, exists, err := a.loadPolicyState(); err != nil {
		firstErr = err
	} else if exists {
		if err := removePolicy(ctx, a.Runner, a.ip(), state); err != nil {
			firstErr = err
		}
	}
	if a.interfaceActive(ctx) {
		if err := a.stopInterface(ctx); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("stop %s interface: %w", a.ID(), err)
		}
	}
	for _, path := range []string{a.statePath(), a.RuntimeConfigPath} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (a *WARPWireGuardAdapter) Commit(_ context.Context, _ Plan, root string) error {
	snapshot, err := readWarpWGSnapshot(root)
	if err != nil {
		return err
	}
	profile := snapshot.Profile
	if snapshot.ProfileDraft {
		profile = snapshot.StagedProfile
	}
	selection, selected, err := readWarpWGSelection(root)
	if err != nil {
		return err
	}
	if selected {
		profile, err = replaceWGEndpoint(profile, selection.Endpoint)
		if err != nil {
			return err
		}
	}
	if snapshot.ProfileDraft || selected {
		if err := installStagedBytes(profile, snapshot.ProfilePath, 0o600); err != nil {
			return err
		}
	}
	if snapshot.ProfileDraft {
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
	return writeAtomic(a.statePath(), data, 0o600)
}

func (a *WARPWireGuardAdapter) Rollback(ctx context.Context, _ Plan, root string) error {
	snapshot, err := readWarpWGSnapshot(root)
	if err != nil {
		return err
	}
	var firstErr error
	if desired, readErr := a.readStagedPolicy(root); readErr == nil {
		if err := removePolicy(ctx, a.Runner, a.ip(), desired); err != nil {
			firstErr = err
		}
	}
	if a.interfaceActive(ctx) {
		if err := a.stopInterface(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if err := restoreOptional(a.RuntimeConfigPath, snapshot.RuntimeConfig, snapshot.RuntimeExisted); err != nil && firstErr == nil {
		firstErr = err
	}
	if snapshot.InterfaceWasActive && snapshot.RuntimeExisted {
		if err := a.startInterface(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if snapshot.StateExisted {
		if err := applyPolicy(ctx, a.Runner, a.ip(), snapshot.State); err != nil && firstErr == nil {
			firstErr = err
		}
		data, _ := json.MarshalIndent(snapshot.State, "", "  ")
		if err := os.MkdirAll(a.StateRoot, 0o700); err == nil {
			_ = writeAtomic(a.statePath(), data, 0o600)
		}
	} else {
		_ = os.Remove(a.statePath())
	}
	if err := restoreOptional(snapshot.ProfilePath, snapshot.Profile, snapshot.ProfileExisted); err != nil && firstErr == nil {
		firstErr = err
	}
	if snapshot.ProfileDraft {
		if _, err := a.Configs.Stage(a.ID(), "main", string(snapshot.StagedProfile)); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (a *WARPWireGuardAdapter) loadPolicyState() (PolicyState, bool, error) {
	data, existed, err := optionalFile(a.statePath())
	if err != nil || !existed {
		return PolicyState{}, existed, err
	}
	var state PolicyState
	if err := json.Unmarshal(data, &state); err != nil {
		return PolicyState{}, true, fmt.Errorf("decode WARP ownership state: %w", err)
	}
	return state, true, nil
}

func (a *WARPWireGuardAdapter) readStagedPolicy(root string) (PolicyState, error) {
	data, err := os.ReadFile(filepath.Join(root, "policy.staged.json"))
	if err != nil {
		return PolicyState{}, err
	}
	var state PolicyState
	if err := json.Unmarshal(data, &state); err != nil {
		return PolicyState{}, err
	}
	if state.Interface != a.interfaceName() || state.Table != a.table() || state.PriorityBase != a.priorityBase() || len(state.Prefixes) == 0 || len(effectivePolicyRules(state)) > maxPolicyPrefixes {
		return PolicyState{}, errors.New("invalid staged WARP policy ownership")
	}
	return state, nil
}

func (a *WARPWireGuardAdapter) statePath() string { return filepath.Join(a.StateRoot, "policy.json") }
func (a *WARPWireGuardAdapter) interfaceName() string {
	if a.Interface == "" {
		return "rz-warp"
	}
	return a.Interface
}
func (a *WARPWireGuardAdapter) table() int {
	if a.Table == 0 {
		return 201
	}
	return a.Table
}
func (a *WARPWireGuardAdapter) priorityBase() int {
	if a.PriorityBase == 0 {
		return 18100
	}
	return a.PriorityBase
}
func (a *WARPWireGuardAdapter) timeout() time.Duration {
	if a.Timeout <= 0 {
		return 25 * time.Second
	}
	return a.Timeout
}
func (a *WARPWireGuardAdapter) handshakeTimeout() time.Duration {
	if a.HandshakeTimeout <= 0 {
		return 8 * time.Second
	}
	return a.HandshakeTimeout
}

func (a *WARPWireGuardAdapter) confirmHandshake(ctx context.Context, interfaceName string) error {
	deadline := time.Now().Add(a.handshakeTimeout())
	for {
		output, commandErr := a.run(ctx, a.wg(), "show", interfaceName, "latest-handshakes")
		if commandErr == nil && latestHandshakeOK(string(output), time.Now()) {
			return nil
		}
		if time.Now().After(deadline) {
			return WARPHandshakeError{}
		}
		delay := 500 * time.Millisecond
		if remaining := time.Until(deadline); remaining < delay {
			delay = remaining
		}
		if delay <= 0 {
			return WARPHandshakeError{}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}
}

func (a *WARPWireGuardAdapter) warpEndpointPorts() ([]int, error) {
	content, err := os.ReadFile(a.RuntimeConfigPath)
	if err != nil {
		return nil, err
	}
	endpoint, err := wgEndpoint(string(content))
	if err != nil {
		return nil, err
	}
	_, portText, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, errors.New("invalid WireGuard endpoint")
	}
	configured, err := strconv.Atoi(portText)
	if err != nil || configured < 1 || configured > 65535 {
		return nil, errors.New("invalid WireGuard endpoint port")
	}
	fallback := a.FallbackPorts
	if fallback == nil {
		fallback = []int{2408, 500, 1701, 4500}
	}
	ports := []int{configured}
	seen := map[int]bool{configured: true}
	for _, port := range fallback {
		if port < 1 || port > 65535 || seen[port] {
			continue
		}
		seen[port] = true
		ports = append(ports, port)
	}
	return ports, nil
}

func (a *WARPWireGuardAdapter) switchEndpointPort(ctx context.Context, port int) (string, error) {
	content, err := os.ReadFile(a.RuntimeConfigPath)
	if err != nil {
		return "", err
	}
	current, err := wgEndpoint(string(content))
	if err != nil {
		return "", err
	}
	host, _, err := net.SplitHostPort(current)
	if err != nil {
		return "", errors.New("invalid WireGuard endpoint")
	}
	endpoint := net.JoinHostPort(strings.Trim(host, "[]"), strconv.Itoa(port))
	updated, err := replaceWGEndpoint(content, endpoint)
	if err != nil {
		return "", err
	}
	if a.interfaceActive(ctx) {
		if err := a.stopInterface(ctx); err != nil {
			return "", err
		}
	}
	if err := writeAtomic(a.RuntimeConfigPath, updated, 0o600); err != nil {
		return "", err
	}
	if err := a.startInterface(ctx); err != nil {
		return "", err
	}
	return endpoint, nil
}
func (a *WARPWireGuardAdapter) wgQuick() string {
	if a.WGQuick != "" {
		return a.WGQuick
	}
	if a.ID() == "amneziawg" {
		return findExecutable("/opt/bin/awg-quick", "/opt/usr/bin/awg-quick", "/usr/bin/awg-quick", "awg-quick")
	}
	return findExecutable("/opt/bin/wg-quick", "/opt/usr/bin/wg-quick", "wg-quick")
}
func (a *WARPWireGuardAdapter) wg() string {
	if a.WG != "" {
		return a.WG
	}
	if a.ID() == "amneziawg" {
		return findExecutable("/opt/bin/awg", "/opt/usr/bin/awg", "/usr/bin/awg", "awg")
	}
	return findExecutable("/opt/bin/wg", "/opt/usr/bin/wg", "wg")
}
func (a *WARPWireGuardAdapter) ip() string {
	if a.IP != "" {
		return a.IP
	}
	return findExecutable("/opt/sbin/ip", "/opt/bin/ip", "ip")
}
func (a *WARPWireGuardAdapter) run(parent context.Context, name string, args ...string) ([]byte, error) {
	if a.Runner == nil || name == "" {
		return nil, errors.New("WARP command runner is unavailable")
	}
	ctx, cancel := context.WithTimeout(parent, a.timeout())
	defer cancel()
	output, err := a.Runner.Run(ctx, name, args...)
	if ctx.Err() == context.DeadlineExceeded {
		return output, errors.New("WARP command timed out")
	}
	return output, err
}
func (a *WARPWireGuardAdapter) interfaceActive(ctx context.Context) bool {
	if a.ip() == "" {
		return false
	}
	_, err := a.run(ctx, a.ip(), "link", "show", "dev", a.interfaceName())
	return err == nil
}

func (a *WARPWireGuardAdapter) startInterface(ctx context.Context) error {
	if quick := a.wgQuick(); quick != "" {
		output, err := a.run(ctx, quick, "up", a.RuntimeConfigPath)
		if err != nil {
			return fmt.Errorf("wg-quick up: %s", shortOutput(output, err))
		}
		return nil
	}
	return a.startNativeInterface(ctx)
}

func (a *WARPWireGuardAdapter) stopInterface(ctx context.Context) error {
	if quick := a.wgQuick(); quick != "" && regularFile(a.RuntimeConfigPath) {
		if output, err := a.run(ctx, quick, "down", a.RuntimeConfigPath); err == nil {
			return nil
		} else if deleteOutput, deleteErr := a.run(ctx, a.ip(), "link", "delete", "dev", a.interfaceName()); deleteErr != nil {
			return fmt.Errorf("wg-quick down: %s; native fallback: %s", shortOutput(output, err), shortOutput(deleteOutput, deleteErr))
		}
		return nil
	}
	output, err := a.run(ctx, a.ip(), "link", "delete", "dev", a.interfaceName())
	if err != nil {
		return fmt.Errorf("delete interface: %s", shortOutput(output, err))
	}
	return nil
}

// startNativeInterface is the BusyBox/Entware fallback. Entware ships the wg
// binary on several Keenetic targets without the optional wg-quick shell
// helper. Only the exact RAZVILKA-owned interface is created, while service
// routing remains managed separately by the policy transaction.
func (a *WARPWireGuardAdapter) startNativeInterface(ctx context.Context) (retErr error) {
	content, err := os.ReadFile(a.RuntimeConfigPath)
	if err != nil {
		return err
	}
	setconf, addresses, mtu, err := nativeWGConfig(string(content))
	if err != nil {
		return err
	}
	temporary := a.RuntimeConfigPath + ".setconf"
	if err := writeAtomic(temporary, []byte(setconf), 0o600); err != nil {
		return err
	}
	defer os.Remove(temporary)
	if output, err := a.run(ctx, a.ip(), "link", "add", "dev", a.interfaceName(), "type", "wireguard"); err != nil {
		return fmt.Errorf("create interface: %s", shortOutput(output, err))
	}
	defer func() {
		if retErr != nil {
			_, _ = a.run(ctx, a.ip(), "link", "delete", "dev", a.interfaceName())
		}
	}()
	if output, err := a.run(ctx, a.wg(), "setconf", a.interfaceName(), temporary); err != nil {
		return fmt.Errorf("wg setconf: %s", shortOutput(output, err))
	}
	for _, address := range addresses {
		if output, err := a.run(ctx, a.ip(), "address", "add", address, "dev", a.interfaceName()); err != nil {
			return fmt.Errorf("assign address %s: %s", address, shortOutput(output, err))
		}
	}
	if mtu > 0 {
		if output, err := a.run(ctx, a.ip(), "link", "set", "dev", a.interfaceName(), "mtu", strconv.Itoa(mtu)); err != nil {
			return fmt.Errorf("set MTU: %s", shortOutput(output, err))
		}
	}
	if output, err := a.run(ctx, a.ip(), "link", "set", "dev", a.interfaceName(), "up"); err != nil {
		return fmt.Errorf("bring interface up: %s", shortOutput(output, err))
	}
	return nil
}

func nativeWGConfig(content string) (string, []string, int, error) {
	if err := warp.ValidateProfile([]byte(content)); err != nil {
		return "", nil, 0, err
	}
	section := ""
	addresses := []string{}
	mtu := 0
	setconf := make([]string, 0, 16)
	for _, line := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = strings.TrimSpace(trimmed[1 : len(trimmed)-1])
			setconf = append(setconf, trimmed)
			continue
		}
		key, value, assigned := strings.Cut(trimmed, "=")
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if section == "Interface" && assigned {
			switch strings.ToLower(key) {
			case "address":
				for _, address := range splitCommaValues(value) {
					if _, _, err := net.ParseCIDR(address); err != nil {
						return "", nil, 0, fmt.Errorf("invalid interface address %q", address)
					}
					addresses = append(addresses, address)
				}
				continue
			case "mtu":
				parsed, err := strconv.Atoi(value)
				if err != nil || parsed < 576 || parsed > 9000 {
					return "", nil, 0, fmt.Errorf("invalid MTU %q", value)
				}
				mtu = parsed
				continue
			case "dns", "table", "preup", "postup", "predown", "postdown", "saveconfig":
				continue
			}
		}
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") && !strings.HasPrefix(trimmed, ";") {
			setconf = append(setconf, trimmed)
		}
	}
	if len(addresses) == 0 {
		return "", nil, 0, errors.New("WARP interface has no addresses")
	}
	return strings.Join(setconf, "\n") + "\n", addresses, mtu, nil
}

func splitCommaValues(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func readWarpWGSnapshot(root string) (warpWGSnapshot, error) {
	data, err := os.ReadFile(filepath.Join(root, "snapshot.json"))
	if err != nil {
		return warpWGSnapshot{}, err
	}
	var snapshot warpWGSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return warpWGSnapshot{}, err
	}
	return snapshot, nil
}

func readWarpWGSelection(root string) (warpWGSelection, bool, error) {
	data, err := os.ReadFile(filepath.Join(root, "selected-endpoint.json"))
	if errors.Is(err, os.ErrNotExist) {
		return warpWGSelection{}, false, nil
	}
	if err != nil {
		return warpWGSelection{}, false, err
	}
	var selection warpWGSelection
	if err := json.Unmarshal(data, &selection); err != nil {
		return warpWGSelection{}, false, err
	}
	if _, _, err := net.SplitHostPort(selection.Endpoint); err != nil {
		return warpWGSelection{}, false, errors.New("invalid selected WireGuard endpoint")
	}
	return selection, true, nil
}

func wgEndpoint(content string) (string, error) {
	section := ""
	for _, line := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = strings.TrimSpace(trimmed[1 : len(trimmed)-1])
			continue
		}
		key, value, ok := strings.Cut(trimmed, "=")
		if ok && section == "Peer" && strings.EqualFold(strings.TrimSpace(key), "Endpoint") {
			endpoint := strings.TrimSpace(value)
			if _, _, err := net.SplitHostPort(endpoint); err != nil {
				return "", errors.New("invalid WireGuard endpoint")
			}
			return endpoint, nil
		}
	}
	return "", errors.New("WireGuard endpoint is missing")
}

func replaceWGEndpoint(content []byte, endpoint string) ([]byte, error) {
	if _, _, err := net.SplitHostPort(endpoint); err != nil {
		return nil, errors.New("invalid WireGuard endpoint")
	}
	lines := strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n")
	section := ""
	replaced := false
	for index, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = strings.TrimSpace(trimmed[1 : len(trimmed)-1])
			continue
		}
		key, _, ok := strings.Cut(trimmed, "=")
		if ok && section == "Peer" && strings.EqualFold(strings.TrimSpace(key), "Endpoint") {
			indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
			lines[index] = indent + "Endpoint = " + endpoint
			replaced = true
			break
		}
	}
	if !replaced {
		return nil, errors.New("WireGuard endpoint is missing")
	}
	return []byte(strings.TrimRight(strings.Join(lines, "\n"), "\n") + "\n"), nil
}

func sanitizeWGQuickProfile(content string) (string, error) {
	if err := warp.ValidateProfile([]byte(content)); err != nil {
		return "", err
	}
	lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	section := ""
	out := make([]string, 0, len(lines)+1)
	tableWritten := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			if section == "Interface" && !tableWritten {
				out = append(out, "Table = off")
				tableWritten = true
			}
			section = strings.TrimSpace(trimmed[1 : len(trimmed)-1])
			out = append(out, line)
			continue
		}
		key, _, hasAssignment := strings.Cut(trimmed, "=")
		key = strings.TrimSpace(key)
		if section == "Interface" && hasAssignment {
			switch strings.ToLower(key) {
			case "preup", "postup", "predown", "postdown", "saveconfig", "dns":
				continue
			case "table":
				if !tableWritten {
					out = append(out, "Table = off")
					tableWritten = true
				}
				continue
			}
		}
		out = append(out, line)
	}
	if section == "Interface" && !tableWritten {
		out = append(out, "Table = off")
	}
	return strings.TrimRight(strings.Join(out, "\n"), "\n") + "\n", nil
}

func excludeWGEndpoint(ctx context.Context, prefixes []string, profile string, resolver PrefixResolver) ([]string, error) {
	endpoint := ""
	section := ""
	for _, line := range strings.Split(profile, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = strings.TrimSpace(trimmed[1 : len(trimmed)-1])
			continue
		}
		key, value, ok := strings.Cut(trimmed, "=")
		if ok && section == "Peer" && strings.EqualFold(strings.TrimSpace(key), "Endpoint") {
			endpoint = strings.TrimSpace(value)
			break
		}
	}
	host, _, splitErr := net.SplitHostPort(endpoint)
	if splitErr != nil || host == "" {
		return nil, errors.New("invalid WireGuard endpoint")
	}
	host = strings.Trim(host, "[]")
	address, parseErr := netip.ParseAddr(host)
	addresses := []netip.Addr{}
	if parseErr == nil {
		addresses = append(addresses, address)
	} else {
		if resolver == nil {
			resolver = func(ctx context.Context, host string) ([]netip.Addr, error) {
				return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
			}
		}
		resolved, err := resolver(ctx, host)
		if err != nil || len(resolved) == 0 {
			return nil, fmt.Errorf("resolve WireGuard endpoint %s: %w", host, err)
		}
		addresses = append(addresses, resolved...)
	}
	excluded := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if address.IsValid() {
			excluded = append(excluded, address)
		}
	}
	out := make([]string, 0, len(prefixes))
	for _, value := range prefixes {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, err
		}
		for _, address := range excluded {
			if prefix.Contains(address) {
				return nil, fmt.Errorf("WireGuard endpoint %s overlaps selected service prefix %s; refusing self-tunnel loop", address, prefix)
			}
		}
		out = append(out, value)
	}
	return out, nil
}

func latestHandshakeOK(output string, now time.Time) bool {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		seconds, err := strconv.ParseInt(fields[len(fields)-1], 10, 64)
		if err == nil && seconds > 0 && now.Sub(time.Unix(seconds, 0)) < 5*time.Minute {
			return true
		}
	}
	return false
}

func validateAmneziaProfile(content string) error {
	values := map[string]string{}
	section := ""
	for _, line := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if ok && section == "Interface" {
			values[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
		}
	}
	parse := func(key string, maximum uint64) (uint64, error) {
		value := strings.TrimSpace(values[strings.ToLower(key)])
		if value == "" {
			return 0, nil
		}
		number, err := strconv.ParseUint(value, 10, 32)
		if err != nil || number > maximum {
			return 0, fmt.Errorf("AmneziaWG %s must be an integer from 0 to %d", key, maximum)
		}
		return number, nil
	}
	jc, err := parse("Jc", 128)
	if err != nil {
		return err
	}
	jmin, err := parse("Jmin", 65535)
	if err != nil {
		return err
	}
	jmax, err := parse("Jmax", 65535)
	if err != nil {
		return err
	}
	if jc > 0 && (jmin == 0 || jmax == 0 || jmin > jmax) {
		return errors.New("AmneziaWG requires 0 < Jmin <= Jmax when Jc is enabled")
	}
	for _, key := range []string{"S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4"} {
		if _, err := parse(key, 1<<32-1); err != nil {
			return err
		}
	}
	return nil
}

func defaultTunnelProbe(ctx context.Context, rawURL string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	request.Header.Set("User-Agent", "RAZVILKA-Tunnel-Health/1")
	client := &http.Client{Timeout: 15 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode >= 500 {
		return fmt.Errorf("HTTP %d", response.StatusCode)
	}
	return nil
}

func mustRead(path string) []byte {
	data, _ := os.ReadFile(path)
	return data
}

func installStagedBytes(data []byte, destination string, mode os.FileMode) error {
	if len(data) == 0 {
		return errors.New("staged data is empty")
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	return writeAtomic(destination, data, mode)
}
