package dataplane

import (
	"bytes"
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

	"github.com/ArtixSx/razvilka/internal/awgprofile"
	"github.com/ArtixSx/razvilka/internal/cloudflareprovider"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/netresolve"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/warp"
)

type WARPWireGuardAdapter struct {
	EngineID             string
	Configs              *engineconfig.Manager
	StateRoot            string
	RuntimeConfigPath    string
	Interface            string
	Table                int
	PriorityBase         int
	WGQuick              string
	WG                   string
	IP                   string
	Runner               NFQWS2Runner
	Resolver             PrefixResolver
	HealthProbe          func(context.Context, string) error
	CanaryProbe          func(context.Context, string, string) error
	Timeout              time.Duration
	HandshakeTimeout     time.Duration
	FallbackPorts        []int
	NativeOnly           bool
	AWGCapabilities      func(context.Context) awgprofile.Capabilities
	Profiles             WireGuardProfileProvider
	EndpointResolver     WGEndpointResolver
	EndpointNow          func() time.Time
	activeEndpoint       *WGEndpointState
	isolatedCandidate    bool
	policyReceiptOptions policyAdditionOptions // package-test fault/boot seam; production leaves zero
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
	NamedProfileID       string                 `json:"named_profile_id,omitempty"`
	NamedProfileRevision string                 `json:"named_profile_revision,omitempty"`
	ProfilePath          string                 `json:"profile_path"`
	ProfileExisted       bool                   `json:"profile_existed"`
	Profile              []byte                 `json:"profile,omitempty"`
	ProfileDraft         bool                   `json:"profile_draft"`
	StagedProfile        []byte                 `json:"staged_profile,omitempty"`
	RuntimeExisted       bool                   `json:"runtime_existed"`
	RuntimeConfig        []byte                 `json:"runtime_config,omitempty"`
	InterfaceWasActive   bool                   `json:"interface_was_active"`
	StateExisted         bool                   `json:"state_existed"`
	State                PolicyState            `json:"state"`
	PolicyGeneration     *warpWGPolicyReference `json:"policy_generation,omitempty"`
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

// NewWireGuardAdapter manages an ordinary WireGuard client profile of the
// owner's own server. It shares the WARP/AWG lifecycle but needs no Cloudflare
// registration, never switches to WARP fallback ports and probes connectivity
// by handshake and the selected services, not by a Cloudflare endpoint.
func NewWireGuardAdapter(configs *engineconfig.Manager, stateRoot string) *WARPWireGuardAdapter {
	runtimeRoot := filepath.Join(stateRoot, "runtime", "wireguard")
	return &WARPWireGuardAdapter{
		EngineID: "wireguard", Configs: configs, StateRoot: runtimeRoot, RuntimeConfigPath: filepath.Join(runtimeRoot, "rz-wg.conf"),
		Interface: "rz-wg", Table: 206, PriorityBase: 28000, Runner: nfqws2ExecRunner{}, Timeout: 25 * time.Second, NativeOnly: true,
	}
}

func (a *WARPWireGuardAdapter) ID() string {
	if a.EngineID == "" {
		return "warp-wg"
	}
	return a.EngineID
}

func (a *WARPWireGuardAdapter) Snapshot(ctx context.Context, plan Plan, root string) (retErr error) {
	ctx, retErr = a.namedProfileReviewContext(ctx, plan.Routes)
	if retErr != nil {
		return retErr
	}
	defer func() { retErr = errors.Join(retErr, checkWGNamedReviewContext(ctx)) }()
	if err := a.checkWGPolicyOperation(); err != nil {
		return err
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	var snapshot warpWGSnapshot
	var err error
	profileID := "main"
	if a.ID() == "wireguard" {
		profileID, err = selectedWireGuardProfile(plan)
		if err != nil {
			return err
		}
	}
	if profileID != "main" && profileID != "" {
		if a.Profiles == nil {
			return errors.New("named WireGuard profile provider is unavailable")
		}
		p, err := a.Profiles.Get(ctx, profileID)
		if err != nil {
			return err
		}
		snapshot.Profile = []byte(p.Config())
		snapshot.NamedProfileID, snapshot.NamedProfileRevision = profileID, p.Public().Revision
	} else {
		if a.Configs == nil {
			return errors.New("WireGuard config manager is unavailable")
		}
		content, readErr := a.Configs.ReadExpert(a.ID(), "main")
		if readErr != nil {
			return readErr
		}
		snapshot.ProfilePath, snapshot.ProfileDraft = content.Path, planUsesEngineDraft(plan, a.ID(), "main") && content.Source == "staged"
		snapshot.Profile, snapshot.ProfileExisted, err = optionalFile(content.Path)
		if err != nil {
			return err
		}
		if snapshot.ProfileDraft {
			snapshot.StagedProfile = []byte(content.Content)
		}
	}
	snapshot.RuntimeConfig, snapshot.RuntimeExisted, err = optionalFile(a.RuntimeConfigPath)
	if err != nil {
		return err
	}
	snapshot.State, snapshot.StateExisted, err = a.loadPolicyState()
	if err != nil {
		return err
	}
	if snapshot.StateExisted {
		ref, err := a.committedWGPolicyReference(snapshot.State)
		if err != nil {
			return err
		}
		snapshot.PolicyGeneration = &ref
	}
	snapshot.InterfaceWasActive = a.interfaceActive(ctx)
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	if err := checkWGNamedReviewContext(ctx); err != nil {
		return err
	}
	return writeAtomic(filepath.Join(root, "snapshot.json"), data, 0o600)
}

func (a *WARPWireGuardAdapter) Stage(ctx context.Context, plan Plan, root string) (retErr error) {
	ctx, retErr = a.namedProfileReviewContext(ctx, plan.Routes)
	if retErr != nil {
		return retErr
	}
	defer func() { retErr = errors.Join(retErr, checkWGNamedReviewContext(ctx)) }()
	snapshot, err := readWarpWGSnapshot(root)
	if err != nil {
		return err
	}
	if err := a.verifyNamedProfile(ctx, snapshot); err != nil {
		return err
	}
	if a.validWGSnapshotPolicyReference(snapshot) != nil {
		return ErrPolicyAdditionReceipt
	}
	profile := snapshot.Profile
	if snapshot.ProfileDraft {
		profile = snapshot.StagedProfile
	}
	if len(profile) == 0 {
		return errors.New("WARP WireGuard profile is missing")
	}
	profileText := string(profile)
	var endpointState *WGEndpointState
	if err := warp.ValidateProfile(profile); err != nil {
		return err
	}
	if a.ID() == "wireguard" {
		if _, err := awgprofile.ParsePlainWireGuard(profileText); err != nil {
			return err
		}
		// The endpoint exclusion and the tunnel must use one resolved address;
		// otherwise wg could resolve the name again to a different target.
		profileText, endpointState, err = a.stageWGEndpoint(ctx, profileText)
		if err != nil {
			return fmt.Errorf("WireGuard server address: %w; a server inside the local network is not supported yet, use a public address or DNS name", err)
		}
	}
	if a.ID() == "amneziawg" {
		if err := validateAmneziaProfile(profileText); err != nil {
			return err
		}
		profileText, err = a.pinAWGEndpoint(ctx, profileText)
		if err != nil {
			return err
		}
	}
	runtimeProfile, err := sanitizeWGQuickProfile(profileText)
	if err != nil {
		return err
	}
	if err := checkWGNamedReviewContext(ctx); err != nil {
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
	state := PolicyState{Interface: a.interfaceName(), Table: a.table(), PriorityBase: a.priorityBase(), Prefixes: prefixes, Rules: rules, WireGuardEndpoint: endpointState}
	initializePolicyLayout(&state)
	if _, err := kernelRulesForPolicy(state); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(state, "", "  ")
	if err := checkWGNamedReviewContext(ctx); err != nil {
		return err
	}
	return writeAtomic(filepath.Join(root, "policy.staged.json"), data, 0o600)
}

func (a *WARPWireGuardAdapter) Validate(ctx context.Context, plan Plan, root string) (retErr error) {
	ctx, retErr = a.namedProfileReviewContext(ctx, plan.Routes)
	if retErr != nil {
		return retErr
	}
	defer func() { retErr = errors.Join(retErr, checkWGNamedReviewContext(ctx)) }()
	for _, path := range []string{filepath.Join(root, "rz-warp.conf.staged"), filepath.Join(root, "policy.staged.json")} {
		if !regularFile(path) {
			return fmt.Errorf("WARP transaction file is missing: %s", path)
		}
	}
	if err := warp.ValidateProfile(mustRead(filepath.Join(root, "rz-warp.conf.staged"))); err != nil {
		return err
	}
	if a.ID() == "amneziawg" {
		if _, err := a.advancedAWG(ctx, string(mustRead(filepath.Join(root, "rz-warp.conf.staged")))); err != nil {
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

// Canary validates a staged WireGuard profile on a temporary interface before
// Activate is allowed to touch the live interface or service policy. The only
// temporary policy rule matches the candidate's bound socket interface, so LAN
// clients and the router's ordinary traffic keep their current routes.
func (a *WARPWireGuardAdapter) Canary(ctx context.Context, plan RoutePlan, root string) (retErr error) {
	ctx, retErr = a.namedProfileReviewContext(ctx, plan.Routes)
	if retErr != nil {
		return retErr
	}
	defer func() { retErr = errors.Join(retErr, checkWGNamedReviewContext(ctx)) }()
	staged := filepath.Join(root, "rz-warp.conf.staged")
	profile, err := os.ReadFile(staged)
	if err != nil {
		return fmt.Errorf("read WARP canary profile: %w", err)
	}
	if err := warp.ValidateProfile(profile); err != nil {
		return err
	}
	if a.ID() == "wireguard" {
		if _, err := awgprofile.ParsePlainWireGuard(string(profile)); err != nil {
			return err
		}
	}
	runtimeProfile, err := sanitizeWGQuickProfile(string(profile))
	if err != nil {
		return err
	}
	_, addresses, _, err := nativeWGConfig(runtimeProfile)
	if err != nil {
		return err
	}
	source, err := firstTunnelAddress(addresses)
	if err != nil {
		return err
	}
	// A locally isolated socket cannot isolate the remote peer's Noise session
	// or roaming endpoint. Never start a second interface with an in-use key.
	if err := a.ensureWGCanaryIdentityFree(ctx, []byte(runtimeProfile)); err != nil {
		return err
	}
	if a.ID() == "amneziawg" {
		if _, _, err := a.advancedAWGTool(ctx, runtimeProfile); err != nil {
			return err
		}
	}
	if a.ID() == "wireguard" {
		state, err := a.readStagedPolicy(root)
		if err != nil {
			return err
		}
		if err := a.revalidateWGEndpoint(ctx, state.WireGuardEndpoint); err != nil {
			return err
		}
	}

	candidate := *a
	candidate.Interface = "rz-warp-canary"
	switch a.ID() {
	case "amneziawg":
		candidate.Interface = "rz-awg-canary"
	case "wireguard":
		candidate.Interface = "rz-wg-canary"
	}
	candidate.StateRoot = filepath.Join(root, "canary")
	candidate.RuntimeConfigPath = filepath.Join(candidate.StateRoot, candidate.Interface+".conf")
	// wg-quick derives its link name from the file and may install connected
	// routes in main. The candidate must use the explicit, isolated native path.
	candidate.NativeOnly = true
	candidate.isolatedCandidate = true
	candidate.Table = 219
	candidate.PriorityBase = 18050
	if candidate.interfaceActive(ctx) {
		return fmt.Errorf("temporary interface %s already exists", candidate.interfaceName())
	}
	if err := candidate.ensureCanaryPolicyFree(ctx); err != nil {
		return err
	}
	owned, err := ownedfs.Open(root)
	if err != nil {
		return err
	}
	defer owned.Close()
	if err := owned.MkdirAll("canary", 0o700); err != nil {
		return err
	}
	if err := owned.WriteAtomic(filepath.Join("canary", candidate.Interface+".conf"), []byte(runtimeProfile), 0o600); err != nil {
		return err
	}
	interfaceStarted, policyInstalled := false, false
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		var cleanupErr error
		if policyInstalled {
			cleanupErr = candidate.cleanupCanaryPolicy(cleanupCtx, source)
		}
		if interfaceStarted && candidate.interfaceActive(cleanupCtx) {
			if err := candidate.stopInterface(cleanupCtx); cleanupErr == nil {
				cleanupErr = err
			}
		}
		if cleanupErr == nil {
			cleanupErr = owned.RemoveAll("canary")
		}
		if cleanupErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("cleanup WARP canary: %w", cleanupErr))
		}
	}()
	if err := candidate.startInterface(ctx); err != nil {
		return fmt.Errorf("start temporary WARP interface: %w", err)
	}
	interfaceStarted = true
	if err := candidate.installCanaryPolicy(ctx, source); err != nil {
		return err
	}
	policyInstalled = true

	probe := candidate.CanaryProbe
	if probe == nil {
		probe = sourceBoundWARPProbe
		if a.ID() == "amneziawg" || a.ID() == "wireguard" {
			probe = sourceBoundAWGProbe
		}
	}
	ctx = context.WithValue(ctx, wgSocketInterfaceKey{}, candidate.interfaceName())
	return candidate.probeCanaryServices(ctx, plan, root, probe, source.String())
}

func firstTunnelAddress(addresses []string) (netip.Addr, error) {
	if source, err := firstIPv4TunnelAddress(addresses); err == nil {
		return source, nil
	}
	for _, raw := range addresses {
		if prefix, err := netip.ParsePrefix(strings.TrimSpace(raw)); err == nil && prefix.Addr().Is6() {
			return prefix.Addr(), nil
		}
	}
	return netip.Addr{}, errors.New("WireGuard canary requires a tunnel address")
}

func firstIPv4TunnelAddress(addresses []string) (netip.Addr, error) {
	for _, raw := range addresses {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err == nil && prefix.Addr().Is4() {
			return prefix.Addr(), nil
		}
	}
	return netip.Addr{}, errors.New("WARP canary requires an IPv4 tunnel address")
}

func (a *WARPWireGuardAdapter) ensureCanaryPolicyFree(ctx context.Context) error {
	for _, family := range []string{"-4", "-6"} {
		if err := a.ensureCanaryFamilyFree(ctx, family); err != nil {
			return err
		}
	}
	return nil
}

func (a *WARPWireGuardAdapter) ensureCanaryFamilyFree(ctx context.Context, family string) error {
	rules, err := a.run(ctx, a.ip(), canaryFamilyArgs(family, "rule", "show")...)
	if err != nil {
		return fmt.Errorf("inspect temporary WARP rule priority: %w", err)
	}
	prefix := strconv.Itoa(a.priorityBase()) + ":"
	for _, line := range strings.Split(string(rules), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), prefix) {
			return fmt.Errorf("temporary WARP rule priority %d is already used", a.priorityBase())
		}
	}
	routes, err := a.run(ctx, a.ip(), canaryFamilyArgs(family, "route", "show", "table", strconv.Itoa(a.table()))...)
	if err != nil {
		// iproute2 reports an absent FIB table as an error on a clean boot.
		if strings.Contains(string(routes), "FIB table does not exist") {
			return nil
		}
		return fmt.Errorf("inspect temporary WARP route table: %w", err)
	}
	if strings.TrimSpace(string(routes)) != "" {
		return fmt.Errorf("temporary WARP route table %d is already used", a.table())
	}
	return nil
}

func (a *WARPWireGuardAdapter) installCanaryPolicy(ctx context.Context, source netip.Addr) error {
	family := canarySourceFamily(source)
	if _, err := a.run(ctx, a.ip(), canaryFamilyArgs(family, "route", "add", "default", "dev", a.interfaceName(), "table", strconv.Itoa(a.table()))...); err != nil {
		return fmt.Errorf("add temporary WARP route: %w", err)
	}
	prefix := netip.PrefixFrom(source, source.BitLen()).String()
	if _, err := a.run(ctx, a.ip(), canaryFamilyArgs(family, "rule", "add", "priority", strconv.Itoa(a.priorityBase()), "from", prefix, "oif", a.interfaceName(), "lookup", strconv.Itoa(a.table()))...); err != nil {
		cleanup, cancel := context.WithTimeout(wgNamedCleanupContext(context.WithoutCancel(ctx)), 8*time.Second)
		defer cancel()
		_, cleanupErr := a.run(cleanup, a.ip(), canaryFamilyArgs(family, "route", "del", "default", "dev", a.interfaceName(), "table", strconv.Itoa(a.table()))...)
		return errors.Join(fmt.Errorf("add temporary WARP socket rule: %w", err), cleanupErr)
	}
	return nil
}

func (a *WARPWireGuardAdapter) cleanupCanaryPolicy(ctx context.Context, source netip.Addr) error {
	ctx = wgNamedCleanupContext(ctx)
	var first error
	family := canarySourceFamily(source)
	prefix := netip.PrefixFrom(source, source.BitLen()).String()
	if _, err := a.run(ctx, a.ip(), canaryFamilyArgs(family, "rule", "del", "priority", strconv.Itoa(a.priorityBase()), "from", prefix, "oif", a.interfaceName(), "lookup", strconv.Itoa(a.table()))...); err != nil && !commandMissing(err) {
		first = err
	}
	if _, err := a.run(ctx, a.ip(), canaryFamilyArgs(family, "route", "del", "default", "dev", a.interfaceName(), "table", strconv.Itoa(a.table()))...); err != nil && first == nil && !commandMissing(err) {
		first = err
	}
	return first
}

func (a *WARPWireGuardAdapter) Activate(ctx context.Context, plan Plan, root string) (retErr error) {
	ctx, retErr = a.namedProfileReviewContext(ctx, plan.Routes)
	if retErr != nil {
		return retErr
	}
	defer func() { retErr = errors.Join(retErr, checkWGNamedReviewContext(ctx)) }()
	if err := a.checkWGPolicyOperation(); err != nil {
		return err
	}
	snapshot, err := readWarpWGSnapshot(root)
	if err != nil {
		return err
	}
	if err := a.verifyNamedProfile(ctx, snapshot); err != nil {
		return err
	}
	if a.validWGSnapshotPolicyReference(snapshot) != nil {
		return ErrPolicyAdditionReceipt
	}
	currentState, currentExists, err := a.loadPolicyState()
	if err != nil {
		return err
	}
	if currentExists != snapshot.StateExisted {
		return ErrPolicyAdditionUnknown
	}
	if currentExists {
		current, err := a.committedWGPolicyReference(currentState)
		if err != nil || current.ID != snapshot.PolicyGeneration.ID || current.Checksum != snapshot.PolicyGeneration.Checksum {
			return errors.Join(err, ErrPolicyAdditionUnknown)
		}
	}
	state, err := a.readStagedPolicy(root)
	if err != nil {
		return err
	}
	if err := a.revalidateWGEndpoint(ctx, state.WireGuardEndpoint); err != nil {
		return err
	}
	// Recheck before stopping the previous runtime or changing its policy.
	// Validation/Canary may have run before a module or executable replacement.
	if a.ID() == "amneziawg" {
		if _, _, err := a.advancedAWGTool(ctx, string(mustRead(filepath.Join(root, "rz-warp.conf.staged")))); err != nil {
			return err
		}
	}
	if err := writeWGTransactionMarker(ctx, root, "wg-activation-started"); err != nil {
		return err
	}
	if snapshot.StateExisted {
		if snapshot.PolicyGeneration == nil {
			return ErrPolicyAdditionReceipt
		}
		if _, owned, err := a.deactivationOwnership(ctx); err != nil || !owned {
			return errors.Join(err, errors.New("previous WireGuard runtime ownership is not confirmed"))
		}
		if err := a.verifyWGInterfaceIdentity(ctx, snapshot.State.WireGuardEndpoint); err != nil {
			return err
		}
		if err := a.removeWGPolicyReference(ctx, *snapshot.PolicyGeneration, ""); err != nil {
			return fmt.Errorf("remove previous WARP policy: %w", err)
		}
		if err := a.wgPolicyAbsent(ctx, *snapshot.PolicyGeneration); err != nil {
			return err
		}
		if err := a.removeWGEndpoint(ctx, snapshot.State.WireGuardEndpoint); err != nil {
			return err
		}
	}
	if snapshot.InterfaceWasActive {
		if err := a.stopInterface(ctx); err != nil {
			return fmt.Errorf("stop previous WARP interface: %w", err)
		}
	}
	if err := checkWGNamedReviewContext(ctx); err != nil {
		return err
	}
	if err := installStaged(filepath.Join(root, "rz-warp.conf.staged"), a.RuntimeConfigPath); err != nil {
		return err
	}
	if err := a.installWGEndpoint(ctx, state.WireGuardEndpoint); err != nil {
		return err
	}
	if state.WireGuardEndpoint != nil {
		if err := writeAtomic(filepath.Join(root, "wg-endpoint-created"), []byte("owned"), 0o600); err != nil {
			return errors.Join(err, a.removeWGEndpoint(wgNamedCleanupContext(context.WithoutCancel(ctx)), state.WireGuardEndpoint))
		}
		data, _ := json.MarshalIndent(state, "", "  ")
		if err := writeAtomic(filepath.Join(root, "policy.staged.json"), data, 0o600); err != nil {
			return err
		}
	}
	a.activeEndpoint = state.WireGuardEndpoint
	if err := a.startInterface(ctx); err != nil {
		return fmt.Errorf("start WARP interface: %w", err)
	}
	if err := writeWGTransactionMarker(ctx, root, "wg-interface-created"); err != nil {
		return errors.Join(err, a.stopInterface(wgNamedCleanupContext(context.WithoutCancel(ctx))))
	}
	if err := a.applyWGPolicyGeneration(ctx, state, root); err != nil {
		return err
	}
	return nil
}

func (a *WARPWireGuardAdapter) Health(ctx context.Context, plan Plan, root string) (retErr error) {
	ctx, retErr = a.namedProfileReviewContext(ctx, plan.Routes)
	if retErr != nil {
		return retErr
	}
	defer func() { retErr = errors.Join(retErr, checkWGNamedReviewContext(ctx)) }()
	state, err := a.readStagedPolicy(root)
	if err != nil {
		return err
	}
	return a.healthState(ctx, plan, state, root)
}

func (a *WARPWireGuardAdapter) healthState(ctx context.Context, plan Plan, state PolicyState, transactionRoot string) (retErr error) {
	ctx, retErr = a.namedProfileReviewContext(ctx, plan.Routes)
	if retErr != nil {
		return retErr
	}
	defer func() { retErr = errors.Join(retErr, checkWGNamedReviewContext(ctx)) }()
	if !a.interfaceActive(ctx) {
		return fmt.Errorf("WARP interface %s is not active", state.Interface)
	}
	if err := verifyPolicyEvidence(ctx, a.Runner, a.ip(), state); err != nil {
		return err
	}
	if err := a.verifyWGEndpoint(ctx, state.WireGuardEndpoint); err != nil {
		return err
	}
	return a.probeLiveWGServices(ctx, plan, transactionRoot)
}

func (a *WARPWireGuardAdapter) Reconcile(ctx context.Context, plan Plan) (retErr error) {
	ctx, retErr = a.namedProfileReviewContext(ctx, plan.Routes)
	if retErr != nil {
		return retErr
	}
	defer func() { retErr = errors.Join(retErr, checkWGNamedReviewContext(ctx)) }()
	if err := a.checkWGPolicyOperation(); err != nil {
		return err
	}
	state, exists, err := a.loadPolicyState()
	if err != nil {
		return err
	}
	if !exists || !regularFile(a.RuntimeConfigPath) {
		return fmt.Errorf("committed %s runtime state is missing", a.ID())
	}
	ref, err := a.committedWGPolicyReference(state)
	if err != nil {
		return err
	}
	boot, err := a.wgPolicyBoot()
	if err != nil {
		return err
	}
	status, receiptErr := a.inspectWGPolicyReference(ctx, ref, "")
	newBoot := boot != ref.Boot
	if newBoot {
		if !errors.Is(receiptErr, ErrPolicyAdditionUnknown) || a.interfaceActive(ctx) {
			return ErrPolicyAdditionUnknown
		}
		if err := a.wgPolicyAbsent(ctx, ref); err != nil {
			return err
		}
		if state.WireGuardEndpoint != nil {
			if route, rule, err := a.inspectWGEndpoint(ctx, state.WireGuardEndpoint); err != nil || route || rule {
				return errors.Join(err, ErrPolicyAdditionUnknown)
			}
		}
	} else if receiptErr != nil || status.Unknown || status.Promoted {
		return errors.Join(receiptErr, ErrPolicyAdditionUnknown)
	}
	state = cloneWGPolicyState(state)
	if _, owned, err := a.deactivationOwnership(ctx); err != nil || !owned {
		return errors.Join(err, errors.New("committed WireGuard cleanup authority is missing"))
	}
	if err := a.verifyWGInterfaceIdentity(ctx, state.WireGuardEndpoint); err != nil {
		return err
	}
	if err := a.revalidateWGEndpoint(ctx, state.WireGuardEndpoint); err != nil {
		return err
	}
	if status.Complete && a.interfaceActive(ctx) {
		if err := a.healthState(ctx, plan, state, ""); err == nil {
			return nil
		}
	}
	if a.ID() == "amneziawg" {
		if _, _, err := a.advancedAWGTool(ctx, string(mustRead(a.RuntimeConfigPath))); err != nil {
			return err
		}
	}
	if !newBoot {
		if err := a.removeWGPolicyReference(ctx, ref, ""); err != nil {
			return err
		}
		if err := a.wgPolicyAbsent(ctx, ref); err != nil {
			return err
		}
		if err := a.removeWGEndpoint(ctx, state.WireGuardEndpoint); err != nil {
			return err
		}
	}
	if a.interfaceActive(ctx) {
		if err := a.stopInterface(ctx); err != nil {
			return fmt.Errorf("stop stale %s interface: %w", a.ID(), err)
		}
	}
	if err := a.installWGEndpoint(ctx, state.WireGuardEndpoint); err != nil {
		return err
	}
	a.activeEndpoint = state.WireGuardEndpoint
	if err := a.startInterface(ctx); err != nil {
		return errors.Join(fmt.Errorf("recover %s interface: %w", a.ID(), err), a.removeWGEndpoint(wgNamedCleanupContext(context.WithoutCancel(ctx)), state.WireGuardEndpoint))
	}
	newRef, err := a.freshWGPolicyGeneration(ctx, state)
	if err != nil {
		return err
	}
	if err := a.healthState(ctx, plan, state, ""); err != nil {
		cleanup, cancel := context.WithTimeout(wgNamedCleanupContext(context.WithoutCancel(ctx)), 8*time.Second)
		defer cancel()
		if cleanupErr := a.removeWGPolicyReference(cleanup, newRef, ""); cleanupErr != nil {
			return errors.Join(err, cleanupErr)
		}
		return errors.Join(err, a.stopInterface(cleanup), a.removeWGEndpoint(cleanup, state.WireGuardEndpoint))
	}
	return nil
}

func (a *WARPWireGuardAdapter) RefreshPolicy(ctx context.Context, plan Plan) (changed bool, retErr error) {
	ctx, retErr = a.namedProfileReviewContext(ctx, plan.Routes)
	if retErr != nil {
		return false, retErr
	}
	defer func() { retErr = errors.Join(retErr, checkWGNamedReviewContext(ctx)) }()
	if err := a.checkWGPolicyOperation(); err != nil {
		return false, err
	}
	if err := checkAddressRefreshAuthority(ctx); err != nil {
		return false, err
	}
	oldState, exists, err := a.loadPolicyState()
	if err != nil || !exists {
		return false, err
	}
	oldRef, err := a.committedWGPolicyReference(oldState)
	if err != nil {
		return false, err
	}
	oldState = cloneWGPolicyState(oldState)
	if err := a.revalidateWGEndpoint(ctx, oldState.WireGuardEndpoint); err != nil {
		return false, err
	}
	prefixes, rules, err := resolveRefreshPolicyRules(ctx, plan, a.ID(), a.Resolver)
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
	if err := checkAddressRefreshAuthority(ctx); err != nil {
		return false, err
	}
	newState := PolicyState{Interface: a.interfaceName(), Table: a.table(), PriorityBase: a.priorityBase(), Prefixes: prefixes, Rules: rules, RuntimeConfigSHA256: oldState.RuntimeConfigSHA256, WireGuardEndpoint: oldState.WireGuardEndpoint}
	newState.RuleLayout, newState.SharedPriorityBase = oldState.RuleLayout, oldState.SharedPriorityBase
	if samePolicy(oldState, newState) {
		return false, nil
	}
	if err := a.removeWGPolicyReference(ctx, oldRef, ""); err != nil {
		return false, err
	}
	if err := a.wgPolicyAbsent(ctx, oldRef); err != nil {
		return false, err
	}
	newRef, applyErr := a.freshWGPolicyGeneration(ctx, newState)
	if applyErr != nil {
		cleanup, cancel := context.WithTimeout(wgNamedCleanupContext(context.WithoutCancel(ctx)), 30*time.Second)
		defer cancel()
		if err := a.settleWGPolicyOperationForStop(cleanup); err != nil {
			return false, errors.Join(applyErr, err)
		}
		_, restoreErr := a.freshWGPolicyGeneration(cleanup, oldState)
		return false, errors.Join(applyErr, restoreErr)
	}
	rollback := func(cause error) (bool, error) {
		cleanup, cancel := context.WithTimeout(wgNamedCleanupContext(context.WithoutCancel(ctx)), 30*time.Second)
		defer cancel()
		if err := a.removeWGPolicyReference(cleanup, newRef, ""); err != nil {
			return false, errors.Join(cause, err)
		}
		if err := a.wgPolicyAbsent(cleanup, newRef); err != nil {
			return false, errors.Join(cause, err)
		}
		_, restoreErr := a.freshWGPolicyGeneration(cleanup, oldState)
		return false, errors.Join(cause, restoreErr)
	}
	if err := a.healthState(ctx, plan, newState, ""); err != nil {
		return rollback(err)
	}
	if err := checkAddressRefreshAuthority(ctx); err != nil {
		return rollback(err)
	}
	return true, nil
}

func (a *WARPWireGuardAdapter) Deactivate(ctx context.Context) error {
	ctx = wgNamedCleanupContext(ctx)
	state, owned, err := a.deactivationOwnership(ctx)
	if err != nil || !owned {
		return err
	}
	if err := a.settleWGPolicyOperationForStop(ctx); err != nil {
		return err
	}
	ref, err := a.committedWGPolicyReference(state)
	if err != nil {
		return err
	}
	if err := a.verifyWGInterfaceIdentity(ctx, state.WireGuardEndpoint); err != nil {
		return err
	}
	var firstErr error
	if err := a.removeWGPolicyReference(ctx, ref, ""); err != nil {
		return err
	}
	if err := a.wgPolicyAbsent(ctx, ref); err != nil {
		return err
	}
	if err := a.removeWGEndpoint(ctx, state.WireGuardEndpoint); err != nil {
		return err
	}
	active, err := a.deactivationInterfaceActive(ctx)
	if err != nil {
		return errors.Join(firstErr, err)
	}
	if active {
		if err := a.stopInterface(ctx); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("stop %s interface: %w", a.ID(), err)
		}
	}
	if firstErr == nil && active {
		stillActive, err := a.deactivationInterfaceActive(ctx)
		if err != nil {
			firstErr = err
		} else if stillActive {
			firstErr = errors.New("WARP interface remains active; ownership files were retained")
		}
	}
	// Keep the only cleanup authority if a stop/removal is unconfirmed.
	if firstErr != nil {
		return firstErr
	}
	for _, path := range []string{a.statePath(), a.RuntimeConfigPath, filepath.Join(a.StateRoot, wgPolicyReferenceFile)} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (a *WARPWireGuardAdapter) Commit(ctx context.Context, plan Plan, root string) (retErr error) {
	ctx, retErr = a.namedProfileReviewContext(ctx, plan.Routes)
	if retErr != nil {
		return retErr
	}
	defer func() { retErr = errors.Join(retErr, checkWGNamedReviewContext(ctx)) }()
	snapshot, err := readWarpWGSnapshot(root)
	if err != nil {
		return err
	}
	if err := a.verifyNamedProfile(ctx, snapshot); err != nil {
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
		if err := checkWGNamedReviewContext(ctx); err != nil {
			return err
		}
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
	runtimeProfile, err := os.ReadFile(a.RuntimeConfigPath)
	if err != nil {
		return err
	}
	state.RuntimeConfigSHA256 = warpRuntimeDigest(runtimeProfile)
	ref, err := a.promoteWGPolicyGeneration(ctx, state, root)
	if err != nil {
		return err
	}
	return a.publishWGPolicyGeneration(ctx, state, ref)
}

func (a *WARPWireGuardAdapter) Rollback(ctx context.Context, _ Plan, root string) error {
	ctx = wgNamedCleanupContext(ctx)
	snapshot, err := readWarpWGSnapshot(root)
	if err != nil {
		return err
	}
	if err := a.validWGEndpoint(snapshot.State.WireGuardEndpoint, snapshot.RuntimeConfig); err != nil {
		return err
	}
	if a.validWGSnapshotPolicyReference(snapshot) != nil {
		return ErrPolicyAdditionReceipt
	}
	// Validate/Canary/AWG admission failures never entered activation. In
	// particular, a staged policy and a runtime file grant no cleanup rights.
	if !regularFile(filepath.Join(root, "wg-activation-started")) {
		return ctx.Err()
	}
	currentState, currentExists, err := a.loadPolicyState()
	if err != nil {
		return err
	}
	desired, err := a.readStagedPolicy(root)
	if err != nil {
		return err
	}
	ref, issued, err := a.readWGPolicyReference(root, desired, false)
	if err != nil {
		return err
	}
	owner := wgRollbackPolicyOwner(root, snapshot, ref, issued)
	restored, restoredExists, err := a.readWGPolicyReferenceNamed(root, wgPolicyRollbackFile, snapshot.State, true)
	if err != nil {
		return err
	}
	if restoration, exists, err := a.readWGPolicyReferenceNamed(root, wgPolicyRestorationFile, snapshot.State, true); err != nil {
		return err
	} else if exists {
		if restoredExists && restored.Checksum != restoration.Checksum {
			return ErrPolicyAdditionUnknown
		}
		return a.resumeWGRollbackPublication(ctx, root, snapshot, restoration, owner, currentState, currentExists)
	}
	if restoredExists {
		return a.resumeWGRollbackPublication(ctx, root, snapshot, restored, owner, currentState, currentExists)
	}
	// A restoration that failed before publishing its transaction reference
	// must not fall back to stopping the interface under candidate markers.
	if err := a.checkWGPolicyOperation(); err != nil {
		return err
	}
	if currentExists {
		current, err := a.committedWGPolicyReference(currentState)
		if err != nil {
			return err
		}
		priorID := ""
		if snapshot.PolicyGeneration != nil {
			priorID = snapshot.PolicyGeneration.ID
		}
		if current.ID != priorID && (!issued || ref.ID == "" || current.ID != ref.ID) {
			return ErrPolicyAdditionUnknown
		}
	}
	if issued {
		if err := a.removeWGPolicyReference(ctx, ref, root); err != nil {
			return err
		}
	}
	ownedCurrent := regularFile(filepath.Join(root, "wg-interface-created"))
	if ownedCurrent {
		if err := a.verifyWGInterfaceIdentity(ctx, desired.WireGuardEndpoint); err != nil {
			return err
		}
	}
	if regularFile(filepath.Join(root, "wg-endpoint-created")) {
		if err := a.removeWGEndpoint(ctx, desired.WireGuardEndpoint); err != nil {
			return err
		}
	}
	if !ownedCurrent && a.interfaceActive(ctx) {
		// Old policy removal can fail before any command. Preserve an intact
		// prior runtime; never stop an unacknowledged new interface.
		current, _ := os.ReadFile(a.RuntimeConfigPath)
		if snapshot.PolicyGeneration != nil && bytes.Equal(current, snapshot.RuntimeConfig) {
			status, err := a.inspectWGPolicyReference(ctx, *snapshot.PolicyGeneration, "")
			if err == nil && status.Complete && !status.Unknown {
				return verifyPolicyEvidence(ctx, a.Runner, a.ip(), snapshot.State)
			}
		}
		return ErrPolicyAdditionUnknown
	}
	if ownedCurrent && a.interfaceActive(ctx) {
		if err := a.stopInterface(ctx); err != nil {
			return err
		}
	}
	if err := restoreOptional(a.RuntimeConfigPath, snapshot.RuntimeConfig, snapshot.RuntimeExisted); err != nil {
		return err
	}
	if snapshot.StateExisted {
		if snapshot.PolicyGeneration == nil {
			return ErrPolicyAdditionReceipt
		}
		if err := a.removeWGPolicyReference(ctx, *snapshot.PolicyGeneration, ""); err != nil {
			return err
		}
		if err := a.wgPolicyAbsent(ctx, *snapshot.PolicyGeneration); err != nil {
			return err
		}
		previous := cloneWGPolicyState(snapshot.State)
		if snapshot.InterfaceWasActive && snapshot.RuntimeExisted {
			if err := a.revalidateWGEndpoint(ctx, previous.WireGuardEndpoint); err != nil {
				return err
			}
			if err := a.installWGEndpoint(ctx, previous.WireGuardEndpoint); err != nil {
				return err
			}
			a.activeEndpoint = previous.WireGuardEndpoint
			if err := a.startInterface(ctx); err != nil {
				return err
			}
			restored, err := a.freshWGPolicyGenerationBound(ctx, previous, root, owner)
			if err != nil {
				return err
			}
			if err := a.writeWGRollbackReference(ctx, root, restored); err != nil {
				return err
			}
		} else {
			if err := writeWGPolicyReference(ctx, a.StateRoot, *snapshot.PolicyGeneration); err != nil {
				return err
			}
			data, _ := json.MarshalIndent(previous, "", "  ")
			if err := writeAtomic(a.statePath(), data, 0600); err != nil {
				return err
			}
		}
	} else {
		for _, file := range []string{a.statePath(), filepath.Join(a.StateRoot, wgPolicyReferenceFile)} {
			if err := os.Remove(file); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	return a.restoreWGProfileSnapshot(snapshot)
}

func (a *WARPWireGuardAdapter) restoreWGProfileSnapshot(snapshot warpWGSnapshot) error {
	var firstErr error
	if snapshot.NamedProfileID == "" {
		if err := restoreOptional(snapshot.ProfilePath, snapshot.Profile, snapshot.ProfileExisted); err != nil && firstErr == nil {
			firstErr = err
		}
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
	if validPolicyLayout(state) != nil || state.Interface != a.interfaceName() || state.Table != a.table() || state.PriorityBase != a.priorityBase() || len(state.Prefixes) == 0 || len(effectivePolicyRules(state)) > maxPolicyPrefixes {
		return PolicyState{}, errors.New("invalid staged WARP policy ownership")
	}
	if err := a.validWGEndpoint(state.WireGuardEndpoint, mustRead(filepath.Join(root, "rz-warp.conf.staged"))); err != nil {
		return state, err
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
		if _, ok := latestHandshakeTime(string(output), time.Now()); commandErr == nil && ok {
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
	if a.ID() != "warp-wg" {
		fallback = []int{}
	}
	if fallback == nil && a.ID() == "warp-wg" {
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
	// Updating a peer does not destroy its link and the routes just installed
	// for it. Recreating the interface here silently dropped those routes.
	peer := ""
	section := ""
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			section = line
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if ok && section == "[Peer]" && strings.TrimSpace(key) == "PublicKey" {
			peer = strings.TrimSpace(value)
		}
	}
	if peer == "" {
		return "", errors.New("WireGuard peer key is missing")
	}
	active := a.interfaceActive(ctx)
	if active {
		if _, err := a.run(ctx, a.wg(), "set", a.interfaceName(), "peer", peer, "endpoint", endpoint); err != nil {
			return "", errors.New("update WireGuard endpoint failed")
		}
	}
	if err := writeAtomic(a.RuntimeConfigPath, updated, 0o600); err != nil {
		if active {
			cleanup, cancel := context.WithTimeout(wgNamedCleanupContext(context.WithoutCancel(ctx)), 8*time.Second)
			defer cancel()
			_, restoreErr := a.run(cleanup, a.wg(), "set", a.interfaceName(), "peer", peer, "endpoint", current)
			return "", errors.Join(err, restoreErr)
		}
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
		return findExecutable("/opt/sbin/awg", "/opt/bin/awg", "/opt/usr/bin/awg", "/usr/bin/awg", "awg")
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
	if err := checkWGNamedReviewContext(parent); err != nil {
		return nil, err
	}
	if a.Runner == nil || name == "" {
		return nil, errors.New("WARP command runner is unavailable")
	}
	ctx, cancel := context.WithTimeout(parent, a.timeout())
	defer cancel()
	output, err := (wgNamedForwardRunner{base: a.Runner}).Run(ctx, name, args...)
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
	if a.ID() == "amneziawg" {
		return a.startNativeInterface(ctx)
	}
	if quick := a.wgQuick(); !a.NativeOnly && quick != "" {
		output, err := a.run(ctx, quick, "up", a.RuntimeConfigPath)
		if err != nil {
			return fmt.Errorf("wg-quick up: %s", shortOutput(output, err))
		}
		return nil
	}
	return a.startNativeInterface(ctx)
}

func (a *WARPWireGuardAdapter) stopInterface(ctx context.Context) error {
	if quick := a.wgQuick(); a.ID() != "amneziawg" && !a.NativeOnly && quick != "" && regularFile(a.RuntimeConfigPath) {
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
	wg := a.wg()
	if a.ID() == "amneziawg" {
		_, checkedTool, err := a.advancedAWGTool(ctx, string(content))
		if err != nil {
			return err
		}
		wg = checkedTool
		p, err := awgprofile.Parse(string(content))
		if err != nil {
			return err
		}
		content = []byte(p.Config()) // normalize flags to on/off before native CLI.
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
	kind := "wireguard"
	if a.ID() == "amneziawg" {
		kind = "amneziawg"
	}
	if output, err := a.run(ctx, a.ip(), "link", "add", "dev", a.interfaceName(), "type", kind); err != nil {
		return fmt.Errorf("create interface: %s", shortOutput(output, err))
	}
	defer func() {
		if retErr != nil {
			_, _ = a.run(ctx, a.ip(), "link", "delete", "dev", a.interfaceName())
		}
	}()
	if output, err := a.run(ctx, wg, "setconf", a.interfaceName(), temporary); err != nil {
		_ = output
		return errors.New("tunnel setconf failed; profile retained, inspect local redacted diagnostics")
	}
	if a.activeEndpoint != nil && !a.isolatedCandidate {
		if _, err := a.run(ctx, wg, "set", a.interfaceName(), "fwmark", fmt.Sprintf("0x%x", a.activeEndpoint.Mark)); err != nil {
			return errors.New("set WireGuard endpoint transport mark failed")
		}
	}
	for _, address := range addresses {
		args := []string{"address", "add", address, "dev", a.interfaceName()}
		if a.isolatedCandidate {
			args = append(args, "noprefixroute")
			if prefix, err := netip.ParsePrefix(address); err == nil && prefix.Addr().Is6() {
				args = append(args, "nodad")
			}
		}
		if output, err := a.run(ctx, a.ip(), args...); err != nil {
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
				return netresolve.LookupNetIP(ctx, "ip", host)
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
	_, ok := latestHandshakeTime(output, now)
	return ok
}

func latestHandshakeTime(output string, now time.Time) (time.Time, bool) {
	var latest time.Time
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		seconds, err := strconv.ParseInt(fields[len(fields)-1], 10, 64)
		observed := time.Unix(seconds, 0).UTC()
		if err == nil && seconds > 0 && !observed.After(now.Add(5*time.Second)) && now.Sub(observed) < 5*time.Minute && observed.After(latest) {
			latest = observed
		}
	}
	return latest, !latest.IsZero()
}

func validateAmneziaProfile(content string) error {
	_, err := awgprofile.Parse(content)
	return err
}

// Recheck the actual loaded implementation before every AWG start.
// No module download/reload and no silent downgrade of unsupported parameters.
func (a *WARPWireGuardAdapter) advancedAWG(ctx context.Context, content string) (bool, error) {
	advanced, _, err := a.advancedAWGTool(ctx, content)
	return advanced, err
}

func (a *WARPWireGuardAdapter) advancedAWGTool(ctx context.Context, content string) (bool, string, error) {
	tool := a.wg()
	if a.ID() != "amneziawg" {
		return false, tool, nil
	}
	p, err := awgprofile.Parse(content)
	if err != nil {
		return false, "", err
	}
	inspect := a.AWGCapabilities
	if inspect == nil {
		inspect = func(ctx context.Context) awgprofile.Capabilities { return awgprofile.DetectTool(ctx, tool) }
	}
	caps := inspect(ctx)
	if issues := awgprofile.CheckRuntime(p.Public(), caps); len(issues) > 0 {
		return true, "", issues[0]
	}
	// Tests may inject a capability reader, but its receipt must still describe
	// the executable about to receive the profile. Resolve PATH once, then pin
	// this checked path for setconf instead of discovering a second CLI later.
	checkedTool, err := awgprofile.VerifyTool(ctx, caps, tool)
	return p.Public().MinimumMajor >= 3, checkedTool, err
}

func defaultTunnelProbe(ctx context.Context, rawURL string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	request.Header.Set("User-Agent", "RAZVILKA-Tunnel-Health/1")
	client := &http.Client{Timeout: 15 * time.Second}
	response, err := serviceProbeClient(client, rawURL).Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, err = strictServiceResponse(rawURL, response)
	return err
}

func sourceBoundWARPProbe(ctx context.Context, rawURL, source string) error {
	return sourceBoundTunnelProbe(ctx, rawURL, source, true)
}
func sourceBoundAWGProbe(ctx context.Context, rawURL, source string) error {
	return sourceBoundTunnelProbe(ctx, rawURL, source, false)
}
func sourceBoundTunnelProbe(ctx context.Context, rawURL, source string, requireWARP bool) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	if request.URL.User != nil || (request.URL.Scheme != "https" && request.URL.Scheme != "http") || request.URL.Hostname() == "" {
		return errors.New("WARP canary URL must be an absolute HTTP(S) URL without credentials")
	}
	client, closeClient, err := newInterfaceBoundWGClient(ctx, source)
	if err != nil {
		return err
	}
	defer closeClient()
	request.Header.Set("User-Agent", "RAZVILKA-WARP-Canary/1")
	response, err := serviceProbeClient(client, rawURL).Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := strictServiceResponse(rawURL, response)
	if err != nil {
		return err
	}
	if requireWARP && request.URL.Hostname() == "www.cloudflare.com" && request.URL.Path == "/cdn-cgi/trace" {
		if err := validateWARPTrace(body); err != nil {
			return err
		}
	}
	return nil
}

func newSourceBoundWARPClient(source string) (*http.Client, func(), error) {
	return newInterfaceBoundWGClient(context.Background(), source)
}

func newInterfaceBoundWGClient(ctx context.Context, source string) (*http.Client, func(), error) {
	sourceIP := net.ParseIP(source)
	if sourceIP == nil {
		return nil, nil, errors.New("invalid WireGuard canary source")
	}
	dialer := wgSocketDialer(ctx, sourceIP, false)
	family := "4"
	if sourceIP.To4() == nil {
		family = "6"
	}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(dialCtx context.Context, _ string, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			if port != "80" && port != "443" {
				return nil, errors.New("WARP canary permits only HTTP/HTTPS service ports")
			}
			ips, err := net.DefaultResolver.LookupIP(dialCtx, "ip"+family, host)
			if err != nil {
				return nil, err
			}
			var last error
			for _, ip := range ips {
				if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
					continue
				}
				conn, err := dialer.DialContext(dialCtx, "tcp"+family, net.JoinHostPort(ip.String(), port))
				if err == nil {
					return conn, nil
				}
				last = err
			}
			if last != nil {
				return nil, last
			}
			return nil, errors.New("WireGuard canary target has no public address in the tunnel family")
		},
		TLSHandshakeTimeout: 8 * time.Second,
		ForceAttemptHTTP2:   true,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
		CheckRedirect: func(next *http.Request, via []*http.Request) error {
			if len(via) >= 2 || next.URL.Scheme != via[0].URL.Scheme || !strings.EqualFold(next.URL.Hostname(), via[0].URL.Hostname()) {
				return errors.New("WARP canary rejected a cross-origin or excessive redirect")
			}
			return nil
		},
	}
	return client, transport.CloseIdleConnections, nil
}

func validateWARPTrace(body []byte) error {
	trace, err := cloudflareprovider.ParseCloudflareTrace(body)
	if err != nil {
		return errors.New("Cloudflare trace response is invalid or ambiguous")
	}
	if trace.WARP != "on" {
		return errors.New("Cloudflare trace did not confirm warp=on")
	}
	return nil
}

func commandMissing(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "not found") || strings.Contains(message, "no such") || strings.Contains(message, "cannot find")
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
