package dataplane

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

var ErrProxyRuntimeInactive = errors.New("fresh proxy runtime inactivity proof is unavailable")

const proxyInactiveBudget = 10 * time.Second

// VerifyRuntimeInactive observes the current adapter's reserved resources. It
// grants no cleanup authority, consults no prior deactivation result and writes
// no receipts. Manager must hold its operation and recovery gates around it.
func (a *ProxyTunnelAdapter) VerifyRuntimeInactive(ctx context.Context) error {
	proof, err := proxyInactivePlatformProof()
	if err != nil {
		return errors.Join(ErrProxyRuntimeInactive, err)
	}
	return a.verifyRuntimeInactive(ctx, proof)
}

// Private local fixtures can supply a populated proc tree and interface list;
// production always uses the actual Linux inventory, never Running(false).
type proxyInactiveProof struct {
	procRoot   string
	selfPID    int
	interfaces func() ([]net.Interface, error)
	readlink   func(string) (string, error)
}

type proxyInactiveRunner struct{ adapter *ProxyTunnelAdapter }

func (r proxyInactiveRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return r.adapter.run(ctx, name, args...)
}

func (a *ProxyTunnelAdapter) verifyRuntimeInactive(parent context.Context, proof proxyInactiveProof) error {
	ctx, cancel := context.WithTimeout(parent, proxyInactiveBudget)
	defer cancel()
	refuse := func(stage string, err error) error {
		return errors.Join(ErrProxyRuntimeInactive, fmt.Errorf("%s: %w", stage, err))
	}
	if err := ctx.Err(); err != nil {
		return refuse("context", err)
	}
	if a == nil || proof.interfaces == nil || proof.readlink == nil {
		return ErrProxyRuntimeInactive
	}
	// Resource coordinates and commands are local startup intent, never loaded
	// from a historical receipt. Custom or changed coordinates have no proof.
	frozen := *a
	owner, transitPriority, err := frozen.inactiveCoordinates()
	if err != nil {
		return refuse("adapter coordinates", err)
	}
	// Both ends of the read-only kernel inspection get fresh file/process/socket
	// inventories. This detects drift without pretending to lock outside writers.
	for pass := 0; pass < 2; pass++ {
		if err := frozen.inactiveFiles(ctx); err != nil {
			return refuse("runtime files or generations", err)
		}
		if err := proxyInactiveProc(ctx, proof, &frozen); err != nil {
			return refuse("process or socket inventory", err)
		}
		interfaces, err := proof.interfaces()
		if err != nil || len(interfaces) == 0 || len(interfaces) > 4096 {
			return refuse("interface inventory", errors.Join(err, ErrProxyRuntimeInactive))
		}
		seen, loopback := map[string]bool{}, false
		for _, device := range interfaces {
			if device.Index < 1 || device.Name == "" || seen[device.Name] || device.Name == frozen.Interface {
				return ErrProxyRuntimeInactive
			}
			seen[device.Name] = true
			loopback = loopback || device.Name == "lo"
		}
		if !loopback {
			return ErrProxyRuntimeInactive
		}
		if err := frozen.inactiveKernel(ctx, owner, transitPriority); err != nil {
			return refuse("kernel resources", err)
		}
	}
	if a.StateRoot != frozen.StateRoot || a.ID() != frozen.ID() || a.Interface != frozen.Interface || a.Table != frozen.Table ||
		a.Priority != frozen.Priority || a.SOCKSPort != frozen.SOCKSPort || a.ip() != frozen.ip() ||
		a.EngineBin != frozen.EngineBin || a.SidecarBin != frozen.SidecarBin || a.SidecarKind != frozen.SidecarKind ||
		a.firewallBinary(false) != frozen.firewallBinary(false) || a.firewallBinary(true) != frozen.firewallBinary(true) {
		return ErrProxyRuntimeInactive
	}
	return ctx.Err()
}

// Cold self-update constructs observers without a configuration manager. A
// negative resource inventory needs startup coordinates, not activation or
// materialization capability. Every resource and process guard still applies.
func (a *ProxyTunnelAdapter) inactiveCoordinates() (PolicyOwnershipSpec, int, error) {
	refuse := func(err error) (PolicyOwnershipSpec, int, error) {
		return PolicyOwnershipSpec{}, 0, errors.Join(ErrProxyRuntimeInactive, err)
	}
	if a == nil || a.Runner == nil || a.Processes == nil || a.SOCKSPort < 1024 || a.SOCKSPort > 65535 ||
		!filepath.IsAbs(a.StateRoot) || filepath.Clean(a.StateRoot) != a.StateRoot ||
		a.StateRoot == filepath.VolumeName(a.StateRoot)+string(filepath.Separator) || filepath.Base(a.StateRoot) != a.ID() {
		return refuse(nil)
	}
	switch a.ID() {
	case "usque", "sing-box", "xray":
	default:
		return refuse(nil)
	}
	var owner PolicyOwnershipSpec
	for _, spec := range PolicyOwnershipSpecs() {
		if spec.Adapter == a.ID() {
			owner = spec
		}
	}
	if owner.Adapter == "" || owner.Interface != a.Interface || owner.Table != a.Table || owner.PriorityBase != a.Priority {
		return refuse(nil)
	}
	transitPriority := 0
	for _, spec := range NodeTransitOwnershipSpecs() {
		if spec.Engine == a.ID() && spec.Interface == a.Interface && spec.Table == a.Table {
			transitPriority = spec.Priority
		}
	}
	if transitPriority == 0 {
		return refuse(nil)
	}
	for _, command := range []string{a.ip(), a.firewallBinary(false), a.firewallBinary(true)} {
		if command == "" || strings.ContainsAny(command, "\x00\r\n") {
			return refuse(nil)
		}
	}
	if _, err := a.inactiveProcessNames(); err != nil {
		return refuse(err)
	}
	for _, spec := range []ProcessSpec{a.engineProcess(), a.sidecarProcess()} {
		if err := validateProxyInactiveProcessScope(spec); err != nil {
			return refuse(err)
		}
	}
	if err := a.checkSidecarIdentity(); err != nil {
		return refuse(err)
	}
	return owner, transitPriority, nil
}

// These are fixed startup identities, not an executable lookup or an activation
// grant. Uninstalled defaults still hold when a foreign/canary process uses the
// known name. Explicit binaries add their basename even if their file is absent.
func (a *ProxyTunnelAdapter) inactiveProcessNames() ([]string, error) {
	if a == nil {
		return nil, ErrProxyRuntimeInactive
	}
	switch a.ID() {
	case "usque", "sing-box", "xray":
	default:
		return nil, ErrProxyRuntimeInactive
	}
	names := []string{a.ID()}
	switch a.effectiveSidecar() {
	case "sing-box":
		names = append(names, "sing-box")
	case "hev":
		if a.SidecarBin == "" {
			return nil, ErrProxyRuntimeInactive
		}
	default:
		return nil, ErrProxyRuntimeInactive
	}
	for _, binary := range []string{a.EngineBin, a.SidecarBin} {
		if binary == "" {
			continue
		}
		if len(binary) > 4096 || strings.ContainsAny(binary, "\x00\r\n") || !filepath.IsAbs(binary) ||
			filepath.Clean(binary) != binary || filepath.Base(binary) == "." || filepath.Base(binary) == string(filepath.Separator) ||
			binary == filepath.VolumeName(binary)+string(filepath.Separator) {
			return nil, ErrProxyRuntimeInactive
		}
		names = append(names, filepath.Base(binary))
	}
	return names, nil
}

// Negative observation validates the same private file scope without requiring
// an installed executable. It never fills Binary, starts a process or converts
// absence into permission to activate. Only trusted startup constructors supply
// these specs; process identities are checked separately above.
func validateProxyInactiveProcessScope(spec ProcessSpec) error {
	if spec.ID == "" || strings.ContainsAny(spec.ID, "/\\\x00\r\n") || !filepath.IsAbs(spec.Dir) ||
		filepath.Clean(spec.Dir) != spec.Dir || spec.Dir == filepath.VolumeName(spec.Dir)+string(filepath.Separator) ||
		len(spec.Args) == 0 || len(spec.Args) > 256 {
		return ErrProxyRuntimeInactive
	}
	for _, path := range []string{spec.PIDPath, spec.LogPath, spec.MatchArg} {
		relative, err := filepath.Rel(spec.Dir, path)
		if err != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || !filepath.IsLocal(relative) || relative == "." || strings.ContainsAny(path, "\x00\r\n") {
			return ErrProxyRuntimeInactive
		}
	}
	matched, bytes := false, 0
	for _, arg := range spec.Args {
		bytes += len(arg)
		if arg == "" || strings.ContainsRune(arg, '\x00') || bytes > 64<<10 {
			return ErrProxyRuntimeInactive
		}
		matched = matched || arg == spec.MatchArg
	}
	if !matched {
		return ErrProxyRuntimeInactive
	}
	if _, err := os.Lstat(spec.Dir); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	root, err := ownedfs.Open(spec.Dir)
	if err != nil {
		return err
	}
	defer root.Close()
	for _, path := range []string{spec.PIDPath, spec.LogPath, spec.MatchArg, spec.PIDPath + routeidentity.ReceiptSuffix} {
		relative, _ := filepath.Rel(spec.Dir, path)
		if err := root.Check(relative); err != nil {
			return err
		}
	}
	return nil
}

func (a *ProxyTunnelAdapter) inactiveKernel(ctx context.Context, owner PolicyOwnershipSpec, transitPriority int) error {
	runner := proxyInactiveRunner{adapter: a}
	numeric := numericPolicyReadRunner{base: runner}
	state := PolicyState{Table: a.Table}
	for _, family := range []int{4, 6} {
		// Reuse CORE's sole RPDB parser. Unknown syntax, aliases and any foreign
		// selector of this table hold inactivity, independently of receipt ACKs.
		if err := AssertPolicyDefaultUnreferenced(ctx, runner, a.ip(), state, family); err != nil {
			return err
		}
		lines, err := readPolicyRules(ctx, numeric, a.ip(), family)
		if err != nil {
			return err
		}
		local, main, seen := false, false, map[int]bool{}
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			priority, ok := policyLinePriority(line)
			if !ok || seen[priority] || priority >= owner.PriorityBase && priority <= owner.PriorityEnd ||
				priority >= owner.SharedPriorityBase && priority <= owner.SharedPriorityEnd || priority == transitPriority ||
				owner.EndpointPriority != 0 && priority == owner.EndpointPriority {
				return ErrProxyRuntimeInactive
			}
			seen[priority] = true
			canonical := strings.Join(strings.Fields(line), " ")
			local = local || canonical == "0: from all lookup 255"
			main = main || canonical == "32766: from all lookup 254"
			// This later slot inventory must itself retain any newly observed
			// own-table reference or unknown grammar, even after the earlier
			// dependency read was clear. Use the same CORE parsers, no argv grant.
			switch canonical {
			case "0: from all lookup 255", "32766: from all lookup 254", "32767: from all lookup 253":
			default:
				parsed, ok := parseKernelPolicyRule(family, canonical)
				if ok {
					if parsed.table == a.Table {
						return ErrProxyRuntimeInactive
					}
				} else if table, known := knownWGTransportRuleTable(family, canonical); (!known || table == a.Table) && !firmwarePolicyRule(family, canonical) {
					// Reuse the same closed foreign-firmware grammar as the
					// preceding dependency read; unknown syntax and own slots
					// still refuse in this later, independently fresh inventory.
					return ErrProxyRuntimeInactive
				}
			}
		}
		if !local || !main {
			return ErrProxyRuntimeInactive // Empty or incomplete RPDB is no proof.
		}
		out, err := readPolicyTable(ctx, numeric, a.ip(), state, family)
		if err != nil || strings.TrimSpace(string(out)) != "" {
			return errors.Join(ErrProxyRuntimeInactive, err)
		}
	}
	for _, v6 := range []bool{false, true} {
		for _, pair := range [][2]string{{"filter", "FORWARD"}, {"nat", "POSTROUTING"}} {
			snapshot, err := a.firewallSnapshot(ctx, proxyFirewallTable{v6: v6, table: pair[0], parent: pair[1], chain: a.forwardingChain()})
			if err != nil || snapshot.declared || len(snapshot.own) != 0 || len(snapshot.references) != 0 {
				return errors.Join(ErrProxyRuntimeInactive, err)
			}
		}
	}
	return ctx.Err()
}

func (a *ProxyTunnelAdapter) inactiveFiles(ctx context.Context) error {
	info, err := os.Lstat(a.StateRoot)
	if errors.Is(err, os.ErrNotExist) {
		return ctx.Err() // Kernel and populated OS inventories are still mandatory.
	}
	if err != nil || !proxyInactivePrivateDirectory(info) {
		return ErrProxyRuntimeInactive
	}
	root, err := ownedfs.Open(a.StateRoot)
	if err != nil {
		return err
	}
	defer root.Close()
	for _, path := range []string{a.policyPath(), a.policyBindingPath(), a.forwardingPath(), a.transportPath(), a.engineConfigPath(), a.sidecarConfigPath(),
		a.nodeManifestPath(), a.nodeInterfacePath(), a.engineProcess().PIDPath, a.sidecarProcess().PIDPath,
		a.engineProcess().PIDPath + routeidentity.ReceiptSuffix, a.sidecarProcess().PIDPath + routeidentity.ReceiptSuffix} {
		if err := ctx.Err(); err != nil {
			return err
		}
		name, err := filepath.Rel(a.StateRoot, path)
		if err != nil {
			return err
		}
		if _, err := root.Stat(name); !errors.Is(err, os.ErrNotExist) {
			return ErrProxyRuntimeInactive
		}
	}
	info, err = root.Stat("policy-generations")
	if errors.Is(err, os.ErrNotExist) {
		return ctx.Err()
	}
	if err != nil || !proxyInactivePrivateDirectory(info) {
		return ErrProxyRuntimeInactive
	}
	dir, err := root.OpenFile("policy-generations", os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	entries, readErr := dir.ReadDir(4097)
	_ = dir.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || len(entries) > 4096 {
		return ErrProxyRuntimeInactive
	}
	var bytes int64
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		path, err := a.policyGenerationRoot(entry.Name())
		if err != nil || !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return ErrProxyRuntimeInactive
		}
		info, err := root.Stat(filepath.Join("policy-generations", entry.Name()))
		if err != nil || !proxyInactivePrivateDirectory(info) {
			return ErrProxyRuntimeInactive
		}
		generation, err := ownedfs.Open(path)
		if err != nil {
			return err
		}
		session := policyAdditionSession{root: generation, path: path, options: policyAdditionOptions{boot: a.currentBootIdentity}}
		// Open/read existing metadata only: do not call the receipt opener, which
		// can create a permanent lock. No argv, path or grant comes from this doc.
		lockInfo, lockErr := generation.Stat(policyAdditionLock)
		marker, markerErr := generation.ReadLimited(policyAdditionLock, int64(len(policyAdditionMarker)+1))
		if lockErr != nil || !validCloudflareScanLockFile(lockInfo) || markerErr != nil || string(marker) != policyAdditionMarker {
			_ = generation.Close()
			return ErrProxyRuntimeInactive
		}
		info, err = generation.Stat(policyAdditionFile)
		if err == nil {
			bytes += info.Size()
		}
		if err != nil || bytes > 16<<20 {
			_ = generation.Close()
			return ErrProxyRuntimeInactive
		}
		err = session.loadDocument(ctx)
		if err == nil {
			err = session.validateIdentity(ctx)
		}
		_ = generation.Close()
		if err != nil || !proxyInactiveRemovedDocument(session.doc) || !session.status().Removed || session.status().Unknown {
			return errors.Join(ErrProxyRuntimeInactive, err)
		}
	}
	return ctx.Err()
}

// Shape validation is negative metadata inspection only, not reconstruction of
// an expected executable plan. A removed receipt cannot authorize any effect.
func proxyInactiveRemovedDocument(doc policyAdditionDocument) bool {
	if doc.Phase != "active" || len(doc.ID) != 32 || strings.Trim(doc.ID, "0123456789abcdef") != "" ||
		doc.Schema != 1 && doc.Schema != 2 || len(doc.Steps) == 0 || len(doc.Steps) > MaxPolicyEffects {
		return false
	}
	if doc.Schema == 1 && (!validPlanDigest(doc.PolicyHash) || doc.Generation != "" || doc.EffectsHash != "") ||
		doc.Schema == 2 && (doc.PolicyHash != "" || !validPlanDigest(doc.Generation) || !validPlanDigest(doc.EffectsHash)) {
		return false
	}
	bytes, args, deps := 0, 0, 0
	for index, step := range doc.Steps {
		if step.State != "planned" && step.State != "removed" || !validPolicyEffectArgs(step.Add) || !validPolicyEffectArgs(step.Delete) {
			return false
		}
		if doc.Schema == 1 && (step.Tool != "" || len(step.Needs) != 0) || doc.Schema == 2 &&
			step.Tool != PolicyEffectIP && step.Tool != PolicyEffectIPTables && step.Tool != PolicyEffectIP6Tables {
			return false
		}
		for j, parent := range step.Needs {
			if parent < 0 || parent >= index || j > 0 && parent <= step.Needs[j-1] {
				return false
			}
		}
		args += len(step.Add) + len(step.Delete)
		deps += len(step.Needs)
		for _, arg := range step.Add {
			bytes += len(arg)
		}
		for _, arg := range step.Delete {
			bytes += len(arg)
		}
		if bytes > maxPolicyEffectPlanRawBytes || args > maxPolicyEffectPlanArgs || deps > maxPolicyEffectPlanNeeds {
			return false
		}
	}
	return true
}
