package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

type nfqwsScopedReadMode int

const (
	nfqwsScopedNew nfqwsScopedReadMode = iota
	nfqwsScopedPartial
	nfqwsScopedComplete
	nfqwsScopedCleanup
	nfqwsScopedAbsent
	nfqwsScopedBeforeStart
)

type nfqwsScopedRules map[PolicyEffectTool]map[string][][]string

// Local read result only. A typed capture is produced by the retained whole
// inventory reader, bound to this exact network binding and compiled plan.
// Neither this image nor its pure classification grants effects or ownership.
type nfqwsScopedReadImage struct {
	rules   nfqwsScopedRules
	capture *nfqwsScopedReadCapture
}

type nfqwsScopedReadCapture struct {
	source   *nfqwsScopedNetworkBinding
	plan     *NFQWSScopedPlan
	snapshot BackendInventorySnapshot
}

// These copies never escape to Apply or a writer Runner. The common issuer's
// Current guard may prove prepared phases without granting a capture effect.
func nfqwsScopedBeforeStartCurrent(ctx context.Context, b *NFQWSScopedBinding, p *NFQWSScopedPlan, current func(context.Context, *NFQWSScopedPlan) error) error {
	if b == nil || current == nil {
		return ErrNFQWSScopedOwner
	}
	readonly := *b
	readonly.ApplyGuard = func(c context.Context, got *NFQWSScopedPlan, _ PolicyEffect) error { return current(c, got) }
	return readonly.CheckBeforeProcessStart(ctx, p)
}

func nfqwsScopedPreparedCurrent(ctx context.Context, b *NFQWSScopedBinding, p *NFQWSScopedPlan, root string, current func(context.Context, *NFQWSScopedPlan) error) error {
	if b == nil || current == nil {
		return ErrNFQWSScopedOwner
	}
	readonly := *b
	readonly.ApplyGuard = func(c context.Context, got *NFQWSScopedPlan, _ PolicyEffect) error { return current(c, got) }
	return readonly.VerifyPrepared(ctx, p, root)
}

// iptables -S quotes match arguments. Interpret quotes without shell expansion;
// Fields alone could mistake a quoted comment for an actual NFQUEUE target.
func nfqwsScopedTokens(line string) ([]string, error) {
	out, err := backendXTablesTokens(line)
	if err != nil {
		return nil, ErrNFQWSScopedOwner
	}
	return out, nil
}

func (b *NFQWSScopedBinding) readRules(ctx context.Context, p *NFQWSScopedPlan) (nfqwsScopedReadImage, error) {
	if err := b.AdditionalReadback(ctx, p); err != nil {
		return nfqwsScopedReadImage{}, err
	}
	result, err := b.readClassicRules(ctx, p)
	if err != nil {
		return nfqwsScopedReadImage{}, err
	}
	if err := b.AdditionalReadback(ctx, p); err != nil {
		return nfqwsScopedReadImage{}, err
	}
	return result, ctx.Err()
}

// Final decision boundary: preserve the whole other-backend/namespace bracket,
// discard its classic image before the closing callback, then collect a new
// all-ten-table image with no external predicate callback after those rows.
func (b *NFQWSScopedBinding) readFinalRules(ctx context.Context, p *NFQWSScopedPlan) (nfqwsScopedReadImage, error) {
	if _, err := b.readRules(ctx, p); err != nil {
		return nfqwsScopedReadImage{}, err
	}
	return b.readClassicRules(ctx, p)
}

// The runner performs only trusted fixed read commands here. Process, LAN,
// Guard and AdditionalReadback predicate callbacks belong before this image.
func (b *NFQWSScopedBinding) readClassicRules(ctx context.Context, p *NFQWSScopedPlan) (nfqwsScopedReadImage, error) {
	if b.network != nil {
		return b.network.rules(ctx, p)
	}
	if p == nil || p.resources.NetworkIdentity != nil {
		return nfqwsScopedReadImage{}, ErrNFQWSScopedOwner
	}
	result := nfqwsScopedRules{}
	for _, tool := range []PolicyEffectTool{PolicyEffectIPTables, PolicyEffectIP6Tables} {
		result[tool] = map[string][][]string{}
		// SECURITY can also contain a queue or foreign reference. Missing or
		// unreadable tables are an explicit capability refusal, never absence.
		for _, table := range []string{"raw", "mangle", "nat", "filter", "security"} {
			out, err := b.Runner.Run(ctx, b.Tools.command(tool), "-t", table, "-S")
			if err != nil || ctx.Err() != nil || len(out) > 1<<20 || !utf8.Valid(out) {
				return nfqwsScopedReadImage{}, errors.Join(ErrNFQWSScopedOwner, err, ctx.Err())
			}
			lines := strings.Split(string(out), "\n")
			if len(lines) > 8192 {
				return nfqwsScopedReadImage{}, ErrNFQWSScopedOwner
			}
			for _, line := range lines {
				if strings.TrimSpace(line) == "" {
					continue
				}
				fields, err := backendXTablesRowTokens(line)
				if err != nil {
					return nfqwsScopedReadImage{}, ErrNFQWSScopedOwner
				}
				result[tool][table] = append(result[tool][table], fields)
			}
		}
	}
	return nfqwsScopedReadImage{rules: result}, ctx.Err()
}

func nfqwsScopedRuleEqual(a, b []string) bool {
	if len(a) > 0 && len(b) > 0 && a[0] != "-A" && a[0] != "-N" && b[0] != "-A" && b[0] != "-N" {
		a = append([]string{"-A", "body"}, a...)
		b = append([]string{"-A", "body"}, b...)
	}
	return nfqwsScopedRuleKey(a) == nfqwsScopedRuleKey(b)
}

// iptables -S prints base selectors and extension modules in canonical order,
// which differs from compiler argv. Normalize ONLY this compiler's commuting
// vocabulary. Unknown extensions, negation and duplicate selectors stay foreign.
func nfqwsScopedRuleKey(fields []string) string {
	unknown := "unknown\x00" + strings.Join(fields, "\x00")
	if len(fields) < 2 || fields[0] != "-A" && fields[0] != "-N" {
		return unknown
	}
	if fields[0] == "-N" {
		if len(fields) == 2 {
			return strings.Join(fields, "\x00")
		}
		return unknown
	}
	values, modules := map[string]string{}, map[string]bool{}
	for i := 2; i < len(fields); i += 2 {
		if i+1 >= len(fields) {
			return unknown
		}
		key, value := fields[i], fields[i+1]
		if key == "-m" {
			if value != "mark" && value != "tcp" && value != "udp" && value != "mac" || modules[value] {
				return unknown
			}
			modules[value] = true
			continue
		}
		if _, exists := values[key]; exists {
			return unknown
		}
		switch key {
		case "-i", "-j", "--dport", "--queue-num":
		case "-p":
			if value == "6" {
				value = "tcp"
			}
			if value == "17" {
				value = "udp"
			}
		case "-s", "-d", "--mark":
			value = strings.Split(lanClassifierChainKey([]string{key, value}), " ")[1]
		case "--mac-source":
			mac, err := net.ParseMAC(value)
			if err != nil || len(mac) != 6 || mac[0]&1 != 0 || mac.String() == "00:00:00:00:00:00" || !strings.EqualFold(value, mac.String()) {
				return unknown
			}
			value = strings.ToUpper(mac.String())
		default:
			return unknown
		}
		values[key] = value
	}
	if modules["mac"] != (values["--mac-source"] != "") {
		return unknown
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	result := []string{fields[0], fields[1]}
	for _, key := range keys {
		result = append(result, key, values[key])
	}
	for _, module := range sortedMapKeys(modules) {
		result = append(result, "-m", module)
	}
	return strings.Join(result, "\x00")
}

// Classification is pure: callers may consume counts only in the same local
// read boundary. It never supplies a receipt or an admission grant.
func (p *NFQWSScopedPlan) scopedRowCounts(rules nfqwsScopedRules) ([]int, error) {
	return p.scopedRowCountsCompared(rules, nil)
}

func (p *NFQWSScopedPlan) scopedRowCountsCompared(rules nfqwsScopedRules, comparison []BackendInventoryRow) ([]int, error) {
	compared := map[nfqwsDirectStockRowKey]bool{}
	for _, row := range comparison {
		compared[nfqwsDirectStockKey(row)] = true
	}
	counts := make([]int, len(p.mixed.Effects))
	for tool, tables := range rules {
		for table, lines := range tables {
			for _, fields := range lines {
				owned := false
				for i, effect := range p.mixed.Effects {
					if tool == effect.Tool && table == "mangle" && nfqwsScopedRuleEqual(fields, effect.Add[2:]) {
						counts[i]++
						owned = true
					}
				}
				family := 4
				if tool == PolicyEffectIP6Tables {
					family = 6
				}
				if len(compared) != 0 && compared[nfqwsDirectStockKey(BackendInventoryRow{Family: family, Table: table, Tokens: fields})] {
					continue // Only exact rows from the SAME complete graph proof.
				}
				// This is a conservative global conflict policy. A different
				// queue does not prove disjoint DPI processing of this scope.
				for i, value := range fields {
					if i == 1 && strings.HasPrefix(value, "RZQ_") && !owned {
						return nil, ErrNFQWSScopedOwner
					}
					if i > 1 && (value == "-j" || value == "-g") && i+1 < len(fields) && (fields[i+1] == "NFQUEUE" || fields[i+1] == "QUEUE" || strings.HasPrefix(fields[i+1], "RZQ_")) && !owned {
						return nil, ErrNFQWSScopedOwner
					}
					if (value == "--queue-num" || value == "--queue-balance" || value == "--queue-bypass" || value == "--queue-cpu-fanout") && !owned {
						return nil, ErrNFQWSScopedOwner
					}
				}
			}
		}
	}
	return counts, nil
}

func (p *NFQWSScopedPlan) ruleCounts(rules nfqwsScopedRules, mode nfqwsScopedReadMode) ([]int, error) {
	return p.ruleCountsCompared(rules, mode, nil)
}

func (p *NFQWSScopedPlan) ruleCountsCompared(rules nfqwsScopedRules, mode nfqwsScopedReadMode, comparison []BackendInventoryRow) ([]int, error) {
	counts, err := p.scopedRowCountsCompared(rules, comparison)
	if err != nil {
		return nil, err
	}
	for _, count := range counts {
		if count > 1 || (mode == nfqwsScopedNew || mode == nfqwsScopedAbsent || mode == nfqwsScopedBeforeStart) && count != 0 || mode == nfqwsScopedComplete && count != 1 {
			return nil, ErrNFQWSScopedOwner
		}
	}
	for _, chain := range p.chains {
		declared, body, attached := 0, 0, false
		for _, fields := range rules[chain.tool]["mangle"] {
			if len(fields) == 2 && fields[0] == "-N" && fields[1] == chain.name {
				declared++
			}
			if fields[0] == "-A" && fields[1] == chain.name {
				if body >= len(chain.body) || !nfqwsScopedRuleEqual(fields[2:], chain.body[body]) {
					return nil, ErrNFQWSScopedOwner
				}
				body++
			}
			for i := 2; i+1 < len(fields); i++ {
				if (fields[i] == "-j" || fields[i] == "-g") && fields[i+1] == chain.name {
					attached = true // exact allowed reference was checked above
				}
			}
		}
		if declared > 1 || (body > 0 || attached) && declared != 1 || attached && body != len(chain.body) {
			return nil, ErrNFQWSScopedOwner
		}
		if attached {
			// Every published jump needs BOTH prepared family bodies.
			for _, peer := range p.chains {
				for i, e := range p.mixed.Effects {
					if e.Tool == peer.tool && e.Add[3] == peer.name && counts[i] != 1 {
						return nil, ErrNFQWSScopedOwner
					}
				}
			}
		}
	}
	return counts, nil
}

func (b *NFQWSScopedBinding) checkProcess(ctx context.Context, p *NFQWSScopedPlan, inactive bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if inactive {
		proof, err := b.ProcessInactive(ctx, p)
		if err != nil || nfqwsScopedProcessProof(p, proof, true) != nil {
			return errors.Join(ErrNFQWSScopedOwner, err)
		}
		if err := b.checkQueue(ctx, p, nil); err != nil {
			return err
		}
		after, err := b.ProcessInactive(ctx, p)
		if err != nil || proof != after || nfqwsScopedProcessProof(p, after, true) != nil {
			return errors.Join(ErrNFQWSScopedOwner, err)
		}
		return ctx.Err()
	}
	proof, err := b.ProcessRunning(ctx, p)
	if err != nil || nfqwsScopedProcessProof(p, proof, false) != nil {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	if err := b.checkQueue(ctx, p, &proof.Child); err != nil {
		return err
	}
	after, err := b.ProcessRunning(ctx, p)
	if err != nil || proof != after || nfqwsScopedProcessProof(p, after, false) != nil {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	return ctx.Err()
}

func nfqwsScopedProcessProof(p *NFQWSScopedPlan, proof NFQWSScopedProcessProof, inactive bool) error {
	r, c := proof.Receipt, proof.Child
	if p == nil || proof.SessionID != p.resources.SessionID || proof.CommandSHA256 != p.resources.CommandSHA256 || r.CommandSHA256 != proof.CommandSHA256 || r.BootID != p.resources.BootID || r.PID <= 1 || r.Group != r.PID || !nfqws2ManagedPositive(r.Start) || r.ExitCode < 0 || r.ExitCode > 255 {
		return ErrNFQWSScopedOwner
	}
	zeroChild := c == (components.NFQWSRuntimeProcessIdentity{})
	if !zeroChild && (c.BootID != r.BootID || c.PID != r.ChildPID || c.PID <= 1 || c.ParentPID != r.PID || c.Group != c.PID || !nfqws2ManagedPositive(c.Start) || c.Executable == "" || c.ArgumentsSHA256 != p.resources.ArgumentsHash) {
		return ErrNFQWSScopedOwner
	}
	if inactive {
		if !proof.Acknowledged || !r.WaitECHILD || r.Cancelled && r.ExitCode != 125 {
			return ErrNFQWSScopedOwner
		}
		if r.State == "not-started" && !r.Started && zeroChild && r.ChildPID == 0 && !r.DirectReaped && r.Reaped == 0 && r.ExitCode == 125 {
			return nil
		}
		if r.State == "reaped" && r.Started && r.ChildPID > 1 && r.DirectReaped && r.Reaped >= 1 {
			return nil
		}
		return ErrNFQWSScopedOwner
	}
	if r.State != "running" || proof.Acknowledged || !r.Started || zeroChild || r.DirectReaped || r.Reaped != 0 || r.WaitECHILD || r.Cancelled || r.ExitCode != 0 {
		return ErrNFQWSScopedOwner
	}
	return nil
}

// ReadNFQWSScopedManagedProcess binds the existing producer's exact session
// observation to this frozen queue candidate. It is not a launch constructor.
func ReadNFQWSScopedManagedProcess(ctx context.Context, adapter *NFQWS2Adapter, p *NFQWSScopedPlan, inactive bool) (NFQWSScopedProcessProof, error) {
	return nfqwsScopedReadManagedProcess(ctx, adapter, p, inactive, nil)
}

// The paired issuer supplies the exact retained eight-field identity. Compare
// it in the SAME two-sided observed lease, never a separate metadata sample.
func nfqwsScopedReadExecutionProcess(ctx context.Context, adapter *NFQWS2Adapter, p *NFQWSScopedPlan, binding NFQWSExecutionBinding, inactive bool) (NFQWSScopedProcessProof, error) {
	return nfqwsScopedReadManagedProcess(ctx, adapter, p, inactive, &binding)
}

func nfqwsScopedLeaseExecutionMatches(lease nfqws2ManagedProcessLease, p *NFQWSScopedPlan, binding NFQWSExecutionBinding) bool {
	if p == nil || lease.LaunchBinding == nil || *lease.LaunchBinding != binding || !nfqws2ManagedStartBindingValid(binding, lease.Command) {
		return false
	}
	r := p.Resources()
	return binding.PlanID == r.PlanID && binding.PlanDigest == r.PlanDigest && binding.ResourceGeneration == r.Generation &&
		binding.EffectsDigest == p.Digest() && binding.SessionID == r.SessionID && binding.CommandSHA256 == r.CommandSHA256
}

func nfqwsScopedReadManagedProcess(ctx context.Context, adapter *NFQWS2Adapter, p *NFQWSScopedPlan, inactive bool, binding *NFQWSExecutionBinding) (NFQWSScopedProcessProof, error) {
	var zero NFQWSScopedProcessProof
	if adapter == nil || p == nil || ctx == nil {
		return zero, ErrNFQWSScopedOwner
	}
	var lease nfqws2ManagedProcessLease
	var err error
	if inactive {
		lease, err = adapter.observeManagedNFQWSProcessInactive(ctx)
	} else {
		lease, err = adapter.observeManagedNFQWSProcessRunning(ctx)
	}
	if err != nil {
		return zero, err
	}
	if binding != nil && !nfqwsScopedLeaseExecutionMatches(lease, p, *binding) {
		return zero, ErrNFQWSScopedOwner
	}
	if lease.Command.ID != p.resources.SessionID || lease.CommandSHA256 != p.resources.CommandSHA256 || lease.Command.Parent.BootID != p.resources.BootID || components.NFQWSRuntimeArgumentsSHA256(lease.Command.Program.Path, lease.Command.Args) != p.resources.ArgumentsHash {
		return zero, ErrNFQWSScopedOwner
	}
	queueArgs := 0
	for _, arg := range lease.Command.Args {
		if strings.HasPrefix(arg, "--qnum=") {
			if arg != "--qnum="+strconv.Itoa(int(p.resources.Queue)) {
				return zero, ErrNFQWSScopedOwner
			}
			queueArgs++
		}
		if arg == "--qnum" || arg == "--daemon" || strings.HasPrefix(arg, "--daemon=") || arg == "--intercept=0" {
			return zero, ErrNFQWSScopedOwner
		}
	}
	if queueArgs != 1 {
		return zero, ErrNFQWSScopedOwner
	}
	proof := NFQWSScopedProcessProof{SessionID: lease.Command.ID, CommandSHA256: lease.CommandSHA256, Receipt: lease.Receipt, Child: lease.Child, Acknowledged: lease.Acknowledged}
	if err := nfqwsScopedProcessProof(p, proof, inactive); err != nil {
		return zero, err
	}
	return proof, ctx.Err()
}

func (b *NFQWSScopedBinding) readback(ctx context.Context, p *NFQWSScopedPlan, mode nfqwsScopedReadMode, index int) error {
	return b.readbackPrefix(ctx, p, mode, index, -1)
}

func (b *NFQWSScopedBinding) readbackPrefix(ctx context.Context, p *NFQWSScopedPlan, mode nfqwsScopedReadMode, index, prefix int) error {
	if ctx == nil || p == nil {
		return ErrNFQWSScopedOwner
	}
	if prefix >= 0 {
		if mode != nfqwsScopedPartial || prefix >= len(p.mixed.Effects) {
			return ErrNFQWSScopedOwner
		}
		// Finish all ordinary process/LAN callbacks before collecting the
		// exact prefix. Their nominal success cannot validate an earlier
		// rules image after they changed a peer body or added a fresh copy.
		if err := b.readback(ctx, p, mode, index); err != nil {
			return err
		}
		rules, err := b.readFinalRules(ctx, p)
		if err != nil {
			return err
		}
		counts, err := b.ruleCountsImage(p, rules, mode)
		if err != nil {
			return err
		}
		for i, count := range counts {
			wanted := 0
			if i < prefix {
				wanted = 1
			}
			if count != wanted {
				return ErrNFQWSScopedOwner
			}
		}
		for _, parent := range p.mixed.Effects[prefix].Needs {
			if parent >= prefix || counts[parent] != 1 {
				return ErrNFQWSScopedOwner
			}
		}
		return ctx.Err() // No external predicate callback after this image.
	}
	check := func() error {
		if mode == nfqwsScopedBeforeStart {
			return b.checkQueue(ctx, p, nil)
		}
		return b.checkProcess(ctx, p, mode == nfqwsScopedCleanup || mode == nfqwsScopedAbsent)
	}
	if err := check(); err != nil {
		return err
	}
	if mode != nfqwsScopedCleanup && mode != nfqwsScopedAbsent {
		if err := b.VerifyLAN(ctx, CloneLANPolicyRuntime(p.lan)); err != nil {
			return err
		}
	}
	rules, err := b.readRules(ctx, p)
	if err != nil {
		return err
	}
	counts, err := b.ruleCountsImage(p, rules, mode)
	if err != nil || index >= len(counts) {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	if err := check(); err != nil {
		return err
	}
	if mode != nfqwsScopedCleanup && mode != nfqwsScopedAbsent {
		if err := b.VerifyLAN(ctx, CloneLANPolicyRuntime(p.lan)); err != nil {
			return err
		}
	}
	if mode == nfqwsScopedComplete {
		// Closing process/LAN/other-backend callbacks must not invalidate
		// a previously sampled body while returning nominal success.
		rules, err := b.readFinalRules(ctx, p)
		if err != nil {
			return err
		}
		if _, err := b.ruleCountsImage(p, rules, mode); err != nil {
			return err
		}
	}
	return ctx.Err()
}

// CheckBeforeProcessStart is a read-only gate before the common authority
// starts the managed child. It requires the retained registrar and LAN gate,
// empty queue namespace and no capture. Actual Start still consumes admission.
func (b *NFQWSScopedBinding) CheckBeforeProcessStart(ctx context.Context, p *NFQWSScopedPlan) error {
	r, _, err := b.prepare(p, false)
	if err != nil {
		return err
	}
	if err := r.Guard(ctx, 0); err != nil {
		return err
	}
	if err := b.readback(ctx, p, nfqwsScopedBeforeStart, -1); err != nil {
		return err
	}
	return r.Guard(ctx, 0)
}

// CheckKnownReferences is the common LAN ConsumerCheck bridge while this
// registered owner has its receipt writer lock. It checks only exact allowed
// partial bodies/references and the current process/queue, without recursively
// calling LAN.Verify or reacquiring the same receipt lock. ApplyGuard MUST
// require the registrar's retained exact typed owner; this is not adoption of
// matching rules, an alternative cleanup grant, or a Complete receipt proof.
func (b *NFQWSScopedBinding) CheckKnownReferences(ctx context.Context, p *NFQWSScopedPlan) error {
	r, _, err := b.prepare(p, false)
	if err != nil {
		return err
	}
	if err := r.Guard(ctx, 0); err != nil {
		return err
	}
	if err := b.checkProcess(ctx, p, false); err != nil {
		return err
	}
	rules, err := b.readRules(ctx, p)
	if err != nil {
		return err
	}
	if _, err := b.ruleCountsImage(p, rules, nfqwsScopedPartial); err != nil {
		return err
	}
	if err := b.checkProcess(ctx, p, false); err != nil {
		return err
	}
	return r.Guard(ctx, 0)
}

// VerifyPrepared is the registrar's pre-effect closure. It requires an exact
// live owned queue/process and LAN gate, absent capture, and a fresh childroot
// with neither receipt nor receipt lock. It does not create files or require a
// Complete receipt before the first effect.
func (b *NFQWSScopedBinding) VerifyPrepared(ctx context.Context, p *NFQWSScopedPlan, path string) error {
	r, _, err := b.prepare(p, false)
	if err != nil {
		return err
	}
	if err := r.Guard(ctx, 0); err != nil {
		return err
	}
	root, err := nfqwsScopedOpenReceiptRoot(path)
	if err != nil {
		return err
	}
	defer root.Close()
	absent := func() error {
		for _, name := range []string{policyAdditionFile, policyAdditionLock} {
			if _, err := root.Stat(name); !errors.Is(err, os.ErrNotExist) {
				return errors.Join(ErrNFQWSScopedOwner, err)
			}
		}
		return ctx.Err()
	}
	if err := absent(); err != nil {
		return err
	}
	if err := b.readback(ctx, p, nfqwsScopedNew, -1); err != nil {
		return err
	}
	if err := absent(); err != nil {
		return err
	}
	return r.Guard(ctx, 0)
}

func nfqwsScopedOpenReceiptRoot(path string) (*ownedfs.Root, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrNFQWSScopedOwner
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return nil, errors.Join(ErrNFQWSScopedOwner, err)
	}
	root, err := ownedfs.Open(path)
	if err != nil {
		return nil, errors.Join(ErrNFQWSScopedOwner, err)
	}
	return root, nil
}

// Reuse the common receipt's EXACT parser and lock, opening an existing marker
// only. The generic inspector may create a missing marker, which is unsuitable
// for a read-only inactivity observer or a missing-owner refusal.
func nfqwsScopedInspectReceipt(ctx context.Context, plan PolicyEffectPlan, path string, options policyAdditionOptions) (PolicyAdditionStatus, error) {
	var zero PolicyAdditionStatus
	if ctx == nil || ctx.Err() != nil {
		return zero, ErrNFQWSScopedOwner
	}
	plan, hash, err := copyPolicyEffectPlan(plan)
	if err != nil {
		return zero, err
	}
	root, err := nfqwsScopedOpenReceiptRoot(path)
	if err != nil {
		return zero, err
	}
	defer root.Close()
	file, err := openNFQWS2LockFile(root, policyAdditionLock, false)
	if err != nil {
		return zero, errors.Join(ErrNFQWSScopedOwner, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !validCloudflareScanLockFile(info) {
		return zero, ErrNFQWSScopedOwner
	}
	if err := lockCloudflareScanFile(file); err != nil {
		return zero, ErrPolicyAdditionBusy
	}
	defer unlockCloudflareScanFile(file)
	current, err := root.Stat(policyAdditionLock)
	marker, readErr := io.ReadAll(io.LimitReader(file, int64(len(policyAdditionMarker)+1)))
	if err != nil || readErr != nil || !os.SameFile(info, current) || string(marker) != policyAdditionMarker {
		return zero, ErrNFQWSScopedOwner
	}
	if options.boot == nil {
		options.boot = func() (string, error) { return (&ProxyTunnelAdapter{}).currentBootIdentity() }
	}
	s := &policyEffectSession{policyAdditionSession: &policyAdditionSession{root: root, path: path, options: options}, plan: plan, hash: hash}
	if err := s.load(ctx); err != nil {
		return zero, errors.Join(ErrNFQWSScopedOwner, err)
	}
	return s.status(), nil
}

func (b *NFQWSScopedBinding) inspect(ctx context.Context, p *NFQWSScopedPlan, index int) (int, error) {
	if index < 0 || index >= len(p.mixed.Effects) {
		return 0, ErrNFQWSScopedOwner
	}
	rules, err := b.readRules(ctx, p)
	if err != nil {
		return 0, err
	}
	counts, err := b.ruleCountsImage(p, rules, nfqwsScopedPartial)
	if err != nil {
		return 0, err
	}
	return counts[index], nil
}

func (b *NFQWSScopedBinding) beforeDelete(ctx context.Context, p *NFQWSScopedPlan, index int) error {
	e := p.mixed.Effects[index]
	if e.Add[2] != "-N" {
		return nil // reverse Needs protects bodies until attachments are gone
	}
	rules, err := b.readRules(ctx, p)
	if err != nil {
		return err
	}
	name := e.Add[3]
	for _, tables := range rules.rules {
		for _, lines := range tables {
			for _, f := range lines {
				if f[0] == "-A" && f[1] == name {
					return ErrNFQWSScopedOwner
				}
				for i := 2; i+1 < len(f); i++ {
					if (f[i] == "-j" || f[i] == "-g") && f[i+1] == name {
						return ErrNFQWSScopedOwner
					}
				}
			}
		}
	}
	return nil
}

type nfqwsScopedQueue struct {
	number    uint16
	portID    uint32
	copyMode  uint8
	copyRange uint32
}

func nfqwsScopedQueues(text string) ([]nfqwsScopedQueue, error) {
	if len(text) > 1<<20 || !utf8.ValidString(text) || strings.ContainsAny(text, "\x00\r") {
		return nil, ErrNFQWSScopedOwner
	}
	lines := strings.Split(text, "\n")
	if len(lines) > 4096 {
		return nil, ErrNFQWSScopedOwner
	}
	var result []nfqwsScopedQueue
	seen := map[uint16]bool{}
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 9 {
			return nil, ErrNFQWSScopedOwner
		}
		var values [9]uint64
		for i, v := range f {
			n, err := strconv.ParseUint(v, 10, 32)
			if err != nil || strconv.FormatUint(n, 10) != v {
				return nil, ErrNFQWSScopedOwner
			}
			values[i] = n
		}
		if values[0] > 65535 || values[1] == 0 || values[3] > 2 || values[4] > 65535 || values[8] != 1 || seen[uint16(values[0])] {
			return nil, ErrNFQWSScopedOwner
		}
		seen[uint16(values[0])] = true
		result = append(result, nfqwsScopedQueue{number: uint16(values[0]), portID: uint32(values[1]), copyMode: uint8(values[3]), copyRange: uint32(values[4])})
	}
	return result, nil
}

func nfqwsScopedSocketInode(text string, portID uint32) (string, error) {
	if len(text) > 1<<20 || !utf8.ValidString(text) {
		return "", ErrNFQWSScopedOwner
	}
	lines := strings.Split(text, "\n")
	if len(lines) == 0 || len(lines) > 8192 || strings.Join(strings.Fields(lines[0]), " ") != "sk Eth Pid Groups Rmem Wmem Dump Locks Drops Inode" {
		return "", ErrNFQWSScopedOwner
	}
	inode := ""
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 10 {
			return "", ErrNFQWSScopedOwner
		}
		protocol, err := strconv.ParseUint(f[1], 10, 8)
		port, portErr := strconv.ParseUint(f[2], 10, 32)
		n, inodeErr := strconv.ParseUint(f[9], 10, 64)
		if err != nil || portErr != nil || inodeErr != nil || strconv.FormatUint(protocol, 10) != f[1] || strconv.FormatUint(port, 10) != f[2] || strconv.FormatUint(n, 10) != f[9] {
			return "", ErrNFQWSScopedOwner
		}
		if protocol == 12 && port == uint64(portID) {
			if inode != "" || n == 0 {
				return "", ErrNFQWSScopedOwner
			}
			inode = f[9]
		}
	}
	if inode == "" {
		return "", ErrNFQWSScopedOwner
	}
	return inode, nil
}

func nfqwsScopedReadProc(ctx context.Context, path string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	f, err := os.Open(path)
	if err != nil {
		if path == "/proc/net/netfilter/nfnetlink_queue" && errors.Is(err, os.ErrNotExist) {
			return "", errors.Join(ErrNFQWSScopedOwner, ErrNFQWSScopedQueueInventory, err)
		}
		return "", errors.Join(ErrNFQWSScopedOwner, err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil || len(data) > 1<<20 || ctx.Err() != nil {
		return "", errors.Join(ErrNFQWSScopedOwner, err, ctx.Err())
	}
	return string(data), nil
}

// CheckNFQWSScopedQueue is the actual Linux /proc reader for QueueCheck. The
// queue's peer_portid is a netlink port ID, NOT a numeric process PID. It binds
// NETLINK_NETFILTER port -> socket inode -> exact supervised child's open fd,
// with namespace and process birth/exe/argv checked on both sides. nil requires
// the entire queue namespace empty. Missing/unreadable proc is never empty.
func CheckNFQWSScopedQueue(ctx context.Context, namespace string, queue uint16, child *components.NFQWSRuntimeProcessIdentity) error {
	if runtime.GOOS != "linux" || ctx == nil || !nfqwsScopedNamespace(namespace) || queue == 0 {
		return ErrNFQWSScopedOwner
	}
	checkIdentity := func() error {
		current, err := os.Readlink("/proc/self/ns/net")
		if err != nil || current != namespace {
			return errors.Join(ErrNFQWSScopedOwner, err)
		}
		if child != nil {
			if child.PID <= 1 {
				return ErrNFQWSScopedOwner
			}
			actual, err := components.ReadNFQWSRuntimeProcessIdentity(child.PID)
			childNS, nsErr := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", child.PID))
			if err != nil || nsErr != nil || actual != *child || childNS != namespace {
				return errors.Join(ErrNFQWSScopedOwner, err, nsErr)
			}
		}
		return ctx.Err()
	}
	if err := checkIdentity(); err != nil {
		return err
	}
	read := func() ([]nfqwsScopedQueue, error) {
		text, err := nfqwsScopedReadProc(ctx, "/proc/net/netfilter/nfnetlink_queue")
		if err != nil {
			return nil, err
		}
		return nfqwsScopedQueues(text)
	}
	queues, err := read()
	if err != nil {
		return err
	}
	if child == nil {
		if len(queues) != 0 {
			return ErrNFQWSScopedOwner
		}
	} else {
		if len(queues) != 1 || queues[0].number != queue || queues[0].copyMode != 2 || queues[0].copyRange < 65531 {
			return ErrNFQWSScopedOwner
		}
		text, err := nfqwsScopedReadProc(ctx, "/proc/net/netlink")
		if err != nil {
			return err
		}
		inode, err := nfqwsScopedSocketInode(text, queues[0].portID)
		if err != nil {
			return err
		}
		dir := fmt.Sprintf("/proc/%d/fd", child.PID)
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) > 4096 {
			return errors.Join(ErrNFQWSScopedOwner, err)
		}
		found := false
		for _, e := range entries {
			link, err := os.Readlink(filepath.Join(dir, e.Name()))
			if err != nil {
				return errors.Join(ErrNFQWSScopedOwner, err)
			}
			found = found || link == "socket:["+inode+"]"
		}
		if !found {
			return ErrNFQWSScopedOwner
		}
		// Re-resolve port ownership as well as queue ownership after fd read.
		text, err = nfqwsScopedReadProc(ctx, "/proc/net/netlink")
		if err != nil {
			return err
		}
		afterInode, err := nfqwsScopedSocketInode(text, queues[0].portID)
		if err != nil || inode != afterInode {
			return errors.Join(ErrNFQWSScopedOwner, err)
		}
	}
	after, err := read()
	if err != nil || !slices.Equal(queues, after) {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	return checkIdentity()
}

// CheckNFQWSScopedOtherBackends is a concrete additional readback for legacy
// iptables. It refuses an nft-backed iptables projection (not a whole ruleset)
// and any separate nft queue/capture in any family, including bridge. All tool
// paths come from trusted startup wiring, never persisted receipt commands.
func CheckNFQWSScopedOtherBackends(ctx context.Context, runner NFQWS2Runner, tools PolicyEffectTools, nft, namespace string) error {
	if runtime.GOOS != "linux" || ctx == nil || runner == nil || nft == "" || !nfqwsScopedNamespace(namespace) {
		return ErrNFQWSScopedOwner
	}
	checkNS := func() error {
		current, err := os.Readlink("/proc/self/ns/net")
		if err != nil || current != namespace {
			return errors.Join(ErrNFQWSScopedOwner, err)
		}
		return ctx.Err()
	}
	if err := checkNS(); err != nil {
		return err
	}
	for _, command := range []string{tools.IPTables, tools.IP6Tables} {
		if command == "" {
			return ErrNFQWSScopedOwner
		}
		out, err := runner.Run(ctx, command, "--version")
		if err != nil || len(out) > 1024 || !strings.Contains(string(out), "(legacy)") || strings.Contains(string(out), "nf_tables") {
			return errors.Join(ErrNFQWSScopedOwner, err)
		}
	}
	out, err := runner.Run(ctx, nft, "-j", "list", "ruleset")
	if err != nil || nfqwsScopedNFTRuleset(out) != nil {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	return checkNS()
}

func nfqwsScopedNFTRuleset(out []byte) error {
	if len(out) > 1<<20 || !utf8.Valid(out) || nfqws2ManagedUniqueJSON(out) != nil {
		return ErrNFQWSScopedOwner
	}
	decoder := json.NewDecoder(bytes.NewReader(out))
	var document map[string]json.RawMessage
	if err := decoder.Decode(&document); err != nil || len(document) != 1 || document["nftables"] == nil {
		return ErrNFQWSScopedOwner
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return ErrNFQWSScopedOwner
	}
	var entries []map[string]json.RawMessage
	if bytes.Equal(bytes.TrimSpace(document["nftables"]), []byte("null")) || json.Unmarshal(document["nftables"], &entries) != nil {
		return ErrNFQWSScopedOwner
	}
	for _, entry := range entries {
		if len(entry) != 1 {
			return ErrNFQWSScopedOwner
		}
		for kind, raw := range entry {
			switch kind {
			case "metainfo", "table", "chain", "set", "map", "element", "counter", "quota", "limit", "ct helper", "ct timeout", "ct expectation":
			case "rule", "flowtable":
				// A full executable nft expression owner is not part of this
				// legacy binding. Refuse every active rule, rather than infer
				// safety from searching only known queue/mark spellings.
				return ErrNFQWSScopedOwner
			default:
				return ErrNFQWSScopedOwner
			}
			var value map[string]any
			if json.Unmarshal(raw, &value) != nil || len(value) == 0 || nfqwsScopedNFTCapture(value) {
				return ErrNFQWSScopedOwner
			}
		}
	}
	return nil
}

func nfqwsScopedNFTCapture(value any) bool {
	switch v := value.(type) {
	case map[string]any:
		for key, item := range v {
			if key == "queue" || key == "dup" || key == "fwd" || key == "flow" || key == "key" && item == "mark" || nfqwsScopedNFTCapture(item) {
				return true
			}
		}
	case []any:
		for _, item := range v {
			if nfqwsScopedNFTCapture(item) {
				return true
			}
		}
	}
	return false
}
