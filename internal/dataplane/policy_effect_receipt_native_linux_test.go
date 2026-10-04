//go:build linux

package dataplane

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

type nativeEffectFixture struct {
	plan       PolicyEffectPlan
	state      LANClassifierState
	rules      map[int]lanClassifierRule
	chainSteps map[int]bool
	bodySteps  map[int]bool
	jumpSteps  map[int]bool
	probes     []int
	tools      PolicyEffectTools
	runner     *nativeEffectRunner
}

type nativeEffectRunner struct {
	tools PolicyEffectTools
	plan  PolicyEffectPlan
	calls int
}

func (r *nativeEffectRunner) Run(ctx context.Context, command string, args ...string) ([]byte, error) {
	allowed := false
	for _, effect := range r.plan.Effects {
		if command == r.tools.command(effect.Tool) && (reflect.DeepEqual(args, effect.Add) || reflect.DeepEqual(args, effect.Delete)) {
			allowed = true
		}
	}
	if command == r.tools.IP && (reflect.DeepEqual(args, []string{"rule", "show"}) || reflect.DeepEqual(args, []string{"-4", "rule", "show"}) || reflect.DeepEqual(args, []string{"-6", "rule", "show"})) {
		allowed = true
	}
	if (command == r.tools.IPTables || command == r.tools.IP6Tables) && reflect.DeepEqual(args, []string{"-t", "mangle", "-S"}) {
		allowed = true
	}
	if !allowed {
		return nil, errors.New("native mixed fixture refused an uncompiled command")
	}
	r.calls++
	return (nfqws2ExecRunner{}).Run(ctx, command, args...)
}

func newNativeEffectFixture(token string, tools PolicyEffectTools) nativeEffectFixture {
	f := nativeEffectFixture{
		plan: PolicyEffectPlan{Generation: routeidentity.Hash([]byte("native-policy-effects-v1\x00" + token))},
		state: LANClassifierState{Chain: "RZC_" + token, Ingress: []string{"rzef-" + token[:6]}, DefaultTable: 229,
			ExcludedSources: []string{"192.168.88.25/32", "fd88::25/128"}, DirectDestinations: []string{"198.51.100.7/32", "2001:db8::7/128"}},
		rules: map[int]lanClassifierRule{}, chainSteps: map[int]bool{}, bodySteps: map[int]bool{}, jumpSteps: map[int]bool{}, tools: tools,
	}
	appendEffect := func(tool PolicyEffectTool, add, remove []string, needs []int) int {
		index := len(f.plan.Effects)
		f.plan.Effects = append(f.plan.Effects, PolicyEffect{Tool: tool, Add: add, Delete: remove, Needs: needs})
		return index
	}
	for _, tool := range []PolicyEffectTool{PolicyEffectIPTables, PolicyEffectIP6Tables} {
		f.chainSteps[appendEffect(tool, []string{"-t", "mangle", "-N", f.state.Chain}, []string{"-t", "mangle", "-X", f.state.Chain}, nil)] = true
	}
	for _, family := range []int{4, 6} {
		rule := lanClassifierRule{family: family, priority: 22972, source: "all", action: "fwmark 0x10000000/0x10000000 lookup 229"}
		f.rules[appendEffect(PolicyEffectIP, rule.args("add"), rule.args("del"), nil)] = rule
	}
	for index, family := range []int{4, 6} {
		rule := lanClassifierRule{family: family, priority: 22959, source: f.state.ExcludedSources[index], action: "goto 22972"}
		f.rules[appendEffect(PolicyEffectIP, rule.args("add"), rule.args("del"), []int{2 + index})] = rule
	}
	firstV6Body := 0
	for familyIndex, tool := range []PolicyEffectTool{PolicyEffectIPTables, PolicyEffectIP6Tables} {
		if familyIndex == 1 {
			firstV6Body = len(f.plan.Effects)
		}
		for _, rule := range lanClassifierChainRules(f.state, familyIndex == 1) {
			add := append([]string{"-t", "mangle", "-A", f.state.Chain}, rule...)
			remove := append([]string{"-t", "mangle", "-D", f.state.Chain}, rule...)
			f.bodySteps[appendEffect(tool, add, remove, []int{familyIndex, 2 + familyIndex, 4 + familyIndex})] = true
		}
	}
	prerequisites := make([]int, len(f.plan.Effects))
	for i := range prerequisites {
		prerequisites[i] = i
	}
	firstJump := len(f.plan.Effects)
	for _, tool := range []PolicyEffectTool{PolicyEffectIPTables, PolicyEffectIP6Tables} {
		jump := lanClassifierJumps(f.state)[0]
		f.jumpSteps[appendEffect(tool, append([]string{"-t", "mangle", "-A", "PREROUTING"}, jump...), append([]string{"-t", "mangle", "-D", "PREROUTING"}, jump...), append([]int(nil), prerequisites...))] = true
	}
	// Both families are represented: create, negative guard, attachment,
	// anchor and goto. Each is crossed at all six durable boundaries.
	f.probes = []int{0, firstV6Body + 1, firstJump, 2, 5}
	f.runner = &nativeEffectRunner{tools: tools, plan: f.plan}
	return f
}

func (f nativeEffectFixture) adapter() *ProxyTunnelAdapter {
	return &ProxyTunnelAdapter{Runner: f.runner, IPTables: f.tools.IPTables, IP6Tables: f.tools.IP6Tables}
}

func (f nativeEffectFixture) firewall(ctx context.Context, v6 bool) (proxyFirewallSnapshot, error) {
	snapshot, err := f.adapter().firewallSnapshot(ctx, proxyFirewallTable{v6: v6, table: "mangle", parent: "PREROUTING", chain: f.state.Chain})
	if err != nil {
		return snapshot, err
	}
	allowed := map[string]bool{}
	for _, rule := range lanClassifierChainRules(f.state, v6) {
		allowed[lanClassifierChainKey(rule)] = true
	}
	for _, rule := range snapshot.own {
		if !allowed[lanClassifierChainKey(rule)] {
			return snapshot, errors.New("native classifier has a foreign body")
		}
	}
	expectedJump := lanClassifierJumps(f.state)[0]
	for _, reference := range snapshot.references {
		if len(reference) == 0 || reference[0] != "PREROUTING" || lanClassifierChainKey(reference[1:]) != lanClassifierChainKey(expectedJump) {
			return snapshot, errors.New("native classifier has a foreign reference")
		}
	}
	return snapshot, nil
}

func (f nativeEffectFixture) presence(ctx context.Context, index int) (int, error) {
	effect := f.plan.Effects[index]
	if rule, ok := f.rules[index]; ok {
		lines, err := readPolicyRules(ctx, f.runner, f.tools.IP, rule.family)
		if err != nil {
			return 0, err
		}
		count := 0
		for _, raw := range lines {
			line := strings.Join(strings.Fields(raw), " ")
			if priority, ok := policyLinePriority(line); ok && priority == rule.priority {
				if line != rule.line() {
					return 0, errors.New("native classifier RPDB priority has a foreign occupant")
				}
				count++
			}
		}
		if count > 1 {
			return 0, errors.New("native classifier RPDB selector is duplicated")
		}
		return count, nil
	}
	snapshot, err := f.firewall(ctx, effect.Tool == PolicyEffectIP6Tables)
	if err != nil {
		return 0, err
	}
	if f.chainSteps[index] {
		if snapshot.declared {
			return 1, nil
		}
		return 0, nil
	}
	rules := snapshot.own
	if f.jumpSteps[index] {
		rules = snapshot.parent
	}
	count := 0
	for _, rule := range rules {
		if lanClassifierChainKey(rule) == lanClassifierChainKey(effect.Add[4:]) {
			count++
		}
	}
	if count > 1 {
		return 0, errors.New("native classifier firewall effect is duplicated")
	}
	return count, nil
}

func (f nativeEffectFixture) runtime() PolicyEffectRuntime {
	return PolicyEffectRuntime{Runner: f.runner, Tools: f.tools, Guard: func(ctx context.Context, _ int) error { return ctx.Err() },
		Preflight: func(ctx context.Context) error {
			for index := range f.plan.Effects {
				if count, err := f.presence(ctx, index); err != nil || count != 0 {
					return errors.Join(errors.New("native mixed namespace is occupied"), err)
				}
			}
			return ctx.Err()
		},
		ExactPresence: f.presence,
		BeforeDelete: func(ctx context.Context, index int) error {
			if rule, ok := f.rules[index]; ok {
				if rule.priority == 22972 {
					lines, err := readPolicyRules(ctx, f.runner, f.tools.IP, rule.family)
					if err != nil {
						return err
					}
					for _, line := range lines {
						fields := strings.Fields(line)
						for i := 0; i+1 < len(fields); i++ {
							if fields[i] == "goto" && fields[i+1] == "22972" {
								return errors.New("native anchor still has a goto reference")
							}
						}
					}
				}
				return ctx.Err()
			}
			snapshot, err := f.firewall(ctx, f.plan.Effects[index].Tool == PolicyEffectIP6Tables)
			if err != nil {
				return err
			}
			if (f.chainSteps[index] || f.bodySteps[index]) && len(snapshot.references) != 0 || f.chainSteps[index] && len(snapshot.own) != 0 {
				return errors.New("native classifier prerequisite is still referenced")
			}
			return ctx.Err()
		},
	}
}

func nativeEffectRun(t *testing.T, command string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, command, args...).CombinedOutput()
	if err != nil || len(out) > 64<<10 {
		t.Fatalf("native fixture %s %v: %v: %s", command, args, err, out)
	}
	return string(out)
}

func (f nativeEffectFixture) kernelSnapshot(t *testing.T) string {
	t.Helper()
	return nativeEffectRun(t, f.tools.IPTables, "-t", "mangle", "-S") + "\nIPv6\n" + nativeEffectRun(t, f.tools.IP6Tables, "-t", "mangle", "-S") +
		"\nRPDB4\n" + nativeEffectRun(t, f.tools.IP, "-4", "rule", "show") + "\nRPDB6\n" + nativeEffectRun(t, f.tools.IP, "-6", "rule", "show")
}

func (f nativeEffectFixture) foreign(t *testing.T, verb string) {
	t.Helper()
	for index, tool := range []string{f.tools.IPTables, f.tools.IP6Tables} {
		nativeEffectRun(t, tool, f.foreignFirewallArgs(index, verb)...)
	}
	ipVerb := "add"
	if verb == "-D" {
		ipVerb = "del"
	}
	for index, family := range []int{4, 6} {
		rule := lanClassifierRule{family: family, priority: 22960, source: []string{"192.168.88.26/32", "fd88::26/128"}[index], action: "lookup main"}
		nativeEffectRun(t, f.tools.IP, rule.args(ipVerb)...)
	}
}

func (f nativeEffectFixture) foreignFirewallArgs(familyIndex int, verb string) []string {
	source := []string{"192.168.88.26/32", "fd88::26/128"}[familyIndex]
	return []string{"-t", "mangle", verb, "PREROUTING", "-i", f.state.Ingress[0], "-s", source, "-j", "RETURN"}
}

// -S may reorder the fixed header matches (-s before -i). Let the kernel
// verify the exact inserted tuple with -C; textual preservation then compares
// the actual canonical baseline, never an assumed option order. This is only
// a positive check of this empty-namespace fixture's synthetic foreign rule.
func (f nativeEffectFixture) foreignFirewallReadback(t *testing.T, ctx context.Context, familyIndex int, stage string) proxyFirewallSnapshot {
	t.Helper()
	tool := []string{f.tools.IPTables, f.tools.IP6Tables}[familyIndex]
	args := f.foreignFirewallArgs(familyIndex, "-C")
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, checkErr := exec.CommandContext(checkCtx, tool, args...).CombinedOutput()
	snapshot, readErr := f.firewall(ctx, familyIndex == 1)
	if checkErr != nil || readErr != nil || len(out) > 64<<10 {
		t.Fatalf("synthetic foreign firewall tuple unavailable %s IPv%d: expected=%q check_err=%v read_err=%v check_output=%q actual_parent=%q", stage, []int{4, 6}[familyIndex], args, checkErr, readErr, out[:min(len(out), 4096)], snapshot.parent)
	}
	return snapshot
}

// Only an exclusively assigned empty namespace may execute this fixture. The
// normal router/VM namespace and a namespace already containing interfaces or
// firewall/policy rules refuse BEFORE the first networking mutation.
func TestNativePolicyEffectReceiptCrashBoundaries(t *testing.T) {
	if os.Getenv("RAZVILKA_POLICY_RECEIPT_NETNS") != "1" {
		t.Skip("requires an exclusively assigned empty Linux network namespace")
	}
	self, e1 := os.Readlink("/proc/self/ns/net")
	owner, e2 := os.Readlink("/proc/1/ns/net")
	if os.Geteuid() != 0 || e1 != nil || e2 != nil || self == owner {
		t.Fatal("requires root in an isolated network namespace")
	}
	tools := PolicyEffectTools{}
	for _, item := range []struct {
		name string
		path *string
	}{{"ip", &tools.IP}, {"iptables", &tools.IPTables}, {"ip6tables", &tools.IP6Tables}} {
		path, err := exec.LookPath(item.name)
		if err != nil {
			t.Fatal(err)
		}
		*item.path = path
	}
	role := os.Getenv("RAZVILKA_EFFECT_CHILD")
	if role != "" {
		token := os.Getenv("RAZVILKA_EFFECT_TOKEN")
		if len(token) != 12 || strings.Trim(token, "0123456789abcdef") != "" || os.Getenv("RAZVILKA_EFFECT_NETNS") != self {
			t.Fatal("child fixture identity is invalid")
		}
		f := newNativeEffectFixture(token, tools)
		interfaces, err := net.Interfaces()
		if err != nil || len(interfaces) != 2 || !nativeEffectHasInterface(interfaces, "lo") || !nativeEffectHasInterface(interfaces, f.state.Ingress[0]) {
			t.Fatal("child lacks its exclusively assigned fixture namespace")
		}
		index, err := strconv.Atoi(os.Getenv("RAZVILKA_EFFECT_INDEX"))
		point := os.Getenv("RAZVILKA_EFFECT_POINT")
		valid := false
		for _, probe := range f.probes {
			valid = valid || probe == index
		}
		if err != nil || !valid || role != "apply" && role != "remove" || role == "apply" && point != "intent" && point != "add" && point != "added" || role == "remove" && point != "cleanup-intent" && point != "delete" && point != "removed" {
			t.Fatal("child crash selection is invalid")
		}
		options := policyAdditionOptions{fault: func(got string, at int) error {
			if got == point && at == index {
				os.Exit(73)
			}
			return nil
		}}
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		if role == "apply" {
			err = applyPolicyEffects(ctx, f.runtime(), f.plan, os.Getenv("RAZVILKA_EFFECT_ROOT"), options)
		} else {
			err = removePolicyEffects(ctx, f.runtime(), f.plan, os.Getenv("RAZVILKA_EFFECT_ROOT"), options)
		}
		t.Fatalf("child missed its durable crash boundary: %v", err)
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		t.Fatal("fixture requires only loopback; refusing networking mutations")
	}
	for _, tool := range []string{tools.IPTables, tools.IP6Tables} {
		for _, line := range strings.Split(nativeEffectRun(t, tool, "-t", "mangle", "-S"), "\n") {
			fields := strings.Fields(line)
			if len(fields) != 0 && (len(fields) != 3 || fields[0] != "-P" || fields[2] != "ACCEPT") {
				t.Fatal("fixture requires an empty mangle ruleset in both families")
			}
		}
	}
	for _, family := range []string{"-4", "-6"} {
		for _, line := range strings.Split(nativeEffectRun(t, tools.IP, family, "rule", "show"), "\n") {
			line = strings.Join(strings.Fields(line), " ")
			if line != "" && line != "0: from all lookup local" && line != "32766: from all lookup main" && line != "32767: from all lookup default" {
				t.Fatal("fixture requires only built-in RPDB rules in both families")
			}
		}
	}
	var nonce [6]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	f := newNativeEffectFixture(hex.EncodeToString(nonce[:]), tools)
	if validLANClassifier(f.state) != nil {
		t.Fatal("fixture compiler intent is invalid")
	}
	nativeEffectRun(t, tools.IP, "link", "add", f.state.Ingress[0], "type", "dummy")
	t.Cleanup(func() { nativeEffectRun(t, tools.IP, "link", "delete", f.state.Ingress[0]) })
	for _, role := range []string{"apply", "remove"} {
		points := []string{"intent", "add", "added"}
		if role == "remove" {
			points = []string{"cleanup-intent", "delete", "removed"}
		}
		for _, index := range f.probes {
			for _, point := range points {
				t.Run(fmt.Sprintf("%s-%s-%d", role, point, index), func(t *testing.T) {
					// Explicit test teardown owns these exact tuples because the
					// parent proved the namespace empty. It never flushes or grants
					// production reconciliation authority to an unknown receipt.
					t.Cleanup(func() {
						cleanupCtx, stopCleanup := context.WithTimeout(context.Background(), 15*time.Second)
						defer stopCleanup()
						for i := len(f.plan.Effects) - 1; i >= 0; i-- {
							effect := f.plan.Effects[i]
							_, _ = exec.CommandContext(cleanupCtx, f.tools.command(effect.Tool), effect.Delete...).CombinedOutput()
						}
						if cleanupCtx.Err() != nil {
							t.Error("native fixture exact teardown exceeded its deadline")
						}
					})
					root := privateScopedXrayFixtureDir(t)
					ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
					defer cancel()
					if role == "remove" {
						if err := ApplyPolicyEffectsWithReceipt(ctx, f.runtime(), f.plan, root); err != nil {
							t.Fatal(err)
						}
					}
					child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNativePolicyEffectReceiptCrashBoundaries$", "-test.count=1")
					child.Env = append(os.Environ(), "RAZVILKA_EFFECT_CHILD="+role, "RAZVILKA_EFFECT_POINT="+point, "RAZVILKA_EFFECT_INDEX="+strconv.Itoa(index),
						"RAZVILKA_EFFECT_ROOT="+root, "RAZVILKA_EFFECT_TOKEN="+strings.TrimPrefix(f.state.Chain, "RZC_"), "RAZVILKA_EFFECT_NETNS="+self)
					out, childErr := child.CombinedOutput()
					var exit *exec.ExitError
					if !errors.As(childErr, &exit) || exit.ExitCode() != 73 {
						t.Fatalf("child did not stop at the requested boundary: %v: %s", childErr, out)
					}
					status, err := InspectPolicyEffectsReceipt(ctx, f.plan, root)
					unknown := point != "added" && point != "removed"
					if err != nil || status.Unknown != unknown {
						t.Fatal("fresh ledger did not retain its durable outcome", status, err)
					}
					wantPresence := 1
					if point == "intent" || point == "delete" || point == "removed" {
						wantPresence = 0
					}
					if count, err := f.presence(ctx, index); err != nil || count != wantPresence {
						t.Fatal("kernel does not match the actual crash boundary", index, count, err)
					}
					f.foreign(t, "-A")
					t.Cleanup(func() { f.foreign(t, "-D") })
					var foreignKeys [2]string
					for familyIndex := range []int{4, 6} {
						snapshot := f.foreignFirewallReadback(t, ctx, familyIndex, "before cleanup")
						jumpKey := lanClassifierChainKey(lanClassifierJumps(f.state)[0])
						var foreignRules [][]string
						for _, rule := range snapshot.parent {
							if lanClassifierChainKey(rule) != jumpKey {
								foreignRules = append(foreignRules, rule)
							}
						}
						if len(foreignRules) != 1 {
							t.Fatalf("synthetic foreign baseline is not unique IPv%d: expected=%q actual_parent=%q", []int{4, 6}[familyIndex], f.foreignFirewallArgs(familyIndex, "-C"), snapshot.parent)
						}
						foreignKeys[familyIndex] = lanClassifierChainKey(foreignRules[0])
						insertedKey := lanClassifierChainKey(f.foreignFirewallArgs(familyIndex, "-A")[4:])
						if foreignKeys[familyIndex] != insertedKey {
							t.Logf("kernel canonicalized the exact -C-verified synthetic rule IPv%d: inserted=%q actual=%q", []int{4, 6}[familyIndex], insertedKey, foreignKeys[familyIndex])
						}
					}
					before, calls := f.kernelSnapshot(t), f.runner.calls
					cleanupErr := RemovePolicyEffectsWithReceipt(ctx, f.runtime(), f.plan, root)
					if unknown {
						if !errors.Is(cleanupErr, ErrPolicyAdditionUnknown) || f.runner.calls != calls || f.kernelSnapshot(t) != before {
							t.Fatal("unknown mixed receipt performed RPC or lost a prerequisite", cleanupErr)
						}
					} else {
						if cleanupErr != nil {
							t.Fatal("known ACK cleanup failed", cleanupErr)
						}
						for i := range f.plan.Effects {
							if count, err := f.presence(ctx, i); err != nil || count != 0 {
								t.Fatal("known ACK cleanup left a compiled effect", i, count, err)
							}
						}
					}
					for familyIndex := range []int{4, 6} {
						source := []string{"192.168.88.26/32", "fd88::26/128"}[familyIndex]
						snapshot := f.foreignFirewallReadback(t, ctx, familyIndex, "after cleanup")
						count := 0
						for _, rule := range snapshot.parent {
							if lanClassifierChainKey(rule) == foreignKeys[familyIndex] {
								count++
							}
						}
						if count != 1 {
							t.Fatalf("synthetic foreign firewall baseline changed IPv%d: expected=%q before_key=%q actual_parent=%q count=%d", []int{4, 6}[familyIndex], f.foreignFirewallArgs(familyIndex, "-C"), foreignKeys[familyIndex], snapshot.parent, count)
						}
						family := []string{"-4", "-6"}[familyIndex]
						foreignRule := lanClassifierRule{family: []int{4, 6}[familyIndex], priority: 22960, source: source, action: "lookup main"}
						count = 0
						for _, line := range strings.Split(nativeEffectRun(t, tools.IP, family, "rule", "show"), "\n") {
							if strings.Join(strings.Fields(line), " ") == foreignRule.line() {
								count++
							}
						}
						if count != 1 {
							t.Fatal("receipt cleanup removed a foreign near-match RPDB rule")
						}
					}
				})
			}
		}
	}
	t.Log("native mixed chain/negative-guard/attachment/anchor/goto crash boundaries preserve unknown fences and foreign near-matches")
}

func nativeEffectHasInterface(interfaces []net.Interface, name string) bool {
	for _, iface := range interfaces {
		if iface.Name == name {
			return true
		}
	}
	return false
}
