//go:build linux && (amd64 || arm64)

package dataplane

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The same native harness as the defect reproduction, now through the
// production restoration: Manager.RestoreCommittedNFQWS2Hooks with the bound
// startup source (frozen collector, queue observer, process review), the
// adapter's exec runner and the reviewed legacy binaries.

// files reads every owned byte a restoration must leave untouched.
func (n *nfqws2NDMNative) files(t *testing.T) map[string][]byte {
	t.Helper()
	a := n.f.a
	lease, err := a.readLease()
	if err != nil || lease == nil {
		t.Fatal(err)
	}
	lists := a.ownedListPaths()
	result := map[string][]byte{}
	for _, path := range []string{filepath.Join(a.StateRoot, nfqws2LeaseFile), a.ConfigPath, a.ConfigPath + ".run", a.InitPath, a.firstStartPIDPath(),
		filepath.Join(lease.Transaction, "nfqws2.conf.staged"), filepath.Join(lease.Transaction, "S51nfqws2.staged"), lists[0], lists[1], lists[2], lists[3]} {
		data, err := os.ReadFile(path)
		if err == nil {
			result[path] = data
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
	}
	return result
}

func nfqws2NDMSameFiles(left, right map[string][]byte) bool {
	if len(left) != len(right) {
		return false
	}
	for path, data := range left {
		if other, ok := right[path]; !ok || !bytes.Equal(data, other) {
			return false
		}
	}
	return true
}

// nfqws2NDMLines keeps the lines that contain none of drop.
func nfqws2NDMLines(image string, drop ...string) string {
	var kept []string
	for _, line := range strings.Split(image, "\n") {
		if !slices.ContainsFunc(drop, func(token string) bool { return strings.Contains(line, token) }) {
			kept = append(kept, line)
		}
	}
	return strings.Join(kept, "\n")
}

// nfqws2NDMAppend adds declarations after the table header and rules before
// its COMMIT; image holds exactly one table.
func nfqws2NDMAppend(image string, declarations []string, rules ...string) string {
	lines := strings.Split(image, "\n")
	var out []string
	for _, line := range lines {
		if line == "COMMIT" {
			out = append(out, rules...)
		}
		out = append(out, line)
		if strings.HasPrefix(line, "*") {
			out = append(out, declarations...)
		}
	}
	return strings.Join(out, "\n")
}

// tokens reports whether -S and iptables-save print the owned rows with the
// same tokens on this iptables build; the router's 1.4.21 is not covered.
func (n *nfqws2NDMNative) tokens(t *testing.T, family int) int {
	t.Helper()
	var listed, saved [][]string
	for _, line := range strings.Split(n.command(t, "", n.tools[family], "-t", "mangle", "-S"), "\n") {
		if strings.Contains(line, "nfqws") {
			tokens, err := backendXTablesTokens(line)
			if err != nil {
				t.Fatal(err)
			}
			listed = append(listed, tokens)
		}
	}
	for _, line := range strings.Split(n.save(t, family, "mangle"), "\n") {
		if strings.HasPrefix(line, ":nfqws") {
			saved = append(saved, []string{"-N", strings.Fields(line[1:])[0]})
		} else if strings.Contains(line, "nfqws") {
			tokens, err := backendXTablesTokens(line)
			if err != nil {
				t.Fatal(err)
			}
			saved = append(saved, tokens)
		}
	}
	if len(listed) != 12 || !slices.EqualFunc(listed, saved, slices.Equal[[]string]) {
		t.Fatalf("-S and iptables-save disagree on the owned rows:\n%q\n%q", listed, saved)
	}
	return len(listed)
}

func (n *nfqws2NDMNative) restoreOK(t *testing.T, plan Plan, families []int) NFQWS2HookRestore {
	t.Helper()
	writes := n.runner.count()
	result, err := n.f.m.RestoreCommittedNFQWS2Hooks(nfqws2NDMContext(t), plan)
	if err != nil || result.Class != NFQWS2HooksLoss || !slices.Equal(result.Restored, families) || result.Reason != "" || result.RolledBack || result.Uncertain {
		t.Fatalf("lost graph not restored: %+v %v", result, err)
	}
	if len(result.Commands) != 12*len(families) || n.runner.count()-writes != len(result.Commands) {
		t.Fatal("restoration commands", len(result.Commands), n.runner.count()-writes)
	}
	return result
}

// noOp requires a refusal or FULL observation without a single firewall
// command and without any table byte changing.
func (n *nfqws2NDMNative) noOp(t *testing.T, plan Plan) (NFQWS2HookRestore, error) {
	t.Helper()
	before, writes := n.state(t), n.runner.count()
	result, err := n.f.m.RestoreCommittedNFQWS2Hooks(nfqws2NDMContext(t), plan)
	if len(result.Commands) != 0 || n.runner.count() != writes || n.state(t) != before {
		t.Fatalf("restoration wrote: %+v %v", result, err)
	}
	return result, err
}

// TestNFQWS2HookNDMRestoreNative: FULL is a no-op; after the NDM rewrite the
// restoration re-creates the exact pre-loss tables under the same daemon and
// queue socket, appending the jumps after newer firmware rules; partial,
// foreign and ambiguous states refuse without a command; a rewrite racing
// the restoration leaves no residue and the next attempt succeeds.
func TestNFQWS2HookNDMRestoreNative(t *testing.T) {
	if nfqws2NDMNativeEnter(t) {
		return
	}
	n := newNFQWS2NDMNative(t, false)
	m, plan := n.f.m, n.committed(t)
	full, daemon, files := n.state(t), n.daemon(t), n.files(t)
	version := strings.TrimSpace(n.command(t, "", n.tools[4], "--version"))
	t.Logf("%s: -S and iptables-save agree on %d owned rows", version, n.tokens(t, 4))

	// FULL is a no-op: zero firewall commands, identical tables.
	if result, err := n.noOp(t, plan); err != nil || result.Class != NFQWS2HooksFull {
		t.Fatal("full graph was not a no-op", result, err)
	}

	// The defect, then the production restoration under the same daemon.
	lost := n.rewrite(t, 4, nil)
	if out := n.hook(t, "mangle", "iptables"); !strings.Contains(out, nfqws2NDMInert) {
		t.Fatalf("genuine hook did not reach the guarded init: %q", out)
	}
	if observed, err := m.ObserveCommittedNFQWS2Hooks(nfqws2NDMContext(t), plan); err != nil || observed.Class != NFQWS2HooksLoss {
		t.Fatal("loss not observed", observed, err)
	}
	if err := n.f.a.Health(nfqws2NDMContext(t), plan, ""); err == nil {
		t.Fatal("Health accepted the lost graph")
	}
	result := n.restoreOK(t, plan, []int{4})
	if result.Queue == nil || result.Queue.Number != 300 || daemon.CopyMode != strconv.Itoa(int(result.Queue.CopyMode)) || daemon.CopyRange != strconv.Itoa(int(result.Queue.CopyRange)) {
		t.Fatalf("queue parameters %+v differ from the daemon's %+v", result.Queue, daemon)
	}
	if after := n.state(t); after != full {
		t.Fatalf("restored tables differ from the pre-loss tables:\n%s\n---\n%s", after.Mangle4, full.Mangle4)
	}
	if n.daemon(t) != daemon || !nfqws2NDMSameFiles(n.files(t), files) {
		t.Fatal("restoration changed the daemon, its queue socket or an owned file")
	}
	if err := n.f.a.Health(nfqws2NDMContext(t), plan, ""); err != nil {
		t.Fatal("restored graph fails Health", err)
	}
	if again, err := n.noOp(t, plan); err != nil || again.Class != NFQWS2HooksFull {
		t.Fatal("restored graph is not a no-op", again, err)
	}
	t.Logf("restored %d commands under pid=%d start=%s port=%s inode=%s; queue copy_mode=%d copy_range=%d recorded, not required",
		len(result.Commands), daemon.PID, daemon.Start, daemon.Port, daemon.Inode, result.Queue.CopyMode, result.Queue.CopyRange)

	// NDM's next model ends both hooks with new firmware rules (a RETURN
	// chain, an empty chain as all firmware POSTROUTING hooks are); the
	// restored jumps are appended after them, as stock appends them.
	n.rewrite(t, 4, func(image string) string {
		return nfqws2NDMAppend(image, []string{":_NDM_TEST_POST_TAIL - [0:0]", ":_NDM_TEST_TAIL - [0:0]"},
			"-A PREROUTING -j _NDM_TEST_TAIL", "-A POSTROUTING -j _NDM_TEST_POST_TAIL", "-A _NDM_TEST_TAIL -m mac --mac-source 02:00:00:00:00:04 -j RETURN")
	})
	tail := n.save(t, 4, "mangle")
	n.restoreOK(t, plan, []int{4})
	appended := n.save(t, 4, "mangle")
	var pre, post []string
	for _, line := range strings.Split(appended, "\n") {
		if strings.HasPrefix(line, "-A PREROUTING ") {
			pre = append(pre, line)
		}
		if strings.HasPrefix(line, "-A POSTROUTING ") {
			post = append(post, line)
		}
	}
	if len(pre) < 2 || pre[len(pre)-1] != "-A PREROUTING -j nfqws_pre" || pre[len(pre)-2] != "-A PREROUTING -j _NDM_TEST_TAIL" ||
		len(post) < 2 || post[len(post)-1] != "-A POSTROUTING -j nfqws_post" || post[len(post)-2] != "-A POSTROUTING -j _NDM_TEST_POST_TAIL" {
		t.Fatalf("restored jumps are not last:\n%s", appended)
	}
	if nfqws2NDMLines(appended, "nfqws") != tail {
		t.Fatal("restoration changed a firmware row")
	}
	if err := n.f.a.Health(nfqws2NDMContext(t), plan, ""); err != nil {
		t.Fatal("appended graph fails Health", err)
	}

	// Partial, foreign or ambiguous states refuse before any command.
	n.restore(t, 4, full.Mangle4)
	refusals := []struct {
		name, reason string
		v4, v6       string
	}{
		{name: "post-graph-only", reason: "owned-graph-partial", v4: nfqws2NDMLines(full.Mangle4, "nfqws_pre")},
		{name: "jumps-missing", reason: "owned-graph-partial", v4: nfqws2NDMLines(full.Mangle4, "-j nfqws_post", "-j nfqws_pre")},
		{name: "duplicate-post-jump", reason: "owned-jump-duplicate", v4: nfqws2NDMAppend(full.Mangle4, nil, "-A POSTROUTING -j nfqws_post")},
		{name: "foreign-rule-on-owned-queue", reason: "foreign-rule-references-owned-queue", v4: nfqws2NDMAppend(lost, nil, "-A FORWARD -p tcp -j NFQUEUE --queue-num 300")},
		{name: "foreign-same-name-chain", reason: "owned-chain-body-differs", v4: nfqws2NDMAppend(lost, []string{":nfqws_pre - [0:0]"}, "-A nfqws_pre -j RETURN")},
		{name: "terminal-before-insertion", reason: "prerouting-terminal-before-hook", v4: nfqws2NDMAppend(lost, nil, "-A PREROUTING -j ACCEPT")},
		{name: "nat-hook-lost", reason: "nat-hook-missing", v4: lost + nfqws2NDMLines(full.NAT4, "nfqws")},
		{name: "nat-chain-not-empty", reason: "nat-chain-not-empty", v4: lost + nfqws2NDMAppend(full.NAT4, nil, "-A nfqws_nat -j RETURN")},
		{name: "owned-object-in-filter", reason: "owned-object-outside-mangle", v4: lost + nfqws2NDMAppend(full.Filter4, []string{":nfqws_fwd - [0:0]"})},
		{name: "ipv6-token-while-disabled", reason: "owned-object-with-ipv6-disabled", v4: lost, v6: nfqws2NDMAppend(full.Mangle6, []string{":nfqws_post - [0:0]"})},
	}
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			n.restore(t, 4, full.Mangle4+full.NAT4+full.Filter4)
			n.restore(t, 6, full.Mangle6+full.Filter6)
			n.restore(t, 4, tc.v4)
			if tc.v6 != "" {
				n.restore(t, 6, tc.v6)
			}
			result, err := n.noOp(t, plan)
			if !errors.Is(err, ErrNFQWS2HookRestore) || result.Class != NFQWS2HooksOther || result.Reason != NFQWS2HookReasonOther || result.Queue != nil {
				t.Fatalf("not refused as other: %+v %v", result, err)
			}
			var refused *nfqws2HookRestoreError
			if !errors.As(err, &refused) || refused.detail != tc.reason {
				t.Fatalf("refusal %v (families %+v), want %s", err, result.Families, tc.reason)
			}
			if n.daemon(t) != daemon {
				t.Fatal("refusal changed the daemon")
			}
		})
	}
	n.restore(t, 4, full.Mangle4+full.NAT4+full.Filter4)
	n.restore(t, 6, full.Mangle6+full.Filter6)

	// NDM writes mangle again while the restoration runs. Each race leaves no
	// owned residue; the next attempt restores the exact graph.
	races := []struct {
		name, reason   string
		before, after  []string
		removedObjects int
	}{
		{name: "after-first-chain", reason: NFQWS2HookReasonWrite, after: []string{"-t", "mangle", "-N", "nfqws_post"}, removedObjects: 1},
		{name: "after-last-body", reason: NFQWS2HookReasonChanged, after: []string{"-t", "mangle", "-A", "nfqws_pre", "-i", "eth3", "-p", "tcp", "-m", "mark", "!", "--mark", "0x40000000/0x40000000", "-m", "multiport", "--sports", "443", "-m", "tcp", "--tcp-flags", "RST", "RST", "-j", "NFQUEUE", "--queue-num", "300", "--queue-bypass"}},
		{name: "before-post-jump", reason: NFQWS2HookReasonWrite, before: []string{"-t", "mangle", "-A", "POSTROUTING", "-j", "nfqws_post"}},
		{name: "between-jumps", reason: NFQWS2HookReasonWrite, after: []string{"-t", "mangle", "-A", "POSTROUTING", "-j", "nfqws_post"}},
	}
	for _, tc := range races {
		t.Run("race-"+tc.name, func(t *testing.T) {
			n.restore(t, 4, full.Mangle4)
			lost := n.rewrite(t, 4, nil)
			fired := false
			race := func(match []string) func([]string) {
				if match == nil {
					return nil
				}
				return func(args []string) {
					if !fired && slices.Equal(args, match) {
						fired = true
						n.rewrite(t, 4, nil)
					}
				}
			}
			n.runner.arm(race(tc.before), race(tc.after))
			result, err := n.f.m.RestoreCommittedNFQWS2Hooks(nfqws2NDMContext(t), plan)
			n.runner.arm(nil, nil)
			if !fired || err == nil || result.Reason != tc.reason || !result.RolledBack || result.Uncertain || len(result.Restored) != 0 {
				t.Fatalf("racing rewrite: fired=%t %+v %v", fired, result, err)
			}
			removals := 0
			for _, command := range result.Commands {
				if command.Args[2] == "-D" || command.Args[2] == "-X" {
					removals++
				}
			}
			if removals != tc.removedObjects {
				t.Fatalf("cleanup removed %d objects, want %d: %v", removals, tc.removedObjects, result.Commands)
			}
			if after := n.state(t); after.Mangle4 != lost || after.NAT4 != full.NAT4 || after.Filter4 != full.Filter4 || after.Mangle6 != full.Mangle6 {
				t.Fatalf("racing rewrite left residue:\n%s", after.Mangle4)
			}
			if n.daemon(t) != daemon || !nfqws2NDMSameFiles(n.files(t), files) {
				t.Fatal("race changed the daemon or an owned file")
			}
			n.restoreOK(t, plan, []int{4})
			if n.state(t) != full {
				t.Fatal("next restoration after the race differs from the pre-loss tables")
			}
			t.Logf("race %s: %s, %d commands, rolled back with %d removals", tc.name, result.Reason, len(result.Commands), removals)
		})
	}
	if err := n.f.a.Health(nfqws2NDMContext(t), plan, ""); err != nil || n.daemon(t) != daemon {
		t.Fatal("final graph or daemon", err)
	}
}

// IPv6 enabled: stock appends the same mangle graph through ip6tables (no
// nat); each family is classified and restored independently.
func TestNFQWS2HookNDMRestoreIPv6Native(t *testing.T) {
	if nfqws2NDMNativeEnter(t) {
		return
	}
	n := newNFQWS2NDMNative(t, true)
	m, plan := n.f.m, n.committed(t)
	full, daemon, files := n.state(t), n.daemon(t), n.files(t)
	for _, line := range []string{":nfqws_post -", ":nfqws_pre -", "-A POSTROUTING -j nfqws_post", "-A PREROUTING -j nfqws_pre"} {
		if !strings.Contains(full.Mangle6, line) {
			t.Fatalf("genuine stock start left no IPv6 %q:\n%s", line, full.Mangle6)
		}
	}
	t.Logf("ip6tables: -S and iptables-save agree on %d owned rows", n.tokens(t, 6))
	if result, err := n.noOp(t, plan); err != nil || result.Class != NFQWS2HooksFull {
		t.Fatal("full graph was not a no-op", result, err)
	}
	n.rewrite(t, 4, nil)
	n.rewrite(t, 6, nil)
	for _, kind := range []string{"iptables", "ip6tables"} {
		if out := n.hook(t, "mangle", kind); !strings.Contains(out, nfqws2NDMInert) {
			t.Fatalf("genuine %s hook did not reach the guarded init: %q", kind, out)
		}
	}
	if observed, err := m.ObserveCommittedNFQWS2Hooks(nfqws2NDMContext(t), plan); err != nil || observed.Class != NFQWS2HooksLoss || len(observed.Families) != 2 {
		t.Fatal("loss not observed in both families", observed, err)
	}
	n.restoreOK(t, plan, []int{4, 6})
	if n.state(t) != full || n.daemon(t) != daemon || !nfqws2NDMSameFiles(n.files(t), files) {
		t.Fatal("both-family restoration differs from the pre-loss state")
	}
	n.rewrite(t, 6, nil)
	healthWhileV6Lost := n.f.a.Health(nfqws2NDMContext(t), plan, "")
	n.restoreOK(t, plan, []int{6})
	if n.state(t) != full || n.daemon(t) != daemon {
		t.Fatal("IPv6-only restoration differs from the pre-loss state")
	}
	if err := n.f.a.Health(nfqws2NDMContext(t), plan, ""); err != nil {
		t.Fatal("restored graph fails Health", err)
	}
	t.Logf("restored both families, then IPv6 alone; Health with only the IPv6 graph lost: %v (Health reads the IPv4 save only)", healthWhileV6Lost)
}
