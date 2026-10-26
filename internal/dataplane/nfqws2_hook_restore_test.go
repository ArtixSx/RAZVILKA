package dataplane

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/components"
)

// nfqws2HookModelTable is one legacy xtables table: built-in policies, user
// chains (sorted, as legacy -S and iptables-save print them) and ordered
// rule bodies (the tokens after "-A <chain>").
type nfqws2HookModelTable struct {
	builtins []string
	policies map[string]string
	user     []string
	rules    map[string][][]string
}

func (table *nfqws2HookModelTable) has(chain string) bool {
	return slices.Contains(table.builtins, chain) || slices.Contains(table.user, chain)
}

func (table *nfqws2HookModelTable) chains() []string {
	return append(slices.Clone(table.builtins), table.user...)
}

// nfqws2HookKernel deterministically models both families' complete -S
// inventory and the stock writer semantics restore relies on: -N refuses an
// existing chain, -A appends at the end and needs an existing chain and
// target chain, -D removes the first exact match, -X removes only an empty
// unreferenced user chain. It is a model, never native kernel evidence.
type nfqws2HookKernel struct {
	families map[int]map[string]*nfqws2HookModelTable
}

func newNFQWS2HookKernel(t *testing.T, v4, v6 string) *nfqws2HookKernel {
	t.Helper()
	k := &nfqws2HookKernel{families: map[int]map[string]*nfqws2HookModelTable{}}
	for family, save := range map[int]string{4: v4, 6: v6} {
		tables := map[string]*nfqws2HookModelTable{}
		var table *nfqws2HookModelTable
		for _, line := range strings.Split(save, "\n") {
			switch {
			case line == "" || line == "COMMIT" || strings.HasPrefix(line, "#"):
			case strings.HasPrefix(line, "*"):
				table = &nfqws2HookModelTable{policies: map[string]string{}, rules: map[string][][]string{}}
				tables[line[1:]] = table
			case strings.HasPrefix(line, ":"):
				f := strings.Fields(line[1:])
				if f[1] == "-" {
					table.user = append(table.user, f[0])
				} else {
					table.builtins = append(table.builtins, f[0])
					table.policies[f[0]] = f[1]
				}
			default:
				tokens, err := backendXTablesTokens(line)
				if err != nil || len(tokens) < 3 || tokens[0] != "-A" || !table.has(tokens[1]) {
					t.Fatalf("unmodeled fixture line %q: %v", line, err)
				}
				table.rules[tokens[1]] = append(table.rules[tokens[1]], tokens[2:])
			}
		}
		for _, table := range tables {
			sort.Strings(table.user)
		}
		k.families[family] = tables
	}
	return k
}

func (k *nfqws2HookKernel) tableNames(family int) []string {
	var names []string
	for name := range k.families[family] {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (k *nfqws2HookKernel) rows() []BackendInventoryRow {
	var rows []BackendInventoryRow
	for _, family := range []int{4, 6} {
		for _, name := range k.tableNames(family) {
			table := k.families[family][name]
			for _, chain := range table.builtins {
				rows = append(rows, BackendInventoryRow{Family: family, Table: name, Tokens: []string{"-P", chain, table.policies[chain]}})
			}
			for _, chain := range table.user {
				rows = append(rows, BackendInventoryRow{Family: family, Table: name, Tokens: []string{"-N", chain}})
			}
			for _, chain := range table.chains() {
				for _, rule := range table.rules[chain] {
					rows = append(rows, BackendInventoryRow{Family: family, Table: name, Tokens: append([]string{"-A", chain}, rule...)})
				}
			}
		}
	}
	return rows
}

func (k *nfqws2HookKernel) save(family int) string {
	var out strings.Builder
	for _, name := range k.tableNames(family) {
		table := k.families[family][name]
		out.WriteString("*" + name + "\n")
		for _, chain := range table.builtins {
			out.WriteString(":" + chain + " " + table.policies[chain] + " [0:0]\n")
		}
		for _, chain := range table.user {
			out.WriteString(":" + chain + " - [0:0]\n")
		}
		for _, chain := range table.chains() {
			for _, rule := range table.rules[chain] {
				out.WriteString(strings.Join(append([]string{"-A", chain}, rule...), " ") + "\n")
			}
		}
		out.WriteString("COMMIT\n")
	}
	return out.String()
}

func (k *nfqws2HookKernel) apply(family int, args []string) error {
	if len(args) < 4 || args[0] != "-t" {
		return errors.New("unmodeled command")
	}
	table := k.families[family][args[1]]
	if table == nil {
		return errors.New("table does not exist")
	}
	op, chain, rule := args[2], args[3], slices.Clone(args[4:])
	switch op {
	case "-N":
		if len(rule) != 0 || table.has(chain) {
			return errors.New("Chain already exists.")
		}
		table.user = append(table.user, chain)
		sort.Strings(table.user)
	case "-A":
		if !table.has(chain) || len(rule) == 0 {
			return errors.New("No chain/target/match by that name.")
		}
		for i := 0; i+1 < len(rule); i++ {
			if (rule[i] == "-j" || rule[i] == "-g") && rule[i+1] != strings.ToUpper(rule[i+1]) && !table.has(rule[i+1]) {
				return errors.New("No chain/target/match by that name.")
			}
		}
		table.rules[chain] = append(table.rules[chain], rule)
	case "-D":
		index := slices.IndexFunc(table.rules[chain], func(actual []string) bool { return slices.Equal(actual, rule) })
		if !table.has(chain) || index < 0 {
			return errors.New("Bad rule (does a matching rule exist in that chain?).")
		}
		table.rules[chain] = slices.Delete(table.rules[chain], index, index+1)
	case "-X":
		if len(rule) != 0 || !slices.Contains(table.user, chain) || len(table.rules[chain]) != 0 {
			return errors.New("Directory not empty")
		}
		for _, other := range table.chains() {
			for _, actual := range table.rules[other] {
				for i := 0; i+1 < len(actual); i++ {
					if (actual[i] == "-j" || actual[i] == "-g") && actual[i+1] == chain {
						return errors.New("Too many links")
					}
				}
			}
		}
		table.user = slices.DeleteFunc(table.user, func(name string) bool { return name == chain })
		delete(table.rules, chain)
	default:
		return errors.New("unmodeled command")
	}
	return nil
}

// The NDM whole-table rewrite signature: every owned mangle object is gone,
// the verify-only nat chain and its jump stay.
func nfqws2HookWithoutOwnedMangle(save string) string {
	var kept []string
	table := ""
	for _, line := range strings.Split(save, "\n") {
		if strings.HasPrefix(line, "*") {
			table = line[1:]
		}
		if table == "mangle" && strings.Contains(line, "nfqws") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

func nfqws2HookWithoutOwned(save string) string {
	var kept []string
	for _, line := range strings.Split(save, "\n") {
		if !strings.Contains(line, "nfqws") {
			kept = append(kept, line)
		}
	}
	return strings.Join(kept, "\n")
}

type nfqws2HookWrite struct {
	binary string
	args   []string
}

// nfqws2HookFixture is the first-start consumer model with a modeled kernel:
// owned_start leaves the sanitized router graph, the reviewed iptables paths
// mutate the model and the inventory/queue sources read it.
type nfqws2HookFixture struct {
	*firstStartFixture
	ipv6                bool
	kernel              *nfqws2HookKernel
	iptables, ip6tables string
	writes              []nfqws2HookWrite
	beforeWrite         func(n int, family int, args []string) error
	beforeRead          func(n int)
	reads               int
	readErr             error
	queueOwner          int
	queueInode          string
}

func nfqws2HookFullV4() string {
	return nfqws2RouterNATFixture + nfqws2RouterMangleFixture + nfqws2RouterFilterFixture
}

func (h *nfqws2HookFixture) fullKernel(t *testing.T) *nfqws2HookKernel {
	t.Helper()
	if h.ipv6 {
		return newNFQWS2HookKernel(t, nfqws2HookFullV4(), nfqws2HookTestIPv6Full())
	}
	return newNFQWS2HookKernel(t, nfqws2HookFullV4(), nfqws2RouterIPv6Fixture)
}

// lose applies the NDM rewrite signature to the chosen families.
func (h *nfqws2HookFixture) lose(t *testing.T, families ...int) {
	t.Helper()
	v4, v6 := nfqws2HookFullV4(), nfqws2RouterIPv6Fixture
	if h.ipv6 {
		v6 = nfqws2HookTestIPv6Full()
	}
	if slices.Contains(families, 4) {
		v4 = nfqws2HookWithoutOwnedMangle(v4)
	}
	if slices.Contains(families, 6) {
		v6 = nfqws2HookWithoutOwnedMangle(v6)
	}
	h.kernel = newNFQWS2HookKernel(t, v4, v6)
}

func newNFQWS2HookFixture(t *testing.T, ipv6 bool) *nfqws2HookFixture {
	t.Helper()
	h := &nfqws2HookFixture{firstStartFixture: newFirstStartFixture(t), ipv6: ipv6, iptables: "/opt/sbin/iptables", ip6tables: "/opt/sbin/ip6tables", queueInode: "777"}
	f := h.firstStartFixture
	if ipv6 {
		writeStockText(t, f.a.ConfigPath, strings.Replace(readText(t, f.a.ConfigPath), "IPV6_ENABLED=0", "IPV6_ENABLED=1", 1))
	}
	h.kernel = newNFQWS2HookKernel(t, nfqws2HookWithoutOwned(nfqws2HookFullV4()), nfqws2RouterIPv6Fixture)
	identity, _ := networkPolicyIdentityFixture()
	inner := f.a.Runner
	f.a.Runner = nfqws2RunFunc(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		switch name {
		case h.iptables, h.ip6tables:
			f.calls = append(f.calls, name+" "+strings.Join(args, " "))
			family := map[string]int{h.iptables: 4, h.ip6tables: 6}[name]
			h.writes = append(h.writes, nfqws2HookWrite{binary: name, args: slices.Clone(args)})
			if h.beforeWrite != nil {
				if err := h.beforeWrite(len(h.writes), family, args); err != nil {
					return []byte("modeled write failure"), err
				}
			}
			if err := h.kernel.apply(family, args); err != nil {
				return []byte(err.Error()), errors.New("exit status 1")
			}
			return nil, nil
		case f.a.IPTablesSave:
			f.calls = append(f.calls, name)
			return []byte(h.kernel.save(4)), nil
		}
		output, err := inner.Run(ctx, name, args...)
		if name == f.a.InitPath && len(args) == 1 && err == nil {
			switch args[0] {
			case "owned_start":
				h.kernel, h.queueOwner = h.fullKernel(t), f.identity.PID
				if ipv6 {
					writeStockText(t, f.a.ConfigPath+".run", strings.Replace(readText(t, f.a.ConfigPath+".run"), "IPV6_ENABLED=0", "IPV6_ENABLED=1", 1))
				}
			case "owned_stop":
				h.kernel, h.queueOwner = newNFQWS2HookKernel(t, nfqws2HookWithoutOwned(nfqws2HookFullV4()), nfqws2RouterIPv6Fixture), 0
			}
		}
		return output, err
	})
	f.a.firstStartHookModel = func() nfqws2HookSource {
		return nfqws2HookSource{iptables: h.iptables, ip6tables: h.ip6tables,
			read: func(ctx context.Context) (BackendInventorySnapshot, error) {
				h.reads++
				if h.beforeRead != nil {
					h.beforeRead(h.reads)
				}
				if err := errors.Join(ctx.Err(), h.readErr); err != nil {
					return BackendInventorySnapshot{}, err
				}
				return networkPolicyInventoryTestImage(identity.value, h.kernel.rows()), nil
			},
			queue: func(ctx context.Context, queue uint16, receipt components.NFQWSRuntimeProcessIdentity) (nfqws2FirstStartQueue, error) {
				if ctx.Err() != nil || queue != 300 || h.queueOwner == 0 || receipt.PID != h.queueOwner || receipt != f.identity {
					return nfqws2FirstStartQueue{}, errNFQWS2FirstStartQueue
				}
				return nfqws2FirstStartQueue{Number: queue, PortID: 4242, Inode: h.queueInode, CopyMode: 2, CopyRange: 65531}, nil
			}}
	}
	f.apply(t)
	if !slices.EqualFunc(h.kernel.rows(), h.fullKernel(t).rows(), nfqws2HookSameRow) {
		t.Fatal("applied runtime did not leave the modeled router graph")
	}
	h.writes = nil
	return h
}

func (h *nfqws2HookFixture) committed(t *testing.T) Plan {
	t.Helper()
	plan, exists, err := h.m.Committed()
	if err != nil || !exists || plan.State != "committed" {
		t.Fatal("no committed first-start plan", err)
	}
	return plan
}

// Every byte the restoration must leave untouched.
func (h *nfqws2HookFixture) files(t *testing.T) map[string][]byte {
	t.Helper()
	lease, err := h.a.readLease()
	if err != nil || lease == nil {
		t.Fatal(err)
	}
	result := map[string][]byte{}
	lists := h.a.ownedListPaths()
	for _, path := range []string{filepath.Join(h.a.StateRoot, nfqws2LeaseFile), h.a.ConfigPath, h.a.ConfigPath + ".run", h.a.InitPath, h.a.firstStartPIDPath(),
		filepath.Join(lease.Transaction, "nfqws2.conf.staged"), filepath.Join(lease.Transaction, "S51nfqws2.staged"), lists[0], lists[1], lists[2], lists[3]} {
		data, exists, err := nfqws2Read(path)
		if err != nil {
			t.Fatal(err)
		}
		if exists {
			result[path] = data
		}
	}
	return result
}

func (h *nfqws2HookFixture) assertFiles(t *testing.T, before map[string][]byte) {
	t.Helper()
	after := h.files(t)
	if len(after) != len(before) {
		t.Fatal("restoration changed the owned file set")
	}
	for path, data := range before {
		if !bytes.Equal(after[path], data) {
			t.Fatal("restoration changed owned bytes", filepath.Base(path))
		}
	}
}

func (h *nfqws2HookFixture) assertNoRuntimeCall(t *testing.T, start int) {
	t.Helper()
	for _, call := range h.calls[start:] {
		if strings.HasPrefix(call, h.a.InitPath+" ") || firstStartRuntimeAction(call) {
			t.Fatal("restoration reached the stock init", call)
		}
	}
}

// The exact argv stock S51nfqws2 leaves, taken from the sanitized router
// capture rather than from the builder under test: chains, bodies, jumps.
func nfqws2HookExpectedWrites(t *testing.T, binary string, save string) []nfqws2HookWrite {
	t.Helper()
	var writes []nfqws2HookWrite
	for _, chain := range []string{"nfqws_post", "nfqws_pre"} {
		writes = append(writes, nfqws2HookWrite{binary: binary, args: []string{"-t", "mangle", "-N", chain}})
	}
	for _, line := range nfqws2HookTestOwnedLines(save) {
		tokens, err := backendXTablesTokens(line)
		if err != nil {
			t.Fatal(err)
		}
		writes = append(writes, nfqws2HookWrite{binary: binary, args: append([]string{"-t", "mangle"}, tokens...)})
	}
	return append(writes,
		nfqws2HookWrite{binary: binary, args: []string{"-t", "mangle", "-A", "POSTROUTING", "-j", "nfqws_post"}},
		nfqws2HookWrite{binary: binary, args: []string{"-t", "mangle", "-A", "PREROUTING", "-j", "nfqws_pre"}})
}

func nfqws2HookSameWrites(left, right []nfqws2HookWrite) bool {
	return slices.EqualFunc(left, right, func(a, b nfqws2HookWrite) bool { return a.binary == b.binary && slices.Equal(a.args, b.args) })
}

func TestNFQWS2HookRestoreRecreatesLostGraphUnderSameProcess(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	for _, tc := range []struct {
		name     string
		ipv6     bool
		lost     []int
		restored []int
	}{
		{name: "ipv4", lost: []int{4}, restored: []int{4}},
		{name: "ipv6-both-families", ipv6: true, lost: []int{4, 6}, restored: []int{4, 6}},
		{name: "ipv6-only-v6-lost", ipv6: true, lost: []int{6}, restored: []int{6}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newNFQWS2HookFixture(t, tc.ipv6)
			full := h.kernel.rows()
			plan := h.committed(t)
			before, identity, start := h.files(t), h.identity, len(h.calls)
			h.lose(t, tc.lost...)
			observed, err := h.m.ObserveCommittedNFQWS2Hooks(firstStartContext(t), plan)
			if err != nil || observed.Class != NFQWS2HooksLoss {
				t.Fatal("loss not observed", observed, err)
			}
			result, err := h.m.RestoreCommittedNFQWS2Hooks(firstStartContext(t), plan)
			if err != nil || result.Class != NFQWS2HooksLoss || !slices.Equal(result.Restored, tc.restored) || result.Reason != "" || result.RolledBack || result.Uncertain {
				t.Fatal("lost graph not restored", result, err)
			}
			if observed.Instance == "" || result.Instance != observed.Instance {
				t.Fatal("observation and restoration name different instances", observed.Instance, result.Instance)
			}
			var expected []nfqws2HookWrite
			for _, family := range tc.restored {
				binary := map[int]string{4: h.iptables, 6: h.ip6tables}[family]
				expected = append(expected, nfqws2HookExpectedWrites(t, binary, nfqws2RouterMangleFixture)...)
			}
			// Bodies of every family precede any jump; the jumps come last.
			slices.SortStableFunc(expected, func(a, b nfqws2HookWrite) int {
				jump := func(w nfqws2HookWrite) int {
					if w.args[3] == "POSTROUTING" || w.args[3] == "PREROUTING" {
						return 1
					}
					return 0
				}
				return jump(a) - jump(b)
			})
			if !nfqws2HookSameWrites(h.writes, expected) || len(result.Commands) != len(expected) {
				t.Fatalf("restore commands differ:\n%v\n%v", h.writes, expected)
			}
			if result.Queue == nil || result.Queue.Number != 300 || result.Queue.CopyMode != 2 || result.Queue.CopyRange != 65531 {
				t.Fatal("queue parameters not recorded", result.Queue)
			}
			if !slices.EqualFunc(h.kernel.rows(), full, nfqws2HookSameRow) {
				t.Fatal("restored kernel differs from the original graph")
			}
			h.assertNoRuntimeCall(t, start)
			h.assertFiles(t, before)
			if h.identity != identity || !h.running {
				t.Fatal("restoration changed the live process")
			}
			if err := h.a.Health(firstStartContext(t), plan, ""); err != nil {
				t.Fatal("restored graph fails Health", err)
			}
			again, err := h.m.RestoreCommittedNFQWS2Hooks(firstStartContext(t), plan)
			if err != nil || again.Class != NFQWS2HooksFull || len(again.Commands) != 0 {
				t.Fatal("restored graph is not a no-op", again, err)
			}
		})
	}
}

func TestNFQWS2HookRestoreFullGraphIsNoOp(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	h := newNFQWS2HookFixture(t, false)
	plan, before, start := h.committed(t), h.files(t), len(h.calls)
	observed, err := h.m.ObserveCommittedNFQWS2Hooks(firstStartContext(t), plan)
	if err != nil || observed.Class != NFQWS2HooksFull || len(observed.Families) != 1 || observed.Families[0].Class != NFQWS2HooksFull {
		t.Fatal("full graph not observed", observed, err)
	}
	result, err := h.m.RestoreCommittedNFQWS2Hooks(firstStartContext(t), plan)
	if err != nil || result.Class != NFQWS2HooksFull || len(result.Commands) != 0 || len(result.Restored) != 0 || result.Queue != nil {
		t.Fatal("full graph was not a no-op", result, err)
	}
	if len(h.writes) != 0 || len(h.calls) != start {
		t.Fatal("full graph executed commands", h.calls[start:])
	}
	h.assertFiles(t, before)
}

func TestNFQWS2HookRestoreRefusesBeforeAnyWrite(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	type refusal struct {
		name   string
		reason string
		detail string
		setup  func(*testing.T, *nfqws2HookFixture, *Plan, *context.Context)
		direct bool // Call the adapter with the edited plan, bypassing the Manager.
	}
	phase := func(name string, keep bool) func(*testing.T, *nfqws2HookFixture, *Plan, *context.Context) {
		return func(t *testing.T, h *nfqws2HookFixture, _ *Plan, _ *context.Context) {
			lease, err := h.a.readLease()
			if err != nil {
				t.Fatal(err)
			}
			lease.FirstStart.Phase = name
			if !keep {
				lease.FirstStart.Process = nil
			}
			if err := h.a.writeLease(lease); err != nil {
				t.Fatal(err)
			}
		}
	}
	kernel := func(v4, v6 string) func(*testing.T, *nfqws2HookFixture, *Plan, *context.Context) {
		return func(t *testing.T, h *nfqws2HookFixture, _ *Plan, _ *context.Context) {
			h.kernel = newNFQWS2HookKernel(t, v4, v6)
		}
	}
	lossV4 := nfqws2HookWithoutOwnedMangle(nfqws2HookFullV4())
	for _, tc := range []refusal{
		{name: "phase-stopped", reason: NFQWS2HookReasonLease, setup: phase(nfqws2FirstStopped, true)},
		{name: "phase-starting", reason: NFQWS2HookReasonLease, setup: phase(nfqws2FirstStarting, false)},
		{name: "phase-prepared", reason: NFQWS2HookReasonLease, setup: phase(nfqws2FirstPrepared, false)},
		{name: "phase-retiring", reason: NFQWS2HookReasonLease, setup: phase(nfqws2FirstRetiring, true)},
		{name: "missing-run", reason: NFQWS2HookReasonFiles, setup: func(t *testing.T, h *nfqws2HookFixture, _ *Plan, _ *context.Context) {
			if err := os.Remove(h.a.ConfigPath + ".run"); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "missing-pid", reason: NFQWS2HookReasonProcess, setup: func(t *testing.T, h *nfqws2HookFixture, _ *Plan, _ *context.Context) {
			if err := os.Remove(h.a.firstStartPIDPath()); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "reused-pid", reason: NFQWS2HookReasonProcess, setup: func(_ *testing.T, h *nfqws2HookFixture, _ *Plan, _ *context.Context) {
			h.identity.Start = "999999"
		}},
		{name: "second-nfq-process", reason: NFQWS2HookReasonProcess, setup: func(_ *testing.T, h *nfqws2HookFixture, _ *Plan, _ *context.Context) {
			h.foreign = true
		}},
		{name: "changed-wan", reason: NFQWS2HookReasonScope, setup: func(_ *testing.T, h *nfqws2HookFixture, _ *Plan, _ *context.Context) {
			h.wan = "eth4"
		}},
		{name: "staged-hash-drift", reason: NFQWS2HookReasonBinding, setup: func(t *testing.T, h *nfqws2HookFixture, _ *Plan, _ *context.Context) {
			lease, err := h.a.readLease()
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(lease.Transaction, "nfqws2.conf.staged")
			writeStockText(t, path, readText(t, path)+"# drift\n")
		}},
		{name: "live-config-drift", reason: NFQWS2HookReasonFiles, setup: func(t *testing.T, h *nfqws2HookFixture, _ *Plan, _ *context.Context) {
			writeStockText(t, h.a.ConfigPath, readText(t, h.a.ConfigPath)+"# drift\n")
		}},
		{name: "foreign-transaction", reason: NFQWS2HookReasonBinding, direct: true, setup: func(_ *testing.T, _ *nfqws2HookFixture, plan *Plan, _ *context.Context) {
			plan.PlanID = "dp-foreign"
		}},
		{name: "changed-plan", reason: NFQWS2HookReasonPlan, setup: func(_ *testing.T, _ *nfqws2HookFixture, plan *Plan, _ *context.Context) {
			plan.Digest = strings.Repeat("c", 64)
		}},
		{name: "guard-refuses", reason: NFQWS2HookReasonPlan, setup: func(_ *testing.T, _ *nfqws2HookFixture, _ *Plan, ctx *context.Context) {
			*ctx = WithReviewGuard(*ctx, func(context.Context) error { return ErrReviewChanged })
		}},
		{name: "active-execution", reason: NFQWS2HookReasonOwner, setup: func(t *testing.T, h *nfqws2HookFixture, _ *Plan, _ *context.Context) {
			nfqws2ActiveAdapterMu.Lock()
			h.a.activeExecution = &nfqws2ActiveExecution{}
			nfqws2ActiveAdapterMu.Unlock()
			t.Cleanup(func() {
				nfqws2ActiveAdapterMu.Lock()
				h.a.activeExecution = nil
				nfqws2ActiveAdapterMu.Unlock()
			})
		}},
		{name: "package-version", reason: NFQWS2HookReasonNative, setup: func(t *testing.T, h *nfqws2HookFixture, _ *Plan, _ *context.Context) {
			writeStockText(t, filepath.Join(h.owner.InfoDir, "nfqws2-keenetic.control"), "Package: nfqws2-keenetic\nVersion: 1.3.2\n")
		}},
		{name: "queue-other-socket", reason: NFQWS2HookReasonQueue, setup: func(_ *testing.T, h *nfqws2HookFixture, _ *Plan, _ *context.Context) {
			h.queueOwner = 9999
		}},
		{name: "kernel-unreadable", reason: NFQWS2HookReasonKernel, setup: func(_ *testing.T, h *nfqws2HookFixture, _ *Plan, _ *context.Context) {
			h.readErr = ErrBackendInventoryUnknown
		}},
		{name: "partial-jumps-only", reason: NFQWS2HookReasonOther, detail: string(nfqws2HookPartial), setup: kernel(strings.Replace(strings.Replace(nfqws2HookFullV4(), "-A PREROUTING -j nfqws_pre\n", "", 1), "-A POSTROUTING -j nfqws_post\n", "", 1), nfqws2RouterIPv6Fixture)},
		{name: "nat-missing", reason: NFQWS2HookReasonOther, detail: string(nfqws2HookNATMissing), setup: kernel(nfqws2HookWithoutOwned(nfqws2HookFullV4()), nfqws2RouterIPv6Fixture)},
		{name: "nat-not-empty", reason: NFQWS2HookReasonOther, detail: string(nfqws2HookNATNonEmpty), setup: kernel(strings.Replace(lossV4, "COMMIT\n", "-A nfqws_nat -o eth3 -p udp -j MASQUERADE\nCOMMIT\n", 1), nfqws2RouterIPv6Fixture)},
		{name: "owned-in-filter", reason: NFQWS2HookReasonOther, detail: string(nfqws2HookOutsideMangle), setup: kernel(strings.Replace(lossV4, ":_NDM_ACL - [0:0]\n", ":_NDM_ACL - [0:0]\n:nfqws_filter - [0:0]\n", 1), nfqws2RouterIPv6Fixture)},
		{name: "foreign-queue-reference", reason: NFQWS2HookReasonOther, detail: string(nfqws2HookForeignQueue), setup: kernel(strings.Replace(lossV4, "-A FORWARD -j _NDM_ACL\n", "-A FORWARD -j NFQUEUE --queue-num 300\n", 1), nfqws2RouterIPv6Fixture)},
		{name: "ipv6-tokens-disabled", reason: NFQWS2HookReasonOther, detail: string(nfqws2HookIPv6Disabled), setup: kernel(lossV4, nfqws2HookTestIPv6Full())},
		{name: "terminal-before-prerouting", reason: NFQWS2HookReasonOther, detail: string(nfqws2HookPreTerminal), setup: kernel(strings.Replace(lossV4, "-A PREROUTING -j _NDM_IPSEC_PREROUTING\n", "-A PREROUTING -p tcp -j ACCEPT\n-A PREROUTING -j _NDM_IPSEC_PREROUTING\n", 1), nfqws2RouterIPv6Fixture)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newNFQWS2HookFixture(t, false)
			plan, ctx := h.committed(t), firstStartContext(t)
			h.lose(t, 4)
			tc.setup(t, h, &plan, &ctx)
			before, rows, start := h.files(t), h.kernel.rows(), len(h.calls)
			var result NFQWS2HookRestore
			var err error
			if tc.direct {
				result, err = h.a.restoreFirstStartHooks(ctx, plan, func(c context.Context) error { return c.Err() })
			} else {
				result, err = h.m.RestoreCommittedNFQWS2Hooks(ctx, plan)
			}
			if err == nil || !errors.Is(err, ErrNFQWS2HookRestore) || result.Reason != tc.reason {
				t.Fatalf("refusal %q not reported: %+v %v", tc.reason, result, err)
			}
			if tc.detail != "" && (result.Class != NFQWS2HooksOther || !strings.Contains(err.Error(), tc.detail)) {
				t.Fatalf("classifier detail %q missing: %+v %v", tc.detail, result, err)
			}
			if len(h.writes) != 0 || len(result.Commands) != 0 || result.RolledBack || result.Uncertain {
				t.Fatal("refused restoration wrote", h.writes)
			}
			if !slices.EqualFunc(h.kernel.rows(), rows, nfqws2HookSameRow) {
				t.Fatal("refused restoration changed the kernel")
			}
			h.assertNoRuntimeCall(t, start)
			h.assertFiles(t, before)
		})
	}
}

func TestNFQWS2HookRestoreRollsBackOnlyItsOwnObjects(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	// Each fault installs the model hooks: write n is the n-th iptables
	// write (2 chains, 8 bodies, then the jumps); read n the n-th inventory.
	for _, tc := range []struct {
		name   string
		reason string
		issued int // Forward writes issued before the fault stopped the attempt.
		fault  func(t *testing.T, h *nfqws2HookFixture, cancel context.CancelFunc, stopped *bool)
	}{
		{name: "guard-stops-between-writes", reason: NFQWS2HookReasonGuard, issued: 4, fault: func(_ *testing.T, h *nfqws2HookFixture, _ context.CancelFunc, stopped *bool) {
			h.beforeWrite = func(n int, _ int, _ []string) error {
				*stopped = *stopped || n == 4
				return nil
			}
		}},
		{name: "context-cancelled-mid-write", reason: NFQWS2HookReasonGuard, issued: 6, fault: func(_ *testing.T, h *nfqws2HookFixture, cancel context.CancelFunc, _ *bool) {
			h.beforeWrite = func(n int, _ int, _ []string) error {
				if n == 6 {
					cancel()
				}
				return nil
			}
		}},
		{name: "body-write-fails", reason: NFQWS2HookReasonWrite, issued: 5, fault: func(_ *testing.T, h *nfqws2HookFixture, _ context.CancelFunc, _ *bool) {
			h.beforeWrite = func(n int, _ int, _ []string) error {
				if n == 5 {
					return errors.New("modeled failure")
				}
				return nil
			}
		}},
		{name: "jump-write-fails", reason: NFQWS2HookReasonWrite, issued: 12, fault: func(_ *testing.T, h *nfqws2HookFixture, _ context.CancelFunc, _ *bool) {
			h.beforeWrite = func(_ int, _ int, args []string) error {
				if args[3] == "PREROUTING" {
					return errors.New("modeled failure")
				}
				return nil
			}
		}},
		{name: "ambiguous-jump-write", reason: NFQWS2HookReasonWrite, issued: 11, fault: func(t *testing.T, h *nfqws2HookFixture, _ context.CancelFunc, _ *bool) {
			// The kernel applied the jump but the command reported failure.
			h.beforeWrite = func(_ int, family int, args []string) error {
				if args[3] == "POSTROUTING" {
					if err := h.kernel.apply(family, args); err != nil {
						t.Error(err)
					}
					return errors.New("modeled lost acknowledgement")
				}
				return nil
			}
		}},
		{name: "queue-rebound-before-jumps", reason: NFQWS2HookReasonQueue, issued: 10, fault: func(_ *testing.T, h *nfqws2HookFixture, _ context.CancelFunc, _ *bool) {
			h.beforeWrite = func(n int, _ int, _ []string) error {
				if n == 10 {
					h.queueInode = "778"
				}
				return nil
			}
		}},
		{name: "binary-swapped-before-jumps", reason: NFQWS2HookReasonNative, issued: 10, fault: func(t *testing.T, h *nfqws2HookFixture, _ context.CancelFunc, _ *bool) {
			h.beforeWrite = func(n int, _ int, _ []string) error {
				if n == 3 {
					writeStockText(t, filepath.Join("/opt", "usr", "bin", "nfqws2"), "swapped executable bytes\n")
				}
				return nil
			}
		}},
		{name: "firmware-rewrite-before-readback", reason: NFQWS2HookReasonChanged, issued: 10, fault: func(t *testing.T, h *nfqws2HookFixture, _ context.CancelFunc, _ *bool) {
			// Admission and preparation read twice; the third read is the
			// unattached readback, which now sees another whole-table rewrite.
			h.beforeRead = func(n int) {
				if n == 3 {
					h.lose(t, 4)
				}
			}
		}},
		{name: "firmware-rewrite-before-attached-readback", reason: NFQWS2HookReasonChanged, issued: 12, fault: func(t *testing.T, h *nfqws2HookFixture, _ context.CancelFunc, _ *bool) {
			h.beforeRead = func(n int) {
				if n == 4 {
					h.lose(t, 4)
				}
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newNFQWS2HookFixture(t, false)
			plan := h.committed(t)
			h.lose(t, 4)
			loss, before, start := h.kernel.rows(), h.files(t), len(h.calls)
			stopped := false
			ctx, cancel := context.WithCancel(firstStartContext(t))
			defer cancel()
			ctx = WithReviewGuard(ctx, func(context.Context) error {
				if stopped {
					return errors.New("service stopped")
				}
				return nil
			})
			tc.fault(t, h, cancel, &stopped)
			result, err := h.m.RestoreCommittedNFQWS2Hooks(ctx, plan)
			if err == nil || !errors.Is(err, ErrNFQWS2HookRestore) || errors.Is(err, ErrNFQWS2HookUncertain) || !result.RolledBack || result.Uncertain || len(result.Restored) != 0 {
				t.Fatalf("failed restoration was not rolled back: %+v %v", result, err)
			}
			if result.Reason != tc.reason {
				t.Fatalf("reason %q, want %q: %v", result.Reason, tc.reason, err)
			}
			issued := 0
			for _, write := range h.writes {
				if write.args[2] == "-N" || write.args[2] == "-A" {
					issued++
				}
			}
			if issued != tc.issued || len(result.Commands) != len(h.writes) {
				t.Fatalf("writes continued past the fault: %d, want %d", issued, tc.issued)
			}
			if !slices.EqualFunc(h.kernel.rows(), loss, nfqws2HookSameRow) {
				t.Fatal("rollback left residue or removed a foreign object", h.kernel.save(4))
			}
			for _, write := range h.writes {
				if write.args[2] == "-F" || write.args[2] == "-I" || write.args[1] != "mangle" {
					t.Fatal("restoration flushed, inserted or left mangle", write.args)
				}
			}
			h.assertNoRuntimeCall(t, start)
			h.assertFiles(t, before)
		})
	}
}

func TestNFQWS2HookRestoreRollbackRetainsForeignObjects(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	h := newNFQWS2HookFixture(t, false)
	plan := h.committed(t)
	h.lose(t, 4)
	h.beforeWrite = func(_ int, _ int, args []string) error {
		if args[3] == "PREROUTING" {
			// A foreign writer references an owned chain while the jump fails.
			if err := h.kernel.apply(4, []string{"-t", "mangle", "-A", "FORWARD", "-j", "nfqws_pre"}); err != nil {
				t.Fatal(err)
			}
			return errors.New("modeled failure")
		}
		return nil
	}
	result, err := h.m.RestoreCommittedNFQWS2Hooks(firstStartContext(t), plan)
	if err == nil || !errors.Is(err, ErrNFQWS2HookUncertain) || !result.Uncertain || result.RolledBack {
		t.Fatalf("foreign object did not stop cleanup: %+v %v", result, err)
	}
	for _, write := range h.writes {
		if write.args[2] == "-D" || write.args[2] == "-X" {
			t.Fatal("cleanup touched objects beside a foreign owned object", write.args)
		}
	}
	if !strings.Contains(h.kernel.save(4), "-A FORWARD -j nfqws_pre\n") || !strings.Contains(h.kernel.save(4), "-A POSTROUTING -j nfqws_post\n") {
		t.Fatal("foreign or attempted objects were removed")
	}
}

func TestNFQWS2HookRestoreSkipsBusyDataplane(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	for _, which := range []string{"resources", "operation"} {
		t.Run(which, func(t *testing.T) {
			h := newNFQWS2HookFixture(t, false)
			plan := h.committed(t)
			h.lose(t, 4)
			if which == "resources" {
				unlock, err := h.a.lockResources()
				if err != nil {
					t.Fatal(err)
				}
				defer unlock()
			} else {
				if !h.m.tryBeginOperation() {
					t.Fatal("operation gate unavailable")
				}
				defer h.m.endOperation()
			}
			result, err := h.m.RestoreCommittedNFQWS2Hooks(firstStartContext(t), plan)
			if !errors.Is(err, ErrNFQWS2HookBusy) || result.Reason != NFQWS2HookReasonBusy || len(h.writes) != 0 || h.reads != 0 {
				t.Fatalf("busy dataplane was not skipped: %+v %v", result, err)
			}
		})
	}
}

func TestNFQWS2HookBootRestoresLossBeforeHealth(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	for _, review := range []bool{true, false} {
		t.Run(map[bool]string{true: "startup-review", false: "no-startup-review"}[review], func(t *testing.T) {
			h := newNFQWS2HookFixture(t, false)
			full := h.kernel.rows()
			h.lose(t, 4)
			before, identity, start := h.files(t), h.identity, len(h.calls)
			ctx := firstStartContext(t)
			if review {
				allow := true
				ctx = h.bootContext(t, &allow)
			}
			result, err := h.m.Recover(ctx)
			if !review {
				// Without the trusted startup review nothing is written and the
				// previous degraded outcome is kept.
				if err == nil || result.State != "degraded" || len(h.writes) != 0 {
					t.Fatal("unreviewed boot restored hooks", result, err)
				}
				return
			}
			if err != nil || result.State != "recovered" {
				t.Fatal("boot with a lost graph degraded", result, err)
			}
			if !slices.EqualFunc(h.kernel.rows(), full, nfqws2HookSameRow) || len(h.writes) != 12 {
				t.Fatal("boot did not restore the exact graph", h.writes)
			}
			if h.identity != identity || !h.running {
				t.Fatal("boot replaced the live process")
			}
			for _, call := range h.calls[start:] {
				if strings.HasSuffix(call, " owned_start") || strings.HasSuffix(call, " owned_stop") || strings.HasSuffix(call, " restart") {
					t.Fatal("boot restoration restarted NFQWS2", call)
				}
			}
			h.assertFiles(t, before)
		})
	}
}

// Portable pure checks: no namespace is needed for cleanup selection, the
// queue binding parser, the busy resource lock and plan admission.
func TestNFQWS2HookCleanupSelectsOnlyAttemptedRows(t *testing.T) {
	row := func(family int, table string, tokens ...string) BackendInventoryRow {
		return BackendInventoryRow{Family: family, Table: table, Tokens: tokens}
	}
	attempted := map[int][]BackendInventoryRow{4: {
		row(4, "mangle", "-N", "nfqws_post"),
		row(4, "mangle", "-A", "nfqws_post", "-j", "NFQUEUE", "--queue-num", "300"),
		row(4, "mangle", "-A", "POSTROUTING", "-j", "nfqws_post"),
	}}
	present := []BackendInventoryRow{
		row(4, "mangle", "-P", "POSTROUTING", "ACCEPT"),
		row(4, "mangle", "-N", "nfqws_post"),
		row(4, "mangle", "-A", "POSTROUTING", "-j", "nfqws_post"),
		row(4, "mangle", "-A", "nfqws_post", "-j", "NFQUEUE", "--queue-num", "300"),
		row(4, "nat", "-N", "nfqws_nat"),
		row(6, "mangle", "-N", "nfqws_post"),
	}
	removals, ok := nfqws2HookCleanup(present, []int{4}, attempted)
	want := []BackendInventoryRow{attempted[4][2], attempted[4][1], attempted[4][0]}
	if !ok || !slices.EqualFunc(removals, want, nfqws2HookSameRow) {
		t.Fatal("cleanup order or scope", removals, ok)
	}
	if removals, ok := nfqws2HookCleanup(present[:2], []int{4}, attempted); !ok || len(removals) != 1 || removals[0].Tokens[0] != "-N" {
		t.Fatal("absent attempted rows selected", removals, ok)
	}
	for _, foreign := range []BackendInventoryRow{
		row(4, "mangle", "-A", "FORWARD", "-j", "nfqws_post"),
		row(4, "mangle", "-A", "POSTROUTING", "-j", "nfqws_post"), // A duplicate is not ours.
		row(4, "mangle", "-A", "nfqws_post", "-j", "ACCEPT"),
	} {
		if _, ok := nfqws2HookCleanup(append(slices.Clone(present), foreign), []int{4}, attempted); ok {
			t.Fatal("cleanup accepted a foreign owned row", foreign.Tokens)
		}
	}
	if kept, ok := nfqws2HookWithout(present, attempted[4]); !ok || len(kept) != 3 || kept[0].Tokens[0] != "-P" {
		t.Fatal("exact row subtraction", kept, ok)
	}
	if _, ok := nfqws2HookWithout(present[:1], attempted[4]); ok {
		t.Fatal("absent created row accepted")
	}
}

func TestNFQWS2FirstStartQueueBindsReceiptSocket(t *testing.T) {
	sockets := "sk               Eth Pid        Groups   Rmem     Wmem     Dump  Locks    Drops    Inode\n" +
		"0000000000000000 12  4242       00000000 0        0        0     2        0        777\n" +
		"0000000000000000 12  5151       00000000 0        0        0     2        0        888\n" +
		"0000000000000000 0   4242       00000000 0        0        0     2        0        999\n"
	queues := []nfqwsScopedQueue{{number: 64511, portID: 5151, copyMode: 2, copyRange: 65535}, {number: 300, portID: 4242, copyMode: 0, copyRange: 0}}
	held := []string{"socket:[123]", "socket:[777]"}
	bound, err := nfqws2FirstStartQueueBound(queues, sockets, held, 300)
	if err != nil || bound != (nfqws2FirstStartQueue{Number: 300, PortID: 4242, Inode: "777", CopyMode: 0, CopyRange: 0}) {
		t.Fatal("receipt socket binding refused; copy parameters must be recorded only", bound, err)
	}
	for name, tc := range map[string]struct {
		queues      []nfqwsScopedQueue
		sockets     string
		descriptors []string
		queue       uint16
	}{
		"unregistered":     {queues: queues[:1], sockets: sockets, descriptors: held, queue: 300},
		"zero-port":        {queues: []nfqwsScopedQueue{{number: 300}}, sockets: sockets, descriptors: held, queue: 300},
		"duplicate":        {queues: append(slices.Clone(queues), queues[1]), sockets: sockets, descriptors: held, queue: 300},
		"other-socket":     {queues: queues, sockets: sockets, descriptors: []string{"socket:[888]"}, queue: 300},
		"no-descriptors":   {queues: queues, sockets: sockets, queue: 300},
		"port-not-netlink": {queues: []nfqwsScopedQueue{{number: 300, portID: 9}}, sockets: sockets, descriptors: held, queue: 300},
		"bad-table":        {queues: queues, sockets: "garbage\n", descriptors: held, queue: 300},
		"queue-zero":       {queues: queues, sockets: sockets, descriptors: held, queue: 0},
	} {
		if _, err := nfqws2FirstStartQueueBound(tc.queues, tc.sockets, tc.descriptors, tc.queue); !errors.Is(err, errNFQWS2FirstStartQueue) {
			t.Fatal("queue binding accepted", name, err)
		}
	}
}

func TestNFQWS2ResourceLockReportsOnlyContentionAsBusy(t *testing.T) {
	a, _, _ := newOwnedNFQWS2(t)
	unlock, err := a.lockResources()
	if err != nil {
		t.Skip("platform has no nonblocking resource lock: ", err)
	}
	defer unlock()
	if _, err := a.lockResources(); !errors.Is(err, errNFQWS2ResourceBusy) {
		t.Fatal("contention not reported as busy", err)
	}
}

func TestNFQWS2HookInstanceNamesTransactionAndReceipt(t *testing.T) {
	process := components.NFQWSRuntimeProcessIdentity{BootID: "boot-a", Start: "1001", PID: 4242, Executable: "/opt/usr/bin/nfqws2", ArgumentsSHA256: strings.Repeat("a", 64)}
	lease := func(edit func(*nfqws2Lease)) *nfqws2Lease {
		receipt := process
		l := &nfqws2Lease{Transaction: "/state/transactions/dp-a/nfqws2", FirstStart: &nfqws2FirstStartLease{Phase: nfqws2FirstRunning, Process: &receipt}}
		if edit != nil {
			edit(l)
		}
		return l
	}
	base := nfqws2HookInstance(lease(nil))
	if len(base) != 24 || strings.Trim(base, "0123456789abcdef") != "" || base != nfqws2HookInstance(lease(nil)) {
		t.Fatal("instance is not a stable digest", base)
	}
	if strings.Contains(base, "4242") || strings.Contains(base, "boot-a") {
		t.Fatal("instance leaks a process value", base)
	}
	if nfqws2HookInstance(lease(func(l *nfqws2Lease) { l.FirstStart.Process.Executable = "/other"; l.ConfigHash = "changed" })) != base {
		t.Fatal("fields outside the key changed the instance")
	}
	for name, edit := range map[string]func(*nfqws2Lease){
		"transaction": func(l *nfqws2Lease) { l.Transaction = "/state/transactions/dp-b/nfqws2" },
		"boot":        func(l *nfqws2Lease) { l.FirstStart.Process.BootID = "boot-b" },
		"start":       func(l *nfqws2Lease) { l.FirstStart.Process.Start = "1002" },
		"pid":         func(l *nfqws2Lease) { l.FirstStart.Process.PID = 4243 },
	} {
		if nfqws2HookInstance(lease(edit)) == base {
			t.Fatal("instance ignores a key field", name)
		}
	}
	if nfqws2HookInstance(nil) != "" || nfqws2HookInstance(lease(func(l *nfqws2Lease) { l.FirstStart.Process = nil })) != "" {
		t.Fatal("instance invented for a lease without a receipt")
	}
}

func TestNFQWS2HookHintPathFollowsRegisteredInit(t *testing.T) {
	m := New(t.TempDir())
	if m.NFQWS2HookHintPath() != "" {
		t.Fatal("hint path without a registered adapter")
	}
	a := NewNFQWS2Adapter()
	prefix := filepath.Join(t.TempDir(), "opt")
	a.InitPath = filepath.Join(prefix, "etc", "init.d", "S51nfqws2")
	if err := m.Register(a); err != nil {
		t.Fatal(err)
	}
	if got, want := m.NFQWS2HookHintPath(), filepath.Join(prefix, "etc", "ndm", "netfilter.d", "100-nfqws2.sh"); got != want {
		t.Fatalf("hint path=%q want %q", got, want)
	}
	a.InitPath = "relative/etc/init.d/S51nfqws2"
	if m.NFQWS2HookHintPath() != "" {
		t.Fatal("relative init path produced a hint path")
	}
}

func TestNFQWS2HookPlanAdmitsOnlySettledFirstStart(t *testing.T) {
	base := Plan{PlanID: "dp-hooks", State: "committed", Ready: true, Adapters: []string{"nfqws2"}, Routes: []Route{{ServiceID: "selected", Resolved: "nfqws2", Domains: []string{"selected.example"}}}}
	if !nfqws2HookPlan(base) {
		t.Fatal("settled first-start plan refused")
	}
	for name, edit := range map[string]func(*Plan){
		"draft":      func(p *Plan) { p.State = "reviewed" },
		"not-ready":  func(p *Plan) { p.Ready = false },
		"safe-mode":  func(p *Plan) { p.SafeMode = true },
		"noop":       func(p *Plan) { p.Noop = true },
		"lan-owner":  func(p *Plan) { p.LAN = &LANPolicyRuntimePlan{} },
		"no-plan-id": func(p *Plan) { p.PlanID = "" },
		"no-routes":  func(p *Plan) { p.Routes = nil },
		"no-adapter": func(p *Plan) { p.Adapters = []string{"sing-box"} },
		"twice":      func(p *Plan) { p.Adapters = []string{"nfqws2", "nfqws2"} },
		"no-nfq-route": func(p *Plan) {
			p.Routes = []Route{{ServiceID: "other", Resolved: "sing-box"}}
		},
	} {
		plan := base
		plan.Routes, plan.Adapters = slices.Clone(base.Routes), slices.Clone(base.Adapters)
		edit(&plan)
		if nfqws2HookPlan(plan) {
			t.Fatal("unsettled plan admitted", name)
		}
	}
	m := New(t.TempDir())
	if !m.tryBeginOperation() {
		t.Fatal("idle operation gate refused")
	}
	result, err := m.RestoreCommittedNFQWS2Hooks(context.Background(), base)
	m.endOperation()
	if !errors.Is(err, ErrNFQWS2HookBusy) || result.Reason != NFQWS2HookReasonBusy {
		t.Fatal("busy operation gate was not skipped", result, err)
	}
	if _, err := m.RestoreCommittedNFQWS2Hooks(context.Background(), base); !errors.Is(err, ErrNFQWS2HookRestore) || errors.Is(err, ErrNFQWS2HookBusy) {
		t.Fatal("uncommitted plan was not refused", err)
	}
}
