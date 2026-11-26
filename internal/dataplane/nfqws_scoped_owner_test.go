package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/components"
)

func nfqwsScopedFixture(t *testing.T) (Plan, NFQWSScopedSpec, *NFQWSScopedPlan) {
	t.Helper()
	lan := lanRuntimeFixture(t)
	plan := Plan{SchemaVersion: SchemaVersion, PlanID: "reviewed-plan", Digest: strings.Repeat("b", 64), Revision: 3, NetworkProfileID: "wan-profile-epoch", Ready: true, LAN: lan,
		Routes: []Route{{ServiceID: "ip-service", Selected: "nfqws2", Resolved: "nfqws2", Ingress: []string{"br0"}, Sources: []string{"192.168.1.0/24", "fd00:1::/64"}, CIDRs: []string{"8.8.8.8/32", "2606:4700::/32"}, NetworkPolicyGeneration: lan.Generation}}}
	spec := NFQWSScopedSpec{Queue: 40321, BootID: "01234567-89ab-cdef-0123-456789abcdef", NetNamespace: "net:[12345]", SessionID: strings.Repeat("c", 32), CommandSHA256: strings.Repeat("d", 64),
		Candidate: NFQWSScopedCandidate{ID: "candidate", Incarnation: strings.Repeat("e", 32), ArgumentsSHA256: strings.Repeat("f", 64), Traffic: []NFQWSScopedTraffic{{Protocol: "tcp", First: 443, Last: 443}, {Protocol: "udp", First: 443, Last: 443}}}}
	p, err := CompileNFQWSScopedPlan(plan, spec)
	if err != nil {
		t.Fatal(err)
	}
	return plan, spec, p
}

func TestNFQWSScopedCompilerFreezesScopeAndIncarnation(t *testing.T) {
	plan, spec, p := nfqwsScopedFixture(t)
	before, err := p.Effects()
	if err != nil {
		t.Fatal(err)
	}
	resources := p.Resources()
	resources.Chains[0] = "FOREIGN"
	plan.LAN.Ingress[0].ExcludedMACs[0] = "02:00:00:00:00:22"
	plan.Routes[0].Sources[0] = "0.0.0.0/0"
	spec.Candidate.Traffic[0].First = 1
	before.Effects[0].Add[3] = "ALTERED-COPY"
	after, err := p.Effects()
	if err != nil || after.Effects[0].Add[3] == "ALTERED-COPY" || p.Resources().Chains[0] == "FOREIGN" || p.lan.Ingress[0].ExcludedMACs[0] != "02:00:00:00:00:01" {
		t.Fatal("caller mutation changed frozen authority", err)
	}
	plan, spec, _ = nfqwsScopedFixture(t)
	p2, err := CompileNFQWSScopedPlan(plan, spec)
	if err != nil || p.Digest() != p2.Digest() {
		t.Fatal("compiler is nondeterministic", err)
	}
	spec.Candidate.Incarnation = strings.Repeat("1", 32)
	p2, err = CompileNFQWSScopedPlan(plan, spec)
	if err != nil || p.Digest() == p2.Digest() || slices.Equal(p.Resources().Chains, p2.Resources().Chains) {
		t.Fatal("candidate ABA retained effect identity", err)
	}
	for _, e := range after.Effects {
		joined := strings.Join(e.Add, " ")
		if strings.Contains(joined, "NFQUEUE") && (!strings.Contains(joined, "-i br0") || !strings.Contains(joined, "--mark 0x20000000/0x28000000") || !strings.Contains(joined, "--queue-num 40321") || !strings.Contains(joined, "-s ") || !strings.Contains(joined, "-d ")) {
			t.Fatal("queue bypasses physical positive LAN admission", joined)
		}
		if strings.Contains(joined, "raw") || strings.Contains(joined, "OUTPUT") || strings.Contains(joined, "--queue-bypass") {
			t.Fatal("unreviewed capture semantics", joined)
		}
	}
}

func TestNFQWSScopedCompilerRejectsExpandedOrUnboundScope(t *testing.T) {
	for name, change := range map[string]func(*Plan, *NFQWSScopedSpec){
		"no LAN":                 func(p *Plan, _ *NFQWSScopedSpec) { p.LAN = nil },
		"domain IP substitution": func(p *Plan, _ *NFQWSScopedSpec) { p.Routes[0].Domains = []string{"example.com"} },
		"WAN ingress":            func(p *Plan, _ *NFQWSScopedSpec) { p.Routes[0].Ingress = []string{"eth-wan"} },
		"source outside gate":    func(p *Plan, _ *NFQWSScopedSpec) { p.Routes[0].Sources[0] = "192.168.0.0/16" },
		"old gate generation":    func(p *Plan, _ *NFQWSScopedSpec) { p.Routes[0].NetworkPolicyGeneration = strings.Repeat("2", 64) },
		"all destinations":       func(p *Plan, _ *NFQWSScopedSpec) { p.Routes[0].CIDRs[0] = "0.0.0.0/0" },
		"protected destination":  func(p *Plan, _ *NFQWSScopedSpec) { p.Routes[0].CIDRs[0] = "192.168.1.1/32" },
		"noncanonical prefix":    func(p *Plan, _ *NFQWSScopedSpec) { p.Routes[0].CIDRs[0] = "8.8.8.9/24" },
		"missing WAN":            func(p *Plan, _ *NFQWSScopedSpec) { p.NetworkProfileID = "" },
		"safe mode":              func(p *Plan, _ *NFQWSScopedSpec) { p.SafeMode = true },
		"no reserved queue":      func(_ *Plan, s *NFQWSScopedSpec) { s.Queue = 0 },
		"unknown namespace":      func(_ *Plan, s *NFQWSScopedSpec) { s.NetNamespace = "net:[012345]" },
		"unknown boot":           func(_ *Plan, s *NFQWSScopedSpec) { s.BootID = "" },
		"unknown session":        func(_ *Plan, s *NFQWSScopedSpec) { s.SessionID = "" },
		"unknown incarnation":    func(_ *Plan, s *NFQWSScopedSpec) { s.Candidate.Incarnation = "" },
		"overlapping traffic": func(_ *Plan, s *NFQWSScopedSpec) {
			s.Candidate.Traffic = append(s.Candidate.Traffic, s.Candidate.Traffic[0])
		},
		"zero port":             func(_ *Plan, s *NFQWSScopedSpec) { s.Candidate.Traffic[0].First = 0 },
		"oversize nested input": func(p *Plan, _ *NFQWSScopedSpec) { p.Routes[0].Sources = make([]string, 1025) },
	} {
		t.Run(name, func(t *testing.T) {
			plan, spec, _ := nfqwsScopedFixture(t)
			change(&plan, &spec)
			if _, err := CompileNFQWSScopedPlan(plan, spec); err == nil {
				t.Fatal("invalid input acquired compiler authority")
			}
		})
	}
}

type nfqwsScopedModel struct {
	p            *NFQWSScopedPlan
	present      map[int]int
	foreign      map[string]string
	calls        []policyEffectCall
	lostAdd      int
	lostDelete   int
	running      bool
	stopped      bool
	foreignQueue bool
	unknownACK   bool
	changedChild bool
	queueChecks  int
	lanReads     int
}

func (m *nfqwsScopedModel) Run(_ context.Context, command string, args ...string) ([]byte, error) {
	for i, e := range m.p.mixed.Effects {
		if command != string(e.Tool) {
			continue
		}
		add, remove := slices.Equal(args, e.Add), slices.Equal(args, e.Delete)
		if !add && !remove {
			continue
		}
		m.calls = append(m.calls, policyEffectCall{index: i, add: add, name: command, args: slices.Clone(args)})
		if add {
			m.present[i]++
			if i == m.lostAdd {
				return nil, errors.New("lost actual add ACK")
			}
		} else {
			m.present[i]--
			if i == m.lostDelete {
				return nil, errors.New("lost actual delete ACK")
			}
		}
		return nil, nil
	}
	if len(args) != 3 || args[0] != "-t" || args[2] != "-S" {
		return nil, errors.New("untrusted model command")
	}
	text := ""
	if args[1] == "mangle" {
		for i, e := range m.p.mixed.Effects {
			if command != string(e.Tool) {
				continue
			}
			for n := 0; n < m.present[i]; n++ {
				text += strings.Join(e.Add[2:], " ") + "\n"
			}
		}
	}
	text += m.foreign[command+":"+args[1]]
	return []byte(text), nil
}

func (m *nfqwsScopedModel) proof(inactive bool) NFQWSScopedProcessProof {
	r := m.p.Resources()
	proof := NFQWSScopedProcessProof{SessionID: r.SessionID, CommandSHA256: r.CommandSHA256,
		Receipt: components.NFQWSSupervisionReceipt{State: "running", BootID: r.BootID, Start: "100", PID: 4000, Group: 4000, ChildPID: 4001, CommandSHA256: r.CommandSHA256, Started: true},
		Child:   components.NFQWSRuntimeProcessIdentity{BootID: r.BootID, Start: "101", PID: 4001, ParentPID: 4000, Group: 4001, Executable: "/opt/reviewed/nfqws2", ArgumentsSHA256: r.ArgumentsHash}}
	if inactive {
		proof.Receipt.State, proof.Receipt.DirectReaped, proof.Receipt.WaitECHILD, proof.Receipt.Reaped = "reaped", true, true, 1
		proof.Acknowledged = !m.unknownACK
	}
	if m.changedChild {
		proof.Child.Start = "102"
	}
	return proof
}

func nfqwsScopedBindingFixture(t *testing.T) (*NFQWSScopedBinding, *nfqwsScopedModel, string) {
	t.Helper()
	_, _, p := nfqwsScopedFixture(t)
	m := &nfqwsScopedModel{p: p, present: map[int]int{}, foreign: map[string]string{}, lostAdd: -1, lostDelete: -1, running: true}
	b := &NFQWSScopedBinding{Runner: m, Tools: PolicyEffectTools{IP: "ip", IPTables: "iptables", IP6Tables: "ip6tables"}, options: policyAdditionOptions{boot: func() (string, error) { return p.resources.BootID, nil }}}
	b.ApplyGuard = func(_ context.Context, got *NFQWSScopedPlan, _ PolicyEffect) error {
		if got != p || m.stopped {
			return ErrReviewChanged
		}
		return nil
	}
	b.CleanupGuard = func(_ context.Context, got *NFQWSScopedPlan, _ PolicyEffect) error {
		if got != p {
			return ErrReviewChanged
		}
		return nil
	}
	b.VerifyLAN = func(_ context.Context, got *LANPolicyRuntimePlan) error {
		m.lanReads++
		if !reflect.DeepEqual(got, p.lan) || m.stopped {
			return ErrLANPolicyRuntime
		}
		return nil
	}
	b.ProcessRunning = func(context.Context, *NFQWSScopedPlan) (NFQWSScopedProcessProof, error) {
		if !m.running {
			return NFQWSScopedProcessProof{}, ErrNFQWSManagedProcessUnknown
		}
		return m.proof(false), nil
	}
	b.ProcessInactive = func(context.Context, *NFQWSScopedPlan) (NFQWSScopedProcessProof, error) {
		if m.running {
			return NFQWSScopedProcessProof{}, ErrNFQWSManagedProcessUnknown
		}
		return m.proof(true), nil
	}
	b.QueueCheck = func(_ context.Context, ns string, q uint16, child *components.NFQWSRuntimeProcessIdentity) error {
		m.queueChecks++
		if m.foreignQueue || ns != p.resources.NetNamespace || q != p.resources.Queue || (child == nil) == m.running {
			return ErrNFQWSScopedOwner
		}
		return nil
	}
	b.AdditionalReadback = func(context.Context, *NFQWSScopedPlan) error { return nil }
	return b, m, privateScopedXrayFixtureDir(t)
}

func TestNFQWSScopedReceiptLifecycleAndStoppedRetirement(t *testing.T) {
	b, m, root := nfqwsScopedBindingFixture(t)
	ctx := context.Background()
	if err := b.VerifyPrepared(ctx, m.p, root); err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(root); err != nil || len(entries) != 0 {
		t.Fatal("prepared observation created a ledger", entries, err)
	}
	if err := b.Apply(ctx, m.p, root); err != nil {
		t.Fatal(err)
	}
	status, err := b.Inspect(ctx, m.p, root)
	if err != nil || !status.Complete || status.Added != len(m.p.mixed.Effects) {
		t.Fatal(status, err)
	}
	if err := b.VerifyPrepared(ctx, m.p, root); err == nil {
		t.Fatal("reused root was prepared again")
	}
	before := len(m.calls)
	if err := b.Remove(ctx, m.p, root); err == nil || len(m.calls) != before {
		t.Fatal("removed live process capture", err)
	}
	m.running, m.stopped = false, true
	lanBefore := m.lanReads
	if err := b.Remove(ctx, m.p, root); err != nil {
		t.Fatal("cleanup borrowed revoked live authority", err)
	}
	if m.lanReads != lanBefore {
		t.Fatal("cleanup read revoked LAN admission")
	}
	image, err := os.ReadFile(filepath.Join(root, policyAdditionFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.VerifyInactive(ctx, m.p, root); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filepath.Join(root, policyAdditionFile))
	if !bytes.Equal(image, after) {
		t.Fatal("inactivity observer changed durable receipt")
	}
	if err := b.Apply(ctx, m.p, root); err == nil {
		t.Fatal("retired generation replayed")
	}
	for i, n := range m.present {
		if n != 0 {
			t.Fatal("owned effect remained", i, n)
		}
	}
	// Attachments must disappear before either required family body.
	deletes := m.calls[before:]
	for i, call := range deletes {
		if i > 0 && call.index >= deletes[i-1].index || call.add {
			t.Fatal("reverse dependency order violated", deletes)
		}
	}
}

func TestNFQWSScopedUnknownActualAddNeverReplaysOrRetires(t *testing.T) {
	b, m, root := nfqwsScopedBindingFixture(t)
	m.lostAdd = 1
	ctx := context.Background()
	if err := b.Apply(ctx, m.p, root); !errors.Is(err, ErrPolicyAdditionUnknown) {
		t.Fatal(err)
	}
	status, err := b.Inspect(ctx, m.p, root)
	if err != nil || !status.Unknown || status.Complete {
		t.Fatal(status, err)
	}
	before := len(m.calls)
	m.running, m.stopped = false, true
	if err := b.Remove(ctx, m.p, root); err == nil || len(m.calls) != before {
		t.Fatal("unknown receipt issued deletes", err)
	}
	if err := b.VerifyInactive(ctx, m.p, root); err == nil {
		t.Fatal("unknown receipt became inactivity")
	}
}

func TestNFQWSScopedInactivityRejectsForeignIPv6AndQueue(t *testing.T) {
	for _, mode := range []string{"IPv4 foreign reference", "IPv6 foreign same queue", "security queue range", "foreign other queue", "unACKed ECHILD", "missing marker", "reinserted owned attachment"} {
		t.Run(mode, func(t *testing.T) {
			b, m, root := nfqwsScopedBindingFixture(t)
			ctx := context.Background()
			if err := b.Apply(ctx, m.p, root); err != nil {
				t.Fatal(err)
			}
			m.running = false
			if err := b.Remove(ctx, m.p, root); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "IPv4 foreign reference":
				m.foreign["iptables:raw"] = "-A PREROUTING -j " + m.p.chains[0].name + "\n"
			case "IPv6 foreign same queue":
				m.foreign["ip6tables:filter"] = "-A FOREIGN -j NFQUEUE --queue-num 40321\n"
			case "security queue range":
				m.foreign["ip6tables:security"] = "-A FORWARD -j NFQUEUE --queue-balance 40320:40322\n"
			case "foreign other queue":
				m.foreignQueue = true
			case "unACKed ECHILD":
				m.unknownACK = true
			case "missing marker":
				if err := os.Remove(filepath.Join(root, policyAdditionLock)); err != nil {
					t.Fatal(err)
				}
			case "reinserted owned attachment":
				m.present[len(m.p.mixed.Effects)-1] = 1
			}
			before, _ := os.ReadFile(filepath.Join(root, policyAdditionFile))
			calls := len(m.calls)
			if err := b.VerifyInactive(ctx, m.p, root); err == nil {
				t.Fatal("foreign/unknown runtime cleared fence")
			}
			after, _ := os.ReadFile(filepath.Join(root, policyAdditionFile))
			if !bytes.Equal(before, after) || len(m.calls) != calls {
				t.Fatal("read-only refusal changed owner")
			}
			if mode == "missing marker" {
				if _, err := os.Stat(filepath.Join(root, policyAdditionLock)); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("observer recreated missing owner lock", err)
				}
			}
		})
	}
}

func TestNFQWSScopedPreparedRefusesForeignBeforeReceipt(t *testing.T) {
	for _, mode := range []string{"foreign IPv4", "foreign IPv6", "queue bound", "mismatched process", "missing callback"} {
		t.Run(mode, func(t *testing.T) {
			b, m, root := nfqwsScopedBindingFixture(t)
			switch mode {
			case "foreign IPv4":
				m.foreign["iptables:nat"] = "-A OUTPUT -j NFQUEUE --queue-num 99\n"
			case "foreign IPv6":
				m.foreign["ip6tables:raw"] = "-A PREROUTING -j QUEUE\n"
			case "queue bound":
				m.foreignQueue = true
			case "mismatched process":
				b.ProcessRunning = func(context.Context, *NFQWSScopedPlan) (NFQWSScopedProcessProof, error) {
					p := m.proof(false)
					p.CommandSHA256 = strings.Repeat("0", 64)
					return p, nil
				}
			case "missing callback":
				b.QueueCheck = nil
			}
			if err := b.VerifyPrepared(context.Background(), m.p, root); err == nil {
				t.Fatal("foreign capture was prepared")
			}
			entries, err := os.ReadDir(root)
			if err != nil || len(entries) != 0 || len(m.calls) != 0 {
				t.Fatal("preparation mutated receipt/kernel", entries, err)
			}
		})
	}
}

func TestNFQWSScopedExactReadbackCanonicalOrderAndPartialFamily(t *testing.T) {
	_, _, p := nfqwsScopedFixture(t)
	rules := nfqwsScopedRules{PolicyEffectIPTables: {"mangle": {}}, PolicyEffectIP6Tables: {"mangle": {}}}
	for _, e := range p.mixed.Effects {
		rules[e.Tool]["mangle"] = append(rules[e.Tool]["mangle"], slices.Clone(e.Add[2:]))
	}
	if _, err := p.ruleCounts(rules, nfqwsScopedComplete); err != nil {
		t.Fatal(err)
	}
	c := p.chains[0]
	original := append([]string{"-A", c.name}, c.body[0]...)
	canonical := []string{"-A", c.name, "-s", c.body[0][3], "-d", c.body[0][5], "-i", "br0", "-p", "tcp", "-m", "mark", "--mark", "0x20000000/0x28000000", "-m", "tcp", "--dport", "443", "-j", "NFQUEUE", "--queue-num", "40321"}
	if !nfqwsScopedRuleEqual(original, canonical) {
		t.Fatal("canonical iptables -S ordering changed exact tuple", original, canonical)
	}
	rules[PolicyEffectIPTables]["mangle"][1] = canonical
	if _, err := p.ruleCounts(rules, nfqwsScopedComplete); err != nil {
		t.Fatal(err)
	}
	rules[PolicyEffectIP6Tables]["mangle"] = nil
	if _, err := p.ruleCounts(rules, nfqwsScopedPartial); err == nil {
		t.Fatal("one-family attachment survived missing required IPv6 body")
	}
}

func TestNFQWSScopedQueuePortIDIsNotProcessPID(t *testing.T) {
	queues, err := nfqwsScopedQueues("40321 4294967000 0 2 65531 0 0 123 1\n")
	if err != nil || len(queues) != 1 || queues[0].portID != 4294967000 {
		t.Fatal(queues, err)
	}
	text := "sk Eth Pid Groups Rmem Wmem Dump Locks Drops Inode\n0000000000000000 12 4294967000 00000000 0 0 0 2 0 345678\n"
	inode, err := nfqwsScopedSocketInode(text, queues[0].portID)
	if err != nil || inode != "345678" {
		t.Fatal("netlink port did not bind its socket inode", inode, err)
	}
	for _, bad := range []string{"40321 10 0 2 65531 0 0 1\n", "40321 0 0 2 65531 0 0 1 1\n", "40321 10 0 2 65531 0 0 1 1\n40321 11 0 2 65531 0 0 1 1\n", "65536 10 0 2 65531 0 0 1 1\n", "40321 10 0 3 65531 0 0 1 1\n"} {
		if _, err := nfqwsScopedQueues(bad); err == nil {
			t.Fatal("ambiguous proc queue accepted", bad)
		}
	}
	if _, err := nfqwsScopedSocketInode(text+strings.Split(text, "\n")[1]+"\n", queues[0].portID); err == nil {
		t.Fatal("duplicate netlink owner accepted")
	}
}

func TestNFQWSScopedUnknownDeletePreservesRemainingGrants(t *testing.T) {
	b, m, root := nfqwsScopedBindingFixture(t)
	ctx := context.Background()
	if err := b.Apply(ctx, m.p, root); err != nil {
		t.Fatal(err)
	}
	m.running, m.stopped = false, true
	m.lostDelete = len(m.p.mixed.Effects) - 1
	if err := b.Remove(ctx, m.p, root); !errors.Is(err, ErrPolicyAdditionUnknown) {
		t.Fatal(err)
	}
	status, err := b.Inspect(ctx, m.p, root)
	if err != nil || !status.Unknown || status.Removed {
		t.Fatal(status, err)
	}
	before := len(m.calls)
	if err := b.Remove(ctx, m.p, root); err == nil || len(m.calls) != before {
		t.Fatal("unknown deletion consumed retained prerequisites", err)
	}
	if err := b.VerifyInactive(ctx, m.p, root); err == nil {
		t.Fatal("lost delete ACK became inactivity")
	}
}

func TestNFQWSScopedProcessMutationDuringQueueReadRefuses(t *testing.T) {
	b, m, root := nfqwsScopedBindingFixture(t)
	original := b.QueueCheck
	b.QueueCheck = func(ctx context.Context, ns string, q uint16, child *components.NFQWSRuntimeProcessIdentity) error {
		if err := original(ctx, ns, q, child); err != nil {
			return err
		}
		m.changedChild = true
		return nil
	}
	if err := b.VerifyPrepared(context.Background(), m.p, root); err == nil {
		t.Fatal("changed child birth survived two-sided observation")
	}
	if entries, err := os.ReadDir(root); err != nil || len(entries) != 0 {
		t.Fatal("refused preparation created files", entries, err)
	}
}

func TestNFQWSScopedNFTAndQuotedReadbackRemainConservative(t *testing.T) {
	for _, input := range []string{`{"nftables":null}`, `{"nftables":[{"rule":null}]}`, `{"nftables":[{"rule":{"expr":[{"accept":null}]}}]}`, `{"nftables":[],"nftables":[{"rule":{}}]}`, `{"nftables":[{"unknown_capture":{}}]}`} {
		if nfqwsScopedNFTRuleset([]byte(input)) == nil {
			t.Fatal("unknown nft executable ruleset accepted", input)
		}
	}
	if err := nfqwsScopedNFTRuleset([]byte(`{"nftables":[{"metainfo":{"json_schema_version":1}}]}`)); err != nil {
		t.Fatal("empty actual nft baseline refused", err)
	}
	for _, input := range []string{
		`{"queue":{"num":99}}`,
		`{"mangle":{"key":{"meta":{"key":"mark"}},"value":536870912}}`,
		`{"mangle":{"key":{"ct":{"key":"mark"}},"value":536870912}}`,
		`{"flow":{"op":"add","flowtable":"fast"}}`,
		`{"dup":{"addr":"192.168.1.2"}}`,
	} {
		var value any
		if json.Unmarshal([]byte(input), &value) != nil || !nfqwsScopedNFTCapture(value) {
			t.Fatal("foreign nft capture/mark bypass was ignored", input)
		}
	}
	quoted := `-A FORWARD -m comment --comment "ordinary comment with spaces" -j ACCEPT`
	fields, err := nfqwsScopedTokens(quoted)
	if err != nil || !slices.Contains(fields, "ordinary comment with spaces") {
		t.Fatal("iptables quoting was split into fake options", fields, err)
	}
	for _, line := range []string{`-A FORWARD --comment "unterminated`, "-A FORWARD -j ACCEPT\x00", "-A FORWARD -j ACCEPT\\"} {
		if _, err := nfqwsScopedTokens(line); err == nil {
			t.Fatal("unknown readback syntax accepted", line)
		}
	}
	_, _, p := nfqwsScopedFixture(t)
	copy := p.Spec()
	copy.Candidate.Traffic[0].First = 1
	if p.Spec().Candidate.Traffic[0].First == 1 {
		t.Fatal("typed recovery input aliases caller memory")
	}
}
