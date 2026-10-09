package dataplane

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// Explicit complete-inventory models only: these tests neither capture a
// kernel nor establish native packet behavior, ownership or runtime health.
func nfqwsDirectStockQueueFixture() BackendInventorySnapshot {
	identity, _ := networkPolicyIdentityFixture()
	var rows []BackendInventoryRow
	for _, family := range []int{4, 6} {
		for _, hook := range nfqwsDirectStockHooks {
			rows = append(rows, nfqwsDirectStockTestRow(family, "mangle", "-P", hook, "ACCEPT"))
		}
		rows = append(rows,
			nfqwsDirectStockTestRow(family, "mangle", "-N", "local_bridge"),
			nfqwsDirectStockTestRow(family, "mangle", "-N", "local_delay"),
			nfqwsDirectStockTestRow(family, "mangle", "-A", "OUTPUT", "-j", "local_bridge"),
			nfqwsDirectStockTestRow(family, "mangle", "-A", "local_bridge", "-g", "local_delay"),
		)
		source, destination := "192.0.2.0/24", "198.51.100.0/24"
		if family == 6 {
			source, destination = "2001:db8:1::/64", "2001:db8:2::/64"
		}
		rows = append(rows,
			nfqwsDirectStockTestRow(family, "mangle", "-A", "local_delay", "!", "-s", source, "!", "-d", destination, "-m", "ndmmark", "--ndmmark", "0x4/0x4", "-j", "NFQUEUE", "--queue-num", strconv.Itoa(1100+family)),
			nfqwsDirectStockTestRow(family, "mangle", "-A", "PREROUTING", "-j", "MARK", "--set-xmark", "0x4/0xff"),
			nfqwsDirectStockTestRow(family, "mangle", "-A", "OUTPUT", "-j", "CONNMARK", "--restore-mark", "--nfmask", "0xff", "--ctmask", "0xff"),
		)
	}
	// Unrelated nonqueue table grammar remains the caller's responsibility.
	rows = append(rows, nfqwsDirectStockTestRow(4, "nat", "-A", "POSTROUTING", "-m", "comment", "--comment", "NFQUEUE -j QUEUE --queue-num 40321", "-j", "SNAT", "--to-source", "203.0.113.9"))
	return networkPolicyInventoryTestImage(identity.value, rows)
}

func nfqwsDirectStockTestRow(family int, table string, tokens ...string) BackendInventoryRow {
	return BackendInventoryRow{Family: family, Table: table, Tokens: tokens}
}

func nfqwsDirectStockTestClone(snapshot BackendInventorySnapshot) BackendInventorySnapshot {
	snapshot.Rows = cloneNetworkPolicyInventoryTestRows(snapshot.Rows)
	return snapshot
}

func nfqwsDirectStockTestQueueIndex(snapshot BackendInventorySnapshot, family int) int {
	for i, row := range snapshot.Rows {
		if row.Family == family && slices.Contains(row.Tokens, "NFQUEUE") {
			return i
		}
	}
	panic("fixture queue absent")
}

func nfqwsDirectStockTestRefused(t *testing.T, snapshot BackendInventorySnapshot, managed uint16) {
	t.Helper()
	before := nfqwsDirectStockTestClone(snapshot)
	rows, err := inspectNFQWSDirectStockQueues(snapshot, managed)
	if !errors.Is(err, errNFQWSDirectStockQueue) || rows != nil {
		t.Fatalf("expected closed refusal, got %d comparison rows and %v", len(rows), err)
	}
	if !reflect.DeepEqual(before, snapshot) {
		t.Fatal("refusal modified the original capture")
	}
}

func TestNFQWSDirectStockQueueOutputOnlyExactDetachedRows(t *testing.T) {
	for _, queues := range [][2]uint16{{1104, 1106}, {0, 65535}, {64511, 64512}} {
		t.Run(fmt.Sprint(queues), func(t *testing.T) {
			snapshot := nfqwsDirectStockQueueFixture()
			var expected []BackendInventoryRow
			for i, family := range []int{4, 6} {
				index := nfqwsDirectStockTestQueueIndex(snapshot, family)
				snapshot.Rows[index].Tokens[len(snapshot.Rows[index].Tokens)-1] = strconv.Itoa(int(queues[i]))
				snapshot.Rows[index].Tokens = append(snapshot.Rows[index].Tokens, "-m", "comment", "--comment", "inert -g FORWARD --queue-balance 1:65535")
				expected = append(expected, snapshot.Rows[index])
			}
			before := nfqwsDirectStockTestClone(snapshot)
			got, err := inspectNFQWSDirectStockQueues(snapshot, 40321)
			if err != nil || !reflect.DeepEqual(got, expected) || !reflect.DeepEqual(snapshot, before) {
				t.Fatal("OUTPUT-only capture did not preserve exact original comparison rows", err)
			}
			got[0].Tokens[1] = "changed"
			if !reflect.DeepEqual(snapshot, before) {
				t.Fatal("returned comparison rows alias the original capture")
			}
		})
	}
	// No vendor prefix or particular chain spelling conveys authority.
	snapshot := nfqwsDirectStockQueueFixture()
	for _, row := range snapshot.Rows {
		for i, token := range row.Tokens {
			if token == "local_bridge" || token == "local_delay" {
				row.Tokens[i] = "renamed_" + token
			}
		}
	}
	slices.Reverse(snapshot.Rows)
	if rows, err := inspectNFQWSDirectStockQueues(snapshot, 40321); err != nil || len(rows) != 2 {
		t.Fatal("proof depended on row order or chain names", err)
	}
}

func TestNFQWSDirectStockQueueReachabilityOverapproximatesEveryHook(t *testing.T) {
	for _, family := range []int{4, 6} {
		for _, hook := range []string{"PREROUTING", "INPUT", "FORWARD", "POSTROUTING"} {
			for _, control := range []string{"-j", "-g"} {
				t.Run(fmt.Sprintf("%d/%s/%s", family, hook, control), func(t *testing.T) {
					snapshot := nfqwsDirectStockQueueFixture()
					// Even apparently disjoint predicates and earlier terminating
					// verdicts do not remove any edge from the conservative graph.
					snapshot.Rows = append(snapshot.Rows,
						nfqwsDirectStockTestRow(family, "mangle", "-A", hook, "-j", "DROP"),
						nfqwsDirectStockTestRow(family, "mangle", "-A", hook, "!", "-s", "192.0.2.0/24", "-i", "outside+", control, "local_bridge"),
					)
					nfqwsDirectStockTestRefused(t, snapshot, 40321)
				})
			}
		}
	}
	for _, family := range []int{4, 6} {
		t.Run(fmt.Sprintf("orphan/%d", family), func(t *testing.T) {
			snapshot := nfqwsDirectStockQueueFixture()
			snapshot.Rows = slices.DeleteFunc(snapshot.Rows, func(row BackendInventoryRow) bool {
				return row.Family == family && reflect.DeepEqual(row.Tokens, []string{"-A", "OUTPUT", "-j", "local_bridge"})
			})
			nfqwsDirectStockTestRefused(t, snapshot, 40321)
		})
	}
	snapshot := nfqwsDirectStockQueueFixture()
	for _, family := range []int{4, 6} {
		snapshot.Rows[nfqwsDirectStockTestQueueIndex(snapshot, family)].Tokens[1] = "OUTPUT"
	}
	if rows, err := inspectNFQWSDirectStockQueues(snapshot, 40321); err != nil || len(rows) != 2 {
		t.Fatal("direct OUTPUT queue rejected", err)
	}
	snapshot = nfqwsDirectStockQueueFixture()
	snapshot.Rows = slices.DeleteFunc(snapshot.Rows, func(row BackendInventoryRow) bool { return slices.Contains(row.Tokens, "NFQUEUE") })
	if rows, err := inspectNFQWSDirectStockQueues(snapshot, 40321); err != nil || len(rows) != 0 {
		t.Fatal("queue-free capture manufactured comparison rows", err)
	}
}

func TestNFQWSDirectStockQueueReviewedStandardTargets(t *testing.T) {
	snapshot := nfqwsDirectStockQueueFixture()
	for _, family := range []int{4, 6} {
		for _, options := range [][]string{{"--set-mss", "1400"}, {"--clamp-mss-to-pmtu"}} {
			fields := append([]string{"-A", "FORWARD", "-p", "tcp", "-m", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS"}, options...)
			snapshot.Rows = append(snapshot.Rows, nfqwsDirectStockTestRow(family, "mangle", fields...))
		}
	}
	for _, option := range []string{"--ttl-set", "--ttl-inc", "--ttl-dec"} {
		snapshot.Rows = append(snapshot.Rows, nfqwsDirectStockTestRow(4, "mangle", "-A", "PREROUTING", "-j", "TTL", option, "1"))
	}
	if rows, err := inspectNFQWSDirectStockQueues(snapshot, 40321); err != nil || len(rows) != 2 {
		t.Fatal("reviewed nonqueue target verdicts rejected", err)
	}
	for _, body := range [][]string{
		{"-j", "TCPMSS"}, {"-j", "TCPMSS", "--set-mss", "1400", "--clamp-mss-to-pmtu"},
		{"-j", "TTL"}, {"-j", "TTL", "--ttl-inc", "1", "--ttl-set", "2"},
		{"-j", "NFQUEUE", "--queue-num", "1104", "--ttl-set", "1"},
		{"-j", "NFQUEUE", "--queue-num", "1104", "--clamp-mss-to-pmtu"},
	} {
		t.Run(strings.Join(body, " "), func(t *testing.T) {
			s := nfqwsDirectStockQueueFixture()
			s.Rows = append(s.Rows, nfqwsDirectStockTestRow(4, "mangle", append([]string{"-A", "OUTPUT"}, body...)...))
			nfqwsDirectStockTestRefused(t, s, 40321)
		})
	}
	snapshot = nfqwsDirectStockQueueFixture()
	snapshot.Rows = append(snapshot.Rows, nfqwsDirectStockTestRow(6, "mangle", "-A", "OUTPUT", "-j", "TTL", "--ttl-set", "1"))
	nfqwsDirectStockTestRefused(t, snapshot, 40321)
}

func TestNFQWSDirectStockQueueRejectsCollisionAndUnknownQueueABI(t *testing.T) {
	cases := map[string][]string{
		"selected-collision":  {"-j", "NFQUEUE", "--queue-num", "40321"},
		"balance-overlap":     {"-j", "NFQUEUE", "--queue-balance", "40320:40322"},
		"balance-disjoint":    {"-j", "NFQUEUE", "--queue-balance", "100:110"},
		"bypass":              {"-j", "NFQUEUE", "--queue-num", "1104", "--queue-bypass"},
		"fanout":              {"-j", "NFQUEUE", "--queue-num", "1104", "--queue-cpu-fanout"},
		"default-queue":       {"-j", "NFQUEUE"},
		"duplicate-number":    {"-j", "NFQUEUE", "--queue-num", "1104", "--queue-num", "1105"},
		"inline-number":       {"-j", "NFQUEUE", "--queue-num=1104"},
		"hex-number":          {"-j", "NFQUEUE", "--queue-num", "0x450"},
		"leading-zero":        {"-j", "NFQUEUE", "--queue-num", "01104"},
		"overflow":            {"-j", "NFQUEUE", "--queue-num", "65536"},
		"negative-number":     {"-j", "NFQUEUE", "--queue-num", "-1"},
		"negated-number":      {"-j", "NFQUEUE", "!", "--queue-num", "1104"},
		"legacy-queue":        {"-j", "QUEUE"},
		"unknown-flag":        {"-j", "NFQUEUE", "--queue-num", "1104", "--queue-unreviewed"},
		"queue-on-verdict":    {"-j", "ACCEPT", "--queue-num", "1104"},
		"extra-target-option": {"-j", "NFQUEUE", "--queue-num", "1104", "--set-mark", "1"},
		"duplicate-target":    {"-j", "NFQUEUE", "--queue-num", "1104", "-j", "RETURN"},
		"incomplete-comment":  {"-j", "NFQUEUE", "--queue-num", "1104", "--comment"},
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			snapshot := nfqwsDirectStockQueueFixture()
			snapshot.Rows[nfqwsDirectStockTestQueueIndex(snapshot, 4)].Tokens = append([]string{"-A", "local_delay"}, body...)
			nfqwsDirectStockTestRefused(t, snapshot, 40321)
		})
	}
	nfqwsDirectStockTestRefused(t, nfqwsDirectStockQueueFixture(), 0)
	for _, table := range []string{"raw", "filter", "nat", "custom"} {
		for _, control := range [][]string{{"-j", "NFQUEUE", "--queue-num", "1200"}, {"--jump=NFQUEUE"}, {"-jQUEUE"}, {"--goto", "QUEUE"}, {"--queue-balance=1200:1201"}} {
			t.Run(table+"/"+strings.Join(control, " "), func(t *testing.T) {
				snapshot := nfqwsDirectStockQueueFixture()
				snapshot.Rows = append(snapshot.Rows, nfqwsDirectStockTestRow(6, table, append([]string{"-A", "OUTPUT"}, control...)...))
				nfqwsDirectStockTestRefused(t, snapshot, 40321)
			})
		}
	}
}

func TestNFQWSDirectStockQueueRequiresClosedDeclaredGraph(t *testing.T) {
	cases := map[string][]BackendInventoryRow{
		"dangling-jump":             {nfqwsDirectStockTestRow(4, "mangle", "-A", "OUTPUT", "-j", "missing")},
		"dangling-goto":             {nfqwsDirectStockTestRow(6, "mangle", "-A", "OUTPUT", "-g", "missing")},
		"builtin-jump":              {nfqwsDirectStockTestRow(4, "mangle", "-A", "OUTPUT", "-j", "FORWARD")},
		"goto-target":               {nfqwsDirectStockTestRow(4, "mangle", "-A", "OUTPUT", "-g", "ACCEPT")},
		"unknown-vendor":            {nfqwsDirectStockTestRow(4, "mangle", "-A", "PREROUTING", "-j", "NDMMARK")},
		"unknown-conn-vendor":       {nfqwsDirectStockTestRow(6, "mangle", "-A", "OUTPUT", "-j", "CONNNDMMARK")},
		"unknown-option":            {nfqwsDirectStockTestRow(4, "mangle", "-A", "OUTPUT", "--unreviewed-match", "value", "-j", "RETURN")},
		"undeclared-source":         {nfqwsDirectStockTestRow(4, "mangle", "-A", "missing", "-j", "RETURN")},
		"duplicate-chain":           {nfqwsDirectStockTestRow(6, "mangle", "-N", "local_delay")},
		"duplicate-policy":          {nfqwsDirectStockTestRow(4, "mangle", "-P", "OUTPUT", "ACCEPT")},
		"unknown-builtin":           {nfqwsDirectStockTestRow(4, "mangle", "-P", "OTHER", "ACCEPT")},
		"builtin-as-user":           {nfqwsDirectStockTestRow(4, "mangle", "-N", "FORWARD")},
		"target-as-chain":           {nfqwsDirectStockTestRow(4, "mangle", "-N", "NFQUEUE")},
		"foreign-project-chain":     {nfqwsDirectStockTestRow(4, "mangle", "-N", "RZQ_foreign")},
		"foreign-project-reference": {nfqwsDirectStockTestRow(6, "mangle", "-A", "OUTPUT", "-j", "RZQ_foreign")},
		"cycle":                     {nfqwsDirectStockTestRow(4, "mangle", "-A", "local_delay", "-j", "local_bridge")},
		"unreachable-cycle": {
			nfqwsDirectStockTestRow(6, "mangle", "-N", "orphan_a"), nfqwsDirectStockTestRow(6, "mangle", "-N", "orphan_b"),
			nfqwsDirectStockTestRow(6, "mangle", "-A", "orphan_a", "-g", "orphan_b"), nfqwsDirectStockTestRow(6, "mangle", "-A", "orphan_b", "-j", "orphan_a"),
		},
		"trailing-negation":     {nfqwsDirectStockTestRow(4, "mangle", "-A", "OUTPUT", "!")},
		"negated-target":        {nfqwsDirectStockTestRow(4, "mangle", "-A", "OUTPUT", "!", "-j", "RETURN")},
		"malformed-mark-target": {nfqwsDirectStockTestRow(4, "mangle", "-A", "OUTPUT", "-j", "MARK", "--restore-mark")},
		"malformed-comment":     {nfqwsDirectStockTestRow(4, "mangle", "-A", "OUTPUT", "--comment")},
	}
	for name, additional := range cases {
		t.Run(name, func(t *testing.T) {
			snapshot := nfqwsDirectStockQueueFixture()
			snapshot.Rows = append(snapshot.Rows, additional...)
			nfqwsDirectStockTestRefused(t, snapshot, 40321)
		})
	}
	for _, family := range []int{4, 6} {
		for _, missing := range append([]string{"all-family"}, nfqwsDirectStockHooks...) {
			t.Run(fmt.Sprintf("missing/%d/%s", family, missing), func(t *testing.T) {
				snapshot := nfqwsDirectStockQueueFixture()
				snapshot.Rows = slices.DeleteFunc(snapshot.Rows, func(row BackendInventoryRow) bool {
					return row.Family == family && (missing == "all-family" || reflect.DeepEqual(row.Tokens, []string{"-P", missing, "ACCEPT"}))
				})
				nfqwsDirectStockTestRefused(t, snapshot, 40321)
			})
		}
	}
}

func TestNFQWSDirectStockQueueRequiresOriginalCompleteBoundedCapture(t *testing.T) {
	cases := map[string]func(*BackendInventorySnapshot){
		"schema":          func(s *BackendInventorySnapshot) { s.Schema = 2 },
		"identity":        func(s *BackendInventorySnapshot) { s.Scope.Network.BootID = "invalid" },
		"tool-review":     func(s *BackendInventorySnapshot) { s.Scope.ToolReviewID = "invalid" },
		"legacy-coverage": func(s *BackendInventorySnapshot) { s.Coverage.LegacyRegisteredBothFamilies = false },
		"nft-coverage":    func(s *BackendInventorySnapshot) { s.Coverage.NativeNFTAllFamilies = false },
		"tables-coverage": func(s *BackendInventorySnapshot) { s.Coverage.RegisteredTablesComplete = false },
		"nft-present":     func(s *BackendInventorySnapshot) { s.NFTState = BackendNFTPresent },
		"nft-unknown":     func(s *BackendInventorySnapshot) { s.NFTState = BackendNFTUnknown },
		"family":          func(s *BackendInventorySnapshot) { s.Rows[0].Family = 5 },
		"table":           func(s *BackendInventorySnapshot) { s.Rows[0].Table = "mangle\n" },
		"command":         func(s *BackendInventorySnapshot) { s.Rows[0].Tokens[0] = "-I" },
		"empty-token":     func(s *BackendInventorySnapshot) { s.Rows[0].Tokens[1] = "" },
		"nul-token":       func(s *BackendInventorySnapshot) { s.Rows[0].Tokens[1] = "OUTPUT\x00" },
		"invalid-utf8":    func(s *BackendInventorySnapshot) { s.Rows[0].Tokens[1] = string([]byte{0xff}) },
		"token-limit":     func(s *BackendInventorySnapshot) { s.Rows[0].Tokens[1] = strings.Repeat("x", 4097) },
		"row-token-limit": func(s *BackendInventorySnapshot) { s.Rows[0].Tokens = make([]string, 129) },
		"row-limit":       func(s *BackendInventorySnapshot) { s.Rows = make([]BackendInventoryRow, backendClassicRows+1) },
		"aggregate-token-limit": func(s *BackendInventorySnapshot) {
			for range backendClassicTokens / 128 {
				fields := make([]string, 128)
				for i := range fields {
					fields[i] = "x"
				}
				fields[0], fields[1] = "-A", "OUTPUT"
				s.Rows = append(s.Rows, nfqwsDirectStockTestRow(4, "mangle", fields...))
			}
		},
		"aggregate-byte-limit": func(s *BackendInventorySnapshot) {
			for range backendClassicBytes/4000 + 1 {
				s.Rows = append(s.Rows, nfqwsDirectStockTestRow(4, "mangle", "-A", "OUTPUT", "-m", "comment", "--comment", strings.Repeat("x", 4000)))
			}
		},
	}
	for name, alter := range cases {
		t.Run(name, func(t *testing.T) {
			snapshot := nfqwsDirectStockQueueFixture()
			alter(&snapshot)
			nfqwsDirectStockTestRefused(t, snapshot, 40321)
		})
	}
}

func TestNFQWSDirectStockQueueBoundedSharedDAG(t *testing.T) {
	snapshot := nfqwsDirectStockQueueFixture()
	const chains = 1000
	for i := range chains {
		name := fmt.Sprintf("dag_%d", i)
		snapshot.Rows = append(snapshot.Rows, nfqwsDirectStockTestRow(4, "mangle", "-N", name))
		for next := i + 1; next <= i+2 && next < chains; next++ {
			snapshot.Rows = append(snapshot.Rows, nfqwsDirectStockTestRow(4, "mangle", "-A", name, "-j", fmt.Sprintf("dag_%d", next)))
		}
	}
	snapshot.Rows = append(snapshot.Rows,
		nfqwsDirectStockTestRow(4, "mangle", "-A", "OUTPUT", "-j", "dag_0"),
		nfqwsDirectStockTestRow(4, "mangle", "-A", fmt.Sprintf("dag_%d", chains-1), "-g", "local_delay"),
	)
	if rows, err := inspectNFQWSDirectStockQueues(snapshot, 40321); err != nil || len(rows) != 2 {
		t.Fatal("bounded heavily shared DAG rejected", err)
	}
	snapshot.Rows = append(snapshot.Rows, nfqwsDirectStockTestRow(4, "mangle", "-A", "FORWARD", "-j", "dag_0"))
	nfqwsDirectStockTestRefused(t, snapshot, 40321)
}

func nfqwsDirectStockOwnedFixture(t *testing.T, family string) (BackendInventorySnapshot, uint16, []BackendInventoryRow) {
	t.Helper()
	// Use the original compiler and receipt-row producer, without pretending
	// that this pure model authenticates a live owner/receipt/process.
	_, spec, plan := nfqwsScopedDirectFixture(t, family)
	states := make([]string, len(plan.mixed.Effects))
	for i := range states {
		states[i] = "added"
	}
	owned, _, err := networkPolicyNFQReceiptRows(plan, states, false)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := nfqwsDirectStockQueueFixture()
	snapshot.Rows = append(snapshot.Rows, cloneNetworkPolicyInventoryTestRows(owned)...)
	return snapshot, spec.Queue, owned
}

func nfqwsDirectStockOwnedRefused(t *testing.T, snapshot BackendInventorySnapshot, managed uint16, owned []BackendInventoryRow) {
	t.Helper()
	before, beforeOwned := nfqwsDirectStockTestClone(snapshot), cloneNetworkPolicyInventoryTestRows(owned)
	rows, err := inspectNFQWSDirectStockQueuesWithOwned(snapshot, managed, owned)
	if !errors.Is(err, errNFQWSDirectStockQueue) || rows != nil {
		t.Fatalf("expected owned comparison refusal, got %d rows and %v", len(rows), err)
	}
	if !reflect.DeepEqual(before, snapshot) || !reflect.DeepEqual(beforeOwned, owned) {
		t.Fatal("refusal modified complete capture or exact owned comparison input")
	}
}

func TestNFQWSDirectStockQueueWithOwnedOriginalCompiledRows(t *testing.T) {
	for _, family := range []string{"ipv4", "ipv6"} {
		t.Run(family, func(t *testing.T) {
			snapshot, managed, owned := nfqwsDirectStockOwnedFixture(t, family)
			before, beforeOwned := nfqwsDirectStockTestClone(snapshot), cloneNetworkPolicyInventoryTestRows(owned)
			expected, err := inspectNFQWSDirectStockQueues(nfqwsDirectStockQueueFixture(), managed)
			if err != nil {
				t.Fatal(err)
			}
			got, err := inspectNFQWSDirectStockQueuesWithOwned(snapshot, managed, owned)
			if err != nil || !reflect.DeepEqual(got, expected) || !reflect.DeepEqual(snapshot, before) || !reflect.DeepEqual(owned, beforeOwned) {
				t.Fatal("original exact compiled FORWARD capture did not preserve only foreign OUTPUT rows", err)
			}
			got[0].Tokens[1] = "changed"
			if !reflect.DeepEqual(snapshot, before) || !reflect.DeepEqual(owned, beforeOwned) {
				t.Fatal("returned comparison rows alias either original input")
			}
			// The strict first API has no owned exemption, including with nil.
			nfqwsDirectStockTestRefused(t, snapshot, managed)
			nfqwsDirectStockOwnedRefused(t, snapshot, managed, nil)
		})
	}
	// Optional missing planned rows are omitted by the authenticated caller.
	snapshot, managed, owned := nfqwsDirectStockOwnedFixture(t, "ipv4")
	snapshot.Rows = snapshot.Rows[:len(snapshot.Rows)-len(owned)]
	for _, count := range []int{1, len(owned) / 2} {
		partial := nfqwsDirectStockTestClone(snapshot)
		partial.Rows = append(partial.Rows, cloneNetworkPolicyInventoryTestRows(owned[:count])...)
		if rows, err := inspectNFQWSDirectStockQueuesWithOwned(partial, managed, owned[:count]); err != nil || len(rows) != 2 {
			t.Fatal("exact observed receipt prefix rejected", count, err)
		}
	}
}

func TestNFQWSDirectStockQueueWithOwnedRejectsCountScopeAndQueueDefects(t *testing.T) {
	cases := map[string]func(*BackendInventorySnapshot, *[]BackendInventoryRow, uint16){
		"missing-owned-row": func(s *BackendInventorySnapshot, owned *[]BackendInventoryRow, _ uint16) {
			s.Rows = s.Rows[:len(s.Rows)-1]
		},
		"duplicate-owned-input": func(_ *BackendInventorySnapshot, owned *[]BackendInventoryRow, _ uint16) {
			*owned = append(*owned, (*owned)[0])
		},
		"duplicate-actual-row": func(s *BackendInventorySnapshot, owned *[]BackendInventoryRow, _ uint16) {
			s.Rows = append(s.Rows, (*owned)[len(*owned)-1])
		},
		"omitted-comparison-row": func(_ *BackendInventorySnapshot, owned *[]BackendInventoryRow, _ uint16) {
			*owned = (*owned)[:len(*owned)-1]
		},
		"different-token-boundary": func(_ *BackendInventorySnapshot, owned *[]BackendInventoryRow, _ uint16) {
			fields := (*owned)[len(*owned)-1].Tokens
			(*owned)[len(*owned)-1].Tokens = []string{fields[0], fields[1], strings.Join(fields[2:], " ")}
		},
		"wrong-family": func(_ *BackendInventorySnapshot, owned *[]BackendInventoryRow, _ uint16) {
			(*owned)[0].Family = 6
		},
		"wrong-table": func(_ *BackendInventorySnapshot, owned *[]BackendInventoryRow, _ uint16) {
			(*owned)[0].Table = "filter"
		},
		"unrelated-owned-row": func(s *BackendInventorySnapshot, owned *[]BackendInventoryRow, _ uint16) {
			row := nfqwsDirectStockTestRow(4, "mangle", "-A", "OUTPUT", "-j", "NFQUEUE", "--queue-num", "1300")
			s.Rows, *owned = append(s.Rows, row), append(*owned, row)
		},
		"owned-other-table-queue": func(s *BackendInventorySnapshot, owned *[]BackendInventoryRow, _ uint16) {
			row := nfqwsDirectStockTestRow(4, "raw", "-A", (*owned)[0].Tokens[1], "-j", "NFQUEUE", "--queue-num", "1300")
			s.Rows, *owned = append(s.Rows, row), append(*owned, row)
		},
		"unowned-extra-body": func(s *BackendInventorySnapshot, owned *[]BackendInventoryRow, _ uint16) {
			s.Rows = append(s.Rows, nfqwsDirectStockTestRow(4, "mangle", "-A", (*owned)[0].Tokens[1], "-j", "RETURN"))
		},
		"unowned-incoming-jump": func(s *BackendInventorySnapshot, owned *[]BackendInventoryRow, _ uint16) {
			s.Rows = append(s.Rows, nfqwsDirectStockTestRow(4, "mangle", "-A", "INPUT", "-j", (*owned)[0].Tokens[1]))
		},
		"unowned-incoming-goto": func(s *BackendInventorySnapshot, owned *[]BackendInventoryRow, _ uint16) {
			s.Rows = append(s.Rows, nfqwsDirectStockTestRow(4, "mangle", "-A", "OUTPUT", "-g", (*owned)[0].Tokens[1]))
		},
		"foreign-managed-collision": func(s *BackendInventorySnapshot, _ *[]BackendInventoryRow, managed uint16) {
			fields := s.Rows[nfqwsDirectStockTestQueueIndex(*s, 4)].Tokens
			fields[len(fields)-1] = strconv.Itoa(int(managed))
		},
		"wrong-owned-queue": func(s *BackendInventorySnapshot, owned *[]BackendInventoryRow, managed uint16) {
			for i := range *owned {
				if !slices.Contains((*owned)[i].Tokens, "NFQUEUE") {
					continue
				}
				fields := (*owned)[i].Tokens
				fields[len(fields)-1] = strconv.Itoa(int(managed) + 1)
				for j := len(s.Rows) - len(*owned); j < len(s.Rows); j++ {
					if slices.Contains(s.Rows[j].Tokens, "NFQUEUE") {
						s.Rows[j].Tokens[len(s.Rows[j].Tokens)-1] = strconv.Itoa(int(managed) + 1)
						break
					}
				}
				break
			}
		},
		"incomplete-original": func(s *BackendInventorySnapshot, _ *[]BackendInventoryRow, _ uint16) {
			s.Coverage.RegisteredTablesComplete = false
		},
		"malformed-owned-token": func(_ *BackendInventorySnapshot, owned *[]BackendInventoryRow, _ uint16) {
			(*owned)[0].Tokens[1] += "\x00"
		},
		"oversized-owned-row": func(_ *BackendInventorySnapshot, owned *[]BackendInventoryRow, _ uint16) {
			(*owned)[0].Tokens = make([]string, 129)
		},
		"oversized-owned-list": func(_ *BackendInventorySnapshot, owned *[]BackendInventoryRow, _ uint16) {
			*owned = make([]BackendInventoryRow, backendClassicRows+1)
		},
	}
	for name, alter := range cases {
		t.Run(name, func(t *testing.T) {
			snapshot, managed, owned := nfqwsDirectStockOwnedFixture(t, "ipv4")
			alter(&snapshot, &owned, managed)
			nfqwsDirectStockOwnedRefused(t, snapshot, managed, owned)
		})
	}
}

func TestNFQWSDirectStockQueueWithOwnedStillValidatesUntouchedGraph(t *testing.T) {
	for _, body := range [][]string{{"-j", "local_delay"}, {"-j", "missing"}, {"-j", "NDMMARK"}} {
		t.Run(strings.Join(body, " "), func(t *testing.T) {
			snapshot, managed, owned := nfqwsDirectStockOwnedFixture(t, "ipv4")
			row := nfqwsDirectStockTestRow(4, "mangle", append([]string{"-A", owned[0].Tokens[1]}, body...)...)
			snapshot.Rows, owned = append(snapshot.Rows, row), append(owned, row)
			// Even exactly compared owned bodies stay in the graph: the
			// first case makes the foreign queue reachable from FORWARD.
			nfqwsDirectStockOwnedRefused(t, snapshot, managed, owned)
		})
	}
	snapshot, managed, owned := nfqwsDirectStockOwnedFixture(t, "ipv4")
	row := nfqwsDirectStockTestRow(4, "mangle", "-A", owned[0].Tokens[1], "-g", owned[0].Tokens[1])
	snapshot.Rows, owned = append(snapshot.Rows, row), append(owned, row)
	nfqwsDirectStockOwnedRefused(t, snapshot, managed, owned)
}
