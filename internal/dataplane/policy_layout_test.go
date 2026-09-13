package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"testing"
)

type precedenceFixture struct {
	kernel    policyKernelFake
	foreign   map[int][]string
	mutations []string
	failAdd   int
	adds      int
}

func (f *precedenceFixture) Run(ctx context.Context, _ string, args ...string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	family := 4
	commandArgs := args
	if len(commandArgs) > 0 && commandArgs[0] == "-6" {
		family = 6
		commandArgs = commandArgs[1:]
	}
	command := strings.Join(commandArgs, " ")
	if command == "rule show" {
		output, _, err := f.kernel.run(args)
		return append(output, []byte(strings.Join(f.foreign[family], "\n"))...), err
	}
	if strings.HasPrefix(command, "rule add") {
		f.adds++
		if f.failAdd > 0 && f.adds == f.failAdd {
			return nil, errors.New("injected selector creation failure")
		}
	}
	if strings.HasPrefix(command, "rule ") || strings.HasPrefix(command, "route replace") || strings.HasPrefix(command, "route flush") {
		f.mutations = append(f.mutations, strings.Join(args, " "))
	}
	if output, handled, err := f.kernel.run(args); handled {
		return output, err
	}
	if strings.HasPrefix(command, "route get 192.168.1.40") {
		return []byte("192.168.1.40 dev br0 src 192.168.1.1"), nil
	}
	if strings.HasPrefix(command, "route show table main match") {
		return []byte("192.168.1.0/24 dev br0 scope link"), nil
	}
	if strings.HasPrefix(command, "route get") {
		return []byte("203.0.113.20 dev rz-sing table 203"), nil
	}
	return nil, nil
}

func testEarlyPolicy() PolicyState {
	state := PolicyState{Interface: "rz-sing", Table: 203, PriorityBase: 22000, Prefixes: []string{"149.154.167.99/32"}, Rules: []PolicyRule{{Source: "192.168.1.40/32", Destination: "149.154.167.99/32"}}, Exclusions: []string{"203.0.113.9/32"}}
	initializePolicyLayout(&state)
	return state
}

func TestEarlyPolicySelectsOnlyReviewedPairsRegardlessOfFirmwareMark(t *testing.T) {
	state := testEarlyPolicy()
	f := &precedenceFixture{foreign: map[int][]string{4: {"100: from all fwmark 0xffffaaa lookup 4096"}}}
	if err := applyPolicy(context.Background(), f, "ip", state); err != nil {
		t.Fatal(err)
	}
	if err := verifyPolicyEvidence(context.Background(), f, "ip", state); err != nil {
		t.Fatal(err)
	}
	// Independent decision model: firmware policy wins marked packets unless
	// one of our exact, earlier positive selectors matches. No mark is cleared.
	lookup := func(source, destination string, marked bool) string {
		entries := append([]policyKernelEntry(nil), f.kernel.entries...)
		sort.SliceStable(entries, func(i, j int) bool { return entries[i].priority < entries[j].priority })
		for _, rule := range entries {
			if marked && rule.priority > 100 {
				return "firmware-vpn"
			}
			if (rule.source == "all" || netip.MustParsePrefix(rule.source).Contains(netip.MustParseAddr(source))) && netip.MustParsePrefix(rule.dest).Contains(netip.MustParseAddr(destination)) {
				return rule.table
			}
		}
		if marked {
			return "firmware-vpn"
		}
		return "main"
	}
	for _, marked := range []bool{false, true} {
		if got := lookup("192.168.1.40", "149.154.167.99", marked); got != "203" {
			t.Fatalf("selected route mark=%t: %s", marked, got)
		}
	}
	for _, pair := range [][2]string{{"192.168.1.41", "149.154.167.99"}, {"192.168.1.40", "8.8.8.8"}, {"192.168.1.41", "203.0.113.9"}} {
		if got := lookup(pair[0], pair[1], true); got != "firmware-vpn" {
			t.Fatalf("unselected traffic changed: %v -> %s", pair, got)
		}
	}
	if got := lookup("192.168.1.40", "203.0.113.9", true); got != "main" {
		t.Fatalf("selected endpoint exclusion: %s", got)
	}
	for _, rule := range f.kernel.entries {
		if rule.source != "192.168.1.40/32" {
			t.Fatal("early rule broadened client scope", rule)
		}
	}
	foreign := append([]string(nil), f.foreign[4]...)
	if err := removePolicy(context.Background(), f, "ip", state); err != nil {
		t.Fatal(err)
	}
	if len(f.kernel.entries) != 0 || !reflect.DeepEqual(foreign, f.foreign[4]) {
		t.Fatal("cleanup changed foreign policy or left own selectors")
	}
}

func TestLegacyUnmarkedFIBEvidenceCannotHideEarlierFirmwareMarkPolicy(t *testing.T) {
	state := testEarlyPolicy()
	state.RuleLayout, state.SharedPriorityBase = 0, 0
	f := &precedenceFixture{foreign: map[int][]string{4: {"100: from all fwmark 0xffffaaa lookup 4096"}}}
	if err := applyPolicy(context.Background(), f, "ip", state); err != nil {
		t.Fatal(err)
	}
	if err := verifyPolicyEvidence(context.Background(), f, "ip", state); err == nil {
		t.Fatal("legacy unmarked lookup was promoted to marked LAN evidence")
	}
	if err := removePolicy(context.Background(), f, "ip", state); err != nil {
		t.Fatal(err)
	}
}

func TestEarlyPolicyRejectsForeignSlotsAndEarlierAmbiguityBeforeMutation(t *testing.T) {
	for _, line := range []string{
		"64: from 192.168.1.40 to 203.0.113.9 lookup main",
		"65: from 192.168.1.40 to 149.154.167.99 lookup 203",
		"65: from all blackhole",
		"40: from all fwmark 0xffffaaa lookup 4096",
		"40: not from 192.168.1.41 fwmark 0x1 lookup 4096",
		"40: from 192.168.1.41 from 192.168.1.40 lookup 4096",
		"unknown policy syntax",
	} {
		t.Run(line, func(t *testing.T) {
			f := &precedenceFixture{foreign: map[int][]string{4: {line}}}
			if err := applyPolicy(context.Background(), f, "ip", testEarlyPolicy()); err == nil || len(f.mutations) != 0 {
				t.Fatalf("conflict mutated kernel: err=%v calls=%v", err, f.mutations)
			}
		})
	}
	f := &precedenceFixture{foreign: map[int][]string{4: {"40: from 192.168.1.41 fwmark 0xffffaaa lookup 4096"}}}
	if err := applyPolicy(context.Background(), f, "ip", testEarlyPolicy()); err != nil {
		t.Fatal("disjoint device policy blocked", err)
	}
}

func TestEarlyPolicyReadbackRejectsLateForeignChangesDuplicatesAndMissingSelectors(t *testing.T) {
	for _, change := range []string{"earlier-mark", "same-slot-mark", "duplicate", "missing"} {
		t.Run(change, func(t *testing.T) {
			state := testEarlyPolicy()
			f := &precedenceFixture{foreign: map[int][]string{}}
			if err := applyPolicy(context.Background(), f, "ip", state); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "earlier-mark":
				f.foreign[4] = []string{"40: from all fwmark 0x1 lookup 4096"}
			case "same-slot-mark":
				f.foreign[4] = []string{"65: from 192.168.1.40 to 149.154.167.99 fwmark 0x1 lookup 203"}
			case "duplicate":
				f.kernel.entries = append(f.kernel.entries, f.kernel.entries[0])
			case "missing":
				f.kernel.entries = f.kernel.entries[:1]
			}
			if err := verifyPolicyEvidence(context.Background(), f, "ip", state); err == nil {
				t.Fatal("changed precedence accepted")
			}
			if change == "same-slot-mark" || change == "duplicate" {
				before := len(f.mutations)
				if err := removePolicy(context.Background(), f, "ip", state); err == nil || len(f.mutations) != before {
					t.Fatal("ambiguous cleanup mutated foreign/duplicate selectors")
				}
			}
		})
	}
}

func TestEarlyPolicySupports1024SelectorsWithinTwoReservedSlots(t *testing.T) {
	state := testEarlyPolicy()
	state.Exclusions = nil
	state.Prefixes = nil
	state.Rules = nil
	for i := 0; i < maxPolicyPrefixes; i++ {
		prefix := fmt.Sprintf("198.18.%d.%d/32", i/256, i%256)
		state.Prefixes = append(state.Prefixes, prefix)
		state.Rules = append(state.Rules, PolicyRule{Source: "192.168.1.40/32", Destination: prefix})
	}
	f := &precedenceFixture{}
	if err := applyPolicy(context.Background(), f, "ip", state); err != nil {
		t.Fatal(err)
	}
	if len(f.kernel.entries) != 1024 {
		t.Fatal("selectors were truncated")
	}
	for _, rule := range f.kernel.entries {
		if rule.priority != 65 {
			t.Fatal("rule escaped adapter shared slot")
		}
	}
	if err := verifyPolicyPrecedence(context.Background(), f, "ip", state, false); err != nil {
		t.Fatal(err)
	}
	if err := removePolicy(context.Background(), f, "ip", state); err != nil || len(f.kernel.entries) != 0 {
		t.Fatal("bounded shared cleanup failed", err)
	}
}

func TestPolicyLayoutRollbackPreservesRecordedLegacyCoordinates(t *testing.T) {
	legacy := testEarlyPolicy()
	legacy.RuleLayout, legacy.SharedPriorityBase = 0, 0
	encoded, _ := json.Marshal(legacy)
	var recorded PolicyState
	if err := json.Unmarshal(encoded, &recorded); err != nil {
		t.Fatal(err)
	}
	f := &precedenceFixture{}
	if err := applyPolicy(context.Background(), f, "ip", recorded); err != nil {
		t.Fatal(err)
	}
	before := append([]policyKernelEntry(nil), f.kernel.entries...)
	if err := removePolicy(context.Background(), f, "ip", recorded); err != nil {
		t.Fatal(err)
	}
	f.adds, f.failAdd = 0, 2
	if err := applyPolicy(context.Background(), f, "ip", testEarlyPolicy()); err == nil || len(f.kernel.entries) != 0 {
		t.Fatal("failed new apply leaked a shared selector", err)
	}
	f.failAdd = 0
	if err := applyPolicy(context.Background(), f, "ip", recorded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, f.kernel.entries) || !reflect.DeepEqual(recorded, legacy) {
		t.Fatal("legacy rollback coordinates or scope changed")
	}
	if before[0].priority != 22000 || before[1].priority != 22001 {
		t.Fatal("legacy fixture no longer exercises indexed priorities")
	}
	modern := recorded
	initializePolicyLayout(&modern)
	if samePolicy(recorded, modern) {
		t.Fatal("layout change hidden from policy equality")
	}
}
