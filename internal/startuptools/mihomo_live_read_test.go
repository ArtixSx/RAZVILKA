package startuptools

import (
	"slices"
	"testing"
)

func TestMihomoLiveNumericReadKeepsActualFamiliesAndSelectors(t *testing.T) {
	for _, pair := range []struct{ input, expected []string }{
		{[]string{"-N", "rule", "show"}, []string{"-4", "-N", "rule", "show"}},
		{[]string{"-N", "-4", "rule", "show"}, []string{"-4", "-N", "rule", "show"}},
		{[]string{"-N", "-6", "rule", "show"}, []string{"-6", "-N", "rule", "show"}},
		{[]string{"rule", "show"}, []string{"-4", "rule", "show"}},
		{[]string{"-6", "rule", "show"}, []string{"-6", "rule", "show"}},
		{[]string{"-4", "-N", "rule", "show"}, []string{"-4", "-N", "rule", "show"}},
		{[]string{"-N", "route", "show", "table", "main"}, []string{"-N", "route", "show", "table", "main"}},
		{[]string{"-N", "rule", "show", "table", "207"}, []string{"-N", "rule", "show", "table", "207"}},
		{[]string{"rule", "del", "priority", "1"}, []string{"rule", "del", "priority", "1"}},
	} {
		original := slices.Clone(pair.input)
		got := mihomoLiveCanonicalReadArguments(2, pair.input)
		if !slices.Equal(got, pair.expected) || !slices.Equal(pair.input, original) {
			t.Fatal("read family/selector changed", pair.input, got)
		}
		got[0] = "changed caller copy"
		if !slices.Equal(pair.input, original) {
			t.Fatal("canonical read shares caller arguments")
		}
		if !slices.Equal(mihomoLiveCanonicalReadArguments(0, pair.input), original) {
			t.Fatal("firewall ABI was rewritten")
		}
	}
}

func TestMihomoLiveReadABINeverAdmitsEffects(t *testing.T) {
	accepted := [][]string{{"-4", "-N", "rule", "show"}, {"-6", "-j", "route", "show", "table", "all"}, {"-j", "link", "show"}, {"-j", "addr", "show", "dev", "rz-mihomo"}, {"route", "get", "1.1.1.1", "from", "192.168.1.2", "iif", "eth1", "mark", "0x20000000"}, {"route", "show", "table", "main", "match", "192.168.1.2/32"}}
	for _, args := range accepted {
		if !mihomoLiveReadArguments(2, args) {
			t.Fatal("required readonly ABI refused", args)
		}
	}
	refused := [][]string{{"route", "add", "1.1.1.1/32", "dev", "lo"}, {"link", "set", "dev", "eth0", "down"}, {"addr", "flush", "dev", "eth0"}, {"rule", "del", "priority", "1"}, {"-batch", "/tmp/commands"}, {"-netns", "foreign", "route", "show"}, {"route", "get", "service.example.com"}, {"route", "show", "table", "main", "match", "192.168.1.1/24"}, {"route", "get", "1.1.1.1", "iif", "eth0;true"}, {"-4", "-6", "rule", "show"}}
	for _, args := range refused {
		if mihomoLiveReadArguments(2, args) {
			t.Fatal("nonclosed read ABI", args)
		}
	}
	for _, args := range [][]string{{"-t", "filter", "-A", "FORWARD", "-j", "ACCEPT"}, {"-t", "mangle", "-F"}, {"-t", "nat", "--restore"}} {
		if mihomoLiveReadArguments(0, args) {
			t.Fatal("firewall effect became readonly", args)
		}
	}
}

func TestMihomoLiveReadABIOriginalForwardingWANSelector(t *testing.T) {
	for _, args := range [][]string{{"route", "show", "table", "main", "default"}, {"-6", "route", "show", "table", "main", "default"}, {"-4", "-N", "route", "show", "table", "main", "default"}} {
		if !mihomoLiveReadArguments(2, args) {
			t.Fatal("actual original forwarding read rejected", args)
		}
	}
	for _, args := range [][]string{{"route", "show", "default"}, {"route", "show", "table", "all", "default"}, {"route", "show", "table", "main", "default", "dev", "eth0"}, {"route", "show", "table", "main", "default", "add"}, {"route", "show", "table", "main", "defaults"}, {"route", "add", "table", "main", "default"}} {
		if mihomoLiveReadArguments(2, args) {
			t.Fatal("unreviewed selector or effect accepted", args)
		}
	}
}
