package startuptools

import "testing"

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
