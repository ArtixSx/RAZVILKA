package startuptools

import (
	"slices"
	"strings"
	"testing"
)

func TestSyntheticDomainCaptureClosedGrammar(t *testing.T) {
	nat, input := "RZDC_"+strings.Repeat("a", 20), "RZDI_"+strings.Repeat("a", 20)
	commands := [][]string{{"-t", "nat", "-N", nat}, {"-t", "nat", "-A", nat, "-p", "tcp", "-j", "DNAT", "--to-destination", "192.168.1.1:19000"}, {"-t", "filter", "-N", input}, {"-t", "filter", "-A", input, "-j", "ACCEPT"}}
	for _, spec := range []struct{ table, hook, destination, port, chain string }{{"nat", "PREROUTING", "198.18.0.1/32", "443", nat}, {"filter", "INPUT", "192.168.1.1/32", "19000", input}} {
		selector := []string{"-t", spec.table, "-D", spec.hook, "-i", "br0", "-s", "192.168.1.42/32", "-d", spec.destination, "-m", "mac", "--mac-source", "02:00:00:00:00:02", "-p", "tcp", "-m", "tcp", "--dport", spec.port, "-j", spec.chain}
		commands = append(commands, selector, append(append([]string{}, selector[:2]...), append([]string{"-I", spec.hook, "1"}, selector[4:]...)...))
	}
	for _, command := range commands {
		if !syntheticDNSArguments(command) {
			t.Fatal("compiler grammar refused", command)
		}
		if syntheticDNSArguments(append(slices.Clone(command), "extra")) {
			t.Fatal("extra argv admitted")
		}
	}
	for _, change := range []struct {
		index int
		value string
	}{{7, "0.0.0.0/0"}, {9, "1.1.1.1/32"}, {19, "80:443"}, {21, "RZG_foreign"}, {5, "lo"}, {13, "ff:ff:ff:ff:ff:ff"}} {
		altered := slices.Clone(commands[4])
		altered[change.index] = change.value
		if syntheticDNSArguments(altered) {
			t.Fatal("broader selector admitted", altered)
		}
	}
	for _, command := range [][]string{{"-t", "nat", "-F", nat}, {"-t", "filter", "-P", "INPUT", "ACCEPT"}, {"-t", "nat", "-I", "PREROUTING", "2"}, {"-t", "nat", "-A", nat, "-p", "tcp", "-j", "DNAT", "--to-destination", "1.1.1.1:80"}} {
		if syntheticDNSArguments(command) {
			t.Fatal("foreign command admitted", command)
		}
	}
}
