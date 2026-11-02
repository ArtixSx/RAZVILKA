package startuptools

import (
	"slices"
	"testing"
)

func TestSyntheticDomainBaselineClosedToolGrammar(t *testing.T) {
	commands := [][]string{
		{"-4", "route", "add", "local", "192.168.1.10/32", "dev", "lo", "table", "31000", "proto", "static"},
		{"-4", "rule", "add", "priority", "31000", "to", "192.168.1.10/32", "iif", "wan0", "fwmark", "0x525a0001/0xffffffff", "lookup", "31000"},
		{"-t", "raw", "-I", "OUTPUT", "1", "-o", "wan0", "-s", "192.168.1.10/32", "-d", "1.1.1.2/32", "-p", "tcp", "-m", "tcp", "--sport", "49123", "--dport", "443", "-j", "CT", "--notrack"},
		{"-t", "raw", "-I", "PREROUTING", "1", "-i", "wan0", "-s", "1.1.1.2/32", "-d", "192.168.1.10/32", "-p", "tcp", "-m", "tcp", "--sport", "443", "--dport", "49123", "-j", "CT", "--notrack"},
		{"-t", "mangle", "-I", "PREROUTING", "1", "-i", "wan0", "-s", "1.1.1.2/32", "-d", "192.168.1.10/32", "-p", "tcp", "-m", "tcp", "--sport", "443", "--dport", "49123", "-j", "MARK", "--set-xmark", "0x525a0001/0xffffffff"},
	}
	for _, command := range commands {
		accept := syntheticDomainBaselineIPArguments
		if command[0] == "-t" {
			accept = syntheticDomainBaselinePacketArguments
		}
		if !accept(command) {
			t.Fatal("compiled baseline shape refused", command)
		}
		if accept(append(slices.Clone(command), "extra")) {
			t.Fatal("trailing argv accepted")
		}
		cleanup := slices.Clone(command)
		if command[0] == "-t" {
			cleanup[2] = "-D"
			cleanup = append(cleanup[:4], cleanup[5:]...)
		} else {
			cleanup[2] = "del"
		}
		if !accept(cleanup) {
			t.Fatal("exact cleanup refused", cleanup)
		}
		for i, value := range command {
			if value != "31000" && value != "0x525a0001/0xffffffff" && value != "192.168.1.10/32" && value != "1.1.1.2/32" {
				continue
			}
			bad := slices.Clone(command)
			switch value {
			case "31000":
				bad[i] = "31001"
			case "0x525a0001/0xffffffff":
				bad[i] = "0x1/0x1"
			case "192.168.1.10/32":
				bad[i] = "192.168.1.0/24"
			case "1.1.1.2/32":
				bad[i] = "127.0.0.1/32"
			}
			if accept(bad) {
				t.Fatal("broadened baseline grammar", bad)
			}
		}
	}
}
