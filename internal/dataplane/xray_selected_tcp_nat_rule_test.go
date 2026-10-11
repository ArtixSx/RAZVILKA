package dataplane

import (
	"slices"
	"strings"
	"testing"
)

func TestXraySelectedTCPNATRuleKeyNativeNormalizationAndStrictVocabulary(t *testing.T) {
	chain := "RZX_" + strings.Repeat("a", 20)
	compiler := BackendInventoryRow{Family: 4, Table: "nat", Tokens: []string{"-A", "PREROUTING", "-i", "br-lan", "-s", "192.168.1.40/32", "-p", "tcp", "-m", "mac", "--mac-source", "02:00:00:00:00:ab", "-j", chain}}
	actual := BackendInventoryRow{Family: 4, Table: "nat", Tokens: []string{"-A", "PREROUTING", "-s", "192.168.1.40", "-i", "br-lan", "-p", "tcp", "-m", "tcp", "-m", "mac", "--mac-source", "02:00:00:00:00:AB", "-j", chain}}
	want, err := xraySelectedTCPNATRuleKey(compiler)
	if err != nil {
		t.Fatal(err)
	}
	got, err := xraySelectedTCPNATRuleKey(actual)
	if err != nil || want != got {
		t.Fatal("native -S normalization refused", err)
	}
	for _, tail := range [][]string{{"--unknown", "value"}, {"!", "-s"}, {"-p", "tcp"}, {"-m", "tcp"}, {"--to-ports", "23456"}, {"-g", chain}, {"--comment", "inert"}} {
		bad := actual
		bad.Tokens = append(slices.Clone(actual.Tokens), tail...)
		if key, err := xraySelectedTCPNATRuleKey(bad); err == nil || key != "" {
			t.Fatal("unknown/duplicate/changed syntax received key", tail)
		}
	}
	actual.Tokens[3] = "192.168.1.0/24"
	if key, err := xraySelectedTCPNATRuleKey(actual); err != nil || key == want {
		t.Fatal("source expansion collapsed to admitted /32", err)
	}
}
