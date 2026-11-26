package dataplane

import (
	"errors"
	"strings"
	"testing"
)

func TestXraySelectedTCPConntrackRequiresWholeTableAndOriginalRedirectSettlement(t *testing.T) {
	spec := xraySelectedTCPFixtureSpec(t, "node-"+strings.Repeat("1", 64))
	original := "ipv4 2 tcp 6 431999 ESTABLISHED src=192.168.1.40 dst=1.1.1.1 sport=52000 dport=443 src=192.168.1.1 dst=192.168.1.40 sport=16443 dport=52000 [ASSURED] mark=0 use=1\n"
	if err := xraySelectedTCPConntrackSettled([]byte(original), false, spec); !errors.Is(err, ErrXraySelectedTCPConntrackPending) {
		t.Fatal("old redirect did not keep Stop pending", err)
	}
	for _, row := range []string{
		strings.Replace(original, "dst=1.1.1.1", "dst=8.8.8.8", 1),
		strings.Replace(original, "src=192.168.1.40", "src=192.168.2.40", 1),
		strings.Replace(original, "dport=443", "dport=80", 1),
		strings.Replace(original, "sport=16443", "sport=16444", 1),
		"ipv4 2 udp 17 30 src=192.168.1.40 dst=1.1.1.1 sport=52000 dport=443 src=1.1.1.1 dst=192.168.1.40 sport=443 dport=52000 mark=0 use=1\n",
		"",
	} {
		if err := xraySelectedTCPConntrackSettled([]byte(row), false, spec); err != nil {
			t.Fatal("unrelated flow refused", err)
		}
	}
	for _, bad := range []string{
		strings.TrimSuffix(original, "\n"), original + "truncated\n", original + "\n",
		strings.Replace(original, "src=192.168.1.1 ", "", 1),
		strings.Replace(original, "mark=0", "unknown=0", 1),
		strings.Replace(original, "ESTABLISHED", "NOT_A_STATE", 1),
		strings.Replace(original, "tcp 6", "tcp 17", 1),
		strings.Replace(original, "dport=443", "dport=65536", 1),
		strings.Replace(original, "ipv4 2", "ipv4 10", 1),
		strings.Replace(original, "ipv4 2", "ipv6 10", 1),
		strings.Replace(original, "src=192.168.1.40", "src=fd00::40", 1),
		strings.Replace(original, "mark=0", "mark=0 mark=0", 1),
		strings.Replace(original, "mark=0", "mark=0 mark=0 mark=0", 1),
	} {
		if err := xraySelectedTCPConntrackSettled([]byte(bad), false, spec); err == nil || errors.Is(err, ErrXraySelectedTCPConntrackPending) {
			t.Fatal("malformed whole table was not unknown", err)
		}
	}
	legacy := strings.TrimPrefix(original, "ipv4 2 ")
	if err := xraySelectedTCPConntrackSettled([]byte(legacy), true, spec); !errors.Is(err, ErrXraySelectedTCPConntrackPending) {
		t.Fatal("legacy whole proc format lost tuple", err)
	}
	if err := xraySelectedTCPConntrackSettled(nil, false, XraySelectedTCPRedirectSpec{}); err == nil {
		t.Fatal("empty table granted unbound definition")
	}
}
