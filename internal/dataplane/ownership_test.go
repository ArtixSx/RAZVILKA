package dataplane

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

func TestProxyExclusionOwnershipRequiresExactPrivateTuple(t *testing.T) {
	root := t.TempDir()
	manager := New(filepath.Join(root, "manager"))
	adapter, err := NewProxyTunnelAdapter("sing-box", engineconfig.New(filepath.Join(root, "drafts"), filepath.Join(root, "backups")), filepath.Join(root, "configured-private-state"))
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Register(adapter); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(adapter.StateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	state := PolicyState{Interface: adapter.Interface, Table: adapter.Table, PriorityBase: adapter.Priority, Prefixes: []string{"198.51.100.20/32"}, Exclusions: []string{"203.0.113.9/32", "2001:db8::9/128"}}
	write := func(value PolicyState) {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := writeAtomic(adapter.policyPath(), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(state)
	for _, tc := range []struct {
		name, adapter, rule string
		family              int
		want                bool
	}{
		{"IPv4 kernel host form", "sing-box", "22000: from all to 203.0.113.9 lookup main", 4, true},
		{"IPv4 canonical numeric table", "sing-box", "22000: from 0.0.0.0/0 to 203.0.113.9/32 table 254", 4, true},
		{"IPv6", "sing-box", "22001: from all to 2001:db8::9 lookup main", 6, true},
		{"other priority", "sing-box", "22001: from all to 203.0.113.9 lookup main", 4, false},
		{"other endpoint", "sing-box", "22000: from all to 203.0.113.10 lookup main", 4, false},
		{"other source", "sing-box", "22000: from 192.168.1.40 to 203.0.113.9 lookup main", 4, false},
		{"other family", "sing-box", "22000: from all to 203.0.113.9 lookup main", 6, false},
		{"other table", "sing-box", "22000: from all to 203.0.113.9 lookup 999", 4, false},
		{"unregistered", "xray", "22000: from all to 203.0.113.9 lookup main", 4, false},
		{"wide prefix", "sing-box", "22000: from all to 203.0.113.0/24 lookup main", 4, false},
		{"extra mark", "sing-box", "22000: from all to 203.0.113.9 fwmark 0x1 lookup main", 4, false},
		{"extra ingress", "sing-box", "22000: from all to 203.0.113.9 iif br0 lookup main", 4, false},
		{"unknown suffix", "sing-box", "22000: from all to 203.0.113.9 lookup main proto static", 4, false},
		{"negated", "sing-box", "22000: not from all to 203.0.113.9 lookup main", 4, false},
		{"second action", "sing-box", "22000: from all to 203.0.113.9 lookup main goto 99", 4, false},
		{"embedded line", "sing-box", "22000: from all to 203.0.113.9 lookup main\n", 4, false},
		{"overlong", "sing-box", strings.Repeat(" ", 2049) + "22000: from all to 203.0.113.9 lookup main", 4, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := manager.OwnsProxyEndpointExclusion(tc.adapter, tc.family, tc.rule); got != tc.want {
				t.Fatalf("ownership=%t want=%t", got, tc.want)
			}
		})
	}
	rule := "22000: from all to 203.0.113.9 lookup main"
	for _, mutate := range []func(*PolicyState){
		func(s *PolicyState) { s.Interface = "foreign0" },
		func(s *PolicyState) { s.Table = 999 },
		func(s *PolicyState) { s.PriorityBase++ },
		func(s *PolicyState) { s.Exclusions = []string{"203.0.113.9/32", "203.0.113.9/32"} },
		func(s *PolicyState) { s.Exclusions = []string{"203.0.113.9/32", "192.168.1.1/32"} },
		func(s *PolicyState) { s.Prefixes = nil },
		func(s *PolicyState) { s.Exclusions = make([]string, maxPolicyPrefixes+1) },
	} {
		bad := state
		mutate(&bad)
		write(bad)
		if manager.OwnsProxyEndpointExclusion("sing-box", 4, rule) {
			t.Fatal("invalid private policy granted ownership")
		}
	}
	for _, data := range [][]byte{[]byte("not json"), []byte(strings.Repeat(" ", (1<<20)+1))} {
		if err := os.WriteFile(adapter.policyPath(), data, 0o600); err != nil {
			t.Fatal(err)
		}
		if manager.OwnsProxyEndpointExclusion("sing-box", 4, rule) {
			t.Fatal("malformed/oversized private policy granted ownership")
		}
	}
	if err := os.Remove(adapter.policyPath()); err != nil {
		t.Fatal(err)
	}
	if manager.OwnsProxyEndpointExclusion("sing-box", 4, rule) {
		t.Fatal("missing private policy granted ownership")
	}
}
