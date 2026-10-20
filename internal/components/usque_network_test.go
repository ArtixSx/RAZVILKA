package components

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUSQUEPackageAutomaticPoolRejectsLocalSubnetOverlap(t *testing.T) {
	for _, tc := range []struct {
		prefix   string
		conflict bool
	}{
		{"172.16.1.1/24", true}, {"172.16.0.1/16", true},
		{"172.16.1.100/32", true}, {"172.16.1.200/32", true},
		{"172.16.1.1/32", false}, {"172.16.1.99/32", false},
		{"172.16.1.201/32", false}, {"192.168.1.1/24", false}, {"2001:db8::1/64", false},
	} {
		t.Run(tc.prefix, func(t *testing.T) {
			_, network, err := net.ParseCIDR(tc.prefix)
			if err != nil {
				t.Fatal(err)
			}
			err = checkUSQUEAutomaticAddresses([]net.Addr{network})
			if (err != nil) != tc.conflict || err != nil && !strings.Contains(err.Error(), "USQUE_PACKAGE_ADDRESS_CONFLICT") {
				t.Fatalf("conflict=%t error=%v", tc.conflict, err)
			}
		})
	}
}

func TestUSQUENetworkRefusalPrecedesDependenciesAndUpdateJournal(t *testing.T) {
	refusal := errors.New("USQUE_PACKAGE_ADDRESS_CONFLICT: fixture local subnet")
	for _, update := range []bool{false, true} {
		r := &fakeRunner{output: map[string]string{}}
		state := filepath.Join(t.TempDir(), "state")
		m := &Manager{Opkg: "opkg", Runner: r, StateDir: state, usqueNetworkCheck: func() error { return refusal }}
		var err error
		if update {
			_, err = m.ManagedUpdate(context.Background(), "usque", func(context.Context) error { t.Fatal("live check ran"); return nil })
		} else {
			_, err = m.Apply(context.Background(), "usque")
		}
		if !errors.Is(err, refusal) {
			t.Fatal("network conflict was not retained", err)
		}
		for _, call := range r.calls {
			if len(call) < 2 || call[1] != "list-installed" {
				t.Fatal("network refusal reached package mutation", call)
			}
		}
		if _, err := os.Stat(state); !os.IsNotExist(err) {
			t.Fatal("network refusal created transaction or receipt", err)
		}
	}
}

func TestUSQUENetworkPlanBlocksMutationButAllowsRemoval(t *testing.T) {
	for _, action := range []string{"install", "update", "remove"} {
		called := 0
		m := &Manager{Opkg: "opkg", Runner: &fakeRunner{output: map[string]string{}}, BinDir: t.TempDir(), Client: offlineReleases(), usqueNetworkCheck: func() error {
			called++
			return errors.New("USQUE_PACKAGE_ADDRESS_CONFLICT: fixture local subnet")
		}}
		plan, err := m.Plan(context.Background(), "usque", action, false)
		if err != nil {
			t.Fatal(err)
		}
		blocked := action != "remove"
		if hasInventoryIssue(plan, "USQUE_PACKAGE_NETWORK_PREFLIGHT") != blocked || blocked && plan.Ready || (called > 0) != blocked {
			t.Fatalf("action=%s calls=%d plan=%+v", action, called, plan)
		}
	}
}
