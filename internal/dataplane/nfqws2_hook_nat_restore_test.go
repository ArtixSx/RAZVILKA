package dataplane

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"testing"
)

func TestNFQWS2HookCompleteNATLossRetainsCheckpoints(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	for _, mode := range []string{"stop-after-nat-create", "queue-before-jumps", "foreign-nat-before-readback", "rewrite-before-readback"} {
		t.Run(mode, func(t *testing.T) {
			h := newNFQWS2HookFixture(t, false)
			h.kernel = newNFQWS2HookKernel(t, nfqws2HookWithoutOwned(nfqws2HookFullV4()), nfqws2RouterIPv6Fixture)
			before := h.kernel.rows()
			stopped := false
			ctx := WithReviewGuard(firstStartContext(t), func(context.Context) error {
				if stopped {
					return errors.New("modeled stop")
				}
				return nil
			})
			h.beforeWrite = func(n, _ int, _ []string) error {
				if mode == "stop-after-nat-create" && n == 1 {
					stopped = true
				}
				if mode == "queue-before-jumps" && n == 11 {
					h.queueInode = "778"
				}
				return nil
			}
			h.beforeRead = func(n int) {
				if n != 3 {
					return
				}
				if mode == "foreign-nat-before-readback" {
					if err := h.kernel.apply(4, []string{"-t", "nat", "-A", "nfqws_nat", "-j", "RETURN"}); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "rewrite-before-readback" {
					h.kernel = newNFQWS2HookKernel(t, nfqws2HookWithoutOwned(nfqws2HookFullV4()), nfqws2RouterIPv6Fixture)
				}
			}
			result, err := h.m.RestoreCommittedNFQWS2Hooks(ctx, h.committed(t))
			if err == nil || len(result.Restored) != 0 {
				t.Fatal(result, err)
			}
			if mode == "foreign-nat-before-readback" {
				if !result.Uncertain || result.RolledBack {
					t.Fatal("foreign NAT lost uncertainty", result)
				}
				return
			}
			if !result.RolledBack || result.Uncertain || !nfqws2HookSameRows(h.kernel.rows(), before) {
				t.Fatal("checkpoint failure did not restore exact initial graph", result, err)
			}
		})
	}
}

func TestNFQWS2HookRestoreCompleteNATAndMangleLoss(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	for _, ipv6 := range []bool{false, true} {
		t.Run(map[bool]string{false: "ipv4", true: "both-families"}[ipv6], func(t *testing.T) {
			h := newNFQWS2HookFixture(t, ipv6)
			h.kernel = newNFQWS2HookKernel(t, nfqws2HookWithoutOwned(nfqws2HookFullV4()), nfqws2RouterIPv6Fixture)
			plan, files, calls := h.committed(t), h.files(t), len(h.calls)
			before := h.kernel.rows()
			observed, err := h.m.ObserveCommittedNFQWS2Hooks(firstStartContext(t), plan)
			if err != nil || observed.Class != NFQWS2HooksLoss {
				t.Fatalf("complete graph loss was not admitted: %+v %v", observed, err)
			}
			result, err := h.m.RestoreCommittedNFQWS2Hooks(firstStartContext(t), plan)
			want := []int{4}
			if ipv6 {
				want = append(want, 6)
			}
			if err != nil || !slices.Equal(result.Restored, want) || result.Uncertain || result.RolledBack {
				t.Fatalf("complete graph was not restored: %+v %v", result, err)
			}
			if !nfqws2HookSameRows(h.kernel.rows(), h.fullKernel(t).rows()) {
				t.Fatal("restored graph differs from stock capture")
			}
			var created []BackendInventoryRow
			for _, command := range result.Commands {
				if command.Args[2] != "-N" && command.Args[2] != "-A" {
					t.Fatal("unexpected destructive command", command)
				}
				created = append(created, BackendInventoryRow{Family: command.Family, Table: command.Args[1], Tokens: command.Args[2:]})
			}
			remaining, ok := nfqws2HookWithout(h.kernel.rows(), created)
			if !ok || !nfqws2HookSameRows(remaining, before) {
				t.Fatal("foreign graph changed")
			}
			h.assertFiles(t, files)
			h.assertNoRuntimeCall(t, calls)
			committed := h.committed(t)
			if !reflect.DeepEqual(committed, plan) {
				t.Fatal("committed authority changed")
			}
			writes := len(h.writes)
			if again, err := h.m.RestoreCommittedNFQWS2Hooks(firstStartContext(t), plan); err != nil || again.Class != NFQWS2HooksFull || len(h.writes) != writes {
				t.Fatal("restored graph was not a no-op", again, err)
			}
		})
	}
}

func TestNFQWS2HookNATRestoreFailureReceipts(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	for _, tc := range []struct {
		name    string
		at      int
		foreign bool
		unknown bool
	}{
		{name: "nat-create-rejected", at: 1},
		{name: "mangle-create-rejected", at: 2},
		{name: "nat-jump-rejected", at: 12},
		{name: "last-mangle-jump-rejected", at: 14},
		{name: "nat-create-response-lost", at: 1, unknown: true},
		{name: "foreign-nat-create-collision", at: 1, foreign: true},
		{name: "foreign-body-after-nat-create", at: 2, foreign: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newNFQWS2HookFixture(t, false)
			h.kernel = newNFQWS2HookKernel(t, nfqws2HookWithoutOwned(nfqws2HookFullV4()), nfqws2RouterIPv6Fixture)
			before := h.kernel.rows()
			var collided []BackendInventoryRow
			h.beforeWrite = func(n, family int, args []string) error {
				if n != tc.at {
					return nil
				}
				if tc.unknown || tc.foreign && n == 1 {
					if err := h.kernel.apply(family, args); err != nil {
						t.Fatal(err)
					}
				}
				if tc.foreign {
					if err := h.kernel.apply(4, []string{"-t", "nat", "-A", "nfqws_nat", "-j", "RETURN"}); err != nil {
						t.Fatal(err)
					}
				}
				collided = h.kernel.rows()
				return errors.New("modeled rejected or lost command")
			}
			result, err := h.m.RestoreCommittedNFQWS2Hooks(firstStartContext(t), h.committed(t))
			if !errors.Is(err, ErrNFQWS2HookRestore) || len(result.Restored) != 0 {
				t.Fatal(result, err)
			}
			if tc.unknown || tc.foreign {
				if !errors.Is(err, ErrNFQWS2HookUncertain) || !result.Uncertain || result.RolledBack || !nfqws2HookSameRows(h.kernel.rows(), collided) {
					t.Fatal("ambiguous NAT objects were changed or accepted", result, err)
				}
			} else if !result.RolledBack || result.Uncertain || !nfqws2HookSameRows(h.kernel.rows(), before) {
				t.Fatal("acknowledged NAT/mangle effects were not exactly removed", result, err)
			}
		})
	}
}
