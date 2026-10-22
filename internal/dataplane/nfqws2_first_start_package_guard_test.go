package dataplane

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

func TestNFQWS2PackageMutationBlockedObservesRetainedState(t *testing.T) {
	for _, state := range []string{"unowned", "inert-other-owner", "malformed-init", "prepared", "starting", "running", "stopped", "retiring", "corrupt-lease"} {
		t.Run(state, func(t *testing.T) {
			f := newStockAdapterFixture(t)
			if state == "inert-other-owner" || state == "malformed-init" {
				stock, err := os.ReadFile(f.a.InitPath)
				if err != nil {
					t.Fatal(err)
				}
				inert, err := engineconfig.NFQWSFirstStartInit(stock, "0123456789abcdef01234567")
				if err != nil {
					t.Fatal(err)
				}
				if state == "malformed-init" {
					inert = append(inert, []byte("echo foreign\n")...)
				}
				if err := os.WriteFile(f.a.InitPath, inert, 0755); err != nil {
					t.Fatal(err)
				}
			} else if state != "unowned" {
				if err := os.MkdirAll(f.a.StateRoot, 0700); err != nil {
					t.Fatal(err)
				}
				if state == "corrupt-lease" {
					if err := os.WriteFile(filepath.Join(f.a.StateRoot, nfqws2LeaseFile), []byte("{}"), 0600); err != nil {
						t.Fatal(err)
					}
				} else {
					// Data-only durable-observation fixture. This synthetic receipt
					// grants no execution/process authority and invokes no lifecycle.
					owner, err := f.a.owner()
					if err != nil {
						t.Fatal(err)
					}
					hash := strings.Repeat("a", 64)
					first := &nfqws2FirstStartLease{PriorInitHash: hash, StockInitHash: engineconfig.NFQWSFirstStartStockInitSHA256, Phase: state}
					if state == "running" || state == "stopped" || state == "retiring" {
						first.Process = &components.NFQWSRuntimeProcessIdentity{PID: 25, ParentPID: 1, Group: 25, Start: "123", BootID: "fixture", Executable: filepath.Join(t.TempDir(), "nfqws2"), ArgumentsSHA256: hash}
					}
					lease := &nfqws2Lease{Version: 1, Owner: owner, StateRoot: f.a.StateRoot, Transaction: t.TempDir(), ConfigPath: f.a.ConfigPath, InitPath: f.a.InitPath, ConfigHash: hash, InitHash: hash, FirstStart: first}
					for i, path := range f.a.ownedListPaths() {
						lease.Lists[i] = nfqws2ListLease{Path: path, BlockHash: hash}
					}
					if err := f.a.writeLease(lease); err != nil {
						t.Fatal(err)
					}
					// Lease must independently block even after an external deletion
					// of init; absence is never a package mutation exemption.
					if err := os.Remove(f.a.InitPath); err != nil {
						t.Fatal(err)
					}
				}
			}
			blocked, err := f.m.NFQWS2PackageMutationBlocked()
			wantErr := state == "malformed-init" || state == "corrupt-lease"
			if (err != nil) != wantErr || (!wantErr && blocked != (state != "unowned")) {
				t.Fatalf("blocked=%v err=%v", blocked, err)
			}
			if len(f.runner.calls) != 0 {
				t.Fatal("observation executed runtime command", f.runner.calls)
			}
		})
	}
}
