package dataplane

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

func firstStartStoppedInactiveFixture(t *testing.T) *nfqws2InactiveFixture {
	t.Helper()
	f := newNFQWS2InactiveFixture(t)
	prefix := filepath.Join(filepath.Dir(f.a.ConfigPath), "opt")
	f.a.InitPath = filepath.Join(prefix, "etc", "init.d", "S51nfqws2")
	for _, path := range []string{filepath.Dir(f.a.InitPath), filepath.Dir(f.a.firstStartPIDPath())} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	original, err := os.ReadFile(filepath.Join("..", "engineconfig", "testdata", "nfqws2-first-start-1.3.1.conf"))
	if err != nil {
		t.Fatal(err)
	}
	owner, err := f.a.owner()
	if err != nil {
		t.Fatal(err)
	}
	config, err := engineconfig.NFQWSFirstStartConfig(original, owner, []string{"selected.example"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	stock, err := os.ReadFile(filepath.Join("..", "components", "testdata", "nfqws2-keenetic-1.3.1", "S51nfqws2"))
	if err != nil {
		t.Fatal(err)
	}
	init, err := engineconfig.NFQWSFirstStartInit(stock, owner)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.a.ConfigPath, config, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.a.InitPath, init, 0700); err != nil {
		t.Fatal(err)
	}
	lease := &nfqws2Lease{Version: 1, StateRoot: f.a.StateRoot, Owner: owner, Transaction: filepath.Join(prefix, "transaction"), ConfigPath: f.a.ConfigPath, InitPath: f.a.InitPath, ConfigHash: nfqws2Hash(config), ConfigOwner: nfqws2Hash(original), PriorConfig: nfqws2Hash(original), InitHash: nfqws2Hash(init), FirstStart: &nfqws2FirstStartLease{Phase: nfqws2FirstStopped, PriorInitHash: nfqws2Hash(stock), StockInitHash: nfqws2Hash(stock), Process: &components.NFQWSRuntimeProcessIdentity{BootID: f.source.identity.BootID, PID: 999, ParentPID: 1, Group: 999, Start: "123", Executable: filepath.Join(prefix, "usr", "bin", "nfqws2"), ArgumentsSHA256: strings.Repeat("a", 64)}}}
	for index, path := range f.a.ownedListPaths() {
		raw := []byte(managedBegin + "\n# RAZVILKA INSTANCE " + owner + "\n" + managedEnd + "\n")
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		block, err := nfqws2Block(raw)
		if err != nil {
			t.Fatal(err)
		}
		lease.Lists[index] = nfqws2ListLease{Path: path, BlockHash: nfqws2Hash(block)}
	}
	if err := f.a.writeLease(lease); err != nil {
		t.Fatal(err)
	}
	f.source.startup = *f.a // Explicit private source model after moving its fixture paths.
	return f
}

func TestNFQWS2FirstStartStoppedMetadataStillRequiresIndependentAbsence(t *testing.T) {
	f := firstStartStoppedInactiveFixture(t)
	ctx := nfqws2InactiveTestContext(t)
	before, err := nfqws2ReadInactiveFiles(ctx, f.a, f.proof)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.verify(ctx); err != nil {
		t.Fatal("exact stopped metadata refused with all independent observations", err)
	}
	after, err := nfqws2ReadInactiveFiles(ctx, f.a, f.proof)
	if err != nil || !before.same(after) {
		t.Fatal("observer changed stopped state", err)
	}
	f.process(t, 999, "nfqws2", 'S', 0, "/opt/usr/bin/nfqws2\x00--qnum=300\x00")
	if err := f.verify(ctx); err == nil {
		t.Fatal("stopped lease replaced a full process observation")
	}
}

func TestNFQWS2FirstStartStoppedObservationRefusesUnsettledOrDriftedFiles(t *testing.T) {
	for _, which := range []string{"running", "starting", "retiring", "config", "init", "list", "run", "pid"} {
		t.Run(which, func(t *testing.T) {
			f := firstStartStoppedInactiveFixture(t)
			ctx := nfqws2InactiveTestContext(t)
			switch which {
			case "running", "starting", "retiring":
				lease, err := f.a.readLease()
				if err != nil {
					t.Fatal(err)
				}
				lease.FirstStart.Phase = which
				if which == "starting" {
					lease.FirstStart.Process = nil
				}
				if err := f.a.writeLease(lease); err != nil {
					t.Fatal(err)
				}
			case "config":
				writeStockText(t, f.a.ConfigPath, readText(t, f.a.ConfigPath)+"# external\n")
			case "init":
				writeStockText(t, f.a.InitPath, readText(t, f.a.InitPath)+"# external\n")
			case "list":
				writeStockText(t, f.a.UserListPath, strings.Replace(readText(t, f.a.UserListPath), "# RAZVILKA INSTANCE ", "# FOREIGN INSTANCE ", 1))
			case "run":
				writeStockText(t, f.a.ConfigPath+".run", "TCP_PORTS=443\n")
			case "pid":
				writeStockText(t, f.a.firstStartPIDPath(), "999\n")
			}
			if err := f.verify(ctx); err == nil {
				t.Fatal("unsettled or drifted stopped metadata accepted")
			}
		})
	}
}
