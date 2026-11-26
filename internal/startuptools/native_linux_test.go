//go:build linux && (amd64 || arm64)

package startuptools

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Only this test reads a QA opt-in. The production factories have no env,
// fixture program, path override, callback injection or detached-review input.
func TestProductionStartupToolsNative(t *testing.T) {
	mode := os.Getenv("RAZVILKA_STARTUP_TOOLS_NATIVE")
	if mode == "" {
		t.Skip("Root production startup tools native fixture opt-in disabled")
	}
	if os.Geteuid() != 0 {
		t.Fatal("native startup tools require root")
	}
	lifetime, lifetimeCancel := context.WithCancel(context.Background())
	defer lifetimeCancel()
	setup, setupCancel := context.WithTimeout(lifetime, operationTimeout)
	provider := nativeProvider(t, setup, mode)
	setupCancel()
	// Deliberate inherited poison: it must not reach a production child.
	t.Setenv("LD_PRELOAD", "/unreviewed-startup-tools-preload.so")
	t.Setenv("LD_LIBRARY_PATH", "/unreviewed-startup-tools-libraries")
	t.Setenv("XTABLES_LIBDIR", "/unreviewed-startup-tools-extensions")
	var lease *Lease
	var err error
	started := time.Now()
	if mode == "stock-nc1812" {
		lease, err = AcquireReviewedStockNC1812(lifetime, provider)
	} else {
		lease, err = AcquireUbuntuLegacy(lifetime, provider)
	}
	acquired := time.Since(started)
	if err != nil {
		t.Fatalf("production acquisition refused: acquisition-ms=%d stages=%s", acquired.Milliseconds(), nativeStages(err))
	}
	defer lease.Close()
	t.Logf("production acquisition passed: acquisition-ms=%d images=%d bytes=%d nodes=%d review=%s; no mutation grant", acquired.Milliseconds(), len(lease.review.images), lease.review.bytes, len(lease.review.nodes), lease.digest)
	tools, err := lease.InventoryTools()
	if err != nil {
		t.Fatal(err)
	}
	var inventory *dataplane.BackendInventory
	if mode == "stock-nc1812" {
		inventory, err = dataplane.NewReviewedStockNC1812BackendInventory(provider, tools)
	} else {
		inventory, err = dataplane.NewBackendInventory(provider, tools)
	}
	if err != nil {
		t.Fatal(err)
	}
	captureBudget := operationTimeout
	if mode == "stock-nc1812" {
		// Only the whole stock capture gets the agreed six-second parent.
		// Production acquisition, Check and each command still cap at two.
		captureBudget = 6 * time.Second
	}
	read, readCancel := context.WithTimeout(lifetime, captureBudget)
	captureStart := time.Now()
	snapshot, err := inventory.Read(read, lease.identity)
	captureElapsed, captureContext := time.Since(captureStart), nativeContextState(read)
	readCancel()
	if err != nil {
		t.Fatalf("actual production inventory refused: acquisition-ms=%d capture-ms=%d capture-context=%s stages=%s", acquired.Milliseconds(), captureElapsed.Milliseconds(), captureContext, nativeStages(err))
	}
	t.Logf("production inventory passed: acquisition-ms=%d capture-ms=%d capture-context=%s rows=%d; no mutation grant", acquired.Milliseconds(), captureElapsed.Milliseconds(), captureContext, len(snapshot.Rows))
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if err := tools.Check(context.Background(), lease.identity); !errors.Is(err, ErrUnknown) {
		t.Fatal("copied production descriptor survived close", err)
	}
	read, readCancel = context.WithTimeout(context.Background(), operationTimeout)
	defer readCancel()
	if _, err := inventory.Read(read, lease.identity); err == nil {
		t.Fatal("collector issued evidence after tool lease close")
	}
}

func nativeProvider(t *testing.T, ctx context.Context, mode string) *netidentity.Provider {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("native startup tools require root")
	}
	if mode == "ubuntu-legacy" {
		return netidentity.NewProcProvider()
	}
	if mode != "stock-nc1812" {
		t.Fatal("unreviewed native profile")
	}
	provider, err := netidentity.NewReviewedStockNC1812Provider(ctx)
	if err != nil {
		t.Fatal("stock provider refused: stages=", nativeStages(err))
	}
	return provider
}
