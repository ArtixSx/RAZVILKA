//go:build linux

package dataplane

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"golang.org/x/sys/unix"
)

// Root-only ABI evidence on live IPv4 conntrack rows. This invokes the actual
// production CT_GET transport/decoder inside the ORIGINAL provider's current
// same-thread bracket. It creates no synthetic source, ledger, flow owner,
// cleanup lease or mutation permission. A complete count is not settlement.
// CT_GET may autoload a kernel module; the two-second context bounds userspace
// observation, not a synchronous kernel handler. NET only cross-compiles this.
func TestSyntheticConntrackNativeObservation(t *testing.T) {
	if os.Getenv("RAZVILKA_SYNTHETIC_CONNTRACK_NATIVE") != "1" {
		t.Skip("complete=false count=0 error_stage=opt-in-disabled error_reason=none")
	}
	var provider *netidentity.Provider
	var expected netidentity.Kind
	switch os.Getenv("RAZVILKA_SYNTHETIC_CONNTRACK_NATIVE_SCOPE") {
	case "", "proc":
		provider, expected = netidentity.NewProcProvider(), netidentity.ProcNetInode
	case "stock-nc1812":
		setup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		var err error
		provider, err = netidentity.NewReviewedStockNC1812Provider(setup)
		cancel()
		if err != nil {
			t.Fatal("complete=false count=0 error_stage=provider-factory error_reason=unclassified")
		}
		expected = netidentity.ReviewedSingleInitNet
	default:
		t.Fatal("complete=false count=0 error_stage=provider-selection error_reason=unclassified")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	stage := "scope-opening"
	var image syntheticCTImage
	err := provider.WithCurrent(ctx, func(held context.Context, identity netidentity.Identity) error {
		stage = "scope-identity"
		if identity.Validate() != nil || identity.Kind != expected {
			return ErrNetworkPolicyIdentity
		}
		tid := unix.Gettid()
		stage = "conntrack-read"
		var err error
		image, err = readSyntheticConntrack(held, identity)
		if err != nil {
			return err
		}
		stage = "same-thread"
		if unix.Gettid() != tid {
			return ErrNetworkPolicyIdentity
		}
		stage = "conntrack-complete"
		if !image.complete {
			return errSyntheticConntrack
		}
		stage = "scope-closing"
		return nil
	})
	if err != nil || ctx.Err() != nil {
		// Every label comes from the fixed code allowlist above. Never print
		// native errors, identity, sequence/port, IDs, tuples, names or IPs.
		reason := syntheticCTDiagnostic(err)
		if err == nil {
			reason = syntheticCTContext.label()
		}
		t.Fatalf("complete=false count=0 error_stage=%s error_reason=%s", stage, reason)
	}
	t.Logf("complete=true count=%d error_stage=none error_reason=none", len(image.rows))
}
