//go:build linux

package physicalscope

import (
	"context"
	"errors"
	"os"
	"reflect"
	"runtime"
	"testing"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/systemprobe"
)

// Extend the existing native selected-observation test, never introduce a
// duplicate acceptance test. Execution belongs only to Root's router window.
func nativeRetainedIncarnationOptIn(t *testing.T) bool {
	t.Helper()
	if os.Getenv("RAZVILKA_PHYSICAL_SCOPE_RETAINED_NATIVE") != "1" {
		return false
	}
	if runtime.GOARCH != "arm64" || os.Getenv("RAZVILKA_PHYSICAL_SCOPE_NATIVE") != "stock-nc1812" {
		t.Skip("retained native opt-in requires Linux ARM64 and actual reviewed stock NC1812")
	}
	if os.Getenv("RAZVILKA_PHYSICAL_SCOPE_HOME") == "" {
		t.Skip("retained native opt-in requires explicit Root-selected Home segment")
	}
	return true
}

// SelectionReader is ONLY test-owned frozen intent; its revision mutation does
// not edit Store, network configuration or user consent. Physical NDM/kernel/NI
// and both WAN reads use concrete production providers, never private models.
// This read-only sequence issues no cleanup/effect grant and performs no App Apply.
func nativeRetainedIncarnationSequence(t *testing.T, ctx context.Context, provider *netidentity.Provider, observer *Observer, review *Review, selection *Selection, selectionReads *int) {
	t.Helper()
	original := review.Snapshot()
	if original.Identity.Kind != netidentity.ReviewedSingleInitNet {
		t.Fatal("original native Review did not retain the reviewed stock identity")
	}
	readWAN := func() string {
		var id string
		err := provider.WithCurrent(ctx, func(c context.Context, current netidentity.Identity) error {
			if current != original.Identity {
				return ErrUnknown
			}
			wan, err := systemprobe.FreshWANProfile(c)
			if err != nil || !systemprobe.ValidWANProfileID(wan.ID) {
				return errors.Join(ErrUnknown, err)
			}
			id = wan.ID
			return nil
		})
		if err != nil {
			t.Fatal("actual original NI/fresh WAN observation", err)
		}
		return id
	}
	beforeWAN := readWAN()
	checkRetained := func() {
		reads := *selectionReads
		if err := observer.VerifyRetainedIncarnation(ctx, review); err != nil {
			t.Fatal("actual retained physical observation", err)
		}
		if *selectionReads != reads || !reflect.DeepEqual(original, review.Snapshot()) {
			t.Fatal("retained check reread test selection or adopted fresh facts")
		}
	}
	checkRetained()
	// Revoke forward intent ONLY in the test reader. This is not a real policy
	// edit or a native physical mutation; the same open Review/fence is retained.
	selection.Revision++
	reads := *selectionReads
	err := observer.Verify(ctx, review)
	var refusal *failure
	if !errors.As(err, &refusal) || refusal.stage != "verify.selection.changed" || *selectionReads != reads+1 {
		t.Fatal("forward selection-only refusal was not exercised", err)
	}
	checkRetained()
	// Restoring this test DTO cannot revive forward admission.
	*selection = cloneSnapshot(original).Selection
	if !errors.Is(observer.Verify(ctx, review), ErrUnknown) {
		t.Fatal("test selection restoration revived forward Review")
	}
	if afterWAN := readWAN(); afterWAN != beforeWAN {
		t.Fatal("actual WAN epoch changed during read-only retained sequence")
	}
	if err := review.Close(); err != nil {
		t.Fatal("close original native Review", err)
	}
	if !errors.Is(observer.VerifyRetainedIncarnation(ctx, review), ErrUnknown) || !errors.Is(observer.Verify(ctx, review), ErrUnknown) {
		t.Fatal("closed original native Review admitted observation")
	}
	t.Logf("actual_stock_retained=true typed_scope=%s segments=%d devices=%d selection_reader=test_frozen_intent forward_revoked=true snapshot_unchanged=true wan_stable=true closed_refuses=true cleanup_grant=false app_apply=false", original.Identity.Kind, len(original.Segments), len(original.Devices))
}
