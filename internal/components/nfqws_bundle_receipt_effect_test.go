package components

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
)

// Actual fixture installer/receipt CAS, no binary, Lua, process or kernel grant.
func TestManagedNFQWSReceiptRollbackUsesItsActualRemoveOrRenameEffect(t *testing.T) {
	for _, restorePrior := range []bool{false, true} {
		name := "remove-first-receipt"
		if restorePrior {
			name = "rename-prior-receipt"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			first, input, _ := bundleFixtureManifest(t, "receipt-a")
			m := bundleFixtureManager(t, input)
			a := bundleFixtureAuthority()
			current, err := m.InstallManagedBundle(ctx, first, 7, a)
			if err != nil {
				t.Fatal(err)
			}
			prior := current
			if restorePrior {
				next, payload, _ := bundleFixtureManifest(t, "receipt-b")
				m.Client.Transport = bundleFixtureTransport(func(r *http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(payload)), ContentLength: int64(len(payload)), Request: r}, nil
				})
				current, err = m.UpdateManagedBundle(ctx, next, 7, a)
				if err != nil {
					t.Fatal(err)
				}
			}
			admit := a.Admit
			var effects []string
			a.Admit = func(ctx context.Context, tx, id string, sequence, revision uint64, effect string, begin func() error) error {
				effects = append(effects, effect)
				return admit(ctx, tx, id, sequence, revision, effect, begin)
			}
			if _, err := m.RecoverManagedBundle(ctx, current.TransactionID, "rollback", a); err != nil {
				t.Fatal(err)
			}
			wanted := "nfqws-remove-receipt"
			if restorePrior {
				wanted = "nfqws-rollback-receipt"
			}
			if len(effects) != 1 || effects[0] != wanted {
				t.Fatal("trusted producer did not distinguish its actual leaf", effects, wanted)
			}
			root, err := m.managedNFQWSInventory(false)
			if err != nil {
				t.Fatal(err)
			}
			receipt, _, err := readManagedNFQWSReceipt(root)
			_ = root.Close()
			if err != nil || restorePrior && (receipt == nil || *receipt != prior) || !restorePrior && receipt != nil {
				t.Fatal("actual receipt rollback outcome changed", receipt, err)
			}
		})
	}
}
