//go:build linux

package dataplane

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Exercise the actual same-boot home reader's two absence boundaries with
// real owned home files. Absence itself is modeled, not native process/kernel
// evidence; the original parent/ACK fixture supplies that separate proof.
func TestMihomoSameBootHomeOwnsAbsenceBookends(t *testing.T) {
	for _, mode := range []string{"success", "opening-error", "closing-error", "closing-mutation", "opening-cancel", "closing-cancel", "foreign-identity"} {
		t.Run(mode, func(t *testing.T) {
			d, path, receipt, _, parent := mihomoColdHomeFixture(t)
			ctx, cancel := context.WithCancel(parent)
			defer cancel()
			cache := filepath.Join(path, "cache.db")
			originalInfo, err := os.Lstat(cache)
			if err != nil {
				t.Fatal(err)
			}
			original, err := os.ReadFile(cache)
			if err != nil {
				t.Fatal(err)
			}
			expected := bytes.Clone(original)
			sentinel := errors.New("original same-boot absence refused")
			calls := 0
			out, err := observeMihomoOfflineHome(ctx, d, func(observed context.Context) (netidentity.Identity, error) {
				calls++
				if observed != ctx || calls > 2 {
					t.Fatal("observer changed context or repeated absence", calls)
				}
				if mode == "opening-error" && calls == 1 || mode == "closing-error" && calls == 2 {
					return netidentity.Identity{}, sentinel
				}
				if mode == "opening-cancel" && calls == 1 || mode == "closing-cancel" && calls == 2 {
					cancel()
					return netidentity.Identity{}, ctx.Err()
				}
				if mode == "closing-mutation" && calls == 2 {
					expected = []byte("changed private history")
					if err := os.WriteFile(cache, expected, 0600); err != nil {
						t.Fatal(err)
					}
				}
				identity := d.NetworkIdentity
				if mode == "foreign-identity" {
					identity.BootID = "11111111-2222-4333-8444-555555555555"
				}
				return identity, nil
			}, true)
			defer clearMihomoColdHome(&out)
			wantCalls := 2
			if mode == "opening-error" || mode == "opening-cancel" || mode == "foreign-identity" {
				wantCalls = 1
			}
			if calls != wantCalls {
				t.Fatalf("absence calls=%d want=%d", calls, wantCalls)
			}
			if mode == "success" {
				if err != nil || out.State != "present" || !bytes.Equal(out.Files["cache.db"], original) || !bytes.Equal(out.Receipt, receipt) {
					t.Fatal("same-boot two-bookend read failed", err)
				}
			} else if err == nil || !reflect.DeepEqual(out, mihomoColdHomeArchive{}) {
				t.Fatal("refusal returned usable home history", err)
			}
			if (mode == "opening-error" || mode == "closing-error") && !errors.Is(err, sentinel) {
				t.Fatal("original absence error lost", err)
			}
			if (mode == "opening-cancel" || mode == "closing-cancel") && !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation lost", err)
			}
			// Neither success nor refusal archives/removes/rewrites the home.
			// The single explicit test mutation above must remain untouched too.
			entries, readErr := os.ReadDir(path)
			currentInfo, statErr := os.Lstat(cache)
			current, bytesErr := os.ReadFile(cache)
			currentReceipt, receiptErr := os.ReadFile(filepath.Join(path, components.MihomoLiveHomeReceiptName))
			if errors.Join(readErr, statErr, bytesErr, receiptErr) != nil || len(entries) != 2 || !os.SameFile(originalInfo, currentInfo) || currentInfo.Mode() != originalInfo.Mode() || !bytes.Equal(current, expected) || !bytes.Equal(currentReceipt, receipt) {
				t.Fatal("read-only observer changed original home", readErr, statErr, bytesErr, receiptErr)
			}
		})
	}
}
