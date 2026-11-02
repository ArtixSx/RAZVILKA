//go:build linux

package dataplane

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/ArtixSx/razvilka/internal/privaterestore"
)

// Actual protected archive publisher and five private lifetimes. The closing
// source callback here compares only original metadata; it grants no native
// cleanup and is not a complete coordinator/native workflow fixture.
func TestMihomoSameBootArchiveRetryRequiresPublisherACKReason(t *testing.T) {
	for _, kind := range []string{"lost-ack", "closing-source", "foreign-record", "closed"} {
		t.Run(kind, func(t *testing.T) {
			sameBootInputsFixture(t, func(ctx context.Context, set *privaterestore.OfflineServiceControlSet, state string, e Execution) {
				i, err := holdMihomoSameBootInputs(ctx, set, state, e.PlanID, e.Digest)
				if err != nil {
					t.Fatal(err)
				}
				defer i.close()
				a, err := newMihomoSameBootArchive(i)
				if err != nil {
					t.Fatal(err)
				}
				defer a.close()
				c := &mihomoSameBootRetirementCursor{archive: a, owner: &mihomoSameBootCleanup{inputs: i}}
				c.self = c
				c.owner.self = c.owner
				blocked := false
				cause := errors.New("original source or durability exception")
				current := func() error {
					if blocked {
						return cause
					}
					return i.current(ctx)
				}
				doc := struct{ Schema int }{1}
				if kind == "lost-ack" {
					a.fault = func(string) error { return cause }
				}
				if kind == "closing-source" {
					a.fault = func(string) error { blocked = true; return nil }
				}
				err = c.publishArchive("retirement.json", doc, current)
				if kind == "lost-ack" {
					if !errors.Is(err, cause) || c.retryArchive != "retirement.json" {
						t.Fatal("actual publisher ACK not classified", err)
					}
					original := a.records["retirement.json"].info
					a.fault = nil
					if err := c.publishArchive("retirement.json", doc, current); err != nil || c.retryArchive != "" || !os.SameFile(original, a.records["retirement.json"].info) {
						t.Fatal("original ACK retry replaced file or remained pending", err)
					}
					return
				}
				if kind == "closing-source" {
					if !errors.Is(err, cause) || c.retryArchive != "" {
						t.Fatal("source exception became durability retry", err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				r := a.records["retirement.json"]
				if kind == "foreign-record" {
					if err := a.root.WriteFile("foreign", r.data, 0600); err != nil {
						t.Fatal(err)
					}
					if err := a.root.Rename("foreign", r.name); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := r.file.Close(); err != nil {
						t.Fatal(err)
					}
					if err := a.close(); !errors.Is(err, os.ErrClosed) {
						t.Fatal("actual Close cause not retained", err)
					}
				}
				if err := c.publishArchive("retirement.json", doc, current); err == nil || c.retryArchive != "" {
					t.Fatal("foreign/closed publication received retry", err)
				}
			})
		})
	}
}
