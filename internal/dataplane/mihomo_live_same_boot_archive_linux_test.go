//go:build linux

package dataplane

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/ArtixSx/razvilka/internal/privaterestore"
)

func TestMihomoSameBootArchiveRetriesOriginalPublishedFD(t *testing.T) {
	sameBootInputsFixture(t, func(ctx context.Context, s *privaterestore.OfflineServiceControlSet, state string, e Execution) {
		i, err := holdMihomoSameBootInputs(ctx, s, state, e.PlanID, e.Digest)
		if err != nil {
			t.Fatal(err)
		}
		defer i.close()
		c, err := newMihomoSameBootArchive(i)
		if err != nil {
			t.Fatal(err)
		}
		defer c.close()
		value := struct {
			Schema int
			Before []byte
		}{1, i.records[0].data}
		lost := errors.New("actual document published; original ACK lost")
		c.fault = func(string) error { return lost }
		current := func() error { return i.current(ctx) }
		if err := c.publish("retirement.json", value, current); !errors.Is(err, lost) {
			t.Fatal("original publication exception hidden", err)
		}
		r := c.records["retirement.json"]
		if r == nil || r.current() != nil {
			t.Fatal("authored descriptor discarded")
		}
		original, err := r.file.Stat()
		if err != nil {
			t.Fatal(err)
		}
		c.fault = nil
		if err := c.publish("retirement.json", value, current); err != nil {
			t.Fatal("same cursor cannot repeat durable ACK", err)
		}
		named, err := c.root.Lstat("retirement.json")
		if err != nil || !os.SameFile(original, named) {
			t.Fatal("retry replaced original inode", err)
		}
		if err := c.root.WriteFile("foreign.json", r.data, 0600); err != nil {
			t.Fatal(err)
		}
		if err := c.root.Rename("foreign.json", "retirement.json"); err != nil {
			t.Fatal(err)
		}
		if c.publish("retirement.json", value, current) == nil {
			t.Fatal("same-byte replacement adopted")
		}
	})
}

func TestMihomoSameBootArchiveRefusesUnacknowledgedExistingDocument(t *testing.T) {
	sameBootInputsFixture(t, func(ctx context.Context, s *privaterestore.OfflineServiceControlSet, state string, e Execution) {
		i, err := holdMihomoSameBootInputs(ctx, s, state, e.PlanID, e.Digest)
		if err != nil {
			t.Fatal(err)
		}
		defer i.close()
		c, err := newMihomoSameBootArchive(i)
		if err != nil {
			t.Fatal(err)
		}
		defer c.close()
		if err := c.root.WriteFile("retirement.json", []byte("{\"Schema\":1}"), 0600); err != nil {
			t.Fatal(err)
		}
		before, err := c.root.Lstat("retirement.json")
		if err != nil {
			t.Fatal(err)
		}
		if c.publish("retirement.json", struct{ Schema int }{1}, func() error { return i.current(ctx) }) == nil {
			t.Fatal("preexisting document adopted")
		}
		after, err := c.root.Lstat("retirement.json")
		if err != nil || !os.SameFile(before, after) {
			t.Fatal("foreign document overwritten", err)
		}
	})
}
