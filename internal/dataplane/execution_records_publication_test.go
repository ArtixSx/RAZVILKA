package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

func TestOriginalRecordDirectoryFailureKeepsAuthoredFDAndRetry(t *testing.T) {
	for _, failedIndex := range []int{0, 1} {
		t.Run(string(rune('0'+failedIndex)), func(t *testing.T) {
			f, e := retainedNFQWSProbeScopeFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			d := e.records
			if err := d.current(ctx, true); err != nil {
				t.Fatal("fixture records", err)
			}
			s := f.r.scope
			s.mu.Lock()
			s.execution.Error = "modeled durability ACK failure"
			data, err := json.Marshal(s.execution)
			s.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			fault := errors.New("directory fsync result unavailable")
			calls := 0
			for i := range 2 {
				err := d.publishOriginalDurable(i, data, func(root *ownedfs.Root) error {
					calls++
					// Actual directory synchronization is exercised on native Linux; only
					// its reported outcome is faulted. No native runtime grant is modeled.
					if err := syncDataplaneJournalDirectory(root); err != nil {
						return err
					}
					if i == failedIndex {
						return fault
					}
					return nil
				})
				if (i == failedIndex) != errors.Is(err, fault) {
					t.Fatalf("index%d: %v", i, err)
				}
			}
			if calls != 2 {
				t.Fatal("both roots must be synchronized", calls)
			}
			if err := d.current(ctx, true); err != nil {
				t.Fatal("original FD lost after sync failure", err)
			}
			held := d.files[failedIndex]
			info, err := held.Stat()
			if err != nil {
				t.Fatal("accepted FD closed on durability failure", err)
			}
			for i := range 2 {
				if err := d.publishOriginalDurable(i, data, syncDataplaneJournalDirectory); err != nil {
					t.Fatal("same-owner retry", err)
				}
			}
			if err := d.current(ctx, true); err != nil {
				t.Fatal(err)
			}
			next, err := d.files[failedIndex].Stat()
			if err != nil || os.SameFile(info, next) {
				t.Fatal("retry did not author fresh inode", err)
			}
			got := make([]byte, len(data))
			n, err := d.files[failedIndex].ReadAt(got, 0)
			if err != nil || n != len(data) || !bytes.Equal(got, data) {
				t.Fatal("retry changed exact execution", err)
			}
		})
	}
}
