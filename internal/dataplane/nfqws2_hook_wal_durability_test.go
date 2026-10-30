package dataplane

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

func TestNFQWS2HookWALRequiresDirectorySyncBeforeAcknowledgingIntent(t *testing.T) {
	for _, kind := range []string{"boot", "candidate"} {
		t.Run(kind, func(t *testing.T) {
			path := t.TempDir()
			r, err := ownedfs.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			record := nfqws2CandidateHookRecord{Version: 1, PlanID: "dp-aaaaaaaaaaaaaaaa", Digest: strings.Repeat("a", 64), Instance: strings.Repeat("b", 24), State: "pending"}
			boot := &nfqws2BootHookWAL{root: r, path: path, record: record}
			candidate := &nfqws2CandidateHookJournal{root: r, path: path, record: record}
			name, save, current, image := nfqws2BootHookJournal, boot.saveWithSync, boot.current, func() []byte { return boot.image }
			if kind == "candidate" {
				name, save, current, image = nfqws2CandidateHooksJournal, candidate.saveWithSync, candidate.current, func() []byte { return candidate.image }
			}
			denied := errors.New("injected directory sync failure")
			syncs := 0
			err = save(func() error {
				syncs++
				// Directory sync follows publication, but no successful writer
				// image may yet authorize the first effect.
				if raw, err := r.ReadLimited(name, 1<<20); err != nil || len(raw) == 0 || len(image()) != 0 {
					t.Fatal("intent acknowledged before directory sync", err)
				}
				return denied
			})
			if !errors.Is(err, denied) || syncs != 1 || len(image()) != 0 {
				t.Fatal("sync failure was accepted", err, syncs)
			}
			if err := current(); !errors.Is(err, ErrReviewChanged) {
				t.Fatal("unflushed intent retained effect authority", err)
			}
			if kind == "boot" {
				if err := New(path).CheckNFQWS2BootHookRecovery(); !errors.Is(err, ErrExecutionJournal) {
					t.Fatal("failed publication lost conservative restart fence", err)
				}
			}
			// A successful durable retry records the same pending evidence;
			// it does not invent an acknowledged native command.
			if err := save(func() error { syncs++; return syncDataplaneJournalDirectory(r) }); err != nil || syncs != 2 {
				t.Fatal("durable retry failed", err)
			}
			raw, err := r.ReadLimited(name, 1<<20)
			if err != nil || !bytes.Equal(raw, image()) || current() != nil {
				t.Fatal("durable writer did not retain the exact image", err)
			}
		})
	}
}
