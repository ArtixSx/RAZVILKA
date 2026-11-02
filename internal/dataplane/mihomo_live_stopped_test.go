package dataplane

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// Real writer custody and durability, not a terminal/runtime authority fixture.
func mihomoStoppedPublicationModel(t *testing.T) (*mihomoStoppedPlanPublication, context.Context) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	m := New(path)
	root, anchor, err := openNetworkPolicyObservationRoot(m.StateRoot)
	if err != nil {
		t.Fatal(err)
	}
	p := &mihomoStoppedPlanPublication{manager: m, root: root, path: m.StateRoot, anchor: anchor, data: []byte(`{"model":"stopped-plan"}`)}
	t.Cleanup(func() {
		for _, f := range p.files {
			if f.file != nil {
				_ = f.file.Close()
			}
		}
		_ = root.Close()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return p, ctx
}

func TestMihomoLiveStoppedPublicationRetriesOriginalDirectoryACK(t *testing.T) {
	for cut := range 2 {
		t.Run(mihomoStoppedPlanNames[cut], func(t *testing.T) {
			p, ctx := mihomoStoppedPublicationModel(t)
			witness := errors.New("lost directory ACK after actual sync")
			calls := 0
			err := p.publishDurable(ctx, func(root *ownedfs.Root) error {
				if err := syncDataplaneJournalDirectory(root); err != nil {
					return err
				}
				i := calls
				calls++
				if i == cut {
					return witness
				}
				return nil
			})
			if !errors.Is(err, witness) || p.files[cut].file == nil || p.files[cut].ack || p.failure != nil {
				t.Fatal("lost original pending ACK custody", err)
			}
			held, err := p.files[cut].file.Stat()
			if err != nil {
				t.Fatal(err)
			}
			if err := p.close(); err == nil {
				t.Fatal("unacknowledged publication closed")
			}
			if err := p.publish(ctx); err != nil {
				t.Fatal("same writer retry", err)
			}
			for i, f := range p.files {
				data, err := os.ReadFile(filepath.Join(p.path, mihomoStoppedPlanNames[i]))
				if err != nil || !f.ack || !bytes.Equal(data, p.data) {
					t.Fatal("publication incomplete", err)
				}
			}
			after, err := p.files[cut].file.Stat()
			if err != nil || !os.SameFile(held, after) {
				t.Fatal("retry reopened or replaced original writer", err)
			}
		})
	}
}

func TestMihomoLiveStoppedPublicationRejectsChangedOriginalFiles(t *testing.T) {
	for _, mode := range []string{"same-bytes-new-inode", "in-place-data", "changed-time", "replaced-root"} {
		t.Run(mode, func(t *testing.T) {
			p, ctx := mihomoStoppedPublicationModel(t)
			if err := p.publish(ctx); err != nil {
				t.Fatal(err)
			}
			name := mihomoStoppedPlanNames[0]
			path := filepath.Join(p.path, name)
			switch mode {
			case "same-bytes-new-inode":
				if err := p.root.WriteAtomic(name, p.data, 0600); err != nil {
					t.Fatal(err)
				}
			case "in-place-data":
				if err := os.WriteFile(path, bytes.Repeat([]byte("x"), len(p.data)), 0600); err != nil {
					t.Fatal(err)
				}
			case "changed-time":
				stamp := p.files[0].info.ModTime().Add(-time.Hour)
				if err := os.Chtimes(path, stamp, stamp); err != nil {
					t.Fatal(err)
				}
			case "replaced-root":
				if runtime.GOOS == "windows" {
					t.Skip("Windows prevents renaming the open directory; Linux native CI exercises this cut")
				}
				if err := os.Rename(p.path, p.path+"-original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(p.path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := p.current(ctx); err == nil || p.failure == nil {
				t.Fatal("changed publication accepted", err)
			}
			if err := p.publish(ctx); err == nil {
				t.Fatal("failed original writer reopened named input")
			}
		})
	}
}
