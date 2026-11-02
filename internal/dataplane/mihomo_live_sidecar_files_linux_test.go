//go:build linux

package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// Filesystem model only: an incomplete resource deliberately cannot pass the
// real COMMON admission. No fake callback makes it ready or starts a process.
func TestMihomoLiveSidecarStagingKeepsOriginalFDThroughRefusal(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(map[bool]string{false: "known-staging", true: "same-bytes-foreign-inode"}[replace], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			base := t.TempDir()
			private := filepath.Join(base, "private")
			if err := os.Mkdir(private, 0700); err != nil {
				t.Fatal(err)
			}
			root, err := ownedfs.Open(private)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			controlPath := filepath.Join(base, "control")
			if _, err := operationgate.InitializeSelfUpdateControl(ctx, controlPath); err != nil {
				t.Fatal(err)
			}
			gate := &operationgate.Gate{}
			held, release, err := gate.ExclusiveContext(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			control, err := gate.ReviewControlEpoch(held, controlPath)
			if err != nil {
				t.Fatal(err)
			}
			defer control.Close()
			resource := &mihomoLiveResource{control: control}
			resource.self = resource
			n := &mihomoLiveSidecar{root: root, owner: resource}
			n.self = n
			data := []byte("bounded original receipt model")
			if err := n.publishIdentity(held, 0, "sidecar.pid", data); !errors.Is(err, errMihomoLiveMaterial) {
				t.Fatal("incomplete owner passed original COMMON admission", err)
			}
			d := n.identities[0]
			if d == nil || d.file == nil || d.published || n.identityFileCurrent(d, d.temporary) != nil {
				t.Fatal("refused staging lost actual authored descriptor")
			}
			defer func() {
				if d.file != nil {
					_ = d.file.Close()
				}
			}()
			remove := func(effect func() error) error { return control.WithRemove(held, effect) }
			if replace {
				if err := root.Rename(d.temporary, "original-history"); err != nil {
					t.Fatal(err)
				}
				if err := root.WriteAtomic(d.temporary, data, 0600); err != nil {
					t.Fatal(err)
				}
				if err := n.removeIdentity(held, 0, remove); err == nil {
					t.Fatal("same bytes minted original writer ownership")
				}
				if _, err := root.Stat(d.temporary); err != nil {
					t.Fatal("foreign replacement deleted", err)
				}
				if err := root.Remove(d.temporary); err != nil {
					t.Fatal(err)
				}
				if err := root.Rename("original-history", d.temporary); err != nil {
					t.Fatal(err)
				}
			}
			if err := n.removeIdentity(held, 0, remove); err != nil {
				t.Fatal("actual original staging could not retire", err)
			}
			if _, err := root.Stat(d.temporary); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("original staged file remains", err)
			}
		})
	}
}
