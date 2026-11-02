//go:build linux

package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// COMMON retirement is a model. The publication descriptors, component source,
// control epoch and cleanup operations below are genuine native owners. This
// fixture supplies no live child, kernel route or successful service evidence.
func mihomoClosingNativeModel(t *testing.T) (*mihomoLiveClosing, *operationgate.Gate, context.Context, func()) {
	t.Helper()
	archive := os.Getenv("RAZVILKA_MIHOMO_ARCHIVE")
	if archive == "" {
		t.Skip("official pinned native component required")
	}
	data, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)
	base := t.TempDir()
	controlRoot := filepath.Join(base, "control")
	if _, err := operationgate.InitializeSelfUpdateControl(ctx, controlRoot); err != nil {
		t.Fatal(err)
	}
	gate := &operationgate.Gate{}
	held, release, err := gate.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)
	control, err := gate.ReviewControlEpoch(held, controlRoot)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close() })
	cm := components.New()
	cm.BinDir, cm.StateDir, cm.Arch = filepath.Join(base, "bin"), filepath.Join(base, "components"), "amd64"
	cm.Client = &http.Client{Transport: mihomoNativeArchiveTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.33/mihomo-linux-amd64-v1.19.33.gz" {
			return nil, errors.New("unexpected image source")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(data)), Header: make(http.Header)}, nil
	})}
	guard := func(c context.Context, effect func() error) error {
		if err := control.Current(c); err != nil {
			return err
		}
		return errors.Join(effect(), control.Current(c))
	}
	if result, err := cm.ApplyMihomoGuarded(held, guard, control.WithRename, control.WithStart); err != nil || !result.OK {
		t.Fatal(result, err)
	}
	source, err := cm.OpenMihomoLiveSource(held)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = source.Close() })
	m, _, r, _ := mihomoLiveRecordModel(t)
	r.source, r.control = source, control
	if err := m.retainOriginalMihomo(r.scope, true); err != nil {
		t.Fatal(err)
	}
	s := r.scope
	s.execution.State = "rolled-back"
	s.execution.Resources[0].State, s.execution.Resources[0].Phase = "removed", "removed"
	raw, err := json.Marshal(s.execution)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.publishRecords(raw); err != nil {
		t.Fatal(err)
	}
	c, err := r.newClosing(nil, true)
	if err != nil {
		t.Fatal(err)
	}
	return c, gate, held, release
}

func TestMihomoLiveClosingNativeCursorRetainsOriginalCustody(t *testing.T) {
	for _, cut := range []int{0, 3, 5} {
		t.Run(string(rune('0'+cut)), func(t *testing.T) {
			c, gate, held, release := mihomoClosingNativeModel(t)
			cleanup, err := gate.ReviewExclusiveCleanup(held)
			if err != nil {
				t.Fatal(err)
			}
			witness := errors.New("pre-close interrupted")
			once := false
			c.beforeClose = func(index int) error {
				if index == cut && !once {
					once = true
					return witness
				}
				return nil
			}
			if err := c.finish(held, cleanup); !errors.Is(err, witness) {
				t.Fatal("missing exact pre-close cut", err)
			}
			if c.index != cut || c.failure != nil || !c.owner.closed || !c.owner.scope.manager.HasPendingMihomoLive() {
				t.Fatal("lost pending original cursor")
			}
			release()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			foreign := &operationgate.Gate{}
			fctx, frelease, err := foreign.ExclusiveContext(ctx)
			if err != nil {
				t.Fatal(err)
			}
			fc, err := foreign.ReviewExclusiveCleanup(fctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.finish(fctx, fc); err == nil || c.index != cut {
				t.Fatal("foreign cleanup resumed cursor", err)
			}
			frelease()
			next, nrelease, err := gate.ExclusiveContext(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer nrelease()
			nc, err := gate.ReviewExclusiveCleanup(next)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.finish(next, nc); err != nil {
				t.Fatal("original cleanup retry", err)
			}
			if !c.finished || c.owner.scope.manager.HasPendingMihomoLive() || c.owner.scope.manager.originalMihomoLive() != nil || c.owner.scope.open {
				t.Fatal("final custody release incomplete")
			}
		})
	}
}

func TestMihomoLiveClosingNativeActualCloseFailureKeepsFence(t *testing.T) {
	c, gate, held, _ := mihomoClosingNativeModel(t)
	cleanup, err := gate.ReviewExclusiveCleanup(held)
	if err != nil {
		t.Fatal(err)
	}
	// A real descriptor-close failure, not a callback reporting a fake close.
	if err := c.owner.records.files[0].Close(); err != nil {
		t.Fatal(err)
	}
	err = c.finish(held, cleanup)
	if err == nil || c.failure == nil || !c.owner.scope.manager.HasPendingMihomoLive() {
		t.Fatal("unknown close released custody", err)
	}
	index := c.index
	if next := c.finish(held, cleanup); next != c.failure || c.index != index || c.finished || c.owner.scope.manager.originalMihomoLive() != c.owner {
		t.Fatal("ambiguous close retried or dropped original owner", next)
	}
}
