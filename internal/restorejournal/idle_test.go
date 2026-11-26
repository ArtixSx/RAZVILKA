package restorejournal

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type idleNoTargetAccess struct{ t *testing.T }

func (s idleNoTargetAccess) Read(context.Context) (Image, error) {
	s.t.Error("idle-only admission read a restore target")
	return Image{}, ErrUnavailable
}

func (s idleNoTargetAccess) CompareAndSwap(context.Context, Image, Image) error {
	s.t.Error("idle-only admission wrote a restore target")
	return ErrUnavailable
}

func TestRequireIdlePreservesEveryPendingJournalWithoutTargetAccess(t *testing.T) {
	for _, state := range []string{"missing", "idle", "prepared", "committed", "malformed"} {
		t.Run(state, func(t *testing.T) {
			j, path, _, _ := fixture(t)
			switch state {
			case "idle":
				if err := j.save(j.idle()); err != nil {
					t.Fatal(err)
				}
			case "prepared", "committed":
				doc := prepared(t, j)
				doc.State = state
				if err := j.save(doc); err != nil {
					t.Fatal(err)
				}
			case "malformed":
				if err := os.WriteFile(filepath.Join(path, journalFile), []byte(`{"state":"prepared","unknown":true}`), 0600); err != nil {
					t.Fatal(err)
				}
			}
			for id := range j.targets {
				j.targets[id] = idleNoTargetAccess{t}
			}
			before, beforeErr := os.ReadFile(filepath.Join(path, journalFile))
			err := j.RequireIdle(context.Background())
			if (err == nil) != (state == "missing" || state == "idle") {
				t.Fatal("incorrect idle-only admission", state, err)
			}
			after, afterErr := os.ReadFile(filepath.Join(path, journalFile))
			if !bytes.Equal(before, after) || errors.Is(beforeErr, os.ErrNotExist) != errors.Is(afterErr, os.ErrNotExist) {
				t.Fatal("idle-only observation rewrote its journal")
			}
		})
	}
}

func TestRequireIdleRefusesCancelledClosedOrBusy(t *testing.T) {
	j, _, _, _ := fixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(j.RequireIdle(ctx), ErrAborted) || !errors.Is(j.RequireIdle(nil), ErrAborted) {
		t.Fatal("cancelled or missing context admitted")
	}
	j.mu.Lock()
	err := j.RequireIdle(context.Background())
	j.mu.Unlock()
	if !errors.Is(err, ErrBusy) {
		t.Fatal("busy journal admitted", err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(j.RequireIdle(context.Background()), ErrUnavailable) || !errors.Is((*Journal)(nil).RequireIdle(context.Background()), ErrUnavailable) || !errors.Is((&Journal{}).RequireIdle(context.Background()), ErrUnavailable) {
		t.Fatal("closed or missing journal admitted")
	}
}
