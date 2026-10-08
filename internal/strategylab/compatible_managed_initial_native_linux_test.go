//go:build linux

package strategylab

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// Actual protected source/control/rename tests only. No Components install,
// NFQWS/Lua execution, kernel or global inactivity permission is issued.
func TestNativeManagedCompatibilityInitialSource(t *testing.T) {
	for _, outcome := range []string{"initial", "existing", "foreign", "foreign-prepared", "stop-prepared", "cancel-prepared", "stop-written"} {
		t.Run(outcome, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			m, err := New(filepath.Join(root, "strategy-lab.json"))
			if err != nil {
				t.Fatal(err)
			}
			m.Executor, m.Validator = nil, CompatibleValidator{}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			gate := &operationgate.Gate{}
			original, release, err := gate.ExclusiveContext(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			controlPath := filepath.Join(root, "control")
			if _, err := operationgate.InitializeSelfUpdateControl(ctx, controlPath); err != nil {
				t.Fatal(err)
			}
			control, err := gate.ReviewControlEpoch(original, controlPath)
			if err != nil {
				t.Fatal(err)
			}
			defer control.Close()
			_ = m.Snapshot()
			if _, err := os.Stat(m.Path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("readonly source observation initialized a file", err)
			}
			var before []byte
			var info os.FileInfo
			if outcome == "existing" {
				if _, err := m.AddCandidate("tcp-tls", "real saved draft", "--filter-tcp=443 --lua-desync=fake:blob=0x00000000", "expert"); err != nil {
					t.Fatal(err)
				}
				before, err = os.ReadFile(m.Path)
				info, _ = os.Stat(m.Path)
				if err != nil {
					t.Fatal(err)
				}
			}
			foreign := []byte("unknown independently owned source\n")
			if outcome == "foreign" {
				if err := os.WriteFile(m.Path, foreign, 0600); err != nil {
					t.Fatal(err)
				}
			}
			m.compatibilityPublicationHook = func(point string) {
				if outcome == "foreign-prepared" && point == "initial-source-prepared" {
					if err := os.WriteFile(m.Path, foreign, 0600); err != nil {
						t.Fatal(err)
					}
				}
				if outcome == "cancel-prepared" && point == "initial-source-prepared" {
					cancel()
				}
				if outcome == "stop-prepared" && point == "initial-source-prepared" || outcome == "stop-written" && point == "initial-source-written" {
					if _, err := operationgate.RequestSelfUpdateStop(ctx, controlPath, "11111111111111111111111111111111", 1); err != nil {
						t.Fatal(err)
					}
				}
			}
			err = m.InitializeManagedCompatibilitySource(original, control)
			data, readErr := os.ReadFile(m.Path)
			switch outcome {
			case "foreign", "foreign-prepared":
				if !errors.Is(err, restorejournal.ErrConflict) || readErr != nil || !bytes.Equal(data, foreign) || m.image.Exists {
					t.Fatal("initializer adopted or overwrote a foreign source", err, readErr)
				}
			case "stop-prepared", "cancel-prepared":
				if !errors.Is(err, restorejournal.ErrAborted) || !errors.Is(readErr, os.ErrNotExist) || m.image.Exists || m.compatibilityUnknown || m.writeBlocked {
					t.Fatal("known no-rename refusal became source/process unknown", err, readErr)
				}
			case "existing":
				after, statErr := os.Stat(m.Path)
				if err != nil || readErr != nil || statErr != nil || !bytes.Equal(before, data) || !os.SameFile(info, after) {
					t.Fatal("initializer replaced an existing saved source", err, readErr, statErr)
				}
			default:
				if outcome == "initial" && err != nil || outcome == "stop-written" && !errors.Is(err, operationgate.ErrSelfUpdateStopped) || readErr != nil {
					t.Fatal("wrong initial publication outcome", err, readErr)
				}
				var state State
				if json.Unmarshal(data, &state) != nil || !compatibilityJSONEqual(state, emptyState()) || !m.image.Exists || m.compatibilityUnknown || m.writeBlocked {
					t.Fatal("initializer fabricated history or lost its known empty image")
				}
				if outcome == "initial" {
					review, err := m.ReviewManagedCompatibilityInactive(original, control)
					if err != nil {
						t.Fatal("separate original reader could not observe the real written source", err)
					}
					if err := review.Current(original); err != nil {
						t.Fatal(err)
					}
					_ = review.Close()
				}
			}
			if gate.Snapshot().Active != 1 {
				t.Fatal("source writer implicitly released the original operation")
			}
		})
	}
}
