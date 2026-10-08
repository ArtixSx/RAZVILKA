//go:build linux

package updatecheck

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

func TestNativeJournalReaderLegacyABIAndStopAdmission(t *testing.T) {
	for _, test := range []struct {
		name, response, legacy string
		wanted, starts         int
	}{
		{"legacy2", "printf '%s\\n' 'flag provided but not defined: -self-update-read-version' >&2; exit 2", "printf '2\\n'", 2, 2},
		{"reader3", "printf '3\\n'", "exit 91", 3, 1},
		{"reader4", "printf '4\\n'", "exit 91", 4, 1},
		{"panic2", "printf 'panic: failed reader\\n' >&2; exit 2", "printf '2\\n'", 0, 1},
		{"future", fmt.Sprintf("printf '%d\\n'", SelfUpdateReadVersion+1), "printf '2\\n'", 0, 1},
		{"reader4-nonzero", "printf '4\\n'; exit 2", "printf '2\\n'", 0, 1},
		{"reader4-stderr", "printf '4\\n'; printf warning >&2", "printf '2\\n'", 0, 1},
		{"reader4-no-newline", "printf '4'", "printf '2\\n'", 0, 1},
		{"garbage", "printf 'unknown\\n'", "printf '2\\n'", 0, 1},
		{"false-legacy3", "printf '%s\\n' 'flag provided but not defined: -self-update-read-version' >&2; exit 2", "printf '3\\n'", 0, 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			work := t.TempDir()
			control := filepath.Join(work, "control")
			ready, err := operationgate.InitializeSelfUpdateControl(ctx, control)
			if err != nil {
				t.Fatal(err)
			}
			id := "0123456789abcdef0123456789abcdef"
			review := fileReview{ID: id, AuthorityInstallationID: ready.InstallationID, AuthoritySequence: ready.Sequence, Revision: 7}
			program := []byte(fmt.Sprintf("#!/bin/sh\ncase \"$1\" in\n-self-update-read-version) %s;;\n-self-update-schema) %s;;\n*) exit 92;;\nesac\n", test.response, test.legacy))
			path := filepath.Join(work, "fixture-controller")
			if err := os.WriteFile(path, program, 0600); err != nil {
				t.Fatal(err)
			}
			starts := 0
			a := &SelfUpdateFileAdapter{admission: func(ctx context.Context, id, installation string, sequence uint64, action, effect string, begin func() error) error {
				if action != "start/live" || effect != journalReaderProbeEffect {
					t.Fatal("wrong probe admission", action, effect)
				}
				return operationgate.WithSelfUpdateEffectAdmission(ctx, control, id, installation, sequence, effect, func() error { starts++; return begin() })
			}}
			image := selfupdatejournal.BinaryImage{Path: path, SHA256: digestBytes(program)}
			version, err := a.probeJournalReader(ctx, review, image)
			if starts != test.starts || version != test.wanted || (test.wanted == 0) != (err != nil) {
				t.Fatal("unknown ABI downgraded or legacy2 blocked", version, starts, err)
			}
			if _, err := operationgate.RequestSelfUpdateStop(ctx, control, id, review.Revision); err != nil {
				t.Fatal(err)
			}
			if _, err := a.probeJournalReader(ctx, review, image); err == nil || starts != test.starts {
				t.Fatal("Stop launched a reader or its legacy fallback", starts, err)
			}
		})
	}
}
