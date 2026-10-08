//go:build linux

package updatecheck

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

// These inert controller CLI fixtures prove the exact bounded format probe,
// not managed NFQWS execution, Lua compatibility or bundle/runtime authority.
func TestNativeComponentReaderProbeUsesOnlyItsOwnExactCapabilityFlag(t *testing.T) {
	for _, test := range []struct {
		name, output string
		version      int
	}{
		{"old-component2", "2\\n", 2}, {"component3", "3\\n", 3},
		{"future", "4\\n", 0}, {"missing-newline", "3", 0},
		{"node-version-is-not-component-version", "03\\n", 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "controller")
			data := []byte("#!/bin/sh\n[ \"$#\" -eq 1 ] && [ \"$1\" = \"-component-update-schema\" ] || exit 91\nprintf '" + test.output + "'\n")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			version, err := probeComponentHistoryBinary(ctx, selfupdatejournal.BinaryImage{Path: path, SHA256: digestBytes(data)})
			if test.version == 0 {
				if err == nil || version != 0 {
					t.Fatal("unknown component capability accepted", version, err)
				}
			} else if err != nil || version != test.version {
				t.Fatal("exact component flag lost its independent reader", version, err)
			}
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatal("probe chmodded immutable retained controller", err)
			}
			actual, err := os.ReadFile(path)
			if err != nil || string(actual) != string(data) {
				t.Fatal("probe rewrote retained controller", err)
			}
		})
	}
}
