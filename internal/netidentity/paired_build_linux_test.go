//go:build linux && (amd64 || arm64)

package netidentity

import (
	"errors"
	"os"
	"testing"
)

// Real held files and production per-command checks; filesystem immutability
// alone is modeled. No stock NDMC/kernel acceptance is claimed by this test.
func TestPairedBuildSessionChecksEveryCommandAndCloses(t *testing.T) {
	for _, kind := range []string{"immutable", "writable", "command-error", "mutation-between-commands", "filesystem-drift"} {
		t.Run(kind, func(t *testing.T) {
			immutable := kind == "immutable" || kind == "filesystem-drift"
			s, image, fs := immutableImageModel(t, immutable)
			before, err := nativeImageReadChars()
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			first, second, err := readHeldBuildCommands(t.Context(), s, true, func() (buildTuple, error) {
				calls++
				if kind == "command-error" {
					return buildTuple{}, errors.New("modeled command refusal")
				}
				if calls == 1 && kind == "mutation-between-commands" {
					if _, err := image.file.WriteAt([]byte("changed"), 0); err != nil {
						t.Fatal(err)
					}
					// Make metadata look unchanged to require actual byte rereads.
					current, err := image.file.Stat()
					if err != nil {
						t.Fatal(err)
					}
					image.info, image.nodes[0].info = current, current
				}
				if calls == 1 && kind == "filesystem-drift" {
					fs.Blocks++
				}
				return nc1812Profile().Build, nil
			})
			after, readErr := nativeImageReadChars()
			if readErr != nil {
				t.Fatal(readErr)
			}
			if _, statErr := image.file.Stat(); !errors.Is(statErr, os.ErrClosed) {
				t.Fatalf("session descriptor retained: %v", statErr)
			}
			if kind == "immutable" || kind == "writable" {
				if err != nil || calls != 2 || first != nc1812Profile().Build || second != first {
					t.Fatalf("paired commands refused: calls=%d err=%v", calls, err)
				}
				if immutable && after-before > 64<<10 {
					t.Fatal("immutable session reread content", after-before)
				}
				if !immutable && after-before < uint64(4*image.info.Size()) {
					t.Fatal("writable commands omitted before/after full hashes", after-before)
				}
			} else if err == nil || calls != 1 {
				t.Fatalf("refusal reached second command: calls=%d err=%v", calls, err)
			}
		})
	}
}
