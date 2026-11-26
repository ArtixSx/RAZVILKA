//go:build linux

package updatecheck

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

func TestNativeNodeHistoryActualControllerCopyAndCandidateCapabilities(t *testing.T) {
	for _, test := range []struct {
		name, response string
		wanted         int
	}{
		{"legacy1", "printf '1\\n'", 1}, {"raw2", "printf '2\\n'", 2}, {"xhttp3", "printf '3\\n'", 3},
		{"future4", "printf '4\\n'", 0}, {"unknown", "printf 'unknown\\n'", 0},
		{"noncanonical", "printf '03\\n'", 0}, {"trailing-data", "printf '3\\nextra'", 0},
		{"stderr", "printf '3\\n'; printf 'uncertain\\n' >&2", 0},
		{"panic2", "printf 'panic\\n' >&2; exit 2", 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			parent := t.TempDir()
			program := []byte(fmt.Sprintf("#!/bin/sh\ncase \"$1\" in\n-node-history-read-version) %s;;\n-self-update-schema|-component-update-schema) printf '2\\n';;\n-native-enrollment-schema|-subscription-schema) printf '1\\n';;\n*) exit 93;;\nesac\n", test.response))
			path := filepath.Join(parent, "retained-controller")
			if err := os.WriteFile(path, program, 0600); err != nil {
				t.Fatal(err)
			}
			image := selfupdatejournal.BinaryImage{Path: path, SHA256: digestBytes(program)}
			version, err := probeNodeHistoryBinary(ctx, image)
			if version != test.wanted || (test.wanted != 0) != (err == nil) {
				t.Fatal("actual immutable copy probe", version, err)
			}
			before, err := os.ReadFile(path)
			info, statErr := os.Stat(path)
			if err != nil || statErr != nil || !bytes.Equal(before, program) || info.Mode().Perm() != 0600 {
				t.Fatal("retained image mutated or chmodded in place")
			}
			if _, err := probeNodeHistoryBinary(ctx, selfupdatejournal.BinaryImage{Path: path, SHA256: digestBytes([]byte("third image"))}); err == nil {
				t.Fatal("unsealed digest admitted")
			}
			candidate := filepath.Join(parent, "candidate-controller")
			if err := os.WriteFile(candidate, program, 0700); err != nil {
				t.Fatal(err)
			}
			for _, required := range []int{1, 2, 3} {
				allowed := test.wanted >= max(2, required)
				err := checkFileCapabilitiesForNodeHistory(ctx, candidate, required, probeFileCapability)
				if allowed != (err == nil) {
					t.Fatal("actual candidate flag admitted wrong retained requirement", required, err)
				}
			}
		})
	}
}
