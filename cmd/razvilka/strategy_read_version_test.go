package main

import (
	"os"
	"strings"
	"testing"
)

func TestStrategyPairCapabilitiesDoNotOpenStores(t *testing.T) {
	for _, tc := range []struct{ flag, want string }{
		{"strategy-lab-read-version", "7"},
		{"self-update-private-snapshot-read-version", "3"},
	} {
		t.Run(tc.flag, func(t *testing.T) {
			root := t.TempDir()
			output, err := runPrivateRecoveryChild(t, root, tc.flag)
			if err != nil || strings.TrimSpace(strings.TrimSuffix(output, "PASS"+"\n")) != tc.want {
				t.Fatalf("capability: %v %q", err, output)
			}
			entries, err := os.ReadDir(root)
			if err != nil || len(entries) != 0 {
				t.Fatal("capability opened stores", err, entries)
			}
		})
	}
}
