package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSelfUpdateStoppedSettlementCLIRefusesMissingFixedProvider(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("actual fixed Linux provider belongs to Root native window; portable CLI tests use unsupported platform")
	}
	base := t.TempDir()
	other := filepath.Join(base, "public-override")
	for _, key := range []string{"RAZVILKA_SELF_UPDATE_INSTALLATION", "RAZVILKA_SELF_UPDATE_HELPER_STATE", "RAZVILKA_SELF_UPDATE_FILE_STATE", "RAZVILKA_SELF_UPDATE_CONTROL_STATE"} {
		t.Setenv(key, filepath.Join(other, key))
	}
	id := strings.Repeat("a", 32)
	for _, test := range []struct {
		args []string
		code int
	}{
		{[]string{"self-update-files", "settle-stopped-rollback", id, "7"}, 3},
		{[]string{"self-update-files", "settle-stopped-rollback", id, "07"}, 2},
		{[]string{"self-update-files", "settle-stopped-rollback", id, "0"}, 2},
		{[]string{"self-update-files", "settle-stopped-rollback", id, "18446744073709551616"}, 2},
		{[]string{"self-update-files", "settle-stopped-rollback", id, "7", "/caller/root"}, 2},
	} {
		out, diagnostic, code := selfUpdateReadCLI(t, filepath.Join(base, "fixed-empty-journals"), test.args...)
		if code != test.code || out != "" || strings.Contains(diagnostic, other) {
			t.Fatal("CLI invented fixed provider permission or accepted caller fields", test.args, out, diagnostic, code)
		}
	}
	entries, err := os.ReadDir(base)
	if err != nil || len(entries) != 0 {
		t.Fatal("refused fixed CLI bootstrapped or wrote public roots", entries, err)
	}
}
