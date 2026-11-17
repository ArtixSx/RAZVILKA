package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

func TestExternalBootstrapCommandRejectsUnknownInputBeforeProtectedRoots(t *testing.T) {
	if handled, _ := runExternalBootstrapCommand([]string{"status"}, selfUpdateJournalRoots{}); handled {
		t.Fatal("unrelated command intercepted")
	}
	valid := []string{"self-update-bootstrap-old193", strings.Repeat("a", 32), filepath.Join(t.TempDir(), "release.tar.gz"), strings.Repeat("b", 64)}
	for _, args := range [][]string{valid[:1], valid[:2], valid[:3], append(append([]string(nil), valid...), "extra"), {valid[0], strings.Repeat("A", 32), valid[2], valid[3]}, {valid[0], valid[1], "relative.tar.gz", valid[3]}, {valid[0], valid[1], valid[2], strings.Repeat("B", 64)}} {
		if handled, code := runExternalBootstrapCommand(args, selfUpdateJournalRoots{}); !handled || code != 2 {
			t.Fatal("malformed public command did not refuse", code)
		}
	}
	if handled, code := runExternalBootstrapCommand(valid, selfUpdateJournalRoots{}); !handled || code != 3 {
		t.Fatal("public command accepted fixture roots", code)
	}
}

func TestExternalBootstrapDiagnosticNeverPrintsUnknownData(t *testing.T) {
	for _, category := range []string{"candidate-version", "release-script-syntax", "review-capabilities", "staged-migration", "external-bootstrap-refused", "quiesce-deactivate", "quiesce-authority-closing"} {
		if got := externalBootstrapDiagnosticCategory([]byte(externalBootstrapFailureOutput(category) + "\n")); got != category {
			t.Fatal("fixed diagnostic lost its category", got)
		}
	}
	for _, diagnostic := range []string{"", "private-path/token/data", externalBootstrapFailureOutput("private-data") + "\n", externalBootstrapFailureOutput("filesystem") + "\nextra-private-data", "prefix\n" + externalBootstrapFailureOutput("filesystem") + "\n"} {
		if got := externalBootstrapDiagnosticCategory([]byte(diagnostic)); got != "unrecognized-or-absent-diagnostic" {
			t.Fatal("unknown diagnostic entered public output")
		}
	}
}

// A real joined quiesce child already emits these composed original-reader
// diagnostics. The public whole-line recognizer must use the producer's exact
// vocabulary instead of its non-exhaustive static enumeration.
func TestExternalBootstrapDiagnosticRecognizesOriginalObservationDetails(t *testing.T) {
	for _, dns := range []string{"proc-opening-proc.installer-role-open", "proc-closing-proc.installer-role-close", "proc-opening-proc.cmdline-read", "backend-inventory"} {
		stage := updatecheck.RuntimeQuiesceInactiveObservationFailureStage(updatecheck.QuiesceInactiveScopedDNS|updatecheck.QuiesceInactiveNFQKernel, dns, "facts-closing")
		for _, category := range []string{"quiesce-" + stage, "quiesce-" + updatecheck.RuntimeQuiesceSourceCleanupFailureStage(stage)} {
			diagnostic := externalBootstrapFailureOutput(category) + "\n"
			if got := externalBootstrapDiagnosticCategory([]byte(diagnostic)); got != category {
				t.Fatal("actual composed diagnostic lost", got, category)
			}
			for _, changed := range []string{"prefix\n" + diagnostic, diagnostic + "extra-private-data", strings.TrimSuffix(diagnostic, "\n"), strings.Replace(diagnostic, "facts-closing", "private-data", 1)} {
				if changed == diagnostic {
					continue
				}
				if got := externalBootstrapDiagnosticCategory([]byte(changed)); got != "unrecognized-or-absent-diagnostic" {
					t.Fatal("changed complete diagnostic accepted", got)
				}
			}
		}
	}
	for _, category := range []string{"quiesce-runtime-inactivity-scoped-dns-dns-observation-private/path", "quiesce-runtime-inactivity-scoped-dns-dns-observation-source-ordinary-observation-facts-closing", "quiesce-runtime-inactivity-scoped-dns-dns-observation-source-source-close-source-close"} {
		if got := externalBootstrapDiagnosticCategory([]byte(externalBootstrapFailureOutput(category) + "\n")); got != "unrecognized-or-absent-diagnostic" {
			t.Fatal("unrecognized composition accepted", got)
		}
	}
}
