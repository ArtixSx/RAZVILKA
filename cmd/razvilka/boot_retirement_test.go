package main

import (
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func TestBootRetirementFlagsRegisterOnFreshCommandLine(t *testing.T) {
	oldPlan, oldDigest := *retireRollbackBootPlan, *retireRollbackBootDigest
	defer func() { *retireRollbackBootPlan, *retireRollbackBootDigest = oldPlan, oldDigest }()
	flags := flag.NewFlagSet("boot-retirement-fixture", flag.ContinueOnError)
	registerBootRetirementFlags(flags)
	if err := flags.Parse([]string{"-retire-rollback-after-boot-plan", "dp-1111111111111111", "-retire-rollback-after-boot-digest", "digest"}); err != nil {
		t.Fatal(err)
	}
	if *retireRollbackBootPlan != "dp-1111111111111111" || *retireRollbackBootDigest != "digest" || !bootRetirementCLIRequested() {
		t.Fatal("fresh flag set lost explicit recovery request")
	}
}

func TestBootRetirementCLIDiagnosticsKeepPrivatePathsOutAndPreserveFenceIdentity(t *testing.T) {
	oldPlan, oldDigest := *retireRollbackBootPlan, *retireRollbackBootDigest
	defer func() { *retireRollbackBootPlan, *retireRollbackBootDigest = oldPlan, oldDigest }()
	*retireRollbackBootPlan, *retireRollbackBootDigest = "", ""
	_, err := runBootRetirementCLI(context.Background(), nil, "", nil)
	if !errors.Is(err, dataplane.ErrBootRetirement) || !strings.Contains(err.Error(), "stage=cli-flags") {
		t.Fatal("CLI flag refusal lost stage/fence", err)
	}
	*retireRollbackBootPlan = "dp-1111111111111111"
	*retireRollbackBootDigest = strings.Repeat("a", 64)
	path := filepath.Join(t.TempDir(), "private-token-config")
	_, err = runBootRetirementCLI(context.Background(), nil, path, nil)
	if !errors.Is(err, dataplane.ErrBootRetirement) || !strings.Contains(err.Error(), "stage=cli-settings-read") || strings.Contains(err.Error(), "private-token") {
		t.Fatal("CLI read diagnostic unsafe", err)
	}
	if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err = runBootRetirementCLI(context.Background(), nil, path, nil)
	if !errors.Is(err, dataplane.ErrBootRetirement) || dataplane.BootRetirementStage(err) != "inputs" {
		t.Fatal("CLI lost dataplane diagnostic", err)
	}
}

func TestBootRetirementCLIRequiresExplicitPairedFlags(t *testing.T) {
	oldPlan, oldDigest := *retireRollbackBootPlan, *retireRollbackBootDigest
	defer func() { *retireRollbackBootPlan, *retireRollbackBootDigest = oldPlan, oldDigest }()
	for _, tc := range []struct {
		plan, digest       string
		requested, invalid bool
	}{
		{"", "", false, false},
		{"dp-1111111111111111", "", true, true},
		{"", "digest", true, true},
		{"dp-1111111111111111", "digest", true, false}, // Dataplane validates format and reviewed identity.
	} {
		*retireRollbackBootPlan, *retireRollbackBootDigest = tc.plan, tc.digest
		if bootRetirementCLIRequested() != tc.requested || (bootRetirementCLIFlagError() != nil) != tc.invalid {
			t.Fatal("unexpected offline CLI admission", tc.requested, tc.invalid)
		}
	}
}
