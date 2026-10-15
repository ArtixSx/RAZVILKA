package main

import (
	"flag"
	"testing"
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
