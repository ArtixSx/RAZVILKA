package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"os"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

var retireRollbackBootPlan = new(string)
var retireRollbackBootDigest = new(string)

func registerBootRetirementFlags(flags *flag.FlagSet) {
	flags.StringVar(retireRollbackBootPlan, "retire-rollback-after-boot-plan", "", "explicitly archive intact old-boot proxy metadata after proving runtime absence, while the panel is stopped; never confirms rollback or service access")
	flags.StringVar(retireRollbackBootDigest, "retire-rollback-after-boot-digest", "", "reviewed digest required with retire-rollback-after-boot-plan")
}

func bootRetirementCLIRequested() bool {
	return *retireRollbackBootPlan != "" || *retireRollbackBootDigest != ""
}

func bootRetirementCLIFlagError() error {
	if (*retireRollbackBootPlan == "") != (*retireRollbackBootDigest == "") {
		return errors.New("post-reboot retirement requires both the reviewed plan and digest")
	}
	return nil
}

// Invoke only from the existing offline maintenance dispatch, while every
// private-recovery lifetime lease remains held and before starting workers/API.
func runBootRetirementCLI(ctx context.Context, manager *dataplane.Manager, cfgPath string, store *config.Store) (dataplane.Execution, error) {
	if !bootRetirementCLIRequested() || bootRetirementCLIFlagError() != nil {
		return dataplane.Execution{}, dataplane.ErrBootRetirement
	}
	baseline, err := os.ReadFile(cfgPath)
	if err != nil {
		return dataplane.Execution{}, errors.New("post-reboot retirement settings unavailable")
	}
	guard, err := rollbackRecoveryGuard(cfgPath, store)
	if err != nil {
		return dataplane.Execution{}, errors.New("post-reboot retirement settings unavailable")
	}
	current, err := os.ReadFile(cfgPath)
	if err != nil || !bytes.Equal(current, baseline) {
		return dataplane.Execution{}, errors.New("post-reboot retirement settings changed")
	}
	return manager.RetireFailedRollbackAfterBoot(ctx, *retireRollbackBootPlan, *retireRollbackBootDigest, routeidentity.Hash(baseline), guard)
}
