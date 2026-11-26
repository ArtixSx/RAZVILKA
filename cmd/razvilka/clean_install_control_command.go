package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

const cleanInstallControlCommand = "install-control-initialize"

// Cold flash creation includes durable directory/ledger sync and repeated
// installed-image checks. Keep a finite budget without relaxing those checks.
const cleanInstallControlTimeout = 2 * time.Minute

func cleanInstallControlFailureCategory(err, contextErr error) string {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(contextErr, context.DeadlineExceeded) {
		return "CLEAN_INSTALL_CONTROL_DEADLINE"
	}
	return "CLEAN_INSTALL_CONTROL_REFUSED"
}

func cleanInstallConfigUnapplied(raw []byte) bool {
	cfg, _, err := config.InspectBytes(raw)
	return err == nil && !cfg.ServiceControl.Stopped && len(cfg.Services) == 0 && len(cfg.AppliedServices) == 0 &&
		cfg.NetworkPolicy == nil && cfg.DefaultRouteConsent == nil && cfg.AppliedNetworkPolicy == nil
}

// The explicit installer entry precedes ordinary Main. A digest compares the
// installed image with the verified package; it grants nothing without actual
// native root-user/fixed-installation/image/config observations.
func runCleanInstallControlCommand(args []string, roots selfUpdateJournalRoots) (bool, int) {
	if len(args) == 0 || args[0] != cleanInstallControlCommand {
		return false, 0
	}
	if len(args) != 2 {
		return true, 2
	}
	decoded, err := hex.DecodeString(args[1])
	if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != args[1] {
		return true, 2
	}
	if roots != productionSelfUpdateJournalRoots() {
		return true, 3
	}
	parent, cancel := context.WithTimeout(context.Background(), cleanInstallControlTimeout)
	defer cancel()
	var gate operationgate.Gate
	ctx, release, err := gate.ExclusiveContext(parent)
	if err != nil {
		return true, 3
	}
	defer release()
	if err := initializeNativeCleanInstallControl(ctx, &gate, args[1]); err != nil {
		// Native ownership checks may deliberately mask their underlying error.
		// The original deadline still identifies an expired command, while no
		// filesystem path, config data or arbitrary error text is published.
		fmt.Fprintln(os.Stderr, cleanInstallControlFailureCategory(err, parent.Err()))
		return true, 3
	}
	if _, err := fmt.Fprintln(os.Stdout, "CLEAN_INSTALL_CONTROL_READY"); err != nil {
		return true, 3
	}
	return true, 0
}

// Only the existing ledger's no-repair contract lives here. The production
// caller separately retains actual installed-image/config owners. This helper
// cannot grant that native admission from a pathname, digest or callback.
func initializeCleanInstallControlLedger(ctx context.Context, gate *operationgate.Gate, path string) error {
	if gate == nil || ctx == nil {
		return operationgate.ErrSelfUpdateStopJournal
	}
	return gate.WithExclusiveContext(ctx, func() error {
		r, present, err := operationgate.ReadSelfUpdateStop(ctx, path)
		if err != nil {
			return err
		}
		if present {
			if r.Stopped {
				return operationgate.ErrSelfUpdateStopped
			}
			return ctx.Err() // Same ready epoch; no Initialize/repair/republication.
		}
		if _, err := operationgate.InitializeSelfUpdateControl(ctx, path); err != nil {
			return err
		}
		r, present, err = operationgate.ReadSelfUpdateStop(ctx, path)
		if err != nil {
			return err
		}
		if !present || r.Stopped || r.State != "ready" {
			return operationgate.ErrSelfUpdateStopJournal
		}
		return ctx.Err()
	})
}
