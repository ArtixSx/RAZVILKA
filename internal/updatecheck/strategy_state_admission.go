package updatecheck

import (
	"context"
	"errors"
	"os"
	"path/filepath"
)

// StrategyLab contains compatibility ownership/finalizing fences and evidence
// generations. Until the update protocol seals a compatible binary/state pair,
// neither an upgrade nor rollback may replace its controller over this state.
// Refuse all existing objects, including malformed files and dangling symlinks;
// parsing just the schema would not establish a safe rollback pair.
var ErrStrategyStateAdmission = errors.New("strategy-state-pair-required")

func requireNoStrategyState(ctx context.Context, stateRoot string) error {
	return requireNoStrategyStatePath(ctx, filepath.Join(stateRoot, "strategy-lab.json"))
}

func requireNoStrategyStatePath(ctx context.Context, path string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	_, err := os.Lstat(path)
	if !errors.Is(err, os.ErrNotExist) {
		return ErrStrategyStateAdmission
	}
	return ctx.Err()
}

func (a *SelfUpdateFileAdapter) strategyStateAdmission(ctx context.Context) error {
	if a == nil || a.installation == "" {
		return ErrFileProtocol
	}
	return requireNoStrategyState(ctx, filepath.Join(a.installation, "razvilka", "state"))
}
