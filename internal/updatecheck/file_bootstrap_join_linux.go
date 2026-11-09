//go:build linux

package updatecheck

import (
	"context"
	"errors"
	"os"
	"strconv"
)

func originalBootstrapInstallerControllerAdapter(ctx context.Context, id string) (*SelfUpdateFileAdapter, error) {
	c, ok := ctx.Value(bootstrapQuiesceJoinKey{}).(*bootstrapQuiesceJoin)
	// The existing closed production-root/custom-hook predicate grants no role.
	if !ok || c == nil || c.command.ID != id || !productionOrdinaryRoleAdapter(c.adapter) {
		return nil, ErrInstallerControllerRole
	}
	if original, err := bootstrapQuiesceJoinFor(ctx, c.adapter, c.command, os.Getpid()); err != nil || original != c {
		return nil, errors.Join(ErrInstallerControllerRole, err)
	}
	return c.adapter, nil
}

func bootstrapJoinedChildAbsent(ctx context.Context, command fileCommandReceipt) error {
	if ctx.Err() != nil {
		return errors.Join(ErrInstallerControllerRole, ctx.Err())
	}
	_, err := os.Lstat("/proc/" + strconv.Itoa(command.DirectPID))
	if !errors.Is(err, os.ErrNotExist) {
		return errors.Join(ErrInstallerControllerRole, err)
	}
	return ctx.Err()
}
