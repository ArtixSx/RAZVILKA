//go:build !linux

package updatecheck

import (
	"context"
	"os/exec"
)

func runReviewedScriptSyntax(context.Context, string, string, func(context.Context, string, func() error) error, func() error, func() error, func() error) error {
	return errOrdinaryPreparation
}

func newReviewedScriptCommand(context.Context, string, []string) (*exec.Cmd, func() error, func(), error) {
	return nil, nil, nil, errOrdinaryPreparation
}
