package updatecheck

import (
	"context"
	"errors"
	"os/exec"
)

const installerHelperEffect = "installer-helper"

// Read the already sealed immutable review outside the control admission.
// CORE must not reenter Updater methods from the callback: Apply owns u.mu.
func (u *Updater) installerHelperAdmission(ctx context.Context, id string) (func(func() error) error, error) {
	if u.FileEffectAdmission == nil || u.helperOwned == nil || u.eligibility == nil {
		return nil, ErrFileProtocol
	}
	a := &SelfUpdateFileAdapter{directory: u.Directory, owned: u.helperOwned, layout: u.eligibility}
	record, review, err := a.loadHeader(ctx, id)
	if err != nil {
		return nil, err
	}
	if record.FileReviewSHA256 != u.record.FileReviewSHA256 || record.Job.State != "ready" || record.ParentPID != u.record.ParentPID || record.Job.ConfigRevision != u.record.Job.ConfigRevision {
		return nil, ErrReviewChanged
	}
	admission := u.FileEffectAdmission
	return func(begin func() error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return admission(ctx, id, review.AuthorityInstallationID, review.AuthoritySequence, "start/live", installerHelperEffect, begin)
	}, nil
}

// The sole direct-child Wait runs only after admission releases the control
// lock. A callback error after actual Start is a handoff, never not-started.
func startInstallerHelperCommand(ctx context.Context, cmd *exec.Cmd, admission func(func() error) error) (int, <-chan error, error) {
	if admission == nil || cmd == nil {
		return 0, nil, ErrFileProtocol
	}
	if err := ctx.Err(); err != nil {
		return 0, nil, err
	}
	err := admission(func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return cmd.Start()
	})
	if cmd.Process == nil {
		if err == nil {
			err = ErrFileProtocol // an admission which did not execute begin
		}
		return 0, nil, err
	}
	pid := cmd.Process.Pid
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	if err != nil || ctx.Err() != nil {
		return pid, done, errors.Join(ErrHandoffUncertain, err, ctx.Err())
	}
	return pid, done, nil
}
