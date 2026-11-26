//go:build !linux

package dataplane

import "context"

func observeCommittedUSQUEProcessAbsence(context.Context, ProcessSpec, int, committedUSQUESession) (deadCommittedUSQUEProcess, error) {
	return deadCommittedUSQUEProcess{}, ErrUSQUELocalProcessUnconfirmed
}

func (deadCommittedUSQUEProcess) current(context.Context, ProcessSpec, int, committedUSQUESession) error {
	return ErrUSQUELocalProcessUnconfirmed
}

func (deadCommittedUSQUEProcess) currentAfterJoin(context.Context, ProcessSpec, int, committedUSQUESession) error {
	return ErrUSQUELocalProcessUnconfirmed
}
