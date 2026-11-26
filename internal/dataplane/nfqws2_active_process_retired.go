package dataplane

import (
	"context"
	"errors"
	"reflect"
)

// VerifyRetiredObservation authenticates the original final handle only after
// its actual successful process/COMMON/file/queue retirement. It reads the
// original sole Wait result, never the correctly deleted ownership.json.
// This is a read-only completion proof, not cleanup or Start admission. Stop,
// Current and live cleanup proofs remain revoked after retirement.
func (h *NFQWSActiveHandle) VerifyRetiredObservation(ctx context.Context, supplied NFQWSActiveObservation) (err error) {
	defer nfqws2ActivePublicError("retired owner proof", &err)
	if h == nil || h.owner == nil || nfqws2ActiveOperation(ctx) != nil {
		return ErrNFQWSManagedProcessUnknown
	}
	o := h.owner
	check := func() error {
		nfqws2ActiveAdapterMu.Lock()
		defer nfqws2ActiveAdapterMu.Unlock()
		o.mu.Lock()
		defer o.mu.Unlock()
		if o.adapter == nil || o.adapter.StateRoot != o.command.StateRoot || o.adapter.activeProcess != nil || o.retiredActive != h || o.state != "retired" ||
			!o.retirementStarted || !o.finalACK || !o.detached || !o.stopRequested || !nfqws2ActiveDone(o.done) || o.result == nil || o.active != nil || o.prepared != nil || o.activation != nil ||
			ctx.Err() != nil {
			return ErrNFQWSManagedProcessUnknown
		}
		return nil
	}
	if err := check(); err != nil {
		return err
	}
	settled, err := o.result()
	if err != nil || !o.known(settled) || !nfqws2ActiveProcessSettled(settled) || settled.Transfer != "final" || settled.observation() != supplied {
		return errors.Join(ErrNFQWSManagedProcessUnknown, err)
	}
	if err := check(); err != nil {
		return err
	}
	closing, err := o.result()
	if err != nil || !reflect.DeepEqual(closing, settled) {
		return errors.Join(ErrNFQWSManagedProcessUnknown, err)
	}
	return check()
}
