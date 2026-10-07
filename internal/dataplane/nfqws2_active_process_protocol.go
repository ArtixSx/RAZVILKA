package dataplane

import (
	"context"
	"errors"

	"github.com/ArtixSx/razvilka/internal/components"
)

type nfqws2ActiveTransport interface {
	send(nfqws2ActiveFrame) error
	receive() (nfqws2ActiveFrame, error)
	close() error
}

func nfqws2ActiveProtocolCurrent(ctx context.Context, current func() error) error {
	if ctx == nil || current == nil {
		return ErrNFQWSManagedProcessUnknown
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := current(); err != nil {
		return err
	}
	return ctx.Err()
}
func nfqws2ActiveSend(t nfqws2ActiveTransport, base nfqws2ActiveFrame, kind string, child components.NFQWSRuntimeProcessIdentity) error {
	base.Kind, base.Child = kind, child
	return t.send(base)
}
func nfqws2ActiveReceive(t nfqws2ActiveTransport, command nfqws2ActiveProcessCommand, base nfqws2ActiveFrame, kind string, child components.NFQWSRuntimeProcessIdentity) error {
	frame, err := t.receive()
	if err != nil {
		return err
	}
	return nfqws2ActiveExpectedFrame(command, base, frame, kind, child)
}

func nfqws2ActiveStartParent(ctx context.Context, t nfqws2ActiveTransport, c nfqws2ActiveProcessCommand, base nfqws2ActiveFrame, current func() error) (components.NFQWSRuntimeProcessIdentity, error) {
	var zero components.NFQWSRuntimeProcessIdentity
	if t == nil || nfqws2ActiveProtocolCurrent(ctx, current) != nil {
		return zero, ErrNFQWSManagedProcessUnknown
	}
	if err := nfqws2ActiveReceive(t, c, base, "ready", zero); err != nil {
		return zero, nfqws2ActiveFailure("READY", err)
	}
	if err := nfqws2ActiveProtocolCurrent(ctx, current); err != nil {
		return zero, err
	}
	if err := nfqws2ActiveSend(t, base, "permit", zero); err != nil {
		return zero, nfqws2ActiveFailure("PERMIT", err)
	}
	frame, err := t.receive()
	if err != nil || nfqws2ActiveExpectedFrame(c, base, frame, "started", frame.Child) != nil || frame.Child == zero {
		return zero, nfqws2ActiveFailure("STARTED", err)
	}
	if err := nfqws2ActiveProtocolCurrent(ctx, current); err != nil {
		return zero, err
	}
	return frame.Child, nil
}

// WithTransfer holds the separate Manager close barrier around this entire
// call. Provisional publication is BOTH nonterminal records, never ACTIVE.
func nfqws2ActiveTransferParent(ctx context.Context, t nfqws2ActiveTransport, c nfqws2ActiveProcessCommand, base nfqws2ActiveFrame, child components.NFQWSRuntimeProcessIdentity, current func() error, publishACK func() error) error {
	if t == nil || publishACK == nil || !nfqws2ActiveFrameChild(c, base.Helper, child) {
		return ErrNFQWSManagedProcessUnknown
	}
	if err := nfqws2ActiveProtocolCurrent(ctx, current); err != nil {
		return err
	}
	if err := nfqws2ActiveSend(t, base, "transfer", child); err != nil {
		return nfqws2ActiveFailure("TRANSFER", err)
	}
	if err := nfqws2ActiveReceive(t, c, base, "transfer-ack", child); err != nil {
		return nfqws2ActiveFailure("TRANSFER ACK", err)
	}
	if err := nfqws2ActiveProtocolCurrent(ctx, current); err != nil {
		return err
	}
	if err := publishACK(); err != nil {
		return nfqws2ActiveFailure("provisional BOTH", err)
	}
	if err := nfqws2ActiveProtocolCurrent(ctx, current); err != nil {
		return err
	}
	if err := nfqws2ActiveSend(t, base, "finalize", child); err != nil {
		return nfqws2ActiveFailure("FINALIZE", err)
	}
	if err := nfqws2ActiveReceive(t, c, base, "active", child); err != nil {
		return nfqws2ActiveFailure("final ACTIVE ACK", err)
	}
	return ctx.Err()
}

type nfqws2ActiveHelperProtocol struct {
	transport nfqws2ActiveTransport
	command   nfqws2ActiveProcessCommand
	base      nfqws2ActiveFrame
	child     components.NFQWSRuntimeProcessIdentity
	phase     int
}

func (h *nfqws2ActiveHelperProtocol) ready() error {
	if h == nil || h.transport == nil || h.phase != 0 {
		return ErrNFQWSManagedProcessUnknown
	}
	h.phase = -1
	if err := nfqws2ActiveSend(h.transport, h.base, "ready", components.NFQWSRuntimeProcessIdentity{}); err != nil {
		return err
	}
	h.phase = 1
	return nil
}
func (h *nfqws2ActiveHelperProtocol) admit(ctx context.Context, current, begin func() error) error {
	if h == nil || h.phase != 1 || begin == nil {
		return ErrNFQWSManagedProcessUnknown
	}
	h.phase = -1
	if err := nfqws2ActiveReceive(h.transport, h.command, h.base, "permit", components.NFQWSRuntimeProcessIdentity{}); err != nil {
		return err
	}
	if err := nfqws2ActiveProtocolCurrent(ctx, current); err != nil {
		return err
	}
	if err := begin(); err != nil {
		return err
	}
	h.phase = 2
	return nil
}
func (h *nfqws2ActiveHelperProtocol) started(child components.NFQWSRuntimeProcessIdentity) error {
	if h == nil || h.phase != 2 || !nfqws2ActiveFrameChild(h.command, h.base.Helper, child) {
		return ErrNFQWSManagedProcessUnknown
	}
	h.phase = -1
	h.child = child
	if err := nfqws2ActiveSend(h.transport, h.base, "started", child); err != nil {
		return err
	}
	h.phase = 3
	return nil
}
func (h *nfqws2ActiveHelperProtocol) transfer(ctx context.Context, current func() error, durable func(string) error) error {
	if h == nil || h.phase != 3 || durable == nil {
		return ErrNFQWSManagedProcessUnknown
	}
	h.phase = -1 // Every failure consumes this invocation; metadata cannot replay it.
	if err := nfqws2ActiveReceive(h.transport, h.command, h.base, "transfer", h.child); err != nil {
		return err
	}
	if err := nfqws2ActiveProtocolCurrent(ctx, current); err != nil {
		return err
	}
	if err := durable("provisional"); err != nil {
		return err
	}
	if err := nfqws2ActiveProtocolCurrent(ctx, current); err != nil {
		return err
	}
	if err := nfqws2ActiveSend(h.transport, h.base, "transfer-ack", h.child); err != nil {
		return err
	}
	if err := nfqws2ActiveReceive(h.transport, h.command, h.base, "finalize", h.child); err != nil {
		return err
	}
	if err := nfqws2ActiveProtocolCurrent(ctx, current); err != nil {
		return err
	}
	if err := durable("final"); err != nil {
		return err
	}
	if err := nfqws2ActiveProtocolCurrent(ctx, current); err != nil {
		return err
	}
	if err := nfqws2ActiveSend(h.transport, h.base, "active", h.child); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrNFQWSManagedProcessUnknown, err)
	}
	h.phase = 4
	return nil
}
