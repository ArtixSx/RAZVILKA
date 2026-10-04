package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
)

// This detached identity is evidence, never an issuer. It is outside Command
// so compiler/resource hashes cannot create a circular command digest.
type nfqws2ManagedStartBinding = NFQWSExecutionBinding

func nfqws2ManagedStartBindingValid(b nfqws2ManagedStartBinding, command nfqws2ManagedProcessCommand) bool {
	execution := validPlanID(b.ExecutionID) || (strings.HasPrefix(b.ExecutionID, "dp-check-") && nfqws2ManagedHex(strings.TrimPrefix(b.ExecutionID, "dp-check-"), 32))
	return execution && validPlanID(b.PlanID) && validPlanDigest(b.PlanDigest) &&
		strings.HasPrefix(b.ResourceID, "nq-") && nfqws2ManagedHex(strings.TrimPrefix(b.ResourceID, "nq-"), 32) &&
		validNetworkPolicyGeneration(b.ResourceGeneration) && validPlanDigest(b.EffectsDigest) &&
		b.SessionID == command.ID && b.CommandSHA256 == nfqws2ManagedCommandDigest(command)
}

// DEFAULT supplies these only from its live, retained common Execution.
// BeforeStart must durably mark process-pending and check the empty namespace.
// WithStart must linearize scope close with begin until actual child ACK;
// Prepared checks actual process/queue/LAN outside that start barrier.
// Callback presence or a detached binding alone is not production permission.
type nfqws2ManagedProcessAdmission struct {
	Binding     nfqws2ManagedStartBinding
	BeforeStart func(context.Context, nfqws2ManagedStartBinding) error
	WithStart   func(context.Context, nfqws2ManagedStartBinding, func() error) error
	Current     func(context.Context, nfqws2ManagedStartBinding) error
	Prepared    func(context.Context, nfqws2ManagedStartBinding) error
}

func (a *nfqws2ManagedProcessAdmission) valid(command nfqws2ManagedProcessCommand) bool {
	return a != nil && nfqws2ManagedStartBindingValid(a.Binding, command) && a.BeforeStart != nil && a.WithStart != nil && a.Current != nil && a.Prepared != nil
}

func nfqws2ManagedStartContext(ctx context.Context, deadline time.Time) (context.Context, context.CancelFunc, error) {
	now := time.Now()
	if ctx == nil || ctx.Err() != nil || deadline.IsZero() || !now.Before(deadline) || deadline.After(now.Add(15*time.Second)) {
		return nil, nil, ErrNFQWSManagedProcessUnknown
	}
	bounded, cancel := context.WithDeadline(ctx, deadline)
	return bounded, cancel, nil
}

type nfqws2ManagedStartOnce struct {
	mu           sync.Mutex
	open, called bool
	begin        func() error
	outcome      error
}

func (s *nfqws2ManagedStartOnce) run() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.open || s.called || s.begin == nil {
		return ErrNFQWSManagedProcessUnknown
	}
	s.called = true
	s.outcome = ErrNFQWSManagedProcessUnknown // A swallowed panic cannot become success.
	s.outcome = s.begin()
	return s.outcome
}

func (s *nfqws2ManagedStartOnce) seal() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.open = false
	if !s.called {
		return ErrNFQWSManagedProcessUnknown
	}
	return s.outcome
}

func (s *nfqws2ManagedStartOnce) invoke(action func(func() error) error) (err error) {
	defer func() { err = errors.Join(err, s.seal()) }()
	if action == nil {
		return ErrNFQWSManagedProcessUnknown
	}
	return action(s.run)
}

const nfqws2ManagedStartFrameLimit = 4096

type nfqws2ManagedStartFrame struct {
	Version int                                    `json:"version"`
	Kind    string                                 `json:"kind"`
	Binding nfqws2ManagedStartBinding              `json:"binding"`
	Helper  components.NFQWSSupervisionIdentity    `json:"helper"`
	Child   components.NFQWSRuntimeProcessIdentity `json:"child"`
}

type nfqws2ManagedStartTransport interface {
	send(nfqws2ManagedStartFrame) error
	receive() (nfqws2ManagedStartFrame, error)
	close() error
}

func nfqws2ManagedStartDecode(data []byte) (nfqws2ManagedStartFrame, error) {
	var frame nfqws2ManagedStartFrame
	if len(data) == 0 || len(data) > nfqws2ManagedStartFrameLimit || nfqws2ManagedUniqueJSON(data) != nil {
		return frame, ErrNFQWSManagedProcessUnknown
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&frame) != nil || d.Decode(new(any)) != io.EOF || frame.Version != 1 ||
		(frame.Kind != "ready" && frame.Kind != "permit" && frame.Kind != "started") {
		return nfqws2ManagedStartFrame{}, ErrNFQWSManagedProcessUnknown
	}
	return frame, nil
}

func nfqws2ManagedStartBase(command nfqws2ManagedProcessCommand, binding nfqws2ManagedStartBinding, helper components.NFQWSSupervisionIdentity) (nfqws2ManagedStartFrame, error) {
	if !nfqws2ManagedStartBindingValid(binding, command) || helper.PID <= 1 || helper.Group != helper.PID || helper.BootID != command.Parent.BootID || !nfqws2ManagedPositive(helper.Start) {
		return nfqws2ManagedStartFrame{}, ErrNFQWSManagedProcessUnknown
	}
	return nfqws2ManagedStartFrame{Version: 1, Binding: binding, Helper: helper}, nil
}

func nfqws2ManagedStartChild(command nfqws2ManagedProcessCommand, helper components.NFQWSSupervisionIdentity, child components.NFQWSRuntimeProcessIdentity) bool {
	return child.PID > 1 && child.ParentPID == helper.PID && child.Group == child.PID &&
		child.BootID == helper.BootID && nfqws2ManagedPositive(child.Start) &&
		child.Executable == command.Program.Path && child.ArgumentsSHA256 == components.NFQWSRuntimeArgumentsSHA256(command.Program.Path, command.Args)
}

// Parent owns the live Manager barrier for this entire one-use exchange.
// An error after sending permit is unknown, even if the kernel child ran.
func nfqws2ManagedStartParent(ctx context.Context, transport nfqws2ManagedStartTransport, command nfqws2ManagedProcessCommand, binding nfqws2ManagedStartBinding, helper components.NFQWSSupervisionIdentity, current func() error) error {
	base, err := nfqws2ManagedStartBase(command, binding, helper)
	if err != nil || ctx == nil || transport == nil || current == nil {
		return ErrNFQWSManagedProcessUnknown
	}
	ready, err := transport.receive()
	base.Kind = "ready"
	if err != nil || ready != base || ctx.Err() != nil || current() != nil || ctx.Err() != nil {
		return ErrNFQWSManagedProcessUnknown
	}
	base.Kind = "permit"
	if transport.send(base) != nil {
		return ErrNFQWSManagedProcessUnknown
	}
	ack, err := transport.receive()
	base.Kind = "started"
	child := ack.Child
	ack.Child = components.NFQWSRuntimeProcessIdentity{}
	if err != nil || ack != base || !nfqws2ManagedStartChild(command, helper, child) || ctx.Err() != nil || current() != nil || ctx.Err() != nil {
		return ErrNFQWSManagedProcessUnknown
	}
	return nil
}

// The helper gets permission only from the inherited live endpoint. Reading
// ownership.json cannot manufacture this exchange. The channel is not an
// atomic parent-death/fork primitive; lost parent/ACK stays durably pending.
type nfqws2ManagedStartHelper struct {
	transport nfqws2ManagedStartTransport
	base      nfqws2ManagedStartFrame
	phase     int
}

func (h *nfqws2ManagedStartHelper) ready() error {
	if h == nil || h.transport == nil || h.phase != 0 {
		return ErrNFQWSManagedProcessUnknown
	}
	h.phase = 1
	frame := h.base
	frame.Kind = "ready"
	return h.transport.send(frame)
}

func (h *nfqws2ManagedStartHelper) admit(ctx context.Context, current func() error, begin func() error) error {
	if h == nil || h.phase != 1 || ctx == nil || current == nil || begin == nil {
		return ErrNFQWSManagedProcessUnknown
	}
	h.phase = -1 // Consume before receiving; there is no replay on any outcome.
	permit, err := h.transport.receive()
	want := h.base
	want.Kind = "permit"
	if err != nil || permit != want || ctx.Err() != nil || current() != nil {
		return ErrNFQWSManagedProcessUnknown
	}
	if err := begin(); err != nil {
		return err
	}
	h.phase = 2
	return nil
}

func (h *nfqws2ManagedStartHelper) started(command nfqws2ManagedProcessCommand, child components.NFQWSRuntimeProcessIdentity) error {
	if h == nil || h.phase != 2 || !nfqws2ManagedStartChild(command, h.base.Helper, child) {
		return ErrNFQWSManagedProcessUnknown
	}
	h.phase = 3
	frame := h.base
	frame.Kind, frame.Child = "started", child
	return h.transport.send(frame)
}
