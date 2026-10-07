package dataplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

const nfqws2ActiveProcessMode = "manager-active-v1"

// A separately reviewed command shape. ActivationDeadline bounds only the
// one-use Start/transfer protocol. It is never an active process lifetime.
// Serialized commands and matching hashes cannot construct a live owner.
type nfqws2ActiveProcessCommand struct {
	Version                                           int
	Mode                                              string
	ID, StateRoot, Owner, ControlRoot, InstallationID string
	Sequence                                          uint64
	Program                                           nfqws2ManagedFile
	Assets                                            []nfqws2ManagedFile
	Args                                              []string
	Parent                                            components.NFQWSSupervisionIdentity
	NetworkIdentity                                   netidentity.Identity
	ActivationDeadline                                time.Time
}

func (c nfqws2ActiveProcessCommand) clone() nfqws2ActiveProcessCommand {
	c.Assets, c.Args = slices.Clone(c.Assets), slices.Clone(c.Args)
	return c
}

// Metadata validation shares the original immutable file/argv/control shape.
// This view is never passed to the timed producer or its admission callbacks.
func (c nfqws2ActiveProcessCommand) fileShape() nfqws2ManagedProcessCommand {
	return nfqws2ManagedProcessCommand{ID: c.ID, StateRoot: c.StateRoot, Owner: c.Owner, ControlRoot: c.ControlRoot,
		InstallationID: c.InstallationID, Sequence: c.Sequence, Program: c.Program, Assets: c.Assets,
		Args: c.Args, Parent: c.Parent, Deadline: c.ActivationDeadline}
}

func nfqws2ValidateActiveCommand(c nfqws2ActiveProcessCommand) error {
	if c.Version != 1 || c.Mode != nfqws2ActiveProcessMode || c.NetworkIdentity.Validate() != nil ||
		c.NetworkIdentity.BootID != c.Parent.BootID || len(c.Assets) > 16 || len(c.Args) > 128 ||
		nfqws2ValidateManagedCommand(c.fileShape()) != nil {
		return ErrNFQWSManagedProcessUnknown
	}
	return nil
}

func nfqws2ActiveCommandDigest(c nfqws2ActiveProcessCommand) string {
	if nfqws2ValidateActiveCommand(c) != nil {
		return ""
	}
	data, err := json.Marshal(c)
	if err != nil {
		return ""
	}
	hash := sha256.Sum256(append([]byte("nfqws-active-command-v1\x00"), data...))
	return hex.EncodeToString(hash[:])
}

func nfqws2ActiveCommandDecode(data []byte) (nfqws2ActiveProcessCommand, error) {
	var command nfqws2ActiveProcessCommand
	if len(data) == 0 || len(data) > 64<<10 || nfqws2ManagedUniqueJSON(data) != nil {
		return command, ErrNFQWSManagedProcessUnknown
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&command) != nil || decoder.Decode(new(any)) != io.EOF || nfqws2ValidateActiveCommand(command) != nil {
		return nfqws2ActiveProcessCommand{}, ErrNFQWSManagedProcessUnknown
	}
	return command, nil
}

// Static reconstruction intentionally permits a past activation deadline.
// Only a fresh original request may begin an activation; expired metadata
// cannot be fed back into Start or reconstructed into an active capability.
func nfqws2ActiveActivationContext(ctx context.Context, command nfqws2ActiveProcessCommand) (context.Context, context.CancelFunc, error) {
	if nfqws2ValidateActiveCommand(command) != nil {
		return nil, nil, ErrNFQWSManagedProcessUnknown
	}
	return nfqws2ManagedStartContext(ctx, command.ActivationDeadline)
}

func nfqws2ActiveCommandMatchesSpec(command nfqws2ActiveProcessCommand, spec NFQWSScopedSpec) error {
	if nfqws2ValidateActiveCommand(command) != nil || spec.NetworkIdentity == nil || !nfqwsScopedSpecNetworkValid(spec) ||
		*spec.NetworkIdentity != command.NetworkIdentity || spec.CommandSHA256 != nfqws2ActiveCommandDigest(command) {
		return ErrNFQWSScopedOwner
	}
	// Reuse only the accepted pure closed argv grammar. No old process or
	// request authority is borrowed by this metadata-only lexical check.
	view := command.fileShape()
	lexical := spec.Clone()
	lexical.CommandSHA256 = nfqws2ManagedCommandDigest(view)
	return nfqwsExecutionCommandMatches(view, lexical)
}

// Detached operation input for CORE's actual Store/control checks. It is not
// a live-handle constructor or transfer/cleanup grant.
type NFQWSActiveObservation struct {
	Binding         NFQWSExecutionBinding
	NetworkIdentity netidentity.Identity
	Receipt         components.NFQWSSupervisionReceipt
	Child           components.NFQWSRuntimeProcessIdentity
}

const nfqws2ActiveFrameLimit = 8192

type nfqws2ActiveFrame struct {
	Version         int                                    `json:"version"`
	Kind            string                                 `json:"kind"`
	Binding         NFQWSExecutionBinding                  `json:"binding"`
	NetworkIdentity netidentity.Identity                   `json:"network_identity"`
	Helper          components.NFQWSSupervisionIdentity    `json:"helper"`
	Child           components.NFQWSRuntimeProcessIdentity `json:"child"`
}

func nfqws2ActiveFrameKind(kind string) bool {
	switch kind {
	case "ready", "permit", "started", "transfer", "transfer-ack", "finalize", "active":
		return true
	}
	return false
}

func nfqws2ActiveFrameDecode(data []byte) (nfqws2ActiveFrame, error) {
	var frame nfqws2ActiveFrame
	if len(data) == 0 || len(data) > nfqws2ActiveFrameLimit || nfqws2ManagedUniqueJSON(data) != nil {
		return frame, ErrNFQWSManagedProcessUnknown
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&frame) != nil || decoder.Decode(new(any)) != io.EOF || frame.Version != 2 ||
		!nfqws2ActiveFrameKind(frame.Kind) || frame.NetworkIdentity.Validate() != nil {
		return nfqws2ActiveFrame{}, ErrNFQWSManagedProcessUnknown
	}
	return frame, nil
}

func nfqws2ActiveBindingValid(binding NFQWSExecutionBinding, command nfqws2ActiveProcessCommand) bool {
	if nfqws2ValidateActiveCommand(command) != nil || !validPlanID(binding.ExecutionID) || binding.CommandSHA256 != nfqws2ActiveCommandDigest(command) {
		return false
	}
	// Validate the SAME eight fields with the existing pure shape checker.
	// A temporary digest substitution here is never emitted or persisted.
	shape := command.fileShape()
	copy := binding
	copy.CommandSHA256 = nfqws2ManagedCommandDigest(shape)
	return nfqws2ManagedStartBindingValid(copy, shape)
}

func nfqws2ActiveFrameBase(command nfqws2ActiveProcessCommand, binding NFQWSExecutionBinding, helper components.NFQWSSupervisionIdentity) (nfqws2ActiveFrame, error) {
	if !nfqws2ActiveBindingValid(binding, command) || helper.PID <= 1 || helper.Group != helper.PID ||
		helper.BootID != command.NetworkIdentity.BootID || !nfqws2ManagedPositive(helper.Start) {
		return nfqws2ActiveFrame{}, ErrNFQWSManagedProcessUnknown
	}
	return nfqws2ActiveFrame{Version: 2, Binding: binding, NetworkIdentity: command.NetworkIdentity, Helper: helper}, nil
}

func nfqws2ActiveFrameChild(command nfqws2ActiveProcessCommand, helper components.NFQWSSupervisionIdentity, child components.NFQWSRuntimeProcessIdentity) bool {
	return nfqws2ManagedStartChild(command.fileShape(), helper, child)
}

func nfqws2ActiveExpectedFrame(command nfqws2ActiveProcessCommand, base, actual nfqws2ActiveFrame, kind string, child components.NFQWSRuntimeProcessIdentity) error {
	want := base
	want.Kind, want.Child = kind, child
	if actual != want || !nfqws2ActiveFrameKind(kind) {
		return ErrNFQWSManagedProcessUnknown
	}
	if child != (components.NFQWSRuntimeProcessIdentity{}) && !nfqws2ActiveFrameChild(command, base.Helper, child) {
		return ErrNFQWSManagedProcessUnknown
	}
	return nil
}

// Static labels only; wire/command/ownership/control payloads never enter Error.
type nfqws2ActiveDiagnostic struct {
	stage string
	cause error
}

func (e *nfqws2ActiveDiagnostic) Error() string { return "managed NFQWS active " + e.stage }
func (e *nfqws2ActiveDiagnostic) Unwrap() error {
	return errors.Join(ErrNFQWSManagedProcessUnknown, e.cause)
}

func nfqws2ActiveFailure(stage string, cause error) error {
	return &nfqws2ActiveDiagnostic{stage: stage, cause: cause}
}
