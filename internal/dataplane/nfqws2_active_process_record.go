package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// Version 3 uses the SAME ownership.json, never a second process ledger.
// A cold image is evidence only: it cannot reconstruct a live transfer handle.
type nfqws2ActiveProcessLease struct {
	Version       int                                    `json:"version"`
	StateRoot     string                                 `json:"state_root"`
	Owner         string                                 `json:"owner"`
	Command       nfqws2ActiveProcessCommand             `json:"active_command"`
	CommandSHA256 string                                 `json:"command_sha256"`
	Binding       NFQWSExecutionBinding                  `json:"execution_binding"`
	Transfer      string                                 `json:"transfer"`
	Receipt       components.NFQWSSupervisionReceipt     `json:"process_receipt"`
	Child         components.NFQWSRuntimeProcessIdentity `json:"child_identity"`
	Acknowledged  bool                                   `json:"process_acknowledged"`
}

func nfqws2ValidateActiveLease(l nfqws2ActiveProcessLease) error {
	if l.Version != 3 || l.StateRoot != l.Command.StateRoot || l.Owner != l.Command.Owner ||
		nfqws2ValidateActiveCommand(l.Command) != nil || l.CommandSHA256 != nfqws2ActiveCommandDigest(l.Command) ||
		!nfqws2ActiveBindingValid(l.Binding, l.Command) ||
		nfqws2ValidateProcessReceipt(l.Command.fileShape(), l.CommandSHA256, l.Receipt, l.Child, l.Acknowledged) != nil {
		return ErrNFQWSManagedProcessUnknown
	}
	switch l.Transfer {
	case "none":
	case "provisional", "final":
		if !l.Receipt.Started || l.Child == (components.NFQWSRuntimeProcessIdentity{}) ||
			(l.Receipt.State != "running" && l.Receipt.State != "reaped") {
			return ErrNFQWSManagedProcessUnknown
		}
	default:
		return ErrNFQWSManagedProcessUnknown
	}
	if l.Receipt.Started && l.Child == (components.NFQWSRuntimeProcessIdentity{}) {
		return ErrNFQWSManagedProcessUnknown
	}
	return nil
}

func (l nfqws2ActiveProcessLease) observation() NFQWSActiveObservation {
	return NFQWSActiveObservation{Binding: l.Binding, NetworkIdentity: l.Command.NetworkIdentity, Receipt: l.Receipt, Child: l.Child}
}
func (l nfqws2ActiveProcessLease) proof() NFQWSScopedProcessProof {
	return NFQWSScopedProcessProof{SessionID: l.Command.ID, CommandSHA256: l.CommandSHA256, Receipt: l.Receipt, Child: l.Child, Acknowledged: l.Acknowledged}
}
func nfqws2ActiveProcessSettled(l nfqws2ActiveProcessLease) bool {
	return nfqws2ValidateActiveLease(l) == nil && l.Acknowledged && (l.Receipt.State == "reaped" || l.Receipt.State == "not-started")
}

func nfqws2DecodeActiveLease(image restorejournal.Image, root, owner string) (nfqws2ActiveProcessLease, error) {
	var l nfqws2ActiveProcessLease
	if !image.Exists || len(image.Data) > 64<<10 || nfqws2ManagedUniqueJSON(image.Data) != nil {
		return l, ErrNFQWSManagedProcessUnknown
	}
	d := json.NewDecoder(bytes.NewReader(image.Data))
	d.DisallowUnknownFields()
	if d.Decode(&l) != nil || d.Decode(new(any)) != io.EOF || l.StateRoot != root || l.Owner != owner || nfqws2ValidateActiveLease(l) != nil {
		return nfqws2ActiveProcessLease{}, ErrNFQWSManagedProcessUnknown
	}
	return l, nil
}
func nfqws2ActiveLeaseImage(l nfqws2ActiveProcessLease) (restorejournal.Image, error) {
	if nfqws2ValidateActiveLease(l) != nil {
		return restorejournal.Image{}, ErrNFQWSManagedProcessUnknown
	}
	data, err := json.Marshal(l) // Canonical nested typed identity requires compact JSON.
	if err != nil || len(data) > 64<<10 {
		return restorejournal.Image{}, ErrNFQWSManagedProcessUnknown
	}
	return restorejournal.Image{Exists: true, Data: append(data, '\n')}, nil
}

type nfqws2ActiveProcessStore struct {
	target *restorejournal.FileTarget
	image  restorejournal.Image
	lease  nfqws2ActiveProcessLease
}

func (s *nfqws2ActiveProcessStore) publish(ctx context.Context) error {
	after, err := nfqws2ActiveLeaseImage(s.lease)
	if err != nil {
		return err
	}
	if err = s.target.CompareAndSwap(ctx, s.image, after); err != nil {
		return errors.Join(ErrNFQWSManagedProcessUnknown, err)
	}
	s.image = after
	return nil
}

func nfqws2DeclaredLeaseVersion(image restorejournal.Image) int {
	if !image.Exists || len(image.Data) > 64<<10 || nfqws2ManagedUniqueJSON(image.Data) != nil {
		return 0
	}
	var fields map[string]json.RawMessage
	var version int
	if json.Unmarshal(image.Data, &fields) != nil || json.Unmarshal(fields["version"], &version) != nil {
		return 0
	}
	return version // Dispatch only; each selected decoder still checks every field.
}
