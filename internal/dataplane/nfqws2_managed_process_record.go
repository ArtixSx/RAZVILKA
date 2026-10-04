package dataplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

var (
	ErrNFQWSManagedProcessUnknown = errors.New("managed NFQWS process settlement is unknown; invocation must not be replayed")
	ErrNFQWSManagedKernelOwner    = errors.New("managed NFQWS scoped kernel ownership and inactivity observer are unavailable")
)

type nfqws2ManagedFile struct {
	Path, SHA256 string
}

// This command is constructed only by a trusted in-process owner. Its shape
// and Stop admission do not grant a queue, scoped network effect or readiness.
type nfqws2ManagedProcessCommand struct {
	ID, StateRoot, Owner, ControlRoot, InstallationID string
	Sequence                                          uint64
	Program                                           nfqws2ManagedFile
	Assets                                            []nfqws2ManagedFile
	Args                                              []string
	Parent                                            components.NFQWSSupervisionIdentity
	Deadline                                          time.Time
}

// Version 2 lives in the SAME ownership.json as the legacy version 1 resource
// intent. The legacy decoder refuses it; it cannot be cleaned by package init.
type nfqws2ManagedProcessLease struct {
	Version       int                                    `json:"version"`
	StateRoot     string                                 `json:"state_root"`
	Owner         string                                 `json:"owner"`
	Command       nfqws2ManagedProcessCommand            `json:"managed_command"`
	CommandSHA256 string                                 `json:"command_sha256"`
	LaunchBinding *nfqws2ManagedStartBinding             `json:"execution_binding,omitempty"`
	Receipt       components.NFQWSSupervisionReceipt     `json:"process_receipt"`
	Child         components.NFQWSRuntimeProcessIdentity `json:"child_identity"`
	Acknowledged  bool                                   `json:"process_acknowledged"`
}

func nfqws2ManagedHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, c := range value {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}

func nfqws2ManagedPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && len(path) <= 4096 && !strings.ContainsAny(path, "\x00\r\n")
}

func nfqws2ManagedPositive(value string) bool {
	n, err := strconv.ParseUint(value, 10, 64)
	return err == nil && n > 0 && strconv.FormatUint(n, 10) == value
}

func nfqws2ManagedBoot(value string) bool {
	return len(value) == 36 && value[8] == '-' && value[13] == '-' && value[18] == '-' && value[23] == '-' && nfqws2ManagedHex(strings.ReplaceAll(value, "-", ""), 32)
}

func nfqws2ManagedCommandDigest(command nfqws2ManagedProcessCommand) string {
	data, err := json.Marshal(command)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func nfqws2ValidateManagedCommand(command nfqws2ManagedProcessCommand) error {
	if !nfqws2ManagedHex(command.ID, 32) || !nfqws2ManagedHex(command.Owner, 24) || !nfqws2ManagedHex(command.InstallationID, 32) || command.Sequence == 0 || !nfqws2ManagedPath(command.StateRoot) || filepath.Base(command.StateRoot) != "nfqws2" || filepath.Base(filepath.Dir(command.StateRoot)) != "runtime" || !nfqws2ManagedPath(command.ControlRoot) || command.Deadline.IsZero() || !nfqws2ManagedBoot(command.Parent.BootID) || !nfqws2ManagedPositive(command.Parent.Start) || command.Parent.PID <= 1 || command.Parent.Group <= 0 {
		return ErrNFQWSManagedProcessUnknown
	}
	files := append([]nfqws2ManagedFile{command.Program}, command.Assets...)
	if len(command.Assets) > 16 || len(command.Args) == 0 || len(command.Args) > 128 {
		return ErrNFQWSManagedProcessUnknown
	}
	seen := map[string]bool{}
	for _, file := range files {
		if !nfqws2ManagedPath(file.Path) || !nfqws2ManagedHex(file.SHA256, 64) || seen[file.Path] {
			return ErrNFQWSManagedProcessUnknown
		}
		seen[file.Path] = true
	}
	bytes := len(command.Program.Path) + 1
	for _, arg := range command.Args {
		bytes += len(arg) + 1
		if len(arg) == 0 || len(arg) > 8192 || bytes > 32768 || !utf8.ValidString(arg) || strings.ContainsAny(arg, "\x00\r\n") {
			return ErrNFQWSManagedProcessUnknown
		}
	}
	return nil
}

func nfqws2ValidateManagedLease(lease nfqws2ManagedProcessLease) error {
	command, receipt := lease.Command, lease.Receipt
	if lease.Version != 2 || lease.StateRoot != command.StateRoot || lease.Owner != command.Owner || nfqws2ValidateManagedCommand(command) != nil || !nfqws2ManagedHex(lease.CommandSHA256, 64) || lease.CommandSHA256 != nfqws2ManagedCommandDigest(command) {
		return ErrNFQWSManagedProcessUnknown
	}
	if lease.LaunchBinding != nil && !nfqws2ManagedStartBindingValid(*lease.LaunchBinding, command) {
		return ErrNFQWSManagedProcessUnknown
	}
	if receipt.State == "intent" {
		if lease.Acknowledged || lease.Child != (components.NFQWSRuntimeProcessIdentity{}) || !reflect.DeepEqual(receipt, components.NFQWSSupervisionReceipt{State: "intent"}) {
			return ErrNFQWSManagedProcessUnknown
		}
		return nil
	}
	if receipt.BootID != command.Parent.BootID || receipt.CommandSHA256 != lease.CommandSHA256 || !nfqws2ManagedPositive(receipt.Start) || receipt.PID <= 1 || receipt.Group != receipt.PID || receipt.Reaped < 0 || receipt.ExitCode < 0 || receipt.ExitCode > 255 {
		return ErrNFQWSManagedProcessUnknown
	}
	if receipt.Started {
		child := lease.Child
		if receipt.ChildPID <= 1 || (child != (components.NFQWSRuntimeProcessIdentity{}) && (child.PID != receipt.ChildPID || child.ParentPID != receipt.PID || child.Group != child.PID || child.BootID != receipt.BootID || !nfqws2ManagedPositive(child.Start) || child.Executable != command.Program.Path || child.ArgumentsSHA256 != components.NFQWSRuntimeArgumentsSHA256(command.Program.Path, command.Args))) {
			return ErrNFQWSManagedProcessUnknown
		}
	} else if receipt.ChildPID != 0 || receipt.DirectReaped || receipt.Reaped != 0 || lease.Child != (components.NFQWSRuntimeProcessIdentity{}) {
		return ErrNFQWSManagedProcessUnknown
	}
	switch receipt.State {
	case "armed":
		if receipt.Started || receipt.WaitECHILD || receipt.Cancelled || lease.Acknowledged || receipt.ExitCode != 0 {
			return ErrNFQWSManagedProcessUnknown
		}
	case "running":
		if !receipt.Started || receipt.DirectReaped || receipt.WaitECHILD || receipt.Reaped != 0 || receipt.Cancelled || receipt.ExitCode != 0 || lease.Acknowledged {
			return ErrNFQWSManagedProcessUnknown
		}
	case "reaped":
		if !receipt.Started || !receipt.DirectReaped || !receipt.WaitECHILD || receipt.Reaped < 1 || (receipt.Cancelled && receipt.ExitCode != 125) {
			return ErrNFQWSManagedProcessUnknown
		}
	case "not-started":
		if receipt.Started || !receipt.WaitECHILD || receipt.ExitCode != 125 {
			return ErrNFQWSManagedProcessUnknown
		}
	default:
		return ErrNFQWSManagedProcessUnknown
	}
	return nil
}

func nfqws2ManagedProcessSettled(lease nfqws2ManagedProcessLease) bool {
	return nfqws2ValidateManagedLease(lease) == nil && lease.Acknowledged && (lease.Receipt.State == "reaped" || lease.Receipt.State == "not-started")
}

func nfqws2DecodeManagedLease(image restorejournal.Image, stateRoot, owner string) (nfqws2ManagedProcessLease, error) {
	var lease nfqws2ManagedProcessLease
	if !image.Exists || len(image.Data) > 64<<10 || nfqws2ManagedUniqueJSON(image.Data) != nil {
		return lease, ErrNFQWSManagedProcessUnknown
	}
	decoder := json.NewDecoder(bytes.NewReader(image.Data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&lease) != nil || decoder.Decode(new(any)) != io.EOF || lease.StateRoot != stateRoot || lease.Owner != owner || nfqws2ValidateManagedLease(lease) != nil {
		return lease, ErrNFQWSManagedProcessUnknown
	}
	return lease, nil
}

func nfqws2ManagedLeaseImage(lease nfqws2ManagedProcessLease) (restorejournal.Image, error) {
	if nfqws2ValidateManagedLease(lease) != nil {
		return restorejournal.Image{}, ErrNFQWSManagedProcessUnknown
	}
	data, err := json.MarshalIndent(lease, "", "  ")
	if err != nil || len(data) > 64<<10 {
		return restorejournal.Image{}, ErrNFQWSManagedProcessUnknown
	}
	return restorejournal.Image{Exists: true, Data: append(data, '\n')}, nil
}

type nfqws2ManagedProcessStore struct {
	target *restorejournal.FileTarget
	image  restorejournal.Image
	lease  nfqws2ManagedProcessLease
}

func (s *nfqws2ManagedProcessStore) close() { _ = s.target.Close() }
func (s *nfqws2ManagedProcessStore) publish(ctx context.Context) error {
	after, err := nfqws2ManagedLeaseImage(s.lease)
	if err != nil {
		return err
	}
	if err := s.target.CompareAndSwap(ctx, s.image, after); err != nil {
		return errors.Join(ErrNFQWSManagedProcessUnknown, err)
	}
	s.image = after
	return nil
}

// All typed fields must be unambiguous, including encoding/json's Unicode
// simple-fold aliases. Unknown fields are rejected by the typed decoder.
func nfqws2ManagedUniqueJSON(data []byte) error {
	if !utf8.Valid(data) {
		return ErrNFQWSManagedProcessUnknown
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	var visit func(int) error
	visit = func(depth int) error {
		if depth > 32 {
			return ErrNFQWSManagedProcessUnknown
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delim, isDelim := token.(json.Delim)
		if !isDelim {
			return nil
		}
		if delim != '{' && delim != '[' {
			return ErrNFQWSManagedProcessUnknown
		}
		seen := map[string]bool{}
		for decoder.More() {
			if delim == '{' {
				token, err := decoder.Token()
				key, ok := token.(string)
				var fold strings.Builder
				for _, r := range key {
					minimum := r
					for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
						if next < minimum {
							minimum = next
						}
					}
					fold.WriteRune(minimum)
				}
				key = fold.String()
				if err != nil || !ok || seen[key] {
					return ErrNFQWSManagedProcessUnknown
				}
				seen[key] = true
			}
			if err := visit(depth + 1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || (delim == '{' && end != json.Delim('}')) || (delim == '[' && end != json.Delim(']')) {
			return ErrNFQWSManagedProcessUnknown
		}
		return nil
	}
	if err := visit(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrNFQWSManagedProcessUnknown
	}
	return nil
}
