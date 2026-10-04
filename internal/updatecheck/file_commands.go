package updatecheck

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

type fileProcess struct {
	Boot             string `json:"boot"`
	PID              int    `json:"pid"`
	Start            string `json:"start"`
	ExecutableSHA256 string `json:"executable_sha256"`
	Device           uint64 `json:"device"`
	Inode            uint64 `json:"inode"`
}

type fileCommandReceipt struct {
	Schema     int         `json:"schema"`
	ID         string      `json:"id"`
	Command    string      `json:"command"`
	State      string      `json:"state"`
	Parent     fileProcess `json:"parent"`
	Supervisor fileProcess `json:"supervisor"`
	Runtime    fileProcess `json:"runtime"`
	DirectPID  int         `json:"direct_pid,omitempty"`
	Reaped     int         `json:"reaped,omitempty"`
	WaitECHILD bool        `json:"wait_echild,omitempty"`
	Cancelled  bool        `json:"cancelled,omitempty"`
	ExitCode   int         `json:"exit_code,omitempty"`
}

var fileBootPattern = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

// A failed join or missing durable ECHILD receipt leaves the command unknown.
// Callers must not treat cancellation, worker death, or this error as quiescence.
var ErrFileCommandUnsettled = errors.New("self update command cleanup is unconfirmed; outcome remains unknown")

func validFileProcess(process fileProcess) bool {
	start, err := strconv.ParseUint(process.Start, 10, 64)
	return err == nil && start > 0 && strconv.FormatUint(start, 10) == process.Start && process.Inode != 0 && fileBootPattern.MatchString(process.Boot) && process.PID > 1 && validDigest("sha256:"+process.ExecutableSHA256)
}

func validFileCommand(command string) bool {
	switch command {
	case "stop-old-panel", "prepare-private-state", "quiesce-old-runtime", "start-candidate-panel", "stop-candidate-panel", "restore-private-state", "start-rollback-panel":
		return true
	}
	return false
}

func (a *SelfUpdateFileAdapter) commandRoot(id string) (*ownedfs.Root, error) {
	if !jobIDPattern.MatchString(id) {
		return nil, ErrFileProtocol
	}
	return ownedfs.Open(filepath.Join(a.directory, id))
}

func readFileCommand(root *ownedfs.Root, id, command string) (fileCommandReceipt, error) {
	var receipt fileCommandReceipt
	if !validFileCommand(command) {
		return receipt, ErrFileProtocol
	}
	data, err := root.ReadLimited(command+".process.json", 4096)
	if err != nil {
		return receipt, err
	}
	if decodeFileProtocol(data, &receipt) != nil || receipt.Schema != selfUpdateProtocolSchema || receipt.ID != id || receipt.Command != command {
		return receipt, ErrFileProtocol
	}
	if !validFileCommandReceipt(receipt) {
		return receipt, ErrFileProtocol
	}
	return receipt, nil
}

func validFileCommandReceipt(r fileCommandReceipt) bool {
	if r.Schema != selfUpdateProtocolSchema || !jobIDPattern.MatchString(r.ID) || !validFileCommand(r.Command) || !validFileProcess(r.Parent) || r.Reaped < 0 || r.ExitCode < 0 || r.ExitCode > 255 {
		return false
	}
	zero := fileProcess{}
	if r.State == "intent" {
		return r.Supervisor == zero && r.Runtime == zero && r.DirectPID == 0 && r.Reaped == 0 && !r.WaitECHILD && !r.Cancelled && r.ExitCode == 0
	}
	if !validFileProcess(r.Supervisor) || r.Supervisor.Boot != r.Parent.Boot {
		return false
	}
	if r.Runtime != zero && (!validFileProcess(r.Runtime) || r.Runtime.Boot != r.Supervisor.Boot) {
		return false
	}
	switch r.State {
	case "armed":
		return r.Runtime == zero && r.DirectPID == 0 && r.Reaped == 0 && !r.WaitECHILD && !r.Cancelled && r.ExitCode == 0
	case "running":
		return r.Runtime == zero && r.DirectPID > 1 && r.Reaped == 0 && !r.WaitECHILD && !r.Cancelled && r.ExitCode == 0
	case "runtime-ready", "runtime-handed-off":
		return (r.Command == "start-candidate-panel" || r.Command == "start-rollback-panel") && r.Runtime != zero && r.DirectPID > 1 && r.Reaped > 0 && !r.WaitECHILD && !r.Cancelled && r.ExitCode == 0
	case "not-started":
		return r.Runtime == zero && r.DirectPID == 0 && r.Reaped == 0 && r.WaitECHILD && r.Cancelled && r.ExitCode == 125
	case "reaped":
		private := r.Command == "prepare-private-state" || r.Command == "restore-private-state"
		return r.WaitECHILD && (!r.Cancelled || r.ExitCode != 0) && (private && r.DirectPID == 0 && r.Reaped == 0 && r.Runtime == zero || !private && r.DirectPID > 1 && r.Reaped > 0)
	}
	return false
}

func writeFileCommand(root *ownedfs.Root, receipt fileCommandReceipt) error {
	data, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	if err := root.WriteAtomic(receipt.Command+".process.json", data, 0600); err != nil {
		return err
	}
	return syncSelfUpdateDirectory(root)
}

func (a *SelfUpdateFileAdapter) observeFileCommand(ctx context.Context, id, command string) error {
	if err := a.checkStop(ctx, id, "read/observe"); err != nil {
		return err
	}
	_, _, err := a.load(ctx, id)
	if err != nil {
		return err
	}
	root, err := a.commandRoot(id)
	if err != nil {
		return err
	}
	defer root.Close()
	receipt, err := readFileCommand(root, id, command)
	if err != nil {
		return err
	}
	if err := fileCommandInactive(ctx, receipt); err != nil {
		return err
	}
	if command == "stop-old-panel" || command == "stop-candidate-panel" {
		if command == "stop-old-panel" {
			if err := a.oldPanelInactive(ctx, id); err != nil {
				return err
			}
		}
		return a.filePanelAbsent(ctx)
	}
	if command == "prepare-private-state" {
		return a.verifyPrivateSnapshot(ctx, id)
	}
	if command == "restore-private-state" {
		return a.verifyPrivateRestore(ctx, id)
	}
	if command == "start-candidate-panel" || command == "start-rollback-panel" {
		return a.filePanelAbsent(ctx)
	} // Absence permits compensation, never live acceptance.
	if command == "quiesce-old-runtime" {
		if a.runtimeInactive == nil {
			return ErrFileProtocol
		}
		return a.runtimeInactive(ctx, id)
	}
	// Interrupted startup cannot be settled by absence or a cached version.
	return ErrFileProtocol
}

func (a *SelfUpdateFileAdapter) fileQuiescence(ctx context.Context, id string) error {
	if err := a.checkStop(ctx, id, "read/observe"); err != nil {
		return err
	}
	_, _, err := a.load(ctx, id)
	if err != nil {
		return err
	}
	root, err := a.commandRoot(id)
	if err != nil {
		return err
	}
	defer root.Close()
	for _, command := range []string{"stop-old-panel", "prepare-private-state", "quiesce-old-runtime", "start-candidate-panel", "stop-candidate-panel", "restore-private-state", "start-rollback-panel"} {
		receipt, err := readFileCommand(root, id, command)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if err := fileCommandInactive(ctx, receipt); err != nil {
			return err
		}
	}
	store, e := selfupdatejournal.Open(a.installation, a.fileJournal)
	if e == nil {
		receipt, present, err := store.Current()
		store.Close()
		if err != nil {
			return err
		}
		if present && receipt.ID == id {
			stopped, err := readFileCommand(root, id, "stop-old-panel")
			if err != nil {
				return ErrFileProtocol
			}
			if err := fileCommandInactive(ctx, stopped); err != nil {
				return err
			}
			if receipt.Phase == "prepared" || receipt.Phase == "installing" {
				if err := a.oldPanelInactive(ctx, id); err != nil {
					return err
				}
				for _, command := range []string{"stop-old-panel", "prepare-private-state", "quiesce-old-runtime"} {
					r, err := readFileCommand(root, id, command)
					if err != nil || fileCommandInactive(ctx, r) != nil {
						return ErrFileProtocol
					}
				}
				if err := a.verifyPrivateSnapshot(ctx, id); err != nil {
					return err
				}
				if a.runtimeInactive == nil {
					return ErrFileProtocol
				}
				if err := a.runtimeInactive(ctx, id); err != nil {
					return err
				}
			}
			if receipt.Phase == "prepared" || receipt.Phase == "installing" || receipt.Phase == "restoring" || receipt.Phase == "restored" {
				if err := a.filePanelAbsent(ctx); err != nil {
					return err
				}
			}
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	return ctx.Err()
}
