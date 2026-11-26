package components

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/ArtixSx/razvilka/internal/installpath"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

const packageContainment = "linux-subreaper-v1"
const productionPackageJournal = installpath.State + "/components/update-journal"

type packageSupervision struct {
	Schema        int    `json:"schema"`
	TransactionID string `json:"transaction_id"`
	Component     string `json:"component"`
	Action        string `json:"action"`
	Containment   string `json:"containment"`
	State         string `json:"state"` // intent, armed, running, reaped, not-started
	BootID        string `json:"boot_id"`
	CommandSHA256 string `json:"command_sha256"`
	PID           int    `json:"pid,omitempty"`
	Start         string `json:"start,omitempty"`
	Group         int    `json:"group,omitempty"`
	ChildPID      int    `json:"child_pid,omitempty"`
	Reaped        int    `json:"reaped,omitempty"`
	WaitECHILD    bool   `json:"wait_echild,omitempty"`
	ExitCode      int    `json:"exit_code,omitempty"`
	Cancelled     bool   `json:"cancelled,omitempty"`
}

type packageCommand struct {
	Schema        int       `json:"schema"`
	TransactionID string    `json:"transaction_id"`
	Component     string    `json:"component"`
	Action        string    `json:"action"`
	Nonce         string    `json:"nonce"`
	Program       string    `json:"program"`
	Args          []string  `json:"args"`
	Environment   []string  `json:"environment,omitempty"`
	BootID        string    `json:"boot_id"`
	ParentPID     int       `json:"parent_pid"`
	ParentStart   string    `json:"parent_start"`
	Deadline      time.Time `json:"deadline"`
}

// Plain custom runners have no trusted receipt and retain the unknown fence.
type supervisedPackageRunner interface {
	runSupervised(context.Context, string, []string, packageSupervision, *ownedfs.Root, string) ([]byte, error)
}

var bootPattern = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

func validBootID(id string) bool               { return bootPattern.MatchString(id) }
func supervisionName(id, action string) string { return filepath.Join(id, action+".supervision.json") }

func (tx *updateTransaction) runPackage(ctx context.Context, action string, args ...string) ([]byte, error) {
	if err := tx.manager.nfqwsPackageMutationGuard(tx.doc.Component); err != nil {
		return nil, err
	}
	runner, ok := tx.manager.Runner.(supervisedPackageRunner)
	if !ok {
		return tx.manager.run(ctx, args...)
	}
	if action != "upgrade" && action != "rollback" {
		return nil, ErrUpdateUnknown
	}
	if _, err := tx.root.Stat(supervisionName(tx.doc.TransactionID, action)); !errors.Is(err, os.ErrNotExist) {
		return nil, ErrUpdateUnknown
	}
	path := filepath.Join(tx.manager.updateJournalDir(), tx.doc.TransactionID)
	root, err := ownedfs.Open(path)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	record := packageSupervision{Schema: 1, TransactionID: tx.doc.TransactionID, Component: tx.doc.Component, Action: action, Containment: packageContainment, State: "intent"}
	runCtx, cancel := context.WithTimeout(ctx, defaultDuration(tx.manager.Timeout, 90*time.Second))
	defer cancel()
	if err := tx.fault("before:supervision:intent"); err != nil {
		return nil, err
	}
	out, err := tx.manager.withPackageParents(args, func() ([]byte, error) {
		if err := tx.manager.nfqwsPackageMutationGuard(tx.doc.Component); err != nil {
			return nil, err
		}
		return runner.runSupervised(runCtx, tx.manager.Opkg, args, record, root, path)
	})
	if faultErr := tx.fault("after:supervision:result"); faultErr != nil {
		return out, errors.Join(err, faultErr)
	}
	return out, err
}

func strictJSON(data []byte, value any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return ErrUpdateUnknown
	}
	return nil
}

func readSupervision(root *ownedfs.Root, id, component, action string) (packageSupervision, error) {
	var r packageSupervision
	data, err := root.ReadLimited(supervisionName(id, action), 4096)
	if err != nil {
		return r, errors.Join(ErrUpdateUnknown, err)
	}
	if strictJSON(data, &r) != nil || r.Schema != 1 || r.TransactionID != id || r.Component != component || r.Action != action || r.Containment != packageContainment || !validBootID(r.BootID) || len(r.CommandSHA256) != 64 {
		return r, ErrUpdateUnknown
	}
	if _, err := hex.DecodeString(r.CommandSHA256); err != nil {
		return r, ErrUpdateUnknown
	}
	switch r.State {
	case "intent":
		if r.PID != 0 || r.Start != "" || r.Group != 0 || r.ChildPID != 0 || r.WaitECHILD {
			return r, ErrUpdateUnknown
		}
	case "armed", "running", "reaped", "not-started":
		if r.PID <= 1 || r.Start == "" || r.Group != r.PID {
			return r, ErrUpdateUnknown
		}
		if r.State == "reaped" && (!r.WaitECHILD || r.Reaped < 1 || r.ChildPID <= 1) {
			return r, ErrUpdateUnknown
		}
		if r.Cancelled && (r.State != "reaped" || r.ExitCode == 0) {
			return r, ErrUpdateUnknown
		}
		if r.State == "not-started" && (r.ChildPID != 0 || !r.WaitECHILD || r.Reaped != 0) {
			return r, ErrUpdateUnknown
		}
	default:
		return r, ErrUpdateUnknown
	}
	return r, nil
}

func writeSupervision(root *ownedfs.Root, r packageSupervision) error {
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if err := root.WriteAtomic(r.Action+".supervision.json", data, 0600); err != nil {
		return err
	}
	return syncUpdateDirectory(root)
}

func writePackageCommand(root *ownedfs.Root, r packageCommand) (string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	r.Nonce = hex.EncodeToString(nonce[:])
	data, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	f, err := root.OpenFile(r.Action+".command.json", os.O_WRONLY|os.O_CREATE|os.O_EXCL|updateFileFlags(), 0600)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err = f.Write(data); err != nil {
		return "", err
	}
	if err = f.Sync(); err != nil {
		return "", err
	}
	if err = f.Close(); err != nil {
		return "", err
	}
	return digest(data), syncUpdateDirectory(root)
}

// This may run inside a recovery guard: no Manager.mu/global writer lock.
// The separate helper lock and durable ECHILD receipt prove inactivity.
func (m *Manager) Quiescence(ctx context.Context, transactionID, component string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	root, err := openUpdateRoot(m.updateJournalDir(), false)
	if err != nil {
		return errors.Join(ErrUpdateUnknown, err)
	}
	defer root.Close()
	doc, present, err := readUpdateJournal(root)
	if err != nil {
		return err
	}
	if !present || doc.TransactionID != transactionID || doc.Component != component || transactionID == "" {
		return ErrUpdateUnknown
	}
	if doc.Phase == UpdatePrepared || doc.Phase == UpdateAbandoned {
		return nil
	}
	if doc.SupervisionVersion != 1 {
		return ErrUpdateUnknown
	}
	if err := supervisionRootSafe(m.updateJournalDir()); err != nil {
		return err
	}
	if err := supervisionRootSafe(filepath.Join(m.updateJournalDir(), transactionID)); err != nil {
		return err
	}
	snapshot, err := ownedfs.Open(filepath.Join(m.updateJournalDir(), transactionID))
	if err != nil {
		return err
	}
	defer snapshot.Close()
	release, err := lockUpdateWriter(snapshot)
	if err != nil {
		return errors.Join(ErrUpdateUnknown, err)
	}
	defer release()
	for _, action := range []string{"upgrade", "rollback"} {
		if action == "rollback" {
			switch doc.Phase {
			case UpdateRollbackStarted, UpdateRollbackInstalled, UpdateRestoreAfter, UpdateAwaitingRollback, UpdateRolledBack:
			default:
				continue
			}
		}
		r, err := readSupervision(root, transactionID, component, action)
		if err != nil {
			return err
		}
		command, err := snapshot.ReadLimited(action+".command.json", 16384)
		if err != nil || digest(command) != r.CommandSHA256 {
			return ErrUpdateUnknown
		}
		if err := supervisionInactive(ctx, r); err != nil {
			return fmt.Errorf("%w: %s: %v", ErrUpdateUnknown, action, err)
		}
	}
	after, present, err := readUpdateJournal(root)
	if err != nil {
		return err
	}
	if !present || after.TransactionID != doc.TransactionID || after.Component != doc.Component || after.Phase != doc.Phase {
		return ErrUpdateUnknown
	}
	if err := supervisionRootSafe(m.updateJournalDir()); err != nil {
		return err
	}
	if err := supervisionRootSafe(filepath.Join(m.updateJournalDir(), transactionID)); err != nil {
		return err
	}
	return ctx.Err()
}
