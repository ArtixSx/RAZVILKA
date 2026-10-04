package components

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// ComponentUpdateSchema must also be understood by a replacement application
// binary before it is allowed to inherit an unfinished component transaction.
const ComponentUpdateSchema = 2

var (
	ErrUpdatePending         = errors.New("component update requires matching recovery")
	ErrUpdateUnknown         = errors.New("component package command outcome is unknown; command must not be replayed")
	ErrRecoveryAuthority     = errors.New("component recovery is not authorized")
	ErrManagedUpdateRequired = errors.New("installed component requires a checked journaled update")
)

const (
	UpdatePrepared          = "prepared"
	UpdateStarted           = "upgrade-started"
	UpdateInstalled         = "upgrade-finished"
	UpdateAwaitingLive      = "awaiting-live-acceptance"
	UpdateRestoreBefore     = "rollback-config-before"
	UpdateRollbackReady     = "rollback-ready"
	UpdateRollbackStarted   = "rollback-started"
	UpdateRollbackInstalled = "rollback-installed"
	UpdateRestoreAfter      = "rollback-config-after"
	UpdateAwaitingRollback  = "awaiting-rollback-acceptance"
	UpdateAccepted          = "accepted"
	UpdateAcceptedIdle      = "accepted-installed-idle"
	UpdateRolledBack        = "rolled-back"
	UpdateAbandoned         = "abandoned"
)

// ManagedUpdateState contains no private configuration or snapshot paths.
// An unfinished transaction is a maintenance fence, including after a restart.
type ManagedUpdateState struct {
	SchemaVersion int    `json:"schema_version"`
	TransactionID string `json:"transaction_id"`
	Component     string `json:"component"`
	Phase         string `json:"phase"`
	BeforeVersion string `json:"before_version"`
	AfterVersion  string `json:"after_version,omitempty"`
	UpdatedAt     string `json:"updated_at"`
}

type journalConfig struct {
	Path   string `json:"path"`
	Blob   string `json:"blob,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	Mode   uint32 `json:"mode"`
	Exists bool   `json:"exists"`
}

type updateJournal struct {
	ManagedUpdateState
	Package            string                   `json:"package"`
	PackageFile        string                   `json:"package_file"`
	PackageSHA256      string                   `json:"package_sha256"`
	Configs            []journalConfig          `json:"configs"`
	CandidateSnapshot  bool                     `json:"candidate_snapshot,omitempty"`
	CandidateConfigs   []journalConfig          `json:"candidate_configs,omitempty"`
	SupervisionVersion int                      `json:"supervision_version,omitempty"`
	ManagedNFQWS       *managedNFQWSTransaction `json:"managed_nfqws,omitempty"`
}

type updateTransaction struct {
	manager *Manager
	root    *ownedfs.Root
	doc     updateJournal
	release func()
}

func (m *Manager) updateJournalDir() string {
	return filepath.Join(defaultValue(m.StateDir, "/opt/var/lib/razvilka/components"), "update-journal")
}

func openUpdateRoot(path string, create bool) (*ownedfs.Root, error) {
	if create {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return nil, err
		}
	}
	root, err := ownedfs.Open(path)
	if err != nil {
		return nil, err
	}
	if create {
		// Persist the journal directory entry before it can fence a mutation.
		parent, e := ownedfs.Open(filepath.Dir(path))
		if e == nil {
			e = syncUpdateDirectory(parent)
			_ = parent.Close()
		}
		if e != nil {
			_ = root.Close()
			return nil, e
		}
	}
	return root, nil
}

func (m *Manager) lockUpdateJournal() (*updateTransaction, error) {
	root, err := openUpdateRoot(m.updateJournalDir(), true)
	if err != nil {
		return nil, err
	}
	release, err := lockUpdateWriter(root)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	return &updateTransaction{manager: m, root: root, release: release}, nil
}

func (m *Manager) fencePackageMutation() (func(), error) {
	// Legacy in-memory managers are test-only; New always supplies StateDir.
	if m.StateDir == "" {
		return func() {}, nil
	}
	tx, err := m.lockUpdateJournal()
	if err != nil {
		return nil, err
	}
	if err := tx.requireIdle(); err != nil {
		tx.close()
		return nil, err
	}
	return tx.close, nil
}

func (tx *updateTransaction) close() { tx.release(); _ = tx.root.Close() }

func readUpdateJournal(root *ownedfs.Root) (updateJournal, bool, error) {
	var doc updateJournal
	data, err := root.ReadLimited("current.json", 64<<10)
	if errors.Is(err, os.ErrNotExist) {
		return doc, false, nil
	}
	if err != nil {
		return doc, false, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&doc); err != nil {
		return doc, false, err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return doc, false, errors.New("trailing component journal data")
	}
	if err := validateUpdateJournal(doc); err != nil {
		return doc, false, err
	}
	if doc.ManagedNFQWS != nil {
		canonical, err := json.Marshal(doc)
		if err != nil || !bytes.Equal(bytes.TrimSuffix(data, []byte{'\n'}), canonical) {
			return doc, false, ErrManagedNFQWSBundle
		}
	}
	return doc, true, nil
}

func updateTerminal(phase string) bool {
	return phase == UpdateAccepted || phase == UpdateAcceptedIdle || phase == UpdateRolledBack || phase == UpdateAbandoned
}

func validateUpdateJournal(doc updateJournal) error {
	if doc.ManagedNFQWS != nil {
		return validateManagedNFQWSJournal(doc)
	}
	spec, known := lookup(doc.Component)
	_, idErr := hex.DecodeString(doc.TransactionID)
	_, packageErr := hex.DecodeString(doc.PackageSHA256)
	if (doc.SchemaVersion != 1 && doc.SchemaVersion != ComponentUpdateSchema) || len(doc.TransactionID) != 32 || idErr != nil || !known || !ManagedUpdateSupported(doc.Component) || spec.Package != doc.Package || len(doc.PackageSHA256) != 64 || packageErr != nil || doc.BeforeVersion == "" || len(doc.Configs) > maxConffiles {
		return errors.New("unsupported or invalid component update journal")
	}
	if filepath.Base(doc.PackageFile) != doc.PackageFile || !strings.HasPrefix(doc.PackageFile, spec.Package+"_"+doc.BeforeVersion+"_") || !strings.HasSuffix(doc.PackageFile, ".ipk") || strings.ContainsAny(doc.BeforeVersion, "/\\") {
		return errors.New("invalid component rollback package identity")
	}
	switch doc.Phase {
	case UpdatePrepared, UpdateStarted, UpdateInstalled, UpdateAwaitingLive, UpdateRestoreBefore, UpdateRollbackReady, UpdateRollbackStarted, UpdateRollbackInstalled, UpdateRestoreAfter, UpdateAwaitingRollback, UpdateAccepted, UpdateAcceptedIdle, UpdateRolledBack, UpdateAbandoned:
	default:
		return errors.New("unknown component update phase")
	}
	if _, err := time.Parse(time.RFC3339Nano, doc.UpdatedAt); err != nil {
		return errors.New("invalid component journal timestamp")
	}
	seen := map[string]bool{}
	for i, conf := range doc.Configs {
		if !filepath.IsAbs(conf.Path) || filepath.Clean(conf.Path) != conf.Path || seen[conf.Path] || conf.Mode & ^uint32(0o777) != 0 {
			return errors.New("invalid component configuration snapshot")
		}
		seen[conf.Path] = true
		if conf.Exists {
			if conf.Blob != fmt.Sprintf("config-%02d", i) || len(conf.SHA256) != 64 {
				return errors.New("invalid component configuration blob")
			}
			if _, err := hex.DecodeString(conf.SHA256); err != nil {
				return err
			}
		} else if conf.Blob != "" || conf.SHA256 != "" || conf.Mode != 0 {
			return errors.New("invalid absent component configuration")
		}
	}
	if doc.SupervisionVersion != 0 && doc.SupervisionVersion != 1 {
		return errors.New("unsupported package supervision")
	}
	if doc.SchemaVersion == 1 && (doc.SupervisionVersion != 0 || doc.CandidateSnapshot || len(doc.CandidateConfigs) != 0 || doc.Phase == UpdateAcceptedIdle) {
		return errors.New("component journal features require schema 2")
	}
	if !doc.CandidateSnapshot && len(doc.CandidateConfigs) != 0 {
		return errors.New("uncommitted candidate configuration snapshot")
	}
	if len(doc.CandidateConfigs) > maxConffiles {
		return errors.New("too many candidate configuration files")
	}
	seen = map[string]bool{}
	for i, conf := range doc.CandidateConfigs {
		if !filepath.IsAbs(conf.Path) || filepath.Clean(conf.Path) != conf.Path || seen[conf.Path] || conf.Mode & ^uint32(0777) != 0 {
			return errors.New("invalid candidate configuration snapshot")
		}
		seen[conf.Path] = true
		if conf.Exists {
			if conf.Blob != fmt.Sprintf("candidate-config-%02d", i) || len(conf.SHA256) != 64 {
				return errors.New("invalid candidate configuration blob")
			}
			if _, err := hex.DecodeString(conf.SHA256); err != nil {
				return err
			}
		} else if conf.Blob != "" || conf.SHA256 != "" || conf.Mode != 0 {
			return errors.New("invalid absent candidate configuration")
		}
	}
	return nil
}

// PendingManagedUpdate is read-only and independent of the old process. Any
// read/schema error must also fence maintenance; it is never an empty journal.
func (m *Manager) PendingManagedUpdate() (ManagedUpdateState, bool, error) {
	root, err := openUpdateRoot(m.updateJournalDir(), false)
	if errors.Is(err, os.ErrNotExist) {
		return ManagedUpdateState{}, false, nil
	}
	if err != nil {
		return ManagedUpdateState{}, false, err
	}
	defer root.Close()
	doc, exists, err := readUpdateJournal(root)
	return doc.ManagedUpdateState, exists && !updateTerminal(doc.Phase), err
}

func (tx *updateTransaction) requireIdle() error {
	doc, exists, err := readUpdateJournal(tx.root)
	if err != nil {
		return errors.Join(ErrUpdatePending, err)
	}
	if exists && !updateTerminal(doc.Phase) {
		return fmt.Errorf("%w: %s %s", ErrUpdatePending, doc.Component, doc.TransactionID)
	}
	return nil
}

func (tx *updateTransaction) fault(point string) error {
	if tx.manager.updateFault != nil {
		return tx.manager.updateFault(point)
	}
	return nil
}

func (tx *updateTransaction) phase(phase string) error {
	if err := tx.fault("before:" + phase); err != nil {
		return err
	}
	tx.doc.Phase, tx.doc.UpdatedAt = phase, time.Now().UTC().Format(time.RFC3339Nano)
	data, err := json.Marshal(tx.doc)
	if err != nil {
		return err
	}
	if err := tx.root.WriteAtomic("current.json", append(data, '\n'), 0o600); err != nil {
		return err
	}
	if err := syncUpdateDirectory(tx.root); err != nil {
		return err
	}
	return tx.fault("after:" + phase)
}

func digest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

func (tx *updateTransaction) prepare(spec Spec, before, rollback string, images []conffileImage) error {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	id := hex.EncodeToString(nonce[:])
	tx.doc = updateJournal{ManagedUpdateState: ManagedUpdateState{SchemaVersion: ComponentUpdateSchema, TransactionID: id, Component: spec.ID, BeforeVersion: before}, Package: spec.Package, PackageFile: filepath.Base(rollback)}
	if _, ok := tx.manager.Runner.(supervisedPackageRunner); ok {
		tx.doc.SupervisionVersion = 1
	}
	if err := tx.root.MkdirAll(id, 0o700); err != nil {
		return err
	}
	if err := syncUpdateDirectory(tx.root); err != nil {
		return err
	}
	snapshot, err := ownedfs.Open(filepath.Join(tx.manager.updateJournalDir(), id))
	if err != nil {
		return err
	}
	defer snapshot.Close()
	// Stream the package so a low-memory router need not hold two full cores.
	source, err := ownedfs.Open(filepath.Dir(rollback))
	if err != nil {
		return err
	}
	defer source.Close()
	in, err := source.OpenFile(filepath.Base(rollback), os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxRollbackPackageBytes {
		return errors.New("unsafe rollback package")
	}
	out, err := snapshot.OpenFile(tx.doc.PackageFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	hash := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(out, hash), io.LimitReader(in, maxRollbackPackageBytes+1))
	err = errors.Join(copyErr, out.Sync(), out.Close())
	if err != nil {
		return err
	}
	if n != info.Size() || n > maxRollbackPackageBytes {
		return errors.New("rollback package changed during snapshot")
	}
	tx.doc.PackageSHA256 = hex.EncodeToString(hash.Sum(nil))
	for i, image := range images {
		conf := journalConfig{Path: image.path, Mode: uint32(image.mode), Exists: image.exists}
		if image.exists {
			conf.Blob, conf.SHA256 = fmt.Sprintf("config-%02d", i), digest(image.data)
			if err := snapshot.WriteAtomic(conf.Blob, image.data, 0o600); err != nil {
				return err
			}
		}
		tx.doc.Configs = append(tx.doc.Configs, conf)
	}
	if err := syncUpdateDirectory(snapshot); err != nil {
		return err
	}
	return tx.phase(UpdatePrepared)
}

// loadSnapshot verifies all bytes before the first recovery mutation.
func (tx *updateTransaction) loadSnapshot() (string, []conffileImage, error) {
	path := filepath.Join(tx.manager.updateJournalDir(), tx.doc.TransactionID)
	root, err := ownedfs.Open(path)
	if err != nil {
		return "", nil, err
	}
	defer root.Close()
	f, err := root.OpenFile(tx.doc.PackageFile, os.O_RDONLY, 0)
	if err != nil {
		return "", nil, err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxRollbackPackageBytes {
		_ = f.Close()
		return "", nil, errors.New("invalid rollback package snapshot")
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(f, maxRollbackPackageBytes+1))
	_ = f.Close()
	if err != nil || n != info.Size() || hex.EncodeToString(hash.Sum(nil)) != tx.doc.PackageSHA256 {
		return "", nil, errors.New("rollback package snapshot checksum mismatch")
	}
	images := make([]conffileImage, 0, len(tx.doc.Configs))
	total := 0
	for _, conf := range tx.doc.Configs {
		image := conffileImage{path: conf.Path, mode: os.FileMode(conf.Mode), exists: conf.Exists}
		if conf.Exists {
			image.data, err = root.ReadLimited(conf.Blob, maxConffileBytes)
			if err != nil || digest(image.data) != conf.SHA256 {
				return "", nil, errors.New("configuration snapshot checksum mismatch")
			}
			total += len(image.data)
		}
		if total > maxConffileBytes {
			return "", nil, errors.New("configuration snapshot exceeds bound")
		}
		images = append(images, image)
	}
	return filepath.Join(path, tx.doc.PackageFile), images, nil
}

func (tx *updateTransaction) authority(ctx context.Context, guard func(context.Context) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if guard != nil {
		return guard(ctx)
	}
	return nil
}
