package components

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// All callbacks are trusted CORE wiring, never JSON. Review must admit writing
// schema3 across the actual current/candidate/retained controller set. The CLI
// capability stays2 until that consumer is wired and accepted by Root.
// Check/Admit bind the frozen installation+epoch+revision, including recovery;
// an active Stop cannot be exchanged for a freshly read authority token.
type ManagedNFQWSBundleAuthority struct {
	InstallationID string
	Sequence       uint64
	ReaderVersion  int
	Check          func(context.Context, string, uint64, uint64, int) error
	Admit          func(context.Context, string /* transaction ID */, string /* installation ID */, uint64, uint64, string, func() error) error
	Inactive       func(context.Context) error // actual OWN managed runtime; stock remains foreign
}

type ManagedNFQWSBundleReceipt struct {
	Schema         int    `json:"schema"`
	ProviderID     string `json:"provider_id"`
	TransactionID  string `json:"transaction_id"`
	ManifestSHA256 string `json:"manifest_sha256"`
	GenerationPath string `json:"generation_path"`
	Flavor         string `json:"flavor"`
	State          string `json:"state"` // ready-idle describes files, never runtime health
}

type managedNFQWSTransaction struct {
	InstallationID string                     `json:"installation_id"`
	Sequence       uint64                     `json:"sequence"`
	Revision       uint64                     `json:"revision"`
	Stage          string                     `json:"stage"`
	Manifest       ManagedNFQWSManifest       `json:"manifest"`
	After          ManagedNFQWSBundleReceipt  `json:"after"`
	Before         *ManagedNFQWSBundleReceipt `json:"before,omitempty"`
}

func validManagedNFQWSReceipt(r ManagedNFQWSBundleReceipt) bool {
	return r.Schema == 1 && r.ProviderID == ManagedNFQWSProvider && bundleHash(r.TransactionID, 32) && bundleHash(r.ManifestSHA256, 64) && r.Flavor != "" && r.State == "ready-idle" && filepath.IsAbs(r.GenerationPath) && filepath.Clean(r.GenerationPath) == r.GenerationPath && filepath.Base(r.GenerationPath) == r.ManifestSHA256
}

func validateManagedNFQWSJournal(doc updateJournal) error {
	v := doc.ManagedNFQWS
	// Configuration revision zero is the actual freshly persisted Store
	// preimage. Its mandatory canonical JSON field distinguishes it from
	// missing/null data; the control epoch still requires a positive sequence.
	if v == nil || doc.SchemaVersion != ManagedNFQWSJournalSchema || doc.Component != "nfqws2" || !bundleHash(doc.TransactionID, 32) || doc.Package != "" || doc.PackageFile != "" || doc.PackageSHA256 != "" || len(doc.Configs) != 0 || doc.CandidateSnapshot || len(doc.CandidateConfigs) != 0 || doc.SupervisionVersion != 0 || !bundleHash(v.InstallationID, 32) || v.Sequence == 0 || v.Stage != ".stage-"+doc.TransactionID || !validManagedNFQWSReceipt(v.After) || v.After.TransactionID != doc.TransactionID {
		return ErrManagedNFQWSBundle
	}
	hash, err := v.Manifest.Digest()
	if err != nil || hash != v.After.ManifestSHA256 || v.Manifest.Flavor != v.After.Flavor || doc.AfterVersion != v.After.Flavor {
		return ErrManagedNFQWSBundle
	}
	before := "absent"
	if v.Before != nil {
		if !validManagedNFQWSReceipt(*v.Before) || filepath.Dir(v.Before.GenerationPath) != filepath.Dir(v.After.GenerationPath) {
			return ErrManagedNFQWSBundle
		}
		before = v.Before.Flavor
	}
	if doc.BeforeVersion != before {
		return ErrManagedNFQWSBundle
	}
	if _, err := time.Parse(time.RFC3339Nano, doc.UpdatedAt); err != nil {
		return ErrManagedNFQWSBundle
	}
	switch doc.Phase {
	case UpdatePrepared, UpdateStarted, UpdateInstalled, UpdateAwaitingLive, UpdateAcceptedIdle, UpdateRollbackStarted, UpdateRolledBack, UpdateAbandoned:
	default:
		return ErrManagedNFQWSBundle
	}
	return nil
}

func (a ManagedNFQWSBundleAuthority) check(ctx context.Context, v *managedNFQWSTransaction) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if a.ReaderVersion != ManagedNFQWSJournalSchema || a.Check == nil || a.Admit == nil || a.Inactive == nil || !bundleHash(a.InstallationID, 32) || a.Sequence == 0 || v == nil || a.InstallationID != v.InstallationID || a.Sequence != v.Sequence {
		return ErrRecoveryAuthority
	}
	if err := a.Check(ctx, v.InstallationID, v.Sequence, v.Revision, ManagedNFQWSJournalSchema); err != nil {
		return err
	}
	return a.Inactive(ctx)
}

func (a ManagedNFQWSBundleAuthority) admit(ctx context.Context, v *managedNFQWSTransaction, effect string, begin func() error) error {
	if err := a.check(ctx, v); err != nil {
		return err
	}
	if !bundleHash(v.After.TransactionID, 32) {
		return ErrRecoveryAuthority
	}
	return a.Admit(ctx, v.After.TransactionID, v.InstallationID, v.Sequence, v.Revision, effect, begin)
}

func (m *Manager) managedNFQWSLocation() (string, string, error) {
	base, relative := "/opt", filepath.FromSlash("lib/razvilka/nfqws2/releases")
	if m.nfqwsReleases != "" {
		base, relative = filepath.Dir(m.nfqwsReleases), filepath.Base(m.nfqwsReleases)
	}
	// Resolve only the reviewed mount/test base. Reject every symlink below
	// it, so an app-owned intermediate path cannot redirect writes to stock.
	canonicalBase, err := filepath.EvalSymlinks(base)
	if err != nil {
		return "", "", err
	}
	return canonicalBase, relative, nil
}

func (m *Manager) managedNFQWSRoot(create bool) (string, *ownedfs.Root, error) {
	canonicalBase, relative, err := m.managedNFQWSLocation()
	if err != nil {
		return "", nil, err
	}
	if err := m.publicManagedNFQWSPath(filepath.Join(canonicalBase, relative), create); err != nil {
		return "", nil, err // reject existing foreign/private/writable ancestors before mkdir
	}
	baseRoot, err := ownedfs.Open(canonicalBase)
	if err != nil {
		return "", nil, err
	}
	defer baseRoot.Close()
	if err := baseRoot.Check(relative); err != nil {
		return "", nil, err
	}
	if create {
		if err := baseRoot.MkdirAll(relative, 0755); err != nil {
			return "", nil, err
		}
		// Persist every possibly new ancestor entry, including the mount base.
		for parent := filepath.Dir(relative); parent != "."; parent = filepath.Dir(parent) {
			r, err := ownedfs.Open(filepath.Join(canonicalBase, parent))
			if err != nil {
				return "", nil, err
			}
			err = syncUpdateDirectory(r)
			r.Close()
			if err != nil {
				return "", nil, err
			}
		}
		if err := syncUpdateDirectory(baseRoot); err != nil {
			return "", nil, err
		}
	}
	path := filepath.Join(canonicalBase, relative)
	// /opt may be the reviewed Entware mount symlink. The owned releases root
	// itself must be a real directory; descriptor paths resolve its mount once.
	root, err := ownedfs.Open(path)
	if err != nil {
		return "", nil, err
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil {
		root.Close()
		return "", nil, err
	}
	info, err := os.Stat(canonical)
	opened, openErr := os.OpenRoot(path)
	if err != nil || openErr != nil {
		root.Close()
		return "", nil, errors.Join(err, openErr)
	}
	anchored, statErr := opened.Stat(".")
	opened.Close()
	if statErr != nil || !os.SameFile(info, anchored) {
		root.Close()
		return "", nil, ErrManagedNFQWSBundle
	}
	if err := m.publicManagedNFQWSPath(canonical, false); err != nil {
		root.Close()
		return "", nil, err
	}
	if create {
		parent, err := ownedfs.Open(filepath.Dir(canonical))
		if err != nil {
			root.Close()
			return "", nil, err
		}
		err = syncUpdateDirectory(parent)
		parent.Close()
		if err != nil {
			root.Close()
			return "", nil, err
		}
	}
	return canonical, root, nil
}

func (m *Manager) managedNFQWSInventory(create bool) (*ownedfs.Root, error) {
	path := filepath.Join(m.StateDir, "receipts")
	if m.StateDir == "" {
		return nil, ErrManagedNFQWSBundle
	}
	if create {
		parent, err := ownedfs.Open(m.StateDir)
		if err != nil {
			return nil, err
		}
		err = parent.MkdirAll("receipts", 0700)
		if err == nil {
			err = syncUpdateDirectory(parent)
		}
		parent.Close()
		if err != nil {
			return nil, err
		}
	}
	return ownedfs.Open(path)
}

const managedNFQWSReceiptName = "nfqws2-managed.json"

func readManagedNFQWSReceipt(root *ownedfs.Root) (*ManagedNFQWSBundleReceipt, []byte, error) {
	data, err := root.ReadLimited(managedNFQWSReceiptName, 4096)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	var receipt ManagedNFQWSBundleReceipt
	if json.Unmarshal(data, &receipt) != nil || !validManagedNFQWSReceipt(receipt) {
		return nil, nil, ErrManagedNFQWSBundle
	}
	canonical, _ := json.Marshal(receipt)
	if !bytes.Equal(data, canonical) {
		return nil, nil, ErrManagedNFQWSBundle
	}
	return &receipt, data, nil
}

func (m *Manager) reviewManagedNFQWS(manifest ManagedNFQWSManifest) error {
	if _, err := manifest.bytes(); err != nil {
		return err
	}
	if m.nfqwsReview != nil {
		return m.nfqwsReview(manifest)
	}
	approved, err := ReviewedManagedNFQWSManifest(m.Arch)
	if err != nil {
		return err
	}
	a, _ := approved.bytes()
	b, _ := manifest.bytes()
	if !bytes.Equal(a, b) {
		return ErrManagedNFQWSBundle
	}
	return nil
}

func (m *Manager) downloadManagedNFQWS(ctx context.Context, manifest ManagedNFQWSManifest) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, defaultDuration(m.Timeout, 90*time.Second))
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, manifest.ParentAssetURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept-Encoding", "identity")
	client := m.Client
	if client == nil {
		client = releaseHTTPClient()
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Request == nil || !bundleHTTPS(response.Request.URL.String()) || (response.ContentLength >= 0 && response.ContentLength != manifest.ParentAssetSize) {
		return nil, ErrManagedNFQWSBundle
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, manifest.ParentAssetSize+1))
	if err != nil || int64(len(data)) != manifest.ParentAssetSize || digest(data) != manifest.ParentSHA256 {
		return nil, errors.Join(ErrManagedNFQWSBundle, err)
	}
	return data, ctx.Err()
}

func (m *Manager) InstallManagedBundle(ctx context.Context, manifest ManagedNFQWSManifest, expectedRevision uint64, authority ManagedNFQWSBundleAuthority) (ManagedNFQWSBundleReceipt, error) {
	return m.installManagedNFQWS(ctx, manifest, expectedRevision, authority, false)
}

func (m *Manager) UpdateManagedBundle(ctx context.Context, manifest ManagedNFQWSManifest, expectedRevision uint64, authority ManagedNFQWSBundleAuthority) (ManagedNFQWSBundleReceipt, error) {
	return m.installManagedNFQWS(ctx, manifest, expectedRevision, authority, true)
}

func (m *Manager) installManagedNFQWS(ctx context.Context, manifest ManagedNFQWSManifest, revision uint64, authority ManagedNFQWSBundleAuthority, update bool) (ManagedNFQWSBundleReceipt, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var zero ManagedNFQWSBundleReceipt
	if m.reviewManagedNFQWS(manifest) != nil {
		return zero, ErrManagedNFQWSBundle
	}
	v := &managedNFQWSTransaction{InstallationID: authority.InstallationID, Sequence: authority.Sequence, Revision: revision, Manifest: manifest}
	if err := authority.check(ctx, v); err != nil {
		return zero, NoMutation(err)
	}
	if err := m.PreflightManagedNFQWS(ctx); err != nil {
		return zero, NoMutation(err) // no journal initialization or download on an unsafe mount
	}
	tx, err := m.lockUpdateJournal()
	if err != nil {
		return zero, NoMutation(err)
	}
	defer tx.close()
	if err := tx.requireIdle(); err != nil {
		return zero, NoMutation(err)
	}
	path, releases, err := m.managedNFQWSRoot(true)
	if err != nil {
		return zero, err
	}
	defer releases.Close()
	inventory, err := m.managedNFQWSInventory(true)
	if err != nil {
		return zero, err
	}
	defer inventory.Close()
	v.Before, _, err = readManagedNFQWSReceipt(inventory)
	if err != nil || update != (v.Before != nil) {
		return zero, errors.Join(ErrManagedNFQWSBundle, err)
	}
	hash, _ := manifest.Digest()
	if v.Before != nil {
		if filepath.Dir(v.Before.GenerationPath) != path {
			return zero, ErrManagedNFQWSBundle
		}
		if _, err := m.verifyManagedNFQWSTerminal(ctx, *v.Before); err != nil {
			return zero, err
		}
		if v.Before.ManifestSHA256 == hash {
			return *v.Before, authority.check(ctx, v)
		}
	}
	data, err := m.downloadManagedNFQWS(ctx, manifest)
	if err != nil {
		return zero, err
	}
	payload, err := extractManagedNFQWS(ctx, manifest, data)
	if err != nil {
		return zero, err
	}
	stage, err := releases.MkdirTemp(".", ".stage-")
	if err != nil {
		return zero, err
	}
	id := strings.TrimPrefix(stage, ".stage-")
	v.Stage = stage
	v.After = ManagedNFQWSBundleReceipt{1, ManagedNFQWSProvider, id, hash, filepath.Join(path, hash), manifest.Flavor, "ready-idle"}
	if err := stageManagedNFQWS(ctx, filepath.Join(path, v.Stage), manifest, payload); err != nil {
		return zero, err
	}
	if err := syncUpdateDirectory(releases); err != nil {
		return zero, err
	}
	if err := authority.check(ctx, v); err != nil {
		return zero, err
	}
	before := "absent"
	if v.Before != nil {
		before = v.Before.Flavor
	}
	tx.doc = updateJournal{ManagedUpdateState: ManagedUpdateState{SchemaVersion: ManagedNFQWSJournalSchema, TransactionID: id, Component: "nfqws2", BeforeVersion: before, AfterVersion: manifest.Flavor}, ManagedNFQWS: v}
	if err := tx.phase(UpdatePrepared); err != nil {
		return zero, err
	}
	return m.continueManagedNFQWS(ctx, tx, authority)
}

func (m *Manager) continueManagedNFQWS(ctx context.Context, tx *updateTransaction, a ManagedNFQWSBundleAuthority) (ManagedNFQWSBundleReceipt, error) {
	var zero ManagedNFQWSBundleReceipt
	v := tx.doc.ManagedNFQWS
	if err := validateManagedNFQWSJournal(tx.doc); err != nil {
		return zero, err
	}
	if err := a.check(ctx, v); err != nil {
		return zero, err
	}
	path, releases, err := m.managedNFQWSRoot(false)
	if err != nil {
		return zero, err
	}
	defer releases.Close()
	if filepath.Dir(v.After.GenerationPath) != path {
		return zero, ErrManagedNFQWSBundle
	}
	if tx.doc.Phase == UpdatePrepared {
		if _, err := m.verifyManagedNFQWSImage(ctx, filepath.Join(path, v.Stage), v.After.ManifestSHA256, managedNFQWSPrivateStage); err != nil {
			return zero, err
		}
		if err := tx.phase(UpdateStarted); err != nil {
			return zero, err
		}
	}
	if tx.doc.Phase == UpdateStarted {
		if _, err := releases.Stat(v.After.ManifestSHA256); errors.Is(err, os.ErrNotExist) {
			if _, err := m.verifyStartedManagedNFQWSStage(ctx, tx.doc, path); err != nil {
				return zero, err
			}
			publish := m.nfqwsPublish
			if publish == nil {
				publish = publishManagedNFQWS
			}
			if err := tx.fault("before:bundle-generation"); err != nil {
				return zero, err
			}
			if err := publish(ctx, path, v.Stage, v.After.ManifestSHA256, func(begin func() error) error { return a.admit(ctx, v, "nfqws-publish-generation", begin) }, tx.fault); err != nil {
				return zero, err
			}
			if err := syncUpdateDirectory(releases); err != nil {
				return zero, err
			}
			if err := tx.fault("after:bundle-generation"); err != nil {
				return zero, err
			}
		} else if err != nil {
			return zero, err
		}
		if _, err := m.verifyManagedNFQWS(ctx, v.After.GenerationPath, v.After.ManifestSHA256); err != nil {
			return zero, err
		}
		if err := a.check(ctx, v); err != nil {
			return zero, err
		}
		if err := tx.phase(UpdateInstalled); err != nil {
			return zero, err
		}
	}
	if tx.doc.Phase == UpdateInstalled {
		if err := tx.phase(UpdateAwaitingLive); err != nil {
			return zero, err
		}
	}
	if tx.doc.Phase != UpdateAwaitingLive && tx.doc.Phase != UpdateAcceptedIdle {
		return zero, ErrUpdatePending
	}
	if _, err := m.verifyManagedNFQWS(ctx, v.After.GenerationPath, v.After.ManifestSHA256); err != nil {
		return zero, err
	}
	if err := m.publishManagedNFQWSReceipt(ctx, tx, a, false); err != nil {
		return zero, err
	}
	if err := a.check(ctx, v); err != nil {
		return zero, err
	}
	if _, err := m.verifyManagedNFQWS(ctx, v.After.GenerationPath, v.After.ManifestSHA256); err != nil {
		return zero, err
	}
	if err := archiveManagedNFQWS(tx, UpdateAcceptedIdle); err != nil {
		return zero, err
	}
	if tx.doc.Phase != UpdateAcceptedIdle {
		if err := tx.phase(UpdateAcceptedIdle); err != nil {
			return zero, err
		}
	}
	return v.After, a.check(ctx, v)
}

func (m *Manager) publishManagedNFQWSReceipt(ctx context.Context, tx *updateTransaction, a ManagedNFQWSBundleAuthority, rollback bool) error {
	v := tx.doc.ManagedNFQWS
	root, err := m.managedNFQWSInventory(false)
	if err != nil {
		return err
	}
	defer root.Close()
	_, current, err := readManagedNFQWSReceipt(root)
	if err != nil {
		return err
	}
	before := []byte(nil)
	if v.Before != nil {
		before, _ = json.Marshal(v.Before)
	}
	after, _ := json.Marshal(v.After)
	wanted := after
	if rollback {
		wanted = before
	}
	if !bytes.Equal(current, before) && !bytes.Equal(current, after) {
		return ErrManagedNFQWSBundle // preserve third image
	}
	if bytes.Equal(current, wanted) {
		return a.check(ctx, v)
	}
	if err := a.check(ctx, v); err != nil {
		return err
	}
	effect := "nfqws-publish-receipt"
	if rollback {
		effect = "nfqws-rollback-receipt"
		if len(wanted) == 0 {
			effect = "nfqws-remove-receipt"
		}
	}
	name := ".nfqws-receipt-" + tx.doc.TransactionID
	if len(wanted) > 0 {
		// Staged bytes/fsync are outside the short actual-effect admission.
		if existing, err := root.ReadLimited(name, 4096); err == nil {
			if !bytes.Equal(existing, wanted) {
				return ErrManagedNFQWSBundle
			}
		} else if errors.Is(err, os.ErrNotExist) {
			if err := bundleWrite(root, name, wanted, 0600); err != nil {
				return err
			}
		} else {
			return err
		}
	}
	if err := tx.fault("before:" + effect); err != nil {
		return err
	}
	// Same permanent writer lease covers this CAS and every component writer.
	_, fresh, err := readManagedNFQWSReceipt(root)
	if err != nil || !bytes.Equal(fresh, current) {
		return errors.Join(ErrManagedNFQWSBundle, err)
	}
	fs, err := os.OpenRoot(filepath.Join(m.StateDir, "receipts"))
	if err != nil {
		return err
	}
	defer fs.Close()
	if err := a.admit(ctx, v, effect, func() error {
		if len(wanted) == 0 {
			return fs.Remove(managedNFQWSReceiptName)
		}
		return fs.Rename(name, managedNFQWSReceiptName)
	}); err != nil {
		return err
	}
	if err := syncUpdateDirectory(root); err != nil {
		return err
	}
	_, actual, err := readManagedNFQWSReceipt(root)
	if err != nil || !bytes.Equal(actual, wanted) {
		return errors.Join(ErrManagedNFQWSBundle, err)
	}
	return tx.fault("after:" + effect)
}

func archiveManagedNFQWS(tx *updateTransaction, phase string) error {
	doc := tx.doc
	doc.Phase = phase
	name := filepath.Join(doc.TransactionID, "managed-"+phase+".json")
	if err := tx.root.MkdirAll(doc.TransactionID, 0700); err != nil {
		return err
	}
	if err := syncUpdateDirectory(tx.root); err != nil {
		return err
	}
	if data, err := tx.root.ReadLimited(name, 64<<10); err == nil {
		var old updateJournal
		if json.Unmarshal(data, &old) != nil || validateManagedNFQWSJournal(old) != nil {
			return ErrManagedNFQWSBundle
		}
		doc.UpdatedAt = old.UpdatedAt
		expected, _ := json.Marshal(doc)
		if !bytes.Equal(data, expected) {
			return ErrManagedNFQWSBundle
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	data, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	if err := bundleWrite(tx.root, name, data, 0600); err != nil {
		return err
	}
	root, err := ownedfs.Open(filepath.Join(tx.manager.updateJournalDir(), doc.TransactionID))
	if err != nil {
		return err
	}
	defer root.Close()
	return syncUpdateDirectory(root)
}

// Only local complete-image CAS is resumed. No external package, hook, or
// runtime command can be replayed. Rollback preserves all immutable generations.
func (m *Manager) RecoverManagedBundle(ctx context.Context, transactionID, action string, authority ManagedNFQWSBundleAuthority) (ManagedNFQWSBundleReceipt, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var zero ManagedNFQWSBundleReceipt
	tx, err := m.lockUpdateJournal()
	if err != nil {
		return zero, err
	}
	defer tx.close()
	doc, present, err := readUpdateJournal(tx.root)
	if err != nil || !present || doc.ManagedNFQWS == nil || doc.TransactionID != transactionID {
		return zero, errors.Join(ErrUpdatePending, err)
	}
	tx.doc = doc
	v := doc.ManagedNFQWS
	if err := authority.check(ctx, v); err != nil {
		return zero, err
	}
	path, root, err := m.managedNFQWSRoot(false)
	if err != nil {
		return zero, err
	}
	root.Close()
	if filepath.Dir(v.After.GenerationPath) != path {
		return zero, ErrManagedNFQWSBundle
	}
	switch action {
	case "resume":
		return m.continueManagedNFQWS(ctx, tx, authority)
	case "rollback":
		if doc.Phase == UpdateRolledBack || doc.Phase == UpdateAbandoned {
			return zero, ErrUpdatePending
		}
		if v.Before != nil {
			if _, err := m.verifyManagedNFQWSTerminal(ctx, *v.Before); err != nil {
				return zero, err
			}
		}
		if doc.Phase != UpdateRollbackStarted {
			if err := tx.phase(UpdateRollbackStarted); err != nil {
				return zero, err
			}
		}
		if err := m.publishManagedNFQWSReceipt(ctx, tx, authority, true); err != nil {
			return zero, err
		}
		if err := authority.check(ctx, v); err != nil {
			return zero, err
		}
		if err := archiveManagedNFQWS(tx, UpdateRolledBack); err != nil {
			return zero, err
		}
		if err := tx.phase(UpdateRolledBack); err != nil {
			return zero, err
		}
		if err := authority.check(ctx, v); err != nil {
			return zero, err
		}
		if v.Before != nil {
			return *v.Before, nil
		}
		return zero, nil // exact prior absence restored, no runtime acceptance
	default:
		return zero, ErrRecoveryAuthority
	}
}

func (m *Manager) verifyManagedNFQWSTerminal(ctx context.Context, receipt ManagedNFQWSBundleReceipt) (ManagedNFQWSManifest, error) {
	var zero ManagedNFQWSManifest
	if !validManagedNFQWSReceipt(receipt) {
		return zero, ErrManagedNFQWSBundle
	}
	root, err := openUpdateRoot(m.updateJournalDir(), false)
	if err != nil {
		return zero, err
	}
	defer root.Close()
	data, err := root.ReadLimited(filepath.Join(receipt.TransactionID, "managed-"+UpdateAcceptedIdle+".json"), 64<<10)
	var doc updateJournal
	if err != nil || json.Unmarshal(data, &doc) != nil || validateManagedNFQWSJournal(doc) != nil || doc.Phase != UpdateAcceptedIdle || doc.ManagedNFQWS.After != receipt {
		return zero, ErrManagedNFQWSBundle
	}
	canonical, _ := json.Marshal(doc)
	if !bytes.Equal(data, canonical) {
		return zero, ErrManagedNFQWSBundle
	}
	path, releases, err := m.managedNFQWSRoot(false)
	if err != nil {
		return zero, err
	}
	releases.Close()
	if filepath.Dir(receipt.GenerationPath) != path {
		return zero, ErrManagedNFQWSBundle
	}
	return m.verifyManagedNFQWS(ctx, receipt.GenerationPath, receipt.ManifestSHA256)
}
