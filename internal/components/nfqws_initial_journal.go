package components

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"time"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

const NFQWSInitialInstallSchema = 4
const nfqwsInitialPrepared = "initial-install-prepared"
const nfqwsInitialStarted = "initial-install-started"
const nfqwsInitialAccepted = "initial-install-verified-idle"
const nfqwsInitialArchiveName = "nfqws2-keenetic_1.3.1_razvilka-inert.ipk"
const nfqwsInitialDerivation = "inert-s51-and-root-owner-v1"

type nfqwsInitialInstallTransaction struct {
	SourceSHA256   string `json:"source_sha256"`
	SourceSize     int64  `json:"source_size"`
	DerivedSHA256  string `json:"derived_sha256"`
	DerivedSize    int64  `json:"derived_size"`
	InitSHA256     string `json:"init_sha256"`
	Owner          string `json:"owner"`
	Architecture   string `json:"architecture"`
	StatusSHA256   string `json:"status_sha256"`
	InstallationID string `json:"installation_id"`
	Sequence       uint64 `json:"sequence"`
	Revision       uint64 `json:"revision"`
	ReadbackSHA256 string `json:"readback_sha256,omitempty"`
	Derivation     string `json:"derivation"`
}

func validateNFQWSInitialJournal(doc updateJournal) error {
	v := doc.NFQWSInitialInstall
	if v == nil || doc.SchemaVersion != NFQWSInitialInstallSchema || doc.Component != "nfqws2" || doc.Package != "nfqws2-keenetic" ||
		!bundleHash(doc.TransactionID, 32) || doc.BeforeVersion != "absent" || doc.AfterVersion != "1.3.1" || doc.PackageFile != nfqwsInitialArchiveName ||
		doc.PackageSHA256 != v.DerivedSHA256 || !bundleHash(v.DerivedSHA256, 64) || v.DerivedSHA256 == nfqwsInitialSourceSHA || v.DerivedSize < 1 || v.DerivedSize > 4<<20 ||
		v.SourceSHA256 != nfqwsInitialSourceSHA || v.SourceSize != nfqwsInitialSourceSize || !bundleHash(v.InitSHA256, 64) || !bundleHash(v.Owner, 24) || !bundleHash(v.StatusSHA256, 64) ||
		!bundleHash(v.InstallationID, 32) || v.Sequence == 0 || v.Derivation != nfqwsInitialDerivation || doc.SupervisionVersion != 1 || len(doc.Configs) != 0 || doc.CandidateSnapshot || len(doc.CandidateConfigs) != 0 || doc.ManagedNFQWS != nil {
		return ErrNFQWSInitialInstall
	}
	if _, ok := nfqwsInitialArchitectures[v.Architecture]; !ok {
		return ErrNFQWSInitialInstall
	}
	if _, err := time.Parse(time.RFC3339Nano, doc.UpdatedAt); err != nil {
		return ErrNFQWSInitialInstall
	}
	switch doc.Phase {
	case nfqwsInitialPrepared, nfqwsInitialStarted:
		if v.ReadbackSHA256 != "" {
			return ErrNFQWSInitialInstall
		}
	case nfqwsInitialAccepted:
		if !bundleHash(v.ReadbackSHA256, 64) {
			return ErrNFQWSInitialInstall
		}
	default:
		return ErrNFQWSInitialInstall
	}
	return nil
}

func (tx *updateTransaction) loadNFQWSInitialArchive(ctx context.Context) (string, error) {
	if validateNFQWSInitialJournal(tx.doc) != nil {
		return "", ErrNFQWSInitialInstall
	}
	root, err := openUpdateRoot(filepath.Join(tx.manager.updateJournalDir(), tx.doc.TransactionID), false)
	if err != nil {
		return "", err
	}
	defer root.Close()
	data, err := root.ReadLimited(nfqwsInitialArchiveName, 4<<20)
	if err != nil || int64(len(data)) != tx.doc.NFQWSInitialInstall.DerivedSize || digest(data) != tx.doc.NFQWSInitialInstall.DerivedSHA256 {
		return "", errors.Join(ErrNFQWSInitialInstall, err)
	}
	// Re-prove provenance from the retained pristine source, not a derived hash DTO.
	source, err := root.ReadLimited("upstream.ipk", nfqwsInitialSourceSize+1)
	if err != nil {
		return "", err
	}
	archive, err := rebuildNFQWSInitialArchive(ctx, source, tx.doc.NFQWSInitialInstall.Owner)
	if err != nil || digest(archiveBytes(archive)) != digest(data) {
		return "", ErrNFQWSInitialInstall
	}
	manifest, err := root.ReadLimited("derivation.json", 4096)
	if err != nil || !bytes.Equal(manifest, nfqwsInitialDerivationManifest(tx.doc.NFQWSInitialInstall)) {
		return "", ErrNFQWSInitialInstall
	}
	return filepath.Join(tx.manager.updateJournalDir(), tx.doc.TransactionID, nfqwsInitialArchiveName), nil
}

func nfqwsInitialDerivationManifest(v *nfqwsInitialInstallTransaction) []byte {
	data, _ := json.Marshal(struct {
		SourceURL     string `json:"source_url"`
		SourceSHA256  string `json:"source_sha256"`
		SourceSize    int64  `json:"source_size"`
		DerivedSHA256 string `json:"derived_sha256"`
		DerivedSize   int64  `json:"derived_size"`
		InitSHA256    string `json:"inert_s51_sha256"`
		Transform     string `json:"transform"`
		Ownership     string `json:"ownership_normalization"`
	}{nfqwsInitialSourceURL, v.SourceSHA256, v.SourceSize, v.DerivedSHA256, v.DerivedSize, v.InitSHA256, v.Derivation, "all reviewed archive entries UID/GID 0:0; owner names root; paths/modes/content preserved except deterministic inert S51"})
	return data
}

func archiveBytes(a *nfqwsInitialArchive) []byte {
	if a == nil {
		return nil
	}
	return a.bytes
}

func nfqwsInitialOwner(state string) string {
	b, _ := hex.DecodeString(digest([]byte("RAZVILKA inert NFQWS2 installer v1\x00" + state + "\x00" + nfqwsInitialSourceSHA)))
	return hex.EncodeToString(b[:12])
}

type nfqwsInitialJournalWriter struct {
	target *restorejournal.FileTarget
	image  restorejournal.Image
}

func (tx *updateTransaction) initialWriter(ctx context.Context) (*nfqwsInitialJournalWriter, error) {
	target, err := restorejournal.OpenFileTarget(filepath.Join(tx.manager.updateJournalDir(), "current.json"))
	if err != nil {
		return nil, err
	}
	image, err := target.Read(ctx)
	if err != nil {
		target.Close()
		return nil, err
	}
	if image.Exists {
		var doc updateJournal
		if strictJSON(image.Data, &doc) != nil || validateUpdateJournal(doc) != nil || !updateTerminal(doc.Phase) {
			target.Close()
			return nil, ErrUpdatePending
		}
	}
	return &nfqwsInitialJournalWriter{target, image}, nil
}

func (w *nfqwsInitialJournalWriter) phase(ctx context.Context, tx *updateTransaction, phase string) error {
	return w.phaseGuarded(ctx, tx, phase, nil)
}

func (w *nfqwsInitialJournalWriter) phaseGuarded(ctx context.Context, tx *updateTransaction, phase string, guard func() error) error {
	if err := tx.fault("before:" + phase); err != nil {
		return err
	}
	if guard != nil {
		if err := guard(); err != nil {
			return err
		}
	}
	tx.doc.Phase, tx.doc.UpdatedAt = phase, time.Now().UTC().Format(time.RFC3339Nano)
	if validateNFQWSInitialJournal(tx.doc) != nil {
		return ErrNFQWSInitialInstall
	}
	data, err := json.Marshal(tx.doc)
	if err != nil {
		return err
	}
	after := restorejournal.Image{Exists: true, Data: append(data, '\n')}
	if err := w.target.CompareAndSwap(ctx, w.image, after); err != nil {
		return err
	}
	w.image = after
	return tx.fault("after:" + phase)
}
