package cloudflareprovider

import (
	"context"
	"errors"
	"time"

	"github.com/ArtixSx/razvilka/internal/privatebackup"
)

var ErrBackup = errors.New("invalid Cloudflare private backup or password; no snapshots were changed")
var ErrConflict = errors.New("Cloudflare snapshot ID conflicts with an existing copy; restore was not applied")
var ErrReview = errors.New("Cloudflare archive differs from the reviewed backup")

// BackupReview contains no credentials or raw account files.
type BackupReview struct {
	Digest   string `json:"digest"`
	Added    int    `json:"added"`
	Existing int    `json:"existing"`
	Total    int    `json:"total"`
}

// Backup returns ciphertext only, reusing the application's authenticated
// encrypted backup envelope. No plaintext export method is exposed by Store.
func (s *Store) Backup(ctx context.Context, password, version string) (privatebackup.Envelope, error) {
	s.mu.Lock()
	if err := ctx.Err(); err != nil {
		s.mu.Unlock()
		return privatebackup.Envelope{}, err
	}
	doc, err := s.load()
	s.mu.Unlock()
	if err != nil {
		return privatebackup.Envelope{}, err
	}
	if len(doc.Accounts) == 0 {
		return privatebackup.Envelope{}, ErrBackup
	}
	payload := privatebackup.NewPayload(version)
	for _, record := range doc.Accounts {
		payload.ProviderSnapshots = append(payload.ProviderSnapshots, privatebackup.ProviderSnapshot{Provider: "cloudflare", ID: record.ID, SourceKind: record.Kind, Content: string(record.Raw), SHA256: record.Digest, ImportedAt: record.ImportedAt.Format(time.RFC3339Nano)})
	}
	if privatebackup.Seal(&payload) != nil {
		return privatebackup.Envelope{}, ErrBackup
	}
	if err := ctx.Err(); err != nil {
		return privatebackup.Envelope{}, err
	}
	envelope, err := privatebackup.Encrypt(payload, password)
	if err != nil {
		return privatebackup.Envelope{}, ErrBackup
	}
	if err := ctx.Err(); err != nil {
		return privatebackup.Envelope{}, err
	}
	return envelope, nil
}

// RestoreBackup merges copies atomically. It neither deletes existing accounts
// nor replaces an ID with different credentials, and never activates a profile.
// A general router backup must use a coordinated restore, not this narrow API.
func (s *Store) RestoreBackup(ctx context.Context, envelope privatebackup.Envelope, password string) ([]Account, error) {
	return s.restoreBackup(ctx, envelope, password, "")
}

// RestoreReviewedBackup binds explicit restoration to the decrypted archive
// shown in the preview. Store conflicts and capacity are rechecked under lock.
func (s *Store) RestoreReviewedBackup(ctx context.Context, envelope privatebackup.Envelope, password, digest string) ([]Account, error) {
	if len(digest) != 64 {
		return nil, ErrReview
	}
	return s.restoreBackup(ctx, envelope, password, digest)
}

func decodeSnapshotBackup(ctx context.Context, envelope privatebackup.Envelope, password string) (privateDocument, string, error) {
	if err := ctx.Err(); err != nil {
		return privateDocument{}, "", err
	}
	payload, err := privatebackup.Decrypt(envelope, password)
	if err != nil {
		return privateDocument{}, "", ErrBackup
	}
	if err := ctx.Err(); err != nil {
		return privateDocument{}, "", err
	}
	if len(payload.ProviderSnapshots) == 0 || len(payload.Services) != 0 || len(payload.EngineOrder) != 0 || len(payload.EngineFiles) != 0 || len(payload.CustomServices) != 0 || len(payload.Devices) != 0 {
		return privateDocument{}, "", ErrBackup
	}
	restored := privateDocument{Schema: Schema, Owner: "razvilka"}
	for _, item := range payload.ProviderSnapshots {
		at, err := time.Parse(time.RFC3339Nano, item.ImportedAt)
		if err != nil || item.Provider != "cloudflare" {
			return privateDocument{}, "", ErrBackup
		}
		restored.Accounts = append(restored.Accounts, storedAccount{ID: item.ID, Kind: item.SourceKind, Raw: []byte(item.Content), Digest: item.SHA256, ImportedAt: at})
	}
	if validateDocument(restored) != nil {
		return privateDocument{}, "", ErrBackup
	}
	return restored, payload.Digest, nil
}

// PreviewBackup validates the whole archive and merge without creating a file
// or taking a persistent writer lock. The preview is not remote verification.
func (s *Store) PreviewBackup(ctx context.Context, envelope privatebackup.Envelope, password string) (BackupReview, error) {
	restored, digest, err := decodeSnapshotBackup(ctx, envelope, password)
	if err != nil {
		return BackupReview{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return BackupReview{}, err
	}
	doc, err := s.load()
	if err != nil {
		return BackupReview{}, err
	}
	_, _, review, err := mergeSnapshots(doc, restored)
	review.Digest = digest
	return review, err
}

func (s *Store) restoreBackup(ctx context.Context, envelope privatebackup.Envelope, password, expectedDigest string) ([]Account, error) {
	restored, digest, err := decodeSnapshotBackup(ctx, envelope, password)
	if err != nil {
		return nil, err
	}
	if expectedDigest != "" && expectedDigest != digest {
		return nil, ErrReview
	}
	release, err := s.lockWrite(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	doc, err := s.load()
	if err != nil {
		return nil, err
	}
	doc, views, review, err := mergeSnapshots(doc, restored)
	if err != nil {
		return nil, err
	}
	if review.Added > 0 {
		if err := s.commit(ctx, doc); err != nil {
			return nil, err
		}
	}
	return views, nil
}

func mergeSnapshots(doc, restored privateDocument) (privateDocument, []Account, BackupReview, error) {
	index := map[string]storedAccount{}
	for _, record := range doc.Accounts {
		index[record.ID] = record
	}
	var views []Account
	review := BackupReview{Total: len(restored.Accounts)}
	for _, record := range restored.Accounts {
		if before, ok := index[record.ID]; ok {
			if before.Kind != record.Kind || before.Digest != record.Digest {
				return privateDocument{}, nil, BackupReview{}, ErrConflict
			}
			record = before
			review.Existing++
		} else {
			doc.Accounts = append(doc.Accounts, record)
			review.Added++
		}
		parsed, _ := ParseImport(record.Kind, record.Raw)
		views = append(views, accountView(record, parsed))
	}
	if len(doc.Accounts) > MaxAccounts {
		return privateDocument{}, nil, BackupReview{}, ErrCapacity
	}
	return doc, views, review, nil
}
