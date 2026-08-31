package cloudflareprovider

import (
	"context"
	"errors"
	"time"

	"github.com/ArtixSx/razvilka/internal/privatebackup"
)

var ErrBackup = errors.New("invalid Cloudflare private backup or password; no snapshots were changed")
var ErrConflict = errors.New("Cloudflare snapshot ID conflicts with an existing copy; restore was not applied")

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
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	payload, err := privatebackup.Decrypt(envelope, password)
	if err != nil {
		return nil, ErrBackup
	}
	if len(payload.Services) != 0 || len(payload.EngineOrder) != 0 || len(payload.EngineFiles) != 0 || len(payload.CustomServices) != 0 || len(payload.Devices) != 0 {
		return nil, ErrBackup
	}
	restored := privateDocument{Schema: Schema, Owner: "razvilka"}
	for _, item := range payload.ProviderSnapshots {
		at, err := time.Parse(time.RFC3339Nano, item.ImportedAt)
		if err != nil || item.Provider != "cloudflare" {
			return nil, ErrBackup
		}
		restored.Accounts = append(restored.Accounts, storedAccount{ID: item.ID, Kind: item.SourceKind, Raw: []byte(item.Content), Digest: item.SHA256, ImportedAt: at})
	}
	if validateDocument(restored) != nil {
		return nil, ErrBackup
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
	index := map[string]storedAccount{}
	for _, record := range doc.Accounts {
		index[record.ID] = record
	}
	var views []Account
	changed := false
	for _, record := range restored.Accounts {
		if before, ok := index[record.ID]; ok {
			if before.Kind != record.Kind || before.Digest != record.Digest {
				return nil, ErrConflict
			}
			record = before
		} else {
			doc.Accounts = append(doc.Accounts, record)
			changed = true
		}
		parsed, _ := ParseImport(record.Kind, record.Raw)
		views = append(views, accountView(record, parsed))
	}
	if changed {
		if err := s.commit(ctx, doc); err != nil {
			return nil, err
		}
	}
	return views, nil
}
