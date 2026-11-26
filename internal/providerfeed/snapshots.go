package providerfeed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const snapshotDirectory = "feed-snapshots"
const maxSnapshotDiskBytes = 8 << 20
const maxSnapshotFiles = 64

// Small metadata lives in the existing CAS document. Bodies remain private,
// immutable files; changing only a cursor never rewrites a megabyte of keys.
type feedSnapshot struct {
	Digest    string    `json:"digest"`
	Size      int       `json:"size"`
	Entries   int       `json:"entries"`
	Cursor    int       `json:"cursor"`
	FetchedAt time.Time `json:"fetched_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

func snapshotDigest(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func validSnapshot(s *feedSnapshot) bool {
	return s == nil || len(s.Digest) == 64 && strings.Trim(s.Digest, "0123456789abcdef") == "" && s.Size > 0 && s.Size <= MaxBytes && s.Entries > 0 && s.Entries <= MaxEntries && s.Cursor >= 0 && s.Cursor <= s.Entries && !s.FetchedAt.IsZero() && s.ExpiresAt.After(s.FetchedAt) && s.ExpiresAt.Sub(s.FetchedAt) <= OriginTTL
}
func snapshotName(id string, s *feedSnapshot) string {
	return filepath.Join(snapshotDirectory, "feed-"+snapshotDigest([]byte(id))+"-"+s.Digest+".private")
}
func (m *Manager) readSnapshotLocked(id string, s *feedSnapshot) ([]byte, error) {
	if s == nil || !validSnapshot(s) || m.storage == nil || m.storage.blobs == nil {
		return nil, ErrStore
	}
	name := snapshotName(id, s)
	info, err := m.storage.blobs.Stat(name)
	if err != nil || !info.Mode().IsRegular() || info.Size() != int64(s.Size) || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return nil, ErrStore
	}
	raw, err := m.storage.blobs.ReadLimited(name, MaxBytes)
	if err != nil || len(raw) != s.Size || snapshotDigest(raw) != s.Digest {
		return nil, ErrStore
	}
	return raw, nil
}

func snapshotFileName(name string) bool {
	return len(name) == 5+64+1+64+8 && strings.HasPrefix(name, "feed-") && strings.HasSuffix(name, ".private") && name[69] == '-' && strings.Trim(name[5:69]+name[70:134], "0123456789abcdef") == ""
}

// The directory is descriptor-anchored. Never follow links or sweep a parent
// directory; only complete content-addressed files belonging to this cache.
func (m *Manager) snapshotFilesLocked() ([]os.DirEntry, error) {
	f, err := m.storage.blobs.OpenFile(snapshotDirectory, os.O_RDONLY, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, ErrStore
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.IsDir() || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return nil, ErrStore
	}
	entries, err := f.ReadDir(maxSnapshotFiles + 1)
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > maxSnapshotFiles {
		return nil, ErrSize
	}
	return entries, nil
}

func (m *Manager) pruneSnapshotsLocked() error {
	entries, err := m.snapshotFilesLocked()
	if err != nil {
		return err
	}
	keep := map[string]bool{}
	for _, s := range m.storage.doc.States {
		if s.Snapshot != nil {
			keep[snapshotName(s.State.SourceID, s.Snapshot)] = true
		}
	}
	var readBytes int64
	for _, entry := range entries {
		name := filepath.Join(snapshotDirectory, entry.Name())
		if !snapshotFileName(entry.Name()) || keep[name] {
			continue
		}
		info, err := m.storage.blobs.Stat(name)
		if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > MaxBytes {
			continue
		}
		readBytes += info.Size()
		if readBytes > maxSnapshotDiskBytes {
			return ErrSize
		}
		raw, err := m.storage.blobs.ReadLimited(name, MaxBytes)
		if err != nil || snapshotDigest(raw) != entry.Name()[70:134] {
			continue
		}
		if err := m.storage.blobs.Remove(name); err != nil {
			return ErrStore
		}
	}
	return nil
}

func (m *Manager) writeSnapshotLocked(ctx context.Context, id string, s *feedSnapshot, raw []byte) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if !validSnapshot(s) || s == nil || len(raw) != s.Size || snapshotDigest(raw) != s.Digest {
		return ErrStore
	}
	if err := m.pruneSnapshotsLocked(); err != nil {
		return err
	}
	if err := m.storage.blobs.MkdirAll(snapshotDirectory, 0700); err != nil {
		return ErrStore
	}
	entries, err := m.snapshotFilesLocked()
	if err != nil {
		return err
	}
	name := snapshotName(id, s)
	bytes := int64(0)
	for _, entry := range entries {
		info, err := m.storage.blobs.Stat(filepath.Join(snapshotDirectory, entry.Name()))
		if err != nil || !info.Mode().IsRegular() {
			return ErrStore
		}
		if info.Size() < 0 || info.Size() > maxSnapshotDiskBytes {
			return ErrSize
		}
		bytes += info.Size()
	}
	repair := false
	var replacedBytes int64
	if info, err := m.storage.blobs.Stat(name); err == nil {
		replacedBytes = info.Size()
		if _, err = m.readSnapshotLocked(id, s); err == nil {
			return nil
		}
		// A fresh full response may repair a corrupt cache already referenced
		// by our leased manifest. Never replace a same-named foreign orphan.
		for _, old := range m.storage.doc.States {
			if old.Snapshot != nil && snapshotName(old.State.SourceID, old.Snapshot) == name {
				repair = true
				break
			}
		}
		if !repair {
			return ErrStore
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrStore
	}
	if !repair && len(entries) >= maxSnapshotFiles || bytes-replacedBytes+int64(len(raw)) > maxSnapshotDiskBytes {
		return ErrSize
	}
	if err := m.storage.blobs.WriteAtomic(name, raw, 0600); err != nil {
		return ErrStore
	}
	if runtime.GOOS != "windows" {
		f, err := m.storage.blobs.OpenFile(snapshotDirectory, os.O_RDONLY, 0)
		if err != nil {
			return ErrStore
		}
		err = f.Sync()
		_ = f.Close()
		if err != nil {
			return ErrStore
		}
		if err := m.storage.blobs.Sync(); err != nil {
			return ErrStore
		}
	}
	return nil
}
