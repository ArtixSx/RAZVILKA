package components

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

var ErrRetainedManagedUpdate = errors.New("retained component formats are unavailable; preserve retained files")

// RequiredRetainedManagedUpdateReadVersion checks actual configured component
// metadata without creating a directory, taking its writer lease/Manager.mu,
// executing a command, or settling a pending transaction. Version 3 belongs
// only to the managed NFQWS journal/receipt, not to node or self-update formats.
func RequiredRetainedManagedUpdateReadVersion(ctx context.Context, stateDirectory string) (int, error) {
	version, _, err := InspectRetainedManagedUpdateReadVersion(ctx, stateDirectory)
	return version, err
}

// InspectRetainedManagedUpdateReadVersion additionally returns a comparison
// digest of the observed metadata for a reader admission's bookend checks.
// Neither this digest nor the version grants recovery or runtime authority.
// Physical generation/package verification remains with the actual consumer.
func InspectRetainedManagedUpdateReadVersion(ctx context.Context, stateDirectory string) (version int, seal string, err error) {
	if ctx == nil || !filepath.IsAbs(stateDirectory) || ctx.Err() != nil {
		return 0, "", ErrRetainedManagedUpdate
	}
	version = ComponentUpdateSchema
	hash := sha256.New()
	info, err := os.Lstat(stateDirectory)
	if errors.Is(err, os.ErrNotExist) {
		return version, hex.EncodeToString(hash.Sum(nil)), ctx.Err()
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return 0, "", ErrRetainedManagedUpdate
	}
	root, err := ownedfs.Open(stateDirectory)
	if err != nil {
		return 0, "", ErrRetainedManagedUpdate
	}
	defer func() {
		if root.Close() != nil {
			version, seal, err = 0, "", ErrRetainedManagedUpdate
		}
	}()
	var current *updateJournal
	archives := make(map[string]updateJournal)
	entries := 0
	journalPath := filepath.Join(stateDirectory, "update-journal")
	if journalInfo, err := os.Lstat(journalPath); !errors.Is(err, os.ErrNotExist) {
		if err != nil || !journalInfo.IsDir() || journalInfo.Mode()&os.ModeSymlink != 0 {
			return 0, "", ErrRetainedManagedUpdate
		}
		err = filepath.WalkDir(journalPath, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil || ctx.Err() != nil {
				return ErrRetainedManagedUpdate
			}
			entries++
			if entries > 20000 || entry.Type()&os.ModeSymlink != 0 {
				return ErrRetainedManagedUpdate
			}
			relative, err := filepath.Rel(stateDirectory, path)
			if err != nil || !filepath.IsLocal(relative) || root.Check(relative) != nil {
				return ErrRetainedManagedUpdate
			}
			stat, err := root.Stat(relative)
			if err != nil || !stat.IsDir() && !stat.Mode().IsRegular() {
				return ErrRetainedManagedUpdate
			}
			fmt.Fprintf(hash, "%s\x00%d\x00%d\x00%d\n", relative, stat.Mode(), stat.Size(), stat.ModTime().UnixNano())
			if entry.IsDir() {
				return nil
			}
			isCurrent := relative == filepath.Join("update-journal", "current.json")
			isArchive := strings.HasPrefix(entry.Name(), "managed-")
			if filepath.Dir(relative) == "update-journal" && !isCurrent && entry.Name() != ".writer.lock" {
				return ErrRetainedManagedUpdate
			}
			if !isCurrent && !isArchive {
				return nil
			}
			data, err := root.ReadLimited(relative, 64<<10)
			if err != nil {
				return ErrRetainedManagedUpdate
			}
			var doc updateJournal
			if rejectRepeatedComponentFields(data) != nil || strictJSON(data, &doc) != nil || validateUpdateJournal(doc) != nil || doc.SupervisionVersion < 0 || doc.SupervisionVersion > 1 {
				return ErrRetainedManagedUpdate
			}
			if doc.ManagedNFQWS != nil {
				canonical, _ := json.Marshal(doc)
				if !bytes.Equal(bytes.TrimSuffix(data, []byte{'\n'}), canonical) {
					return ErrRetainedManagedUpdate
				}
			}
			if isArchive {
				expected := filepath.Join("update-journal", doc.TransactionID, "managed-"+doc.Phase+".json")
				if doc.ManagedNFQWS == nil || relative != expected || doc.Phase != UpdateAcceptedIdle && doc.Phase != UpdateRolledBack || !bytes.Equal(data, bytes.TrimSuffix(data, []byte{'\n'})) {
					return ErrRetainedManagedUpdate
				}
				archives[relative] = doc
			} else {
				current = &doc
			}
			if doc.SchemaVersion > version {
				version = doc.SchemaVersion
			}
			hash.Write(data)
			return nil
		})
		if err != nil {
			return 0, "", ErrRetainedManagedUpdate
		}
	}
	linked := func(receipt ManagedNFQWSBundleReceipt) bool {
		name := filepath.Join("update-journal", receipt.TransactionID, "managed-"+UpdateAcceptedIdle+".json")
		doc, ok := archives[name]
		return ok && doc.ManagedNFQWS.After == receipt
	}
	for _, doc := range archives {
		if doc.ManagedNFQWS.Before != nil && !linked(*doc.ManagedNFQWS.Before) {
			return 0, "", ErrRetainedManagedUpdate
		}
	}
	if current != nil && current.ManagedNFQWS != nil {
		if current.ManagedNFQWS.Before != nil && !linked(*current.ManagedNFQWS.Before) {
			return 0, "", ErrRetainedManagedUpdate
		}
		if current.Phase == UpdateAcceptedIdle || current.Phase == UpdateRolledBack {
			name := filepath.Join("update-journal", current.TransactionID, "managed-"+current.Phase+".json")
			archive, ok := archives[name]
			if !ok || !sameComponentReadJournal(*current, archive) {
				return 0, "", ErrRetainedManagedUpdate
			}
		}
	}
	name := filepath.Join("receipts", managedNFQWSReceiptName)
	if info, err := root.Stat(name); !errors.Is(err, os.ErrNotExist) {
		if err != nil || !info.Mode().IsRegular() || info.Size() > 4096 {
			return 0, "", ErrRetainedManagedUpdate
		}
		data, readErr := root.ReadLimited(name, 4096)
		var receipt ManagedNFQWSBundleReceipt
		if err != nil || readErr != nil || strictJSON(data, &receipt) != nil || !validManagedNFQWSReceipt(receipt) {
			return 0, "", ErrRetainedManagedUpdate
		}
		canonical, _ := json.Marshal(receipt)
		if !bytes.Equal(data, canonical) {
			return 0, "", ErrRetainedManagedUpdate
		}
		pendingAfter := current != nil && current.ManagedNFQWS != nil && current.Phase == UpdateAwaitingLive && current.ManagedNFQWS.After == receipt
		if !linked(receipt) && !pendingAfter {
			return 0, "", ErrRetainedManagedUpdate
		}
		fmt.Fprintf(hash, "%s\x00", name)
		hash.Write(data)
		version = ManagedNFQWSJournalSchema
	}
	closing, closeErr := os.Lstat(stateDirectory)
	if closeErr != nil || !os.SameFile(info, closing) || root.Check("update-journal") != nil || ctx.Err() != nil {
		return 0, "", ErrRetainedManagedUpdate
	}
	return version, hex.EncodeToString(hash.Sum(nil)), nil
}

func sameComponentReadJournal(current, archive updateJournal) bool {
	// Current phase is written after the immutable terminal archive; each has
	// its own timestamp. Every other exact typed field must match.
	current.UpdatedAt = archive.UpdatedAt
	a, _ := json.Marshal(current)
	b, _ := json.Marshal(archive)
	return bytes.Equal(a, b)
}

func rejectRepeatedComponentFields(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	var value func(int) error
	value = func(depth int) error {
		if depth > 64 {
			return ErrRetainedManagedUpdate
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		seen := make(map[string]bool)
		for d.More() {
			if delimiter == '{' {
				key, err := d.Token()
				name, ok := key.(string)
				if err != nil || !ok || seen[name] {
					return ErrRetainedManagedUpdate
				}
				seen[name] = true
			}
			if err := value(depth + 1); err != nil {
				return err
			}
		}
		_, err = d.Token()
		return err
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrRetainedManagedUpdate
	}
	return nil
}
