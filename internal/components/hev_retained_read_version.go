package components

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

const HEVReleaseReadVersion = 5
const hevRetainedMarker = "RAZVILKA private restore writer v1\n"
const hevRetainedMaxJournal = 12 << 20

// This is a format reader, never a recovery consumer. Trusted configured
// StateDir selects the one closed journal. Images cannot supply paths or code.
type hevRetainedDocument struct {
	Kind    string              `json:"kind"`
	Schema  int                 `json:"schema"`
	Scope   string              `json:"scope"`
	ID      string              `json:"id"`
	State   string              `json:"state"`
	Records []hevRetainedRecord `json:"records"`
	Digest  string              `json:"digest"`
}
type hevRetainedRecord struct {
	Target string               `json:"target"`
	Before restorejournal.Image `json:"before"`
	After  restorejournal.Image `json:"after"`
}

func validHEVRetainedJournal(raw []byte) bool {
	var doc hevRetainedDocument
	if json.Unmarshal(raw, &doc) != nil {
		return false
	}
	canonical, err := json.Marshal(doc)
	if err != nil || !bytes.Equal(raw, canonical) {
		return false
	}
	if doc.Kind != "razvilka-private-restore" || doc.Schema != 1 || !hevRetainedHash(doc.Scope) || !hevRetainedHash(doc.Digest) {
		return false
	}
	claimed := doc.Digest
	doc.Digest = ""
	unsigned, _ := json.Marshal(doc)
	if digest(unsigned) != claimed {
		return false
	}
	if doc.State == "idle" {
		return doc.ID == "" && len(doc.Records) == 0
	}
	id, err := hex.DecodeString(doc.ID)
	if err != nil || len(id) != 16 || hex.EncodeToString(id) != doc.ID || doc.State != "prepared" && doc.State != "committed" || len(doc.Records) == 0 || len(doc.Records) > 3 {
		return false
	}
	total, last := 0, ""
	for _, record := range doc.Records {
		if record.Target <= last || record.Target != "a_binary" && record.Target != "b_receipt" && record.Target != "c_lifecycle" {
			return false
		}
		last = record.Target
		for _, image := range []restorejournal.Image{record.Before, record.After} {
			if len(image.Data) > restorejournal.MaxImageBytes || !image.Exists && len(image.Data) != 0 {
				return false
			}
			total += len(image.Data)
		}
		if record.Before.Exists == record.After.Exists && bytes.Equal(record.Before.Data, record.After.Data) {
			return false
		}
	}
	return total <= restorejournal.MaxPlanBytes
}
func hevRetainedHash(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == value
}

func inspectHEVRetained(ctx context.Context, stateDirectory string, seal io.Writer) (present bool, err error) {
	return inspectReleaseRetained(ctx, stateDirectory, "hev-release-v1", validHEVRetainedJournal, seal)
}

// Both closed release formats use the same original private journal container;
// the caller supplies the format-specific image validator, never import paths.
func inspectReleaseRetained(ctx context.Context, stateDirectory, journalName string, validJournal func([]byte) bool, seal io.Writer) (present bool, err error) {
	path := filepath.Join(stateDirectory, journalName)
	initial, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	owner, ok := hevRetainedOwner(initial, true)
	if err != nil || !ok {
		return false, ErrRetainedManagedUpdate
	}
	root, err := ownedfs.Open(path)
	if err != nil {
		return false, ErrRetainedManagedUpdate
	}
	defer func() {
		if root.Close() != nil {
			present, err = false, ErrRetainedManagedUpdate
		}
	}()
	held, err := root.RootInfo()
	if err != nil || !os.SameFile(initial, held) || initial.Mode() != held.Mode() {
		return false, ErrRetainedManagedUpdate
	}
	entries, err := root.ReadDir(3)
	if err != nil || len(entries) == 0 || len(entries) > 2 {
		return false, ErrRetainedManagedUpdate
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	observed := map[string]os.FileInfo{}
	fmt.Fprintf(seal, "%s\x00%s\x00%d\x00", journalName, owner, initial.Mode())
	markerFound := false
	for _, entry := range entries {
		if ctx.Err() != nil || entry.Name() != ".restore.lock" && entry.Name() != "restore.private.json" {
			return false, ErrRetainedManagedUpdate
		}
		before, err := root.Stat(entry.Name())
		owner, ok := hevRetainedOwner(before, false)
		if err != nil || !ok {
			return false, ErrRetainedManagedUpdate
		}
		limit := int64(hevRetainedMaxJournal)
		if entry.Name() == ".restore.lock" {
			limit = 256
		}
		raw, err := readHEVRetainedFile(root, entry.Name(), limit, before)
		if err != nil {
			return false, ErrRetainedManagedUpdate
		}
		after, err := root.Stat(entry.Name())
		closingOwner, closingOK := hevRetainedOwner(after, false)
		if err != nil || !closingOK || owner != closingOwner || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
			return false, ErrRetainedManagedUpdate
		}
		observed[entry.Name()] = after
		if entry.Name() == ".restore.lock" {
			if string(raw) != hevRetainedMarker {
				return false, ErrRetainedManagedUpdate
			}
			markerFound = true
		} else if !validJournal(raw) {
			return false, ErrRetainedManagedUpdate
		}
		fmt.Fprintf(seal, "%s\x00%s\x00%d\x00%d\x00%d\x00", entry.Name(), owner, before.Mode(), before.Size(), before.ModTime().UnixNano())
		if _, err := seal.Write(raw); err != nil {
			return false, ErrRetainedManagedUpdate
		}
	}
	closing, err := os.Lstat(path)
	closingHeld, heldErr := root.RootInfo()
	closingOwner, closingOK := hevRetainedOwner(closing, true)
	if err != nil || heldErr != nil || !closingOK || closingOwner != owner || !os.SameFile(initial, closing) || !os.SameFile(initial, closingHeld) || initial.Mode() != closing.Mode() || ctx.Err() != nil || !markerFound {
		return false, ErrRetainedManagedUpdate
	}
	closingEntries, err := root.ReadDir(3)
	if err != nil || len(closingEntries) != len(entries) {
		return false, ErrRetainedManagedUpdate
	}
	sort.Slice(closingEntries, func(i, j int) bool { return closingEntries[i].Name() < closingEntries[j].Name() })
	for i := range entries {
		if entries[i].Name() != closingEntries[i].Name() {
			return false, ErrRetainedManagedUpdate
		}
		before := observed[entries[i].Name()]
		after, err := root.Stat(entries[i].Name())
		beforeOwner, _ := hevRetainedOwner(before, false)
		afterOwner, ok := hevRetainedOwner(after, false)
		if err != nil || !ok || beforeOwner != afterOwner || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
			return false, ErrRetainedManagedUpdate
		}
	}
	return true, nil
}

func readHEVRetainedFile(root *ownedfs.Root, name string, limit int64, before os.FileInfo) (raw []byte, err error) {
	f, err := root.OpenFile(name, hevRetainedReadFlags, 0)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	actual, err := f.Stat()
	owner, ok := hevRetainedOwner(actual, false)
	expected, _ := hevRetainedOwner(before, false)
	if err != nil || !ok || owner != expected || !os.SameFile(before, actual) || before.Mode() != actual.Mode() || before.Size() != actual.Size() || !before.ModTime().Equal(actual.ModTime()) {
		return nil, ErrRetainedManagedUpdate
	}
	raw, err = io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, ErrRetainedManagedUpdate
	}
	return raw, nil
}
