package updatecheck

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"

	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

type NodeHistoryReader func(nodestore.PrivateSnapshot) (int, error)

// CORE supplies the typed VLESS history reader. This read-only scan never
// opens a live Store, imports a backup, or clears a pending restore journal.
func RequiredRetainedNodeHistoryReadVersion(ctx context.Context, configRoot, stateRoot string, read NodeHistoryReader) (int, error) {
	if read == nil || !filepath.IsAbs(configRoot) || !filepath.IsAbs(stateRoot) {
		return 0, ErrFileProtocol
	}
	required, entries := 1, 0
	inspect := func(data []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		version, err := read(nodestore.PrivateSnapshot{Content: json.RawMessage(data), SHA256: digestBytes(data)})
		// Node history has its own reader range; self-update receipt evolution
		// must never advertise a future node-history capability by accident.
		if err != nil || !knownNodeHistoryReadVersion(version) {
			return ErrFileProtocol
		}
		if version > required {
			required = version
		}
		return nil
	}
	for _, base := range []string{configRoot, stateRoot} {
		if _, err := os.Lstat(base); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return 0, err
		}
		root, err := ownedfs.Open(base)
		if err != nil {
			return 0, err
		}
		err = filepath.WalkDir(base, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			entries++
			if entries > 20000 || entry.Type()&os.ModeSymlink != 0 {
				return ErrFileProtocol
			}
			if entry.IsDir() {
				return nil
			}
			name := entry.Name()
			if name != "nodes.private.json" && name != "private-snapshot.json" && name != "restore.private.json" {
				return nil
			}
			rel, err := filepath.Rel(base, path)
			if err != nil || !filepath.IsLocal(rel) {
				return ErrFileProtocol
			}
			limit := int64(4 << 20)
			if name == "private-snapshot.json" {
				limit = 6 << 20
			}
			if name == "restore.private.json" {
				limit = 12 << 20
			}
			data, err := root.ReadLimited(rel, limit)
			if err != nil {
				return err
			}
			switch name {
			case "nodes.private.json":
				return inspect(data)
			case "private-snapshot.json":
				var snapshot privateFileSnapshot
				hash, err := root.ReadLimited(filepath.Join(filepath.Dir(rel), "private-snapshot.sha256"), 64)
				if err != nil || string(hash) != digestBytes(data) || decodeFileProtocol(data, &snapshot) != nil || validatePrivateSnapshot(snapshot) != nil {
					return ErrFileProtocol
				}
				return inspectNodeDirectory(snapshot.Images["nodes"], inspect)
			case "restore.private.json":
				return inspectRetainedRestoreNodes(data, inspect)
			}
			return nil
		})
		closeErr := root.Close()
		if err != nil {
			return 0, err
		}
		if closeErr != nil {
			return 0, closeErr
		}
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return required, nil
}

func inspectNodeDirectory(image restorejournal.Image, inspect func([]byte) error) error {
	tree, err := validateDirectoryImage(image)
	if err != nil {
		return err
	}
	for _, item := range tree.Entries {
		if !item.Directory && filepath.Base(item.Name) == "nodes.private.json" {
			if err := inspect(item.Data); err != nil {
				return err
			}
		}
	}
	return nil
}

type retainedRestoreNodeRecord struct {
	Target string               `json:"target"`
	Before restorejournal.Image `json:"before"`
	After  restorejournal.Image `json:"after"`
}
type retainedRestoreNodeJournal struct {
	Kind    string                      `json:"kind"`
	Schema  int                         `json:"schema"`
	Scope   string                      `json:"scope"`
	ID      string                      `json:"id"`
	State   string                      `json:"state"`
	Records []retainedRestoreNodeRecord `json:"records"`
	Digest  string                      `json:"digest"`
}

var retainedTargetPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,47}$`)

func inspectRetainedRestoreNodes(data []byte, inspect func([]byte) error) error {
	var journal retainedRestoreNodeJournal
	if decodeFileProtocol(data, &journal) != nil || journal.Kind != "razvilka-private-restore" || journal.Schema != 1 || !validDigest("sha256:"+journal.Scope) || !validDigest("sha256:"+journal.Digest) {
		return ErrFileProtocol
	}
	hash := journal.Digest
	journal.Digest = ""
	unsigned, err := json.Marshal(journal)
	if err != nil || hash != digestBytes(unsigned) {
		return ErrFileProtocol
	}
	if journal.State == "idle" {
		if journal.ID != "" || len(journal.Records) != 0 {
			return ErrFileProtocol
		}
		return nil
	}
	id, err := hex.DecodeString(journal.ID)
	if err != nil || len(id) != 16 || hex.EncodeToString(id) != journal.ID || (journal.State != "prepared" && journal.State != "committed") || len(journal.Records) == 0 || len(journal.Records) > restorejournal.MaxTargets {
		return ErrFileProtocol
	}
	total, last := 0, ""
	for _, record := range journal.Records {
		if !retainedTargetPattern.MatchString(record.Target) || record.Target <= last || (record.Before.Exists == record.After.Exists && bytes.Equal(record.Before.Data, record.After.Data)) {
			return ErrFileProtocol
		}
		last = record.Target
		for _, image := range []restorejournal.Image{record.Before, record.After} {
			if len(image.Data) > restorejournal.MaxImageBytes || (!image.Exists && len(image.Data) != 0) {
				return ErrFileProtocol
			}
			total += len(image.Data)
			if total > restorejournal.MaxPlanBytes {
				return ErrFileProtocol
			}
			if record.Target != "nodes" || !image.Exists {
				continue
			}
			// The directory format has explicit fields even for an empty tree.
			// Raw typed node snapshots use their own envelope instead.
			var keys map[string]json.RawMessage
			if json.Unmarshal(image.Data, &keys) != nil {
				return ErrFileProtocol
			}
			_, mode := keys["mode"]
			_, entries := keys["entries"]
			if mode || entries {
				if err := inspectNodeDirectory(image, inspect); err != nil {
					return err
				}
			} else if err := inspect(image.Data); err != nil {
				return err
			}
		}
	}
	return nil
}

// The owner validates complete canonical material, including unchecked XHTTP
// secrets. Checks alone cannot prove that a retained image is reader2-safe.
func validatedNodeHistoryRead(snapshot nodestore.PrivateSnapshot) (int, error) {
	return nodestore.RequiredPrivateHistoryReadVersion(snapshot)
}
