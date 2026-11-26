package components

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

func validMihomoRetainedJournal(raw []byte) bool {
	if !validHEVRetainedJournal(raw) {
		return false
	}
	var doc hevRetainedDocument
	if json.Unmarshal(raw, &doc) != nil {
		return false
	}
	for _, record := range doc.Records {
		if record.Target != "a_binary" {
			continue
		}
		for _, image := range []restorejournal.Image{record.Before, record.After} {
			if image.Exists {
				if _, err := mihomoArtifactReferenceOf(image); err != nil {
					return false
				}
			}
		}
	}
	return true
}

// The cache is a format-only observation. It grants no executable or cleanup
// ownership: actual consumers hash the complete held artifact themselves.
// Unpublished stage files survive a crash as inert private data, never sources
// for a journal reference or a process launch.
func inspectMihomoArtifactFormat(ctx context.Context, stateDirectory string, seal io.Writer) (present bool, err error) {
	path := filepath.Join(stateDirectory, "mihomo-artifacts-v1")
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
	if err != nil || !os.SameFile(initial, held) {
		return false, ErrRetainedManagedUpdate
	}
	entries, err := root.ReadDir(129)
	if err != nil || len(entries) > 128 {
		return false, ErrRetainedManagedUpdate
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	observed := map[string]os.FileInfo{}
	fmt.Fprintf(seal, "mihomo-artifacts-v1\x00%s\x00%d\x00", owner, initial.Mode())
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 {
			return false, ErrRetainedManagedUpdate
		}
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		name := entry.Name()
		info, e := root.Stat(name)
		if e != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > ownedfs.MaxAtomicArtifactBytes {
			return false, ErrRetainedManagedUpdate
		}
		if strings.HasSuffix(name, ".bin") && hevRetainedHash(strings.TrimSuffix(name, ".bin")) {
			if !mihomoArtifactOwner(info) || info.Size() < 1 {
				return false, ErrRetainedManagedUpdate
			}
		} else {
			nonce := strings.TrimPrefix(name, ".mihomo-stage-")
			_, private := hevRetainedOwner(info, false)
			stage := nonce != name && len(nonce) == 26 && strings.Trim(nonce, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") == "" && private && info.Mode().Perm() == 0600
			transaction := strings.TrimPrefix(name, ".transaction-")
			atomicStage := transaction != name && len(transaction) == 32 && strings.Trim(transaction, "0123456789abcdef") == "" && mihomoArtifactOwner(info)
			if !stage && !atomicStage {
				return false, ErrRetainedManagedUpdate
			}
		}
		observed[name] = info
		fmt.Fprintf(seal, "%s\x00%d\x00%d\x00%d\x00%s\x00", name, info.Mode(), info.Size(), info.ModTime().UnixNano(), mihomoFileIdentity(info))
	}
	closing, e := os.Lstat(path)
	held, e2 := root.RootInfo()
	closingOwner, ok := hevRetainedOwner(closing, true)
	if e != nil || e2 != nil || !ok || closingOwner != owner || !os.SameFile(initial, closing) || !os.SameFile(initial, held) || ctx.Err() != nil {
		return false, ErrRetainedManagedUpdate
	}
	end, e := root.ReadDir(129)
	if e != nil || len(end) != len(entries) {
		return false, ErrRetainedManagedUpdate
	}
	for _, entry := range end {
		if entry.Type()&os.ModeSymlink != 0 {
			return false, ErrRetainedManagedUpdate
		}
		before := observed[entry.Name()]
		after, e := root.Stat(entry.Name())
		if before == nil || e != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
			return false, ErrRetainedManagedUpdate
		}
	}
	return true, nil
}

func inspectMihomoRetained(ctx context.Context, stateDirectory string, seal io.Writer) (bool, error) {
	journal, err := inspectReleaseRetained(ctx, stateDirectory, "mihomo-release-v1", validMihomoRetainedJournal, seal)
	if err != nil {
		return false, err
	}
	cache, err := inspectMihomoArtifactFormat(ctx, stateDirectory, seal)
	if err != nil || journal && !cache {
		return false, ErrRetainedManagedUpdate
	}
	return journal || cache, nil
}
