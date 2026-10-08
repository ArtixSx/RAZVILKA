package updatecheck

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"time"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

// Read-only concrete controller inventory shared by distinct typed format
// admissions. It conveys sealed image identity, never read or effect authority.
func retainedControllerImages(ctx context.Context, installation, stateRoot string) ([]selfupdatejournal.BinaryImage, error) {
	return retainedControllerImagesWithAdapter(ctx, installation, stateRoot, nil)
}

func retainedControllerImagesWithAdapter(ctx context.Context, installation, stateRoot string, reader *SelfUpdateFileAdapter) ([]selfupdatejournal.BinaryImage, error) {
	var images []selfupdatejournal.BinaryImage
	helperPresent := false
	helperID := ""
	filesPresent := false
	helper := filepath.Join(stateRoot, "self-update")
	if _, err := os.Lstat(helper); err == nil {
		root, err := ownedfs.Open(helper)
		if err != nil {
			return nil, err
		}
		data, readErr := root.ReadLimited("current.json", 64<<10)
		root.Close()
		if readErr != nil {
			return nil, ErrFileProtocol
		}
		var record updateRecord
		if decodeFileProtocol(data, &record) != nil || record.Owner != updaterOwner || !jobIDPattern.MatchString(record.Job.ID) || !terminalHelperState(record.Job.State) {
			return nil, ErrFileProtocol
		}
		helperPresent = true
		helperID = record.Job.ID
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	files := filepath.Join(stateRoot, "self-update-files")
	if _, err := os.Lstat(files); err == nil {
		if reader == nil {
			reader = NewSelfUpdateFileAdapter()
			reader.installation, reader.directory, reader.fileJournal = installation, helper, files
		}
		store, err := selfupdatejournal.OpenWithPairedEvidence(installation, files, reader.verifyPairedState)
		if err != nil {
			return nil, err
		}
		retained, err := store.RetainedBinaryImages(ctx)
		current, present, currentErr := store.Current()
		filesPresent = present
		store.Close()
		if err != nil || currentErr != nil {
			return nil, errors.Join(err, currentErr)
		}
		if helperPresent && (!present || helperID != current.ID) {
			return nil, ErrFileProtocol
		}
		images = append(images, retained...)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if helperPresent && !filesPresent {
		return nil, ErrFileProtocol
	}
	legacy := filepath.Join(stateRoot, "update-backups")
	if _, err := os.Lstat(legacy); err == nil {
		root, err := ownedfs.Open(legacy)
		if err != nil {
			return nil, err
		}
		defer root.Close()
		parent, err := os.OpenRoot(legacy)
		if err != nil {
			return nil, err
		}
		defer parent.Close()
		directory, err := parent.Open(".")
		if err != nil {
			return nil, err
		}
		defer directory.Close()
		entries, err := directory.ReadDir(258)
		if err != nil && err != io.EOF {
			return nil, err
		}
		if len(entries) > 257 {
			return nil, ErrFileProtocol
		}
		for _, entry := range entries {
			if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
				return nil, ErrFileProtocol
			}
			name := filepath.Join(entry.Name(), "razvilka.bin")
			if _, err := root.Stat(name); errors.Is(err, os.ErrNotExist) {
				continue
			} else if err != nil {
				return nil, err
			}
			sha, err := root.ReadLimited(filepath.Join(entry.Name(), "razvilka.sha256"), 64)
			// Historical manifests have no binary digest. They are preserved,
			// and cannot silently supply capability for any new typed write.
			if err != nil || !validDigest("sha256:"+string(sha)) {
				return nil, ErrFileProtocol
			}
			images = append(images, selfupdatejournal.BinaryImage{Path: filepath.Join(legacy, name), SHA256: string(sha)})
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	sort.Slice(images, func(i, j int) bool { return images[i].Path < images[j].Path })
	return images, ctx.Err()
}

func probeRetainedControllerFlag(ctx context.Context, image selfupdatejournal.BinaryImage, flag string) (string, error) {
	// Execute only a bounded copy of the independently sealed image. Never
	// chmod an immutable old/new image or execute an unsealed backup in place.
	root, err := ownedfs.Open(filepath.Dir(image.Path))
	if err != nil {
		return "", err
	}
	defer root.Close()
	data, err := root.ReadLimited(filepath.Base(image.Path), MaximumBinaryBytes)
	if err != nil || digestBytes(data) != image.SHA256 {
		return "", ErrFileProtocol
	}
	temporary, err := os.MkdirTemp("", "razvilka-history-reader-")
	if err != nil {
		return "", err
	}
	defer os.Remove(temporary)
	path := filepath.Join(temporary, "controller")
	defer os.Remove(path)
	if err := os.WriteFile(path, data, 0700); err != nil {
		return "", err
	}
	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	command := exec.CommandContext(probeCtx, path, flag)
	command.Env = commandEnvironment()
	out := &cappedOutput{maximum: 16}
	stderr := &cappedOutput{maximum: 1024}
	command.Stdout = out
	command.Stderr = stderr
	if err := runBoundedCommand(command); err != nil || stderr.Len() != 0 {
		return "", ErrFileProtocol
	}
	return out.String(), ctx.Err()
}
