package dataplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
)

type nfqws2InactiveImage struct {
	info   os.FileInfo
	digest [32]byte
}
type nfqws2InactiveFiles map[string]nfqws2InactiveImage

func (a nfqws2InactiveFiles) same(b nfqws2InactiveFiles) bool {
	if len(a) != len(b) {
		return false
	}
	for path, before := range a {
		after, exists := b[path]
		if !exists || before.digest != after.digest || (before.info == nil) != (after.info == nil) {
			return false
		}
		if before.info != nil && (!os.SameFile(before.info, after.info) || before.info.Mode() != after.info.Mode() ||
			before.info.Size() != after.info.Size() || !before.info.ModTime().Equal(after.info.ModTime())) {
			return false
		}
	}
	return true
}

func nfqws2ReadInactiveFiles(ctx context.Context, a *NFQWS2Adapter, platform nfqws2InactivePlatform) (nfqws2InactiveFiles, error) {
	if ctx == nil || ctx.Err() != nil || a == nil || platform.protected == nil {
		return nil, ErrNFQWSManagedProcessUnknown
	}
	images := nfqws2InactiveFiles{}
	// An absent child is anchored to its actual first existing protected parent.
	// For the private runtime subtree that parent must itself be private.
	anchor := func(path string, private bool) error {
		for steps := 0; steps < 32; steps++ {
			info, err := os.Lstat(path)
			if errors.Is(err, os.ErrNotExist) {
				images[path] = nfqws2InactiveImage{}
				parent := filepath.Dir(path)
				if parent == path {
					return ErrNFQWSManagedProcessUnknown
				}
				path = parent
				continue
			}
			if err != nil || !platform.protected(info, true, private) {
				return ErrNFQWSManagedProcessUnknown
			}
			images[path] = nfqws2InactiveImage{info: info}
			return nil
		}
		return ErrNFQWSManagedProcessUnknown
	}
	readWith := func(path string, private bool, protected func(os.FileInfo, bool, bool) bool) ([]byte, bool, error) {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		if err := anchor(filepath.Dir(path), private); err != nil {
			return nil, false, err
		}
		before, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			images[path] = nfqws2InactiveImage{}
			return nil, false, nil
		}
		if err != nil || !protected(before, false, private) {
			return nil, false, ErrNFQWSManagedProcessUnknown
		}
		file, err := os.Open(path)
		if err != nil {
			return nil, false, ErrNFQWSManagedProcessUnknown
		}
		defer file.Close()
		opened, err := file.Stat()
		if err != nil || !os.SameFile(before, opened) {
			return nil, false, ErrNFQWSManagedProcessUnknown
		}
		raw, readErr := io.ReadAll(io.LimitReader(file, (8<<20)+1))
		after, statErr := os.Lstat(path)
		if readErr != nil || statErr != nil || len(raw) > 8<<20 || ctx.Err() != nil || !protected(after, false, private) || !os.SameFile(opened, after) ||
			after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) || after.Mode() != before.Mode() || int64(len(raw)) != before.Size() {
			return nil, false, ErrNFQWSManagedProcessUnknown
		}
		images[path] = nfqws2InactiveImage{info: after, digest: sha256.Sum256(raw)}
		return raw, true, nil
	}
	read := func(path string, private bool) ([]byte, bool, error) {
		return readWith(path, private, platform.protected)
	}
	// RAZVILKA writes a list only as root and only while it holds a block
	// there. A block-free stock list proves nothing of ours runs, whoever owns
	// the file (the package installs them as its own user).
	listProtected := platform.protected
	if platform.foreignList != nil {
		listProtected = func(info os.FileInfo, directory, _ bool) bool { return !directory && platform.foreignList(info) }
	}
	if err := anchor(a.StateRoot, true); err != nil {
		return nil, err
	}
	info := images[a.StateRoot].info
	if info != nil {
		dir, err := os.Open(a.StateRoot)
		if err != nil {
			return nil, ErrNFQWSManagedProcessUnknown
		}
		opened, statErr := dir.Stat()
		entries, readErr := dir.ReadDir(3)
		_ = dir.Close()
		if statErr != nil || !os.SameFile(info, opened) || readErr != nil && !errors.Is(readErr, io.EOF) || len(entries) > 2 {
			return nil, ErrNFQWSManagedProcessUnknown
		}
		key := nfqws2Hash([]byte(nfqws2LeaseFile))
		lock := ".state-" + key + ".lock"
		for _, entry := range entries {
			switch entry.Name() {
			case nfqws2LeaseFile:
				if _, _, err := read(filepath.Join(a.StateRoot, nfqws2LeaseFile), true); err != nil {
					return nil, err
				}
				// Keep the existing exact managed v2 Wait/ECHILD/parent ACK
				// proof. Legacy/v3/unknown or unsettled metadata refuses.
				if _, err := a.observeManagedNFQWSProcessInactive(ctx); err != nil {
					return nil, err
				}
			case lock:
				raw, present, err := read(filepath.Join(a.StateRoot, lock), true)
				if err != nil || !present || !bytes.Equal(raw, []byte("RAZVILKA state file writer v1 "+key+"\n")) {
					return nil, ErrNFQWSManagedProcessUnknown
				}
			default:
				return nil, ErrNFQWSManagedProcessUnknown
			}
		}
	}
	// Record the positively anchored lease absence even for a never-used or
	// successfully retired v3 participant. It still needs all independent reads.
	if _, exists := images[filepath.Join(a.StateRoot, nfqws2LeaseFile)]; !exists {
		if _, _, err := read(filepath.Join(a.StateRoot, nfqws2LeaseFile), true); err != nil {
			return nil, err
		}
	}
	lists := a.ownedListPaths()
	for _, path := range []string{a.ConfigPath, a.InitPath} {
		if _, _, err := read(path, false); err != nil {
			return nil, err
		}
	}
	for _, path := range lists {
		raw, _, err := readWith(path, false, listProtected)
		if err != nil {
			return nil, err
		}
		block, err := nfqws2Block(raw)
		if err != nil || len(block) != 0 {
			return nil, ErrNFQWSManagedProcessUnknown
		}
	}
	return images, ctx.Err()
}
