package nativeaccept

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

const accountLimit = 8 << 20
const executableLimit = 256 << 20

func realPath(path string) error {
	real, err := filepath.EvalSymlinks(path)
	if err != nil || real != path {
		return errors.New("asset-path-not-canonical")
	}
	return nil
}

func hashExecutable(ctx context.Context, r Request) error {
	if ctx.Err() != nil || realPath(r.Binary) != nil {
		return errors.New("executable-unavailable")
	}
	before, err := os.Lstat(r.Binary)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0o022 != 0 || before.Mode().Perm()&0o111 == 0 || before.Size() <= 0 || before.Size() > executableLimit {
		return errors.New("executable-unavailable")
	}
	f, err := os.Open(r.Binary)
	if err != nil {
		return err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return errors.New("executable-changed")
	}
	h := sha256.New()
	buffer := make([]byte, 64<<10)
	defer clear(buffer)
	var total int64
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		n, readErr := f.Read(buffer)
		total += int64(n)
		if total > executableLimit {
			return errors.New("executable-too-large")
		}
		_, _ = h.Write(buffer[:n])
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	after, statErr := os.Lstat(r.Binary)
	if statErr != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) ||
		hex.EncodeToString(h.Sum(nil)) != r.BinarySHA256 || ctx.Err() != nil {
		return errors.New("executable-pin-changed")
	}
	return nil
}

func readAccount(ctx context.Context, r Request) ([]byte, error) {
	if ctx.Err() != nil || realPath(r.Account) != nil {
		return nil, errors.New("account-unavailable")
	}
	root, err := ownedfs.Open(filepath.Dir(r.Account))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	name := filepath.Base(r.Account)
	before, err := root.Stat(name)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0o077 != 0 || before.Size() <= 0 || before.Size() > accountLimit {
		return nil, errors.New("account-not-private-regular-file")
	}
	data, err := root.ReadLimited(name, accountLimit)
	after, statErr := root.Stat(name)
	if err != nil || statErr != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) ||
		routeidentity.Hash(data) != r.AccountSHA256 || ctx.Err() != nil {
		clear(data)
		return nil, errors.New("account-pin-changed")
	}
	return data, nil
}

func loadAssets(ctx context.Context, r Request) ([]byte, error) {
	if err := hashExecutable(ctx, r); err != nil {
		return nil, err
	}
	return readAccount(ctx, r)
}

type ownedStage struct {
	parent               *ownedfs.Root
	root                 *os.Root
	parentInfo, rootInfo os.FileInfo
	configInfo           os.FileInfo
	request              Request
	path, name           string
}

func stageAssets(ctx context.Context, r Request, data []byte) (stagedAssets, error) {
	if ctx.Err() != nil || realPath(r.WorkParent) != nil {
		return nil, errors.New("staging-parent-unavailable")
	}
	parentInfo, err := os.Lstat(r.WorkParent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("staging-parent-not-private")
	}
	parent, err := ownedfs.Open(r.WorkParent)
	if err != nil {
		return nil, err
	}
	name, err := parent.MkdirTemp(".", "usque-native-")
	if err != nil {
		_ = parent.Close()
		return nil, err
	}
	s := &ownedStage{parent: parent, parentInfo: parentInfo, request: r, name: name, path: filepath.Join(r.WorkParent, name)}
	s.rootInfo, err = parent.Stat(name)
	if err != nil {
		return s, err
	}
	s.root, err = os.OpenRoot(s.path)
	if err != nil {
		return s, err
	}
	if err := s.checkIncarnation(ctx); err != nil {
		return s, err
	}
	// Exclusive creation records this exact secret file's incarnation, including
	// partial write failures. We never overwrite/adopt an existing engine.json.
	f, err := s.root.OpenFile("engine.json", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return s, err
	}
	s.configInfo, err = f.Stat()
	if err == nil {
		err = f.Chmod(0o600)
	}
	if err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil || ctx.Err() != nil {
		return s, errors.New("staged-config-write-failed")
	}
	return s, s.Verify(ctx)
}

func (s *ownedStage) Path() string { return s.path }

func (s *ownedStage) checkIncarnation(ctx context.Context) error {
	if ctx.Err() != nil || s.root == nil || s.rootInfo == nil || realPath(s.path) != nil {
		return errors.New("staged-root-unavailable")
	}
	parentInfo, a := os.Lstat(s.request.WorkParent)
	rootInfo, b := os.Lstat(s.path)
	anchored, c := s.parent.Stat(s.name)
	descriptor, d := s.root.Stat(".")
	if a != nil || b != nil || c != nil || d != nil || !os.SameFile(parentInfo, s.parentInfo) || !os.SameFile(rootInfo, s.rootInfo) || !os.SameFile(anchored, s.rootInfo) || !os.SameFile(descriptor, s.rootInfo) {
		return errors.New("staged-root-replaced")
	}
	return nil
}

func (s *ownedStage) Verify(ctx context.Context) error {
	if s.checkIncarnation(ctx) != nil || s.configInfo == nil || hashExecutable(ctx, s.request) != nil {
		return errors.New("staged-assets-changed")
	}
	info, err := s.root.Lstat("engine.json")
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(info, s.configInfo) || info.Mode().Perm()&0o077 != 0 {
		return errors.New("staged-config-replaced")
	}
	f, err := s.root.Open("engine.json")
	if err != nil {
		return err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(opened, s.configInfo) {
		return errors.New("staged-config-changed-while-opening")
	}
	data, err := io.ReadAll(io.LimitReader(f, accountLimit+1))
	defer clear(data)
	after, statErr := s.root.Lstat("engine.json")
	if err != nil || statErr != nil || !os.SameFile(after, s.configInfo) || len(data) > accountLimit || routeidentity.Hash(data) != s.request.AccountSHA256 || ctx.Err() != nil {
		return errors.New("staged-config-pin-changed")
	}
	return nil
}

func (s *ownedStage) RemoveSecret(ctx context.Context) error {
	if err := s.checkIncarnation(ctx); err != nil {
		return err
	}
	if s.configInfo != nil {
		info, err := s.root.Lstat("engine.json")
		if err != nil || !os.SameFile(info, s.configInfo) {
			return errors.New("staged-secret-replaced")
		}
		if err := s.root.Remove("engine.json"); err != nil {
			return err
		}
	} else if _, err := s.root.Lstat("engine.json"); !errors.Is(err, os.ErrNotExist) {
		return errors.New("staged-secret-not-owned")
	}
	// Remove only an empty directory we just created. CORE may retain logs and
	// receipts; those stay private. Never recursively clear or delete other files.
	_ = s.parent.Remove(s.name)
	return ctx.Err()
}

func (s *ownedStage) Close() error {
	var rootErr error
	if s.root != nil {
		rootErr = s.root.Close()
		s.root = nil
	}
	parentErr := s.parent.Close()
	return errors.Join(rootErr, parentErr)
}
