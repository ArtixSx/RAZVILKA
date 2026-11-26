package dataplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/ArtixSx/razvilka/internal/cloudflareprovider"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/usquediag"
)

var ErrUSQUELiveSession = errors.New("saved USQUE session is unavailable, unsafe, or incompatible")

// USQUELiveSession identifies an existing engine slot. Reading one grants no
// registration, profile write, service check, or route authority.
type USQUELiveSession struct {
	configs *engineconfig.Manager
	path    string
	file    os.FileInfo
	sum     [sha256.Size]byte
}

func (x *USQUEInitialSource) ReviewLiveSession(ctx context.Context, path string) (*USQUELiveSession, error) {
	if x == nil || x.Current(ctx, x.manager, x.configs) != nil {
		return nil, ErrUSQUEInitialSource
	}
	data, info, err := readUSQUELiveSession(ctx, x.configs, path)
	defer clear(data)
	if err != nil || !validUSQUELiveSession(data, x.engineSHA256) {
		return nil, ErrUSQUELiveSession
	}
	if err := x.Current(ctx, x.manager, x.configs); err != nil {
		return nil, err
	}
	return &USQUELiveSession{configs: x.configs, path: path, file: info, sum: sha256.Sum256(data)}, nil
}

func (s *USQUELiveSession) SHA256() string { return hex.EncodeToString(s.sum[:]) }

func (s *USQUELiveSession) Current(ctx context.Context) error {
	if s == nil || s.configs == nil || s.file == nil {
		return ErrUSQUELiveSession
	}
	data, info, err := readUSQUELiveSession(ctx, s.configs, s.path)
	defer clear(data)
	if err != nil || !sameUSQUELiveSessionFile(s.file, info) || s.sum != sha256.Sum256(data) {
		return ErrUSQUELiveSession
	}
	return ctx.Err()
}

func validUSQUELiveSession(data []byte, binaryDigest string) bool {
	parsed, err := cloudflareprovider.ParseImport(cloudflareprovider.SourceUSQUE, data)
	if err != nil || parsed.Preview().Format != "usque-v1" {
		return false
	}
	_, quicErr := usquediag.ValidateOwnedUSQUENativeAssets(data, "QUIC", binaryDigest, runtime.GOARCH)
	_, h2Err := usquediag.ValidateOwnedUSQUENativeAssets(data, "HTTP/2", binaryDigest, runtime.GOARCH)
	return quicErr == nil && h2Err == nil
}

func readUSQUELiveSession(ctx context.Context, configs *engineconfig.Manager, path string) ([]byte, os.FileInfo, error) {
	if ctx == nil || ctx.Err() != nil || configs == nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || !usqueInitialProtectedPath(path) {
		return nil, nil, ErrUSQUELiveSession
	}
	currentSlot := func() bool {
		view, err := configs.Read("usque", "main")
		return err == nil && view.Source == "redacted" && view.Path == path
	}
	if !currentSlot() {
		return nil, nil, ErrUSQUELiveSession
	}
	base, name := filepath.Dir(path), filepath.Base(path)
	root, err := ownedfs.Open(base)
	if err != nil {
		return nil, nil, ErrUSQUELiveSession
	}
	defer root.Close()
	original, err := root.RootInfo()
	if err != nil {
		return nil, nil, ErrUSQUELiveSession
	}
	file, err := root.OpenFile(name, usqueLiveSessionReadFlags, 0)
	if err != nil {
		return nil, nil, ErrUSQUELiveSession
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !usqueInitialPrivateSession(before) || before.Size() <= 0 || before.Size() > cloudflareprovider.MaxImportBytes {
		return nil, nil, ErrUSQUELiveSession
	}
	data, dataErr := io.ReadAll(io.LimitReader(file, cloudflareprovider.MaxImportBytes+1))
	after, fileErr := file.Stat()
	named, nameErr := root.Stat(name)
	parent, parentErr := os.Lstat(base)
	if dataErr != nil || fileErr != nil || nameErr != nil || parentErr != nil || ctx.Err() != nil ||
		int64(len(data)) != before.Size() || !os.SameFile(original, parent) || !sameUSQUELiveSessionFile(before, after) ||
		!sameUSQUELiveSessionFile(before, named) || !usqueInitialProtectedPath(path) || !currentSlot() {
		clear(data)
		return nil, nil, ErrUSQUELiveSession
	}
	return data, before, nil
}

func sameUSQUELiveSessionFile(before, after os.FileInfo) bool {
	return before != nil && after != nil && os.SameFile(before, after) && before.Mode() == after.Mode() &&
		before.Size() == after.Size() && before.ModTime().Equal(after.ModTime()) && usqueInitialSameOwner(before, after)
}
