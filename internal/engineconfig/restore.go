package engineconfig

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// DraftRef contains allowlisted IDs, never a destination path from an archive.
type DraftRef struct{ EngineID, FileID string }

func draftID(ref DraftRef) string { return ref.EngineID + "_" + ref.FileID }

// stageDirectory prepares only private draft directories, never live configs.
// Empty directories and permanent lock markers may remain after an aborted
// preparation. They contain no imported configuration.
func stageDirectory(stageRoot string, ref DraftRef, create bool) (string, error) {
	if _, _, err := lookup(ref.EngineID, ref.FileID); err != nil {
		return "", restorejournal.ErrInvalid
	}
	if strings.TrimSpace(stageRoot) == "" {
		return "", restorejournal.ErrInvalid
	}
	base, err := filepath.Abs(stageRoot)
	if err != nil || base == filepath.VolumeName(base)+string(filepath.Separator) {
		return "", restorejournal.ErrInvalid
	}
	if create {
		if err := os.MkdirAll(base, 0o700); err != nil {
			return "", restorejournal.ErrUnavailable
		}
	}
	root, err := ownedfs.Open(base)
	if err != nil {
		if !create && errors.Is(err, os.ErrNotExist) {
			return "", os.ErrNotExist
		}
		return "", restorejournal.ErrUnavailable
	}
	defer root.Close()
	info, err := os.Stat(base)
	if err != nil || runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return "", restorejournal.ErrUnavailable
	}
	if create {
		if err := root.MkdirAll(ref.EngineID, 0o700); err != nil {
			return "", restorejournal.ErrUnavailable
		}
		if runtime.GOOS == "linux" {
			if err := root.Sync(); err != nil {
				return "", restorejournal.ErrUnavailable
			}
		}
	}
	dir, err := root.Stat(ref.EngineID)
	if errors.Is(err, os.ErrNotExist) && !create {
		return "", os.ErrNotExist
	}
	if err != nil || !dir.IsDir() || runtime.GOOS != "windows" && dir.Mode().Perm()&0o077 != 0 {
		return "", restorejournal.ErrUnavailable
	}
	name := filepath.Join(ref.EngineID, ref.FileID+".draft")
	if err := root.Check(name); err != nil {
		return "", restorejournal.ErrInvalid
	}
	if info, err := root.Stat(name); err == nil {
		if !info.Mode().IsRegular() || info.Size() > maxConfigBytes || runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
			return "", restorejournal.ErrInvalid
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", restorejournal.ErrInvalid
	}
	return filepath.Join(base, name), nil
}

func (m *Manager) readStageImage(ctx context.Context, engineID, fileID string) (restorejournal.Image, error) {
	path, err := stageDirectory(m.StageRoot, DraftRef{engineID, fileID}, false)
	if errors.Is(err, os.ErrNotExist) {
		return restorejournal.Image{}, nil
	}
	if err != nil {
		return restorejournal.Image{}, err
	}
	image, err := restorejournal.ReadFileImage(ctx, path)
	if err != nil {
		return restorejournal.Image{}, err
	}
	if !validDraftImage(image) {
		return restorejournal.Image{}, restorejournal.ErrInvalid
	}
	return image, nil
}

// RestoreTarget owns one private draft slot. Absent/empty/incomplete drafts are
// distinct valid before-images: rollback must preserve a user's unfinished edit.
// Syntax validation belongs to Image/StagePrivate, not the byte-exact undo.
type RestoreTarget struct {
	file *restorejournal.FileTarget
	ref  DraftRef
}

func (*RestoreTarget) String() string   { return "[engine draft recovery target]" }
func (*RestoreTarget) GoString() string { return "[engine draft recovery target]" }
func OpenRestoreTarget(stageRoot, engineID, fileID string) (*RestoreTarget, error) {
	ref := DraftRef{engineID, fileID}
	path, err := stageDirectory(stageRoot, ref, true)
	if err != nil {
		return nil, err
	}
	file, err := restorejournal.OpenFileTarget(path)
	if err != nil {
		return nil, err
	}
	target := &RestoreTarget{file: file, ref: ref}
	if _, err := target.Read(context.Background()); err != nil {
		file.Close()
		return nil, err
	}
	return target, nil
}
func validDraftImage(image restorejournal.Image) bool {
	return len(image.Data) <= maxConfigBytes && (image.Exists || len(image.Data) == 0)
}
func (t *RestoreTarget) Binding() string {
	h := sha256.Sum256([]byte("engine-draft-v1\x00" + draftID(t.ref) + "\x00" + t.file.Binding()))
	return hex.EncodeToString(h[:])
}
func (t *RestoreTarget) Close() error { return t.file.Close() }
func (t *RestoreTarget) Read(ctx context.Context) (restorejournal.Image, error) {
	image, err := t.file.Read(ctx)
	if err != nil {
		return restorejournal.Image{}, err
	}
	if !validDraftImage(image) {
		return restorejournal.Image{}, restorejournal.ErrInvalid
	}
	return image, nil
}
func (t *RestoreTarget) CompareAndSwap(ctx context.Context, before, after restorejournal.Image) error {
	if !validDraftImage(before) || !validDraftImage(after) {
		return restorejournal.ErrInvalid
	}
	return t.file.CompareAndSwap(ctx, before, after)
}
func (t *RestoreTarget) Image(content string) (restorejournal.Image, error) {
	if !ValidatePrivateContent(t.ref.EngineID, t.ref.FileID, content).OK {
		return restorejournal.Image{}, restorejournal.ErrInvalid
	}
	return restorejournal.Image{Exists: true, Data: []byte(content)}, nil
}

type RestoreSession struct {
	mu      sync.Mutex
	manager *Manager
	targets map[string]*RestoreTarget
	order   []string
	closed  bool
}

func (*RestoreSession) String() string   { return "[engine draft restore session]" }
func (*RestoreSession) GoString() string { return "[engine draft restore session]" }

// BeginRestore takes the Manager lock then per-slot file leases in stable order.
// Selected refs must be trusted/validated by the coordinator. No live file or
// runtime is changed. Close only after the coordinator handles journal outcome.
func (m *Manager) BeginRestore(ctx context.Context, refs []DraftRef) (*RestoreSession, error) {
	if ctx.Err() != nil {
		return nil, restorejournal.ErrAborted
	}
	if !m.mu.TryLock() {
		return nil, restorejournal.ErrBusy
	}
	session, err := m.beginRestoreLocked(ctx, refs)
	if err != nil {
		m.mu.Unlock()
		return nil, err
	}
	return session, nil
}
func (m *Manager) beginRestoreLocked(ctx context.Context, refs []DraftRef) (*RestoreSession, error) {
	if len(refs) == 0 || len(refs) > restorejournal.MaxTargets {
		return nil, restorejournal.ErrInvalid
	}
	byID := map[string]DraftRef{}
	order := make([]string, 0, len(refs))
	for _, ref := range refs {
		if _, _, err := lookup(ref.EngineID, ref.FileID); err != nil {
			return nil, restorejournal.ErrInvalid
		}
		id := draftID(ref)
		if _, ok := byID[id]; ok {
			return nil, restorejournal.ErrInvalid
		}
		byID[id] = ref
		order = append(order, id)
	}
	sort.Strings(order)
	s := &RestoreSession{manager: m, targets: map[string]*RestoreTarget{}, order: order}
	for _, id := range order {
		if ctx.Err() != nil {
			s.closeTargets()
			return nil, restorejournal.ErrAborted
		}
		ref := byID[id]
		target, err := OpenRestoreTarget(m.StageRoot, ref.EngineID, ref.FileID)
		if err != nil {
			s.closeTargets()
			return nil, err
		}
		s.targets[id] = target
	}
	return s, nil
}
func (s *RestoreSession) closeTargets() {
	for i := len(s.order) - 1; i >= 0; i-- {
		if t := s.targets[s.order[i]]; t != nil {
			_ = t.Close()
		}
	}
}
func (s *RestoreSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	s.closeTargets()
	s.manager.mu.Unlock()
	return nil
}
func (s *RestoreSession) Binding() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := sha256.New()
	h.Write([]byte("engine-staging-set-v1"))
	for _, id := range s.order {
		h.Write([]byte{0})
		h.Write([]byte(id))
		h.Write([]byte{0})
		h.Write([]byte(s.targets[id].Binding()))
	}
	return hex.EncodeToString(h.Sum(nil))
}
func (s *RestoreSession) Targets() map[string]restorejournal.Target {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]restorejournal.Target{}
	if !s.closed {
		for _, id := range s.order {
			out[id] = sessionTarget{s: s, id: id}
		}
	}
	return out
}
func (s *RestoreSession) Images(items []StageItem) (map[string]restorejournal.Image, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, restorejournal.ErrUnavailable
	}
	images := map[string]restorejournal.Image{}
	for _, item := range items {
		id := draftID(DraftRef{item.EngineID, item.FileID})
		target, ok := s.targets[id]
		if !ok {
			return nil, restorejournal.ErrInvalid
		}
		if _, ok := images[id]; ok {
			return nil, restorejournal.ErrInvalid
		}
		image, err := target.Image(item.Content)
		if err != nil {
			return nil, err
		}
		images[id] = image
	}
	return images, nil
}

type sessionTarget struct {
	s  *RestoreSession
	id string
}

func (sessionTarget) String() string   { return "[engine draft session target]" }
func (sessionTarget) GoString() string { return "[engine draft session target]" }
func (t sessionTarget) Read(ctx context.Context) (restorejournal.Image, error) {
	t.s.mu.Lock()
	defer t.s.mu.Unlock()
	if t.s.closed {
		return restorejournal.Image{}, restorejournal.ErrUnavailable
	}
	return t.s.targets[t.id].Read(ctx)
}
func (t sessionTarget) CompareAndSwap(ctx context.Context, before, after restorejournal.Image) error {
	t.s.mu.Lock()
	defer t.s.mu.Unlock()
	if t.s.closed {
		return restorejournal.ErrUnavailable
	}
	return t.s.targets[t.id].CompareAndSwap(ctx, before, after)
}

func sameImage(a, b restorejournal.Image) bool {
	return a.Exists == b.Exists && bytes.Equal(a.Data, b.Data)
}
