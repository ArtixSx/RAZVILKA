//go:build linux

package nativeowner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/usquediag"
	"github.com/ArtixSx/razvilka/internal/usquediag/nativeaccept"
	"golang.org/x/sys/unix"
)

type linuxPlatform struct{}

func nativePlatform() platform { return linuxPlatform{} }

type heldFile struct {
	mu         sync.Mutex
	closed     bool
	file       *os.File
	info       os.FileInfo
	path, hash string
	limit      int64
}

func protectedPath(path string, private bool) error {
	if !pathShape(path) {
		return ErrOwned
	}
	if real, err := filepath.EvalSymlinks(path); err != nil || real != path {
		return ErrOwned
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return ErrOwned
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		sticky := info.IsDir() && info.Mode()&os.ModeSticky != 0
		if !ok || stat.Uid != 0 && stat.Uid != uint32(os.Geteuid()) || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 && !sticky {
			return ErrOwned
		}
		if current == path && private && info.Mode().Perm()&0o077 != 0 {
			return ErrOwned
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
	}
	return nil
}

func openHeld(ctx context.Context, path, hash string, limit int64, private, executable bool) (*heldFile, error) {
	if ctx.Err() != nil || protectedPath(path, private) != nil || !hexShape(hash, 64) {
		return nil, ErrOwned
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit || executable && info.Mode().Perm()&0o111 == 0 {
		return nil, ErrOwned
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrOwned
	}
	h := &heldFile{file: f, info: info, path: path, hash: hash, limit: limit}
	if unix.Flock(int(f.Fd()), unix.LOCK_SH|unix.LOCK_NB) != nil || h.current(ctx) != nil {
		_ = f.Close()
		return nil, ErrOwned
	}
	return h, nil
}

func (h *heldFile) current(ctx context.Context) error {
	if h == nil {
		return ErrOwned
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if ctx.Err() != nil || h.closed || h.file == nil || protectedPath(h.path, false) != nil {
		return ErrOwned
	}
	before, e1 := h.file.Stat()
	path, e2 := os.Lstat(h.path)
	if e1 != nil || e2 != nil || !os.SameFile(before, h.info) || !os.SameFile(path, h.info) || before.Size() != h.info.Size() || !before.ModTime().Equal(h.info.ModTime()) {
		return ErrOwned
	}
	digest := sha256.New()
	buffer := make([]byte, 64<<10)
	defer clear(buffer)
	reader := io.NewSectionReader(h.file, 0, h.limit+1)
	var total int64
	for {
		if ctx.Err() != nil {
			return ErrOwned
		}
		n, err := reader.Read(buffer)
		total += int64(n)
		_, _ = digest.Write(buffer[:n])
		if total > h.limit {
			return ErrOwned
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return ErrOwned
		}
	}
	after, e3 := h.file.Stat()
	current, e4 := os.Lstat(h.path)
	if e3 != nil || e4 != nil || !os.SameFile(current, h.info) || !os.SameFile(after, h.info) || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) || hex.EncodeToString(digest.Sum(nil)) != h.hash || ctx.Err() != nil {
		return ErrOwned
	}
	return nil
}

func (h *heldFile) close() error {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil
	}
	h.closed = true
	return h.file.Close()
}

func netNamespace(file *os.File) (Namespace, error) {
	if file == nil {
		return Namespace{}, ErrOwned
	}
	info, err := file.Stat()
	if err != nil {
		return Namespace{}, ErrOwned
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Ino == 0 {
		return Namespace{}, ErrOwned
	}
	return Namespace{Device: uint64(stat.Dev), Inode: uint64(stat.Ino)}, nil
}
func namespaceAt(pid string) (Namespace, error) {
	f, err := os.Open("/proc/" + pid + "/ns/net")
	if err != nil {
		return Namespace{}, ErrOwned
	}
	defer f.Close()
	return netNamespace(f)
}

type linuxFacts struct {
	mu        sync.Mutex
	closed    bool
	scope     Scope
	namespace *os.File
	helper    *heldFile
}

func (linuxPlatform) acquire(ctx context.Context, a nativeaccept.Acquisition, helper HelperAsset) (scopeFacts, error) {
	f := &linuxFacts{}
	deadline, _ := ctx.Deadline()
	parent, err := components.ReadNFQWSRuntimeProcessIdentity(os.Getpid())
	if err != nil {
		return nil, ErrOwned
	}
	f.namespace, err = os.Open("/proc/self/ns/net")
	if err != nil {
		return nil, ErrOwned
	}
	ns, err := netNamespace(f.namespace)
	if err != nil {
		_ = f.Close()
		return nil, ErrOwned
	}
	f.helper, err = openHeld(ctx, helper.Path, helper.SHA256, 256<<20, false, true)
	if err != nil {
		_ = f.Close()
		return nil, ErrOwned
	}
	f.scope = Scope{Acquisition: a, Namespace: ns, Parent: parent, Helper: helper, Deadline: deadline}
	if f.Current(ctx) != nil {
		_ = f.Close()
		return nil, ErrOwned
	}
	return f, nil
}
func (f *linuxFacts) Scope() Scope { return f.scope }
func (f *linuxFacts) Current(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || ctx == nil || ctx.Err() != nil || !time.Now().Before(f.scope.Deadline) || f.helper.current(ctx) != nil {
		return ErrOwned
	}
	parent, err := components.ReadNFQWSRuntimeProcessIdentity(os.Getpid())
	ns, e1 := netNamespace(f.namespace)
	actual, e2 := namespaceAt("self")
	if err != nil || e1 != nil || e2 != nil || parent != f.scope.Parent || ns != f.scope.Namespace || actual != ns {
		return ErrOwned
	}
	return ctx.Err()
}
func (f *linuxFacts) Prepare(ctx context.Context, l nativeaccept.Launch, c Control) (processSession, error) {
	if f.Current(ctx) != nil || !launchMatches(f.scope, l) || protectedPath(l.Process.Dir, true) != nil {
		return nil, ErrOwned
	}
	root, err := os.OpenRoot(l.Process.Dir)
	if err != nil {
		return nil, ErrOwned
	}
	r := &linuxSession{facts: f, offer: offer{Version: 1, Scope: f.scope, Launch: cloneLaunch(l), Control: c}, root: root, gate: make(chan struct{}, 1)}
	r.gate <- struct{}{}
	r.rootInfo, err = root.Stat(".")
	if err != nil {
		return r, ErrOwned
	}
	r.binary, err = openHeld(ctx, l.Process.Binary, l.BinarySHA256, 256<<20, false, true)
	if err != nil {
		return r, ErrOwned
	}
	r.config, err = openHeld(ctx, l.Process.MatchArg, l.ConfigSHA256, 8<<20, true, false)
	if err != nil {
		return r, ErrOwned
	}
	r.control, err = openControlAnchors(ctx, c)
	if err != nil {
		return r, ErrOwned
	}
	data, err := io.ReadAll(io.NewSectionReader(r.config.file, 0, 8<<20+1))
	defer clear(data)
	endpoint, e := usquediag.ValidateOwnedUSQUENativeAssets(data, l.Transport, l.BinarySHA256, runtime.GOARCH)
	if err != nil || e != nil || endpoint != l.Endpoint || r.assetsCurrent(ctx) != nil {
		return r, ErrOwned
	}
	return r, nil
}
func (f *linuxFacts) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	f.closed = true
	var e1, e2 error
	if f.helper != nil && f.helper.file != nil {
		e1 = f.helper.close()
	}
	if f.namespace != nil {
		e2 = f.namespace.Close()
	}
	return errors.Join(e1, e2)
}
