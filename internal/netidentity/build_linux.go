//go:build linux && (amd64 || arm64)

package netidentity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type protectedNode struct {
	path, link string
	info       os.FileInfo
}
type protectedImage struct {
	file  *os.File
	nodes []protectedNode
	info  os.FileInfo
	hash  [32]byte
}
type systemImages struct {
	files []*protectedImage
	bytes int64
	seen  map[string]bool
	cache map[string]*protectedImage
	edges int
}

func (s *systemImages) close() {
	for _, f := range s.files {
		_ = f.file.Close()
	}
}

func protectedPath(path string) (string, []protectedNode, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", nil, ErrUnknown
	}
	var nodes []protectedNode
	check := func(p string) error {
		for current := p; ; current = filepath.Dir(current) {
			info, err := os.Lstat(current)
			if err != nil {
				return ErrUnknown
			}
			st, ok := info.Sys().(*syscall.Stat_t)
			if !ok || st.Uid != 0 || info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0022 != 0 {
				return ErrUnknown
			}
			n := protectedNode{path: current, info: info}
			if info.Mode()&os.ModeSymlink != 0 {
				n.link, err = os.Readlink(current)
				if err != nil {
					return ErrUnknown
				}
			}
			nodes = append(nodes, n)
			if current == "/" {
				break
			}
		}
		return nil
	}
	if err := check(path); err != nil {
		return "", nil, err
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || check(resolved) != nil {
		return "", nil, ErrUnknown
	}
	return resolved, nodes, nil
}
func nodesUnchanged(nodes []protectedNode) bool {
	for _, n := range nodes {
		now, err := os.Lstat(n.path)
		if err != nil || !os.SameFile(n.info, now) || n.info.Mode() != now.Mode() || n.info.Size() != now.Size() || n.info.ModTime() != now.ModTime() {
			return false
		}
		before, beforeOK := n.info.Sys().(*syscall.Stat_t)
		after, afterOK := now.Sys().(*syscall.Stat_t)
		if !beforeOK || !afterOK || after.Uid != 0 || before.Uid != after.Uid || before.Gid != after.Gid {
			return false
		}
		if n.link != "" {
			target, err := os.Readlink(n.path)
			if err != nil || target != n.link {
				return false
			}
		}
	}
	return true
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(b []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(b)
}
func imageHash(ctx context.Context, f *os.File, size int64) ([32]byte, error) {
	var zero [32]byte
	if size <= 0 || size > 16<<20 {
		return zero, ErrUnknown
	}
	h := sha256.New()
	n, err := io.Copy(h, contextReader{ctx, io.NewSectionReader(f, 0, size+1)})
	if err != nil || n != size {
		return zero, ErrUnknown
	}
	copy(zero[:], h.Sum(nil))
	return zero, nil
}
func systemLibrary(path string) bool {
	return strings.HasPrefix(path, "/lib/") || strings.HasPrefix(path, "/usr/lib/")
}
func (s *systemImages) open(ctx context.Context, path string, executable bool) (*protectedImage, error) {
	if ctx.Err() != nil || s.edges >= 128 {
		return nil, ErrUnknown
	}
	s.edges++
	resolved, nodes, err := protectedPath(path)
	if err != nil || !executable && !systemLibrary(resolved) {
		return nil, ErrUnknown
	}
	if executable && !(strings.HasPrefix(resolved, "/bin/") || strings.HasPrefix(resolved, "/sbin/") || strings.HasPrefix(resolved, "/usr/bin/") || strings.HasPrefix(resolved, "/usr/sbin/")) {
		return nil, ErrUnknown
	}
	if s.cache == nil {
		s.cache = map[string]*protectedImage{}
	}
	if image := s.cache[resolved]; image != nil {
		image.nodes = append(image.nodes, nodes...)
		return image, nil
	}
	if len(s.files) >= 32 {
		return nil, ErrUnknown
	}
	expected, err := os.Lstat(resolved)
	if err != nil {
		return nil, ErrUnknown
	}
	fd, err := syscall.Open(resolved, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnknown
	}
	f := os.NewFile(uintptr(fd), resolved)
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 16<<20 || !nodesUnchanged(nodes) || !os.SameFile(expected, info) {
		_ = f.Close()
		return nil, ErrUnknown
	}
	if executable && info.Mode().Perm()&0100 == 0 {
		_ = f.Close()
		return nil, ErrUnknown
	}
	s.bytes += info.Size()
	if s.bytes > 64<<20 {
		_ = f.Close()
		return nil, ErrUnknown
	}
	hash, err := imageHash(ctx, f, info.Size())
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	image := &protectedImage{file: f, info: info, nodes: nodes, hash: hash}
	s.files = append(s.files, image)
	s.cache[resolved] = image
	return image, nil
}
func (s *systemImages) dependencies(ctx context.Context, image *protectedImage) error {
	name := image.file.Name()
	if s.seen[name] {
		return nil
	}
	s.seen[name] = true
	e, err := boundedELF(ctx, image.file, image.info.Size())
	if err != nil {
		return ErrUnknown
	}
	defer e.Close()
	interpreters := 0
	for _, p := range e.Progs {
		if p.Type != elf.PT_INTERP {
			continue
		}
		interpreters++
		if interpreters > 1 {
			return ErrUnknown
		}
		if p.Filesz < 2 || p.Filesz > 256 {
			return ErrUnknown
		}
		raw, err := io.ReadAll(io.LimitReader(p.Open(), 257))
		if err != nil || uint64(len(raw)) != p.Filesz || raw[len(raw)-1] != 0 || bytes.IndexByte(raw[:len(raw)-1], 0) >= 0 {
			return ErrUnknown
		}
		loader := string(raw[:len(raw)-1])
		if !systemLibrary(loader) {
			return ErrUnknown
		}
		f, err := s.open(ctx, loader, false)
		if err != nil || s.dependencies(ctx, f) != nil {
			return ErrUnknown
		}
	}
	libs, err := e.ImportedLibraries()
	if err != nil || len(libs) > 32 {
		return ErrUnknown
	}
	for _, lib := range libs {
		if lib == "" || len(lib) > 128 || strings.ContainsAny(lib, "/\\\x00") {
			return ErrUnknown
		}
		for _, b := range []byte(lib) {
			if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || strings.ContainsRune("._+-", rune(b))) {
				return ErrUnknown
			}
		}
		found := false
		for _, dir := range []string{"/lib", "/usr/lib"} {
			path := filepath.Join(dir, lib)
			if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
				continue
			} else if err != nil {
				return ErrUnknown
			}
			f, err := s.open(ctx, path, false)
			if err != nil || s.dependencies(ctx, f) != nil {
				return ErrUnknown
			}
			found = true
			break
		}
		if !found {
			return ErrUnknown
		}
	}
	return ctx.Err()
}
func (s *systemImages) unchanged(ctx context.Context) bool {
	for _, image := range s.files {
		info, err := image.file.Stat()
		if err != nil || !os.SameFile(info, image.info) || info.Mode() != image.info.Mode() || info.Size() != image.info.Size() || info.ModTime() != image.info.ModTime() || !nodesUnchanged(image.nodes) {
			return false
		}
		hash, err := imageHash(ctx, image.file, info.Size())
		if err != nil || hash != image.hash {
			return false
		}
	}
	return ctx.Err() == nil
}

type cappedOutput struct {
	data     []byte
	limit    int
	exceeded bool
}

func (b *cappedOutput) Write(raw []byte) (int, error) {
	if len(raw) > b.limit-len(b.data) {
		b.exceeded = true
		return 0, ErrUnknown
	}
	b.data = append(b.data, raw...)
	return len(raw), nil
}

// The sole command is fixed read-only NDMC metadata. No inherited loader,
// shell, Entware library path, PATH lookup, caller argv or cached report.
func readBuild(ctx context.Context) (buildTuple, error) {
	var zero buildTuple
	if ctx == nil || ctx.Err() != nil {
		return zero, ErrUnknown
	}
	release, machine, ok := kernelTuple()
	if !ok || release != nc1812Profile().KernelRelease || machine != nc1812Profile().Machine {
		return zero, ErrUnknown
	}
	if _, err := os.Lstat("/etc/ld.so.preload"); !errors.Is(err, os.ErrNotExist) {
		return zero, ErrUnknown
	}
	_, preloadNodes, err := protectedPath("/etc")
	if err != nil {
		return zero, ErrUnknown
	}
	s := &systemImages{seen: map[string]bool{}}
	defer s.close()
	image, err := s.open(ctx, "/bin/ndmc", true)
	if err != nil || s.dependencies(ctx, image) != nil || !s.unchanged(ctx) {
		return zero, ErrUnknown
	}
	stdout, stderr := &cappedOutput{limit: 8192}, &cappedOutput{limit: 1024}
	cmd := exec.CommandContext(ctx, "/proc/self/fd/3", "-c", "show version")
	cmd.Args[0] = "/bin/ndmc"
	cmd.ExtraFiles = []*os.File{image.file}
	cmd.Env = []string{"PATH=/bin:/sbin:/usr/bin:/usr/sbin", "LD_LIBRARY_PATH=/lib:/usr/lib", "LANG=C", "LC_ALL=C"}
	cmd.Dir = "/"
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.WaitDelay = 50 * time.Millisecond
	if cmd.Run() != nil || stdout.exceeded || stderr.exceeded || len(stderr.data) != 0 || ctx.Err() != nil || !s.unchanged(ctx) {
		return zero, ErrUnknown
	}
	if _, err := os.Lstat("/etc/ld.so.preload"); !errors.Is(err, os.ErrNotExist) || !nodesUnchanged(preloadNodes) {
		return zero, ErrUnknown
	}
	afterRelease, afterMachine, ok := kernelTuple()
	if !ok || afterRelease != release || afterMachine != machine {
		return zero, ErrUnknown
	}
	return parseBuild(stdout.data)
}
