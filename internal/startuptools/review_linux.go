//go:build linux && (amd64 || arm64)

package startuptools

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func acquire(ctx context.Context, provider *netidentity.Provider, p profile) (*Lease, error) {
	if ctx == nil || ctx.Err() != nil || provider == nil || os.Geteuid() != 0 || runtime.GOARCH != p.arch {
		return nil, at("ACQUIRE_PLATFORM", nil)
	}
	lifetime, lifetimeCancel := context.WithCancel(ctx)
	l := &Lease{provider: provider, profile: p, lifetime: lifetime, cancel: lifetimeCancel, gate: make(chan struct{}, 1), closeDone: make(chan struct{})}
	l.gate <- struct{}{}
	l.review = &heldReview{profile: p, images: map[string]*heldImage{}, nodes: map[string]heldNode{}, absent: map[string]bool{}, roles: map[string]map[imageRole]bool{}}
	c, cancel := context.WithTimeout(lifetime, operationTimeout)
	defer cancel()
	err := provider.WithCurrent(c, func(held context.Context, identity netidentity.Identity) error {
		if !p.acceptsIdentity(identity) {
			return at("ACQUIRE_IDENTITY", nil)
		}
		l.identity = identity
		if err := l.review.capture(held); err != nil {
			return err
		}
		for i := range p.aliases {
			if err := l.version(held, i); err != nil {
				return err
			}
		}
		if p.ipAlias != "" {
			if err := l.ipVersion(held); err != nil {
				return err
			}
		}
		return held.Err()
	})
	if err == nil {
		l.digest, err = l.review.digest()
	}
	if err != nil || c.Err() != nil {
		_ = l.Close()
		return nil, at("ACQUIRE", errors.Join(err, c.Err()))
	}
	return l, nil
}

func protectedInfo(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0 && (info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 == 0) && info.Mode()&(os.ModeSetuid|os.ModeSetgid) == 0
}
func sameNode(before, after os.FileInfo) bool {
	b, bok := before.Sys().(*syscall.Stat_t)
	a, aok := after.Sys().(*syscall.Stat_t)
	if !bok || !aok || !protectedInfo(after) || !os.SameFile(before, after) || before.Mode() != after.Mode() || b.Uid != a.Uid || b.Gid != a.Gid || b.Ctim != a.Ctim && !after.IsDir() {
		return false
	}
	// Directory membership is checked separately where it controls search.
	// An unrelated service file under / or /opt is not part of the tool review.
	return after.IsDir() || before.Size() == after.Size() && before.ModTime().Equal(after.ModTime())
}

func (r *heldReview) node(path string) (heldNode, error) {
	info, err := os.Lstat(path)
	if err != nil || !protectedInfo(info) {
		return heldNode{}, pathOwnerFailure(path, info, err)
	}
	n := heldNode{path: path, info: info}
	if info.Mode()&os.ModeSymlink != 0 {
		n.link, err = os.Readlink(path)
		if err != nil || n.link == "" || len(n.link) > 4096 || strings.ContainsAny(n.link, "\x00\r\n") {
			return heldNode{}, at("PATH_LINK", err)
		}
	}
	if previous, exists := r.nodes[path]; exists && (!sameNode(previous.info, info) || previous.link != n.link) {
		return heldNode{}, at("PATH_CHANGED", nil)
	}
	if len(r.nodes) >= 4096 {
		return heldNode{}, at("PATH_COUNT", nil)
	}
	r.nodes[path] = n
	return n, nil
}

// Record every encountered symlink and intermediate target, not merely an
// original path and EvalSymlinks' final target. A protected final file cannot
// hide a writable intermediate resolution component.
func (r *heldReview) resolve(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 4096 || strings.ContainsAny(path, "\x00\r\n") {
		return "", at("PATH_FORM", nil)
	}
	remaining, current, links := strings.Split(strings.TrimPrefix(path, "/"), "/"), "/", 0
	if _, err := r.node("/"); err != nil {
		return "", err
	}
	for len(remaining) != 0 {
		part := remaining[0]
		remaining = remaining[1:]
		if part == "" {
			continue
		}
		if part == "." {
			continue
		}
		if part == ".." {
			current = filepath.Dir(current)
			continue
		}
		candidate := filepath.Join(current, part)
		n, err := r.node(candidate)
		if err != nil {
			return "", err
		}
		if n.link != "" {
			links++
			if links > 40 {
				return "", at("PATH_LINK_COUNT", nil)
			}
			target := n.link
			if filepath.IsAbs(target) {
				current = "/"
			}
			// Preserve dot-dot traversal until earlier components (including
			// symlinks) have actually been resolved and checked.
			remaining = append(strings.Split(strings.TrimPrefix(target, "/"), "/"), remaining...)
			continue
		}
		if len(remaining) > 0 && !n.info.IsDir() {
			return "", at("PATH_PARENT", nil)
		}
		current = candidate
	}
	return current, nil
}

func (r *heldReview) missing(path string) error {
	parentPath := filepath.Dir(path)
	if _, err := os.Lstat(parentPath); errors.Is(err, os.ErrNotExist) {
		if err := r.missing(parentPath); err != nil {
			return err
		}
	} else {
		parent, err := r.resolve(parentPath)
		if err != nil {
			return err
		}
		if !r.nodes[parent].info.IsDir() {
			return at("ABSENCE_PARENT", nil)
		}
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return at("ABSENCE_CHANGED", err)
	}
	if len(r.absent) >= 4096 {
		return at("ABSENCE_COUNT", nil)
	}
	r.absent[path] = true
	return nil
}

func (r *heldReview) image(ctx context.Context, path string, role imageRole) (*heldImage, error) {
	if ctx.Err() != nil || r.edges >= maxEdges {
		return nil, at("IMAGE_EDGES", ctx.Err())
	}
	r.edges++
	canonical, err := r.resolve(path)
	if err != nil {
		return nil, err
	}
	if role != entryRole && !slices.Contains(r.directories, filepath.Dir(canonical)) {
		return nil, at("IMAGE_LIBRARY_ROOT", nil)
	}
	image := r.images[canonical]
	if image == nil {
		if len(r.images) >= maxImages {
			return nil, at("IMAGE_COUNT", nil)
		}
		before := r.nodes[canonical].info
		if !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > maxImageBytes || r.bytes+before.Size() > maxReviewBytes {
			return nil, at("IMAGE_BOUNDS", nil)
		}
		fd, err := syscall.Open(canonical, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
		if err != nil {
			return nil, at("IMAGE_OPEN", err)
		}
		file := os.NewFile(uintptr(fd), canonical)
		info, err := file.Stat()
		if err != nil || !sameNode(before, info) || !info.Mode().IsRegular() {
			_ = file.Close()
			return nil, at("IMAGE_OPEN_CHANGED", err)
		}
		hash, err := hashImage(ctx, file, info.Size())
		if err != nil {
			_ = file.Close()
			return nil, err
		}
		image = &heldImage{path: canonical, file: file, info: info, hash: hash}
		r.images[canonical] = image
		r.bytes += info.Size()
	}
	if role == entryRole && image.info.Mode().Perm()&0100 == 0 {
		return nil, at("IMAGE_EXECUTABLE", nil)
	}
	if r.roles[canonical] == nil {
		r.roles[canonical] = map[imageRole]bool{}
	}
	if r.roles[canonical][role] {
		return image, nil
	}
	meta, err := inspectELF(ctx, image.file, image.info.Size(), r.profile.arch, role)
	if err != nil || !permittedSearch(r.profile, meta.paths) {
		return nil, at("IMAGE_ELF", err)
	}
	// Mark only this role after validating it; cycles do not skip a later
	// entry-role check for a previously admitted dependency image.
	r.roles[canonical][role] = true
	if role == entryRole {
		if meta.interpreter != r.profile.loader {
			return nil, at("ENTRY_LOADER", nil)
		}
		if _, err := r.image(ctx, meta.interpreter, loaderRole); err != nil {
			return nil, at("ENTRY_LOADER_IMAGE", err)
		}
	}
	for _, name := range meta.needed {
		found := ""
		for _, dir := range r.profile.libraries {
			candidate := filepath.Join(dir, name)
			if _, err := os.Lstat(candidate); err == nil {
				found = candidate
				break
			} else if !errors.Is(err, os.ErrNotExist) {
				return nil, at("DEPENDENCY_LOOKUP", err)
			}
			if err := r.missing(candidate); err != nil {
				return nil, err
			}
		}
		if found == "" {
			return nil, at("DEPENDENCY_MISSING", nil)
		}
		if _, err := r.image(ctx, found, dependencyRole); err != nil {
			return nil, at("DEPENDENCY_IMAGE", err)
		}
	}
	return image, nil
}

func (r *heldReview) capture(ctx context.Context) error {
	for _, dir := range r.profile.libraries {
		canonical, err := r.resolve(dir)
		if err != nil || !r.nodes[canonical].info.IsDir() {
			return at("LIBRARY_DIRECTORY", err)
		}
		r.directories = append(r.directories, canonical)
		// This fixed review does not admit loader CPU/TLS search variants.
		for _, name := range []string{"glibc-hwcaps", "tls", "haswell", "x86_64", "aarch64"} {
			path := filepath.Join(dir, name)
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				return at("LOADER_VARIANT", err)
			}
			if err := r.missing(path); err != nil {
				return err
			}
		}
	}
	main, err := r.resolve(r.profile.main)
	if err != nil {
		return at("MAIN_PATH", err)
	}
	for i, alias := range r.profile.aliases {
		image, err := r.image(ctx, alias, entryRole)
		if err != nil || image.path != main || hex.EncodeToString(image.hash[:]) != r.profile.mainSHA {
			return at("MAIN_PIN", err)
		}
		r.entry[i] = image
	}
	for _, path := range sortedKeys(r.profile.pins) {
		image, err := r.image(ctx, path, dependencyRole)
		if err != nil || !slices.Contains(r.profile.pins[path], hex.EncodeToString(image.hash[:])) {
			return at("BACKEND_PIN", err)
		}
	}
	if r.profile.ipAlias != "" {
		main, err := r.resolve(r.profile.ipMain)
		if err != nil {
			return at("IP_MAIN_PATH", err)
		}
		image, err := r.image(ctx, r.profile.ipAlias, entryRole)
		if err != nil || image.path != main || hex.EncodeToString(image.hash[:]) != r.profile.ipSHA {
			return at("IP_MAIN_PIN", err)
		}
		r.ipEntry = image
	}
	canonical, err := r.resolve(r.profile.extension)
	if err != nil || !r.nodes[canonical].info.IsDir() {
		return at("EXTENSION_DIRECTORY", err)
	}
	file, err := openDirectory(canonical, r.nodes[canonical].info)
	if err != nil {
		return at("EXTENSION_OPEN", err)
	}
	entries, readErr := file.ReadDir(257)
	closeErr := file.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil || len(entries) == 0 || len(entries) > 256 {
		return at("EXTENSION_COUNT", errors.Join(readErr, closeErr))
	}
	for _, entry := range entries {
		if !libraryName(entry.Name()) || !strings.HasSuffix(entry.Name(), ".so") || entry.IsDir() {
			return at("EXTENSION_FORM", nil)
		}
		r.extensions = append(r.extensions, entry.Name())
		// Modules may live in the fixed extension directory itself, or be
		// symlinks into the same admitted library roots.
		r.directories = append(r.directories, canonical)
		if _, err := r.image(ctx, filepath.Join(r.profile.extension, entry.Name()), dependencyRole); err != nil {
			return at("EXTENSION_IMAGE", err)
		}
	}
	slices.Sort(r.extensions)
	for _, path := range []string{"/etc/ld.so.preload", "/opt/etc/ld.so.preload"} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return at("LOADER_PRELOAD", err)
		}
		if err := r.missing(path); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func (r *heldReview) unchanged(ctx context.Context) error {
	if err := r.pathsCurrent(ctx); err != nil {
		return err
	}
	for _, image := range r.images {
		before, err := image.file.Stat()
		path, pathErr := os.Lstat(image.path)
		if err != nil || pathErr != nil || !sameNode(image.info, before) || !sameNode(before, path) {
			return at("CHECK_HELD_FILE", errors.Join(err, pathErr))
		}
		hash, err := hashImage(ctx, image.file, before.Size())
		after, afterErr := image.file.Stat()
		path, pathErr = os.Lstat(image.path)
		if err != nil || afterErr != nil || pathErr != nil || !sameNode(before, after) || !sameNode(after, path) || hash != image.hash {
			return at("CHECK_BYTES", errors.Join(err, afterErr, pathErr))
		}
	}
	canonical, err := r.resolveExisting(r.profile.extension)
	if err != nil {
		return err
	}
	file, err := openDirectory(canonical, r.nodes[canonical].info)
	if err != nil {
		return at("CHECK_EXTENSIONS", err)
	}
	entries, readErr := file.ReadDir(257)
	closeErr := file.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil || len(entries) > 256 {
		return at("CHECK_EXTENSIONS", errors.Join(readErr, closeErr))
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	slices.Sort(names)
	if !slices.Equal(names, r.extensions) {
		return at("CHECK_EXTENSION_SET", nil)
	}
	return r.pathsCurrent(ctx)
}

func (r *heldReview) pathsCurrent(ctx context.Context) error {
	for _, n := range r.nodes {
		if ctx.Err() != nil {
			return at("CHECK_CONTEXT", ctx.Err())
		}
		info, err := os.Lstat(n.path)
		if err != nil || !sameNode(n.info, info) {
			return at("CHECK_PATH", err)
		}
		if n.link != "" {
			link, err := os.Readlink(n.path)
			if err != nil || link != n.link {
				return at("CHECK_LINK", err)
			}
		}
	}
	for path := range r.absent {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return at("CHECK_ABSENCE", err)
		}
	}
	return ctx.Err()
}

func openDirectory(path string, expected os.FileInfo) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, at("DIRECTORY_OPEN", err)
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil || !info.IsDir() || !sameNode(expected, info) {
		_ = file.Close()
		return nil, at("DIRECTORY_CHANGED", err)
	}
	return file, nil
}

// Re-resolve against the captured node set without rebinding any node. The
// regular directory target was already captured, and symlinks are unchanged.
func (r *heldReview) resolveExisting(path string) (string, error) {
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", at("CHECK_DIRECTORY_PATH", err)
	}
	node, ok := r.nodes[canonical]
	if !ok || !node.info.IsDir() {
		return "", at("CHECK_DIRECTORY_PATH", nil)
	}
	return canonical, nil
}

func (l *Lease) current(ctx context.Context, expected netidentity.Identity, versions bool) error {
	if l.review == nil || l.provider == nil || expected != l.identity || !l.profile.acceptsIdentity(expected) {
		return at("CHECK_IDENTITY", nil)
	}
	return l.provider.WithCurrent(ctx, func(held context.Context, actual netidentity.Identity) error {
		if actual != expected || l.closed.Load() || l.lifetime.Err() != nil {
			return at("CHECK_IDENTITY", nil)
		}
		if versions {
			for i := range l.profile.aliases {
				if err := l.version(held, i); err != nil {
					return err
				}
			}
			if l.profile.ipAlias != "" {
				if err := l.ipVersion(held); err != nil {
					return err
				}
			}
			return held.Err()
		}
		return l.review.unchanged(held)
	})
}
