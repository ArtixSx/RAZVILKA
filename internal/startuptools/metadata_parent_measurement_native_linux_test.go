//go:build linux && amd64 && razvilka_native_fixture

package startuptools

import (
	"context"
	_ "embed"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// Measurement only: no production caller or observation authority. Every path
// pass opens and closes its own bounded original parent descriptors. Timings
// include the additional named/held bookends, opens and closes.
type metadataParentModel struct {
	review      *heldReview
	beforeClose func() error // Owned mutation tests only; never set by measurements.
	anchors     int
	fallback    bool
}

//go:embed metadata_parent_measurement_native_linux_test.go
var metadataParentSource string

func (m *metadataParentModel) paths(ctx context.Context) (result error) {
	r := m.review
	m.anchors, m.fallback = 0, false
	parents := map[string]heldNode{}
	for _, node := range r.nodes {
		if node.info == nil || !node.info.Mode().IsRegular() {
			continue
		}
		parent := filepath.Dir(node.path)
		original, ok := r.nodes[parent]
		if !ok || original.path != parent || original.info == nil || !original.info.IsDir() || original.link != "" || !filepath.IsAbs(node.path) || filepath.Clean(node.path) != node.path {
			m.fallback = true
			return r.pathsCurrent(ctx)
		}
		parents[parent] = original
		if len(parents) > 64 {
			m.fallback = true
			return r.pathsCurrent(ctx)
		}
	}
	opened := map[string]*os.File{}
	defer func() {
		if m.beforeClose != nil {
			result = errors.Join(result, m.beforeClose())
		}
		for path, file := range opened {
			original := parents[path]
			same, pathErr := freshPathNode(path, original.info)
			held, heldErr := freshHeldNode(file, original.info)
			if pathErr != nil || heldErr != nil || !same || !held {
				result = errors.Join(result, at("PARENT_CLOSING", errors.Join(pathErr, heldErr)))
			}
			result = errors.Join(result, file.Close())
		}
		result = errors.Join(result, ctx.Err())
	}()
	for path, node := range parents {
		if err := ctx.Err(); err != nil {
			return err
		}
		same, err := freshPathNode(path, node.info)
		if err != nil || !same {
			return at("PARENT_OPENING", err)
		}
		file, err := openDirectory(path, node.info)
		if err != nil {
			return err
		}
		opened[path] = file
		m.anchors++
	}
	for _, node := range r.nodes {
		if err := ctx.Err(); err != nil {
			return at("CHECK_CONTEXT", err)
		}
		var same bool
		var err error
		if node.info != nil && node.info.Mode().IsRegular() {
			same, err = metadataParentLeaf(opened[filepath.Dir(node.path)], filepath.Base(node.path), node.info)
		} else {
			same, err = freshPathNode(node.path, node.info)
		}
		if err != nil || !same {
			return at("CHECK_PATH", err)
		}
		if node.link != "" {
			link, err := os.Readlink(node.path)
			if err != nil || link != node.link {
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

func metadataParentLeaf(parent *os.File, name string, expected os.FileInfo) (bool, error) {
	if parent == nil || expected == nil || name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") || len(name) >= 4096 {
		return false, os.ErrInvalid
	}
	before, ok := expected.Sys().(*syscall.Stat_t)
	if !ok || before == nil {
		return false, os.ErrInvalid
	}
	var after syscall.Stat_t
	var argument [4096]byte
	copy(argument[:], name)
	raw, err := parent.SyscallConn()
	if err != nil {
		return false, err
	}
	var callErr syscall.Errno
	err = raw.Control(func(fd uintptr) {
		_, _, callErr = syscall.Syscall6(freshPathStatSyscall, fd, uintptr(unsafe.Pointer(&argument[0])), uintptr(unsafe.Pointer(&after)), 0x100, 0, 0)
	})
	if err != nil {
		return false, err
	}
	if callErr != 0 {
		return false, callErr
	}
	return sameReviewedStat(before, &after), nil
}

func (m *metadataParentModel) current(ctx context.Context) error {
	r := m.review
	noteVersionMetadataAttempt(r)
	if err := m.paths(ctx); err != nil {
		return err
	}
	for _, image := range r.images {
		// Both complete pathsCurrent passes observe this exact ORIGINAL
		// canonical named node. There is no callback/effect between them;
		// keep the actual held FD check, avoiding a third named-path stat.
		if image == nil || image.file == nil || image.info == nil {
			return at("CHECK_HELD_FILE", nil)
		}
		node, exists := r.nodes[image.path]
		if !exists || node.path != image.path || node.info == nil || node.link != "" || !sameNode(image.info, node.info) {
			return at("CHECK_HELD_FILE", nil)
		}
		same, err := freshHeldNode(image.file, image.info)
		if err != nil || !same {
			return at("CHECK_HELD_FILE", err)
		}
	}
	canonical, err := r.versionExtensionPath()
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
	var nameStorage [256]string
	names := nameStorage[:0]
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	slices.Sort(names)
	if !slices.Equal(names, r.extensions) {
		return at("CHECK_EXTENSION_SET", nil)
	}
	return m.paths(ctx)
}

func TestMetadataParentSourceParity(t *testing.T) {
	production := strings.ReplaceAll(versionNamesProductionSource, "\r\n", "\n")
	candidate := strings.ReplaceAll(metadataParentSource, "\r\n", "\n")
	start := strings.Index(production, "func (r *heldReview) versionMetadataCurrent(")
	if start < 0 {
		t.Fatal("original function absent")
	}
	expected := strings.TrimSpace(production[start:])
	expected = strings.Replace(expected, "func (r *heldReview) versionMetadataCurrent(ctx context.Context)", "func (m *metadataParentModel) current(ctx context.Context)", 1)
	expected = strings.Replace(expected, "noteVersionMetadataAttempt(r)", "r := m.review\n\tnoteVersionMetadataAttempt(r)", 1)
	if strings.Count(expected, "r.pathsCurrent(ctx)") != 2 {
		t.Fatal("path boundaries changed")
	}
	expected = strings.ReplaceAll(expected, "r.pathsCurrent(ctx)", "m.paths(ctx)")
	start = strings.Index(candidate, "func (m *metadataParentModel) current(")
	if start < 0 {
		t.Fatal("candidate absent")
	}
	end := strings.Index(candidate[start:], "\nfunc TestMetadataParentSourceParity(")
	if end < 0 || strings.TrimSpace(candidate[start:start+end]) != expected {
		t.Fatal("full metadata model drift beyond two path traversals")
	}
}

func TestMetadataParentActualPairs(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	l := versionNamesActualLease(t, ctx)
	err := l.WithReadOnlyToolObservation(ctx, l.identity, l.digest, func(held context.Context) error {
		m := &metadataParentModel{review: l.review}
		for sample := 0; sample < 6; sample++ {
			order := []string{"original", "parent_fd"}
			if sample%2 != 0 {
				slices.Reverse(order)
			}
			for _, mode := range order {
				started := time.Now()
				var err error
				if mode == "original" {
					err = l.review.versionMetadataCurrent(held)
				} else {
					err = m.current(held)
				}
				elapsed := time.Since(started)
				if err != nil {
					return err
				}
				if mode == "parent_fd" && (m.fallback || m.anchors == 0) {
					return errors.New("actual graph did not exercise parent descriptors; no performance evidence")
				}
				t.Logf("metadata_parent_pair sample=%d mode=%s wall_ns=%d nodes=%d images=%d parents=%d complete_bookends_and_close=true production_grant=false", sample, mode, elapsed.Nanoseconds(), len(l.review.nodes), len(l.review.images), m.anchors)
			}
		}
		canceled, stop := context.WithCancel(held)
		stop()
		if m.current(canceled) == nil || l.review.versionMetadataCurrent(canceled) == nil {
			return errors.New("canceled full metadata admitted")
		}
		return nil
	})
	if err != nil {
		t.Fatal(nativeStages(err), err)
	}
}

func TestMetadataParentOwnedMutations(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned protected metadata fixture")
	}
	for _, change := range []string{"leaf", "link", "absence", "parent_closing", "cancel_closing", "missing_parent_fallback"} {
		t.Run(change, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, "parent")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			file, link, absent := filepath.Join(dir, "file"), filepath.Join(dir, "link"), filepath.Join(dir, "absent")
			if err := os.WriteFile(file, []byte("original"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("file", link); err != nil {
				t.Fatal(err)
			}
			r := &heldReview{nodes: map[string]heldNode{}, absent: map[string]bool{absent: true}}
			for _, path := range []string{dir, file, link} {
				info, err := os.Lstat(path)
				if err != nil {
					t.Fatal(err)
				}
				node := heldNode{path: path, info: info}
				if path == link {
					node.link = "file"
				}
				r.nodes[path] = node
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			m := &metadataParentModel{review: r}
			if err := m.paths(ctx); err != nil {
				t.Fatal("initial", err)
			}
			switch change {
			case "leaf":
				if err := os.WriteFile(file, []byte("changed!"), 0600); err != nil {
					t.Fatal(err)
				}
			case "link":
				if err := os.Remove(link); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("absent", link); err != nil {
					t.Fatal(err)
				}
			case "absence":
				if err := os.WriteFile(absent, []byte("foreign"), 0600); err != nil {
					t.Fatal(err)
				}
			case "parent_closing":
				m.beforeClose = func() error {
					if err := os.Rename(dir, dir+"-old"); err != nil {
						return err
					}
					return os.Mkdir(dir, 0700)
				}
			case "cancel_closing":
				m.beforeClose = func() error { cancel(); return nil }
			case "missing_parent_fallback":
				delete(r.nodes, dir)
				if err := m.paths(ctx); err != nil {
					t.Fatal("original fallback", err)
				}
				return
			}
			if err := m.paths(ctx); err == nil {
				t.Fatal("mutation admitted")
			}
		})
	}
}
