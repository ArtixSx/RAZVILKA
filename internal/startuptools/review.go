package startuptools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"slices"
	"sync"
)

type heldNode struct {
	path, link string
	info       os.FileInfo
}
type heldImage struct {
	path string
	file *os.File
	info os.FileInfo
	hash [32]byte
}
type heldReview struct {
	profile     profile
	images      map[string]*heldImage
	nodes       map[string]heldNode
	absent      map[string]bool
	roles       map[string]map[imageRole]bool
	directories []string
	extensions  []string
	entry       [2]*heldImage
	ipEntry     *heldImage
	bytes       int64
	edges       int
}

func (r *heldReview) close() error {
	var result error
	if r != nil {
		for _, image := range r.images {
			result = errors.Join(result, image.file.Close())
		}
	}
	return result
}

func hashImage(ctx context.Context, file *os.File, size int64) ([32]byte, error) {
	var result [32]byte
	if ctx == nil || file == nil || size <= 0 || size > maxImageBytes {
		return result, at("HASH_INPUT", nil)
	}
	h := sha256.New()
	buffer := make([]byte, 32<<10)
	for off := int64(0); off < size; {
		if err := ctx.Err(); err != nil {
			return result, at("HASH_CONTEXT", err)
		}
		want := int(min(int64(len(buffer)), size-off))
		n, err := file.ReadAt(buffer[:want], off)
		if n != want || err != nil {
			return result, at("HASH_READ", err)
		}
		_, _ = h.Write(buffer[:n])
		off += int64(n)
	}
	var tail [1]byte
	if n, err := file.ReadAt(tail[:], size); n != 0 || !errors.Is(err, io.EOF) {
		return result, at("HASH_SIZE_CHANGED", err)
	}
	copy(result[:], h.Sum(nil))
	return result, ctx.Err()
}

func (r *heldReview) digest() (string, error) {
	type imageBinding struct {
		Path, SHA256 string
		Size         int64
		Roles        []imageRole
	}
	type nodeBinding struct {
		Path, Link string
		Mode       uint32
	}
	var images []imageBinding
	for _, path := range sortedKeys(r.images) {
		image := r.images[path]
		var roles []imageRole
		for _, role := range []imageRole{entryRole, dependencyRole, loaderRole} {
			if r.roles[path][role] {
				roles = append(roles, role)
			}
		}
		images = append(images, imageBinding{path, hex.EncodeToString(image.hash[:]), image.info.Size(), roles})
	}
	var nodes []nodeBinding
	for _, path := range sortedKeys(r.nodes) {
		n := r.nodes[path]
		nodes = append(nodes, nodeBinding{path, n.link, uint32(n.info.Mode())})
	}
	raw, err := json.Marshal(struct {
		Schema      int
		Profile     string
		Aliases     [2]string
		IPAlias     string `json:",omitempty"`
		Environment []string
		Images      []imageBinding
		Nodes       []nodeBinding
		Absent      []string
		Extensions  []string
	}{1, r.profile.id, r.profile.aliases, r.profile.ipAlias, r.profile.environment(), images, nodes, sortedKeys(r.absent), r.extensions})
	if err != nil || len(raw) > 1<<20 {
		return "", at("REVIEW_DIGEST", err)
	}
	hash := sha256.Sum256(append([]byte("razvilka-startup-xtables-review-v1\x00"), raw...))
	return hex.EncodeToString(hash[:]), nil
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

type output struct {
	mu       sync.Mutex
	data     []byte
	limit    int
	overflow bool
	cancel   context.CancelFunc
}

func (w *output) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(data) > w.limit-len(w.data) {
		w.overflow = true
		if w.cancel != nil {
			w.cancel()
		}
		return 0, at("OUTPUT_LIMIT", nil)
	}
	w.data = append(w.data, data...)
	return len(data), nil
}
