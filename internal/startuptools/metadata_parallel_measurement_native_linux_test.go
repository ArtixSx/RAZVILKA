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
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// A measurement only. It cannot issue a production observation or replace any
// provider check. References are acquired on the original pinned caller; every
// worker pays for its OWN full original provider interval and fresh FD checks.
type metadataParallelModel struct {
	review     *heldReview
	provider   *netidentity.Provider
	identity   netidentity.Identity
	shards     [2]*heldReview
	references [3]*os.File
}

func metadataParallelNew(ctx context.Context, l *Lease, review *heldReview) (*metadataParallelModel, error) {
	m := &metadataParallelModel{review: review, provider: l.provider, identity: l.identity}
	for i := range m.shards {
		m.shards[i] = &heldReview{nodes: map[string]heldNode{}}
	}
	i := 0
	for path, node := range review.nodes {
		m.shards[i%2].nodes[path] = node
		i++
	}
	var observed error
	current := l.provider.WithCurrent(ctx, func(held context.Context, identity netidentity.Identity) error {
		if identity != l.identity {
			observed = errors.New("measurement original identity differs")
			return nil
		}
		for i, path := range []string{"/proc/thread-self/ns/mnt", "/proc/thread-self/ns/net", "/"} {
			file, err := os.Open(path)
			if err != nil {
				observed = err
				return nil
			}
			m.references[i] = file
		}
		observed = m.sameScope(held)
		return nil
	})
	if err := errors.Join(observed, current, ctx.Err()); err != nil {
		return nil, errors.Join(err, m.close())
	}

	return m, nil
}
func (m *metadataParallelModel) close() error {
	var result error
	for i, file := range m.references {
		if file != nil {
			result = errors.Join(result, file.Close())
			m.references[i] = nil
		}
	}
	return result
}
func (m *metadataParallelModel) sameScope(ctx context.Context) error {
	for i, path := range []string{"/proc/thread-self/ns/mnt", "/proc/thread-self/ns/net", "/"} {
		if err := ctx.Err(); err != nil {
			return err
		}
		if m.references[i] == nil {
			return errors.New("measurement original scope closed")
		}
		expected, err := m.references[i].Stat()
		if err != nil {
			return err
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		actual, statErr := file.Stat()
		closeErr := file.Close()
		if statErr != nil || closeErr != nil {
			return errors.Join(statErr, closeErr)
		}
		if !os.SameFile(expected, actual) {
			return errors.New("measurement worker namespace/root differs")
		}
	}
	return ctx.Err()
}
func (m *metadataParallelModel) paths(ctx context.Context) error {
	var joined sync.WaitGroup
	var results [2]error
	for i := range m.shards {
		joined.Add(1)
		go func(i int) {
			defer joined.Done()
			var observed error
			current := m.provider.WithCurrent(ctx, func(held context.Context, identity netidentity.Identity) error {
				if identity != m.identity {
					observed = errors.New("measurement worker original identity differs")
					return nil
				}
				opening := m.sameScope(held)
				if opening == nil {
					observed = m.shards[i].pathsCurrent(held)
				}
				// Do not skip the closing FD check on a metadata failure; returning nil
				// also requires the actual provider's closing observation in that case.
				observed = errors.Join(opening, observed, m.sameScope(held))
				return nil
			})
			results[i] = errors.Join(observed, current)
		}(i)
	}
	joined.Wait()
	if err := errors.Join(results[0], results[1]); err != nil {
		return err
	}
	// The original negative-lookup phase follows ALL positive nodes. No worker
	// cancels another or moves an absence check ahead of a node/link check.
	absent := heldReview{absent: m.review.absent}
	return absent.pathsCurrent(ctx)
}

//go:embed metadata_parallel_measurement_native_linux_test.go
var metadataParallelSource string

func (m *metadataParallelModel) current(ctx context.Context) error {
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

func TestMetadataParallelSourceParity(t *testing.T) {
	production := strings.ReplaceAll(versionNamesProductionSource, "\r\n", "\n")
	candidate := strings.ReplaceAll(metadataParallelSource, "\r\n", "\n")
	start := strings.Index(production, "func (r *heldReview) versionMetadataCurrent(")
	if start < 0 {
		t.Fatal("original function absent")
	}
	expected := strings.TrimSpace(production[start:])
	expected = strings.Replace(expected, "func (r *heldReview) versionMetadataCurrent(ctx context.Context)", "func (m *metadataParallelModel) current(ctx context.Context)", 1)
	expected = strings.Replace(expected, "noteVersionMetadataAttempt(r)", "r := m.review\n\tnoteVersionMetadataAttempt(r)", 1)
	if strings.Count(expected, "r.pathsCurrent(ctx)") != 2 {
		t.Fatal("original path boundaries changed")
	}
	expected = strings.ReplaceAll(expected, "r.pathsCurrent(ctx)", "m.paths(ctx)")
	start = strings.Index(candidate, "func (m *metadataParallelModel) current(")
	if start < 0 {
		t.Fatal("candidate absent")
	}
	end := strings.Index(candidate[start:], "\nfunc TestMetadataParallelSourceParity(")
	if end < 0 || strings.TrimSpace(candidate[start:start+end]) != expected {
		t.Fatal("metadata clone drift beyond two path traversals")
	}
}

func TestMetadataParallelActualParity(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	l := versionNamesActualLease(t, ctx)
	err := l.WithReadOnlyToolObservation(ctx, l.identity, l.digest, func(held context.Context) (result error) {
		m, err := metadataParallelNew(held, l, l.review)
		if err != nil {
			return err
		}
		defer func() { result = errors.Join(result, m.close()) }()
		if err := l.review.versionMetadataCurrent(held); err != nil {
			return err
		}
		if err := m.current(held); err != nil {
			return err
		}
		m.references[0], m.references[1] = m.references[1], m.references[0]
		foreignErr := m.current(held)
		m.references[0], m.references[1] = m.references[1], m.references[0]
		if foreignErr == nil {
			return errors.New("foreign worker namespace reference accepted")
		}
		canceled, stop := context.WithCancel(held)
		stop()
		if m.current(canceled) == nil || l.review.versionMetadataCurrent(canceled) == nil {
			return errors.New("canceled traversal accepted")
		}
		// Reuse after cancellation proves both workers joined and retained no
		// canceled callback or mutable traversal state.
		if err := m.current(held); err != nil {
			return err
		}
		return l.review.versionMetadataCurrent(held)
	})
	if err != nil {
		t.Fatal(nativeStages(err), err)
	}
	t.Log("actual metadata worker model workers=2 original_provider_per_worker=true worker_namespace_root_bookends=true all_workers_joined=true production_grant=false")
}

func TestMetadataParallelOwnedMutations(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	l := versionNamesActualLease(t, ctx)
	for _, change := range []string{"absence", "symlink", "node"} {
		t.Run(change, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			file, link, absent := filepath.Join(root, "file"), filepath.Join(root, "link"), filepath.Join(root, "absent")
			if err := os.WriteFile(file, []byte("original"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("file", link); err != nil {
				t.Fatal(err)
			}
			review := &heldReview{nodes: map[string]heldNode{}, absent: map[string]bool{absent: true}}
			for _, path := range []string{file, link} {
				info, err := os.Lstat(path)
				if err != nil {
					t.Fatal(err)
				}
				node := heldNode{path: path, info: info}
				if path == link {
					node.link = "file"
				}
				review.nodes[path] = node
			}
			err := l.WithReadOnlyToolObservation(ctx, l.identity, l.digest, func(held context.Context) (result error) {
				m, err := metadataParallelNew(held, l, review)
				if err != nil {
					return err
				}
				defer func() { result = errors.Join(result, m.close()) }()
				parity := func(want bool) error {
					old, candidate := review.pathsCurrent(held), m.paths(held)
					if (old == nil) != want || (candidate == nil) != want {
						return errors.New("owned mutation verdict differs")
					}
					return nil
				}
				if err := parity(true); err != nil {
					return err
				}
				switch change {
				case "absence":
					if err := os.WriteFile(absent, []byte("new"), 0600); err != nil {
						return err
					}
				case "symlink":
					if err := os.Remove(link); err != nil {
						return err
					}
					if err := os.Symlink("absent", link); err != nil {
						return err
					}
				case "node":
					if err := os.Remove(file); err != nil {
						return err
					}
				}
				return parity(false)
			})
			if err != nil {
				t.Fatal(nativeStages(err), err)
			}
		})
	}
}

func BenchmarkMetadataParallelCostModel(b *testing.B) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	l := versionNamesActualLease(b, ctx)
	for _, mode := range []string{"original_serial", "two_workers_full_provider"} {
		b.Run(mode, func(b *testing.B) {
			err := l.WithReadOnlyToolObservation(ctx, l.identity, l.digest, func(held context.Context) (result error) {
				m, err := metadataParallelNew(held, l, l.review)
				if err != nil {
					return err
				}
				defer func() { result = errors.Join(result, m.close()) }()
				read := l.review.versionMetadataCurrent
				if mode != "original_serial" {
					read = m.current
				}
				var before, after syscall.Rusage
				if err := syscall.Getrusage(syscall.RUSAGE_SELF, &before); err != nil {
					return err
				}
				b.ReportAllocs()
				b.ResetTimer()
				for range b.N {
					if err := read(held); err != nil {
						b.StopTimer()
						return err
					}
				}
				b.StopTimer()
				if err := syscall.Getrusage(syscall.RUSAGE_SELF, &after); err != nil {
					return err
				}
				micros := (after.Utime.Sec-before.Utime.Sec+after.Stime.Sec-before.Stime.Sec)*1_000_000 + after.Utime.Usec - before.Utime.Usec + after.Stime.Usec - before.Stime.Usec
				b.ReportMetric(float64(micros)*1000/float64(b.N), "process_cpu_ns/op")
				return nil
			})
			if err != nil {
				b.Fatal(nativeStages(err), err)
			}
			b.ReportMetric(float64(len(l.review.nodes)), "nodes/pass")
			b.ReportMetric(0, "production_grants")
		})
	}
}
