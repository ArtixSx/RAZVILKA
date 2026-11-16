//go:build linux && amd64 && razvilka_native_fixture

package restorejournal

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"golang.org/x/sys/unix"
)

// Measurement only: both original fresh complete ReadAt streams remain. One
// stream is SHA-256 authenticated, the other compared byte-for-byte with it.
// Two original 64 KiB IO buffers are the complete payload workspace (128 KiB).
// There is no file-image cache and no observation survives this invocation.
// The original concurrent two-SHA production implementation is the baseline.
//
//go:embed artifact_expected_read_comparison.go
var expectedPairStreamNativeOriginal string

//go:embed expected_pair_stream_measurement_native_linux_test.go
var expectedPairStreamNativeCandidate string

type expectedPairStreamNative struct {
	chunks                  chan []byte
	ack                     chan struct{}
	managedDone, poolDone   chan struct{}
	mismatch                atomic.Bool
	managedBytes, poolBytes int64 // each has exactly one writer; read after original Wait
}

func newExpectedPairStreamNative() *expectedPairStreamNative {
	return &expectedPairStreamNative{chunks: make(chan []byte), ack: make(chan struct{}), managedDone: make(chan struct{}), poolDone: make(chan struct{})}
}
func (p *expectedPairStreamNative) finish(role string) {
	if role == "managed" {
		close(p.managedDone)
	} else {
		close(p.poolDone)
	}
}

type expectedPairStreamNativeWriter struct {
	pair *expectedPairStreamNative
	role string
}

func (w expectedPairStreamNativeWriter) Write(data []byte) (int, error) {
	p := w.pair
	if w.role == "managed" {
		p.managedBytes += int64(len(data))
		select {
		case p.chunks <- data:
			// The sender cannot reuse its buffer until the peer has finished comparing.
			// Peer termination also releases us; its defer runs only after its last use.
			select {
			case <-p.ack:
			case <-p.poolDone:
				p.mismatch.Store(true)
			}
		case <-p.poolDone:
			p.mismatch.Store(true)
		}
	} else {
		p.poolBytes += int64(len(data))
		select {
		case peer := <-p.chunks:
			if !bytes.Equal(peer, data) {
				p.mismatch.Store(true)
			}
			p.ack <- struct{}{}
		case <-p.managedDone:
			p.mismatch.Store(true)
		}
	}
	// A mismatch never stops either full stream. Original read errors/cancellation
	// still propagate through io.CopyBuffer and every original worker is joined.
	return len(data), nil
}

func (t *ArtifactFileTarget) expectedPairStreamNativeComparison(ctx context.Context, expected Image, read func(context.Context, Image, *ArtifactSourceComparison) error, fault func(string, string) error) (result error) {
	if t == nil || t.file == nil || read == nil {
		return ErrUnavailable
	}
	if err := artifactComparisonContext(ctx); err != nil {
		return err
	}
	ref, err := artifactImageReference(expected)
	if err != nil || !expected.Exists {
		return errors.Join(ErrInvalid, err)
	}
	t.file.mu.Lock()
	defer t.file.mu.Unlock()
	if err := t.current(); err != nil {
		return err
	}
	name := ref.SHA256 + ".bin"
	managedOpening, err := t.file.root.Stat(t.file.name)
	if err != nil {
		return err
	}
	managedID, err := artifactReadFingerprint(managedOpening)
	if err != nil {
		return err
	}
	poolOpening, err := t.artifacts.Stat(name)
	if err != nil {
		return err
	}
	poolID, err := artifactReadFingerprint(poolOpening)
	if err != nil {
		return err
	}
	var managed, pool expectedArtifactRead
	var proof *ArtifactSourceComparison
	var workers sync.WaitGroup
	// All started workers are joined before ANY descriptor close, callback,
	// error or panic leaves this invocation. No reader borrows a shared offset.
	defer func() {
		workers.Wait()
		if proof != nil {
			proof.mu.Lock()
			proof.open = false
			result = errors.Join(result, proof.currentLocked())
			proof.mu.Unlock()
		}
		for _, file := range []*os.File{managed.file, pool.file} {
			if file != nil {
				result = errors.Join(result, file.Close())
			}
		}
		result = errors.Join(result, artifactComparisonContext(ctx))
	}()
	pair := newExpectedPairStreamNative()
	launch := func(out *expectedArtifactRead, root *ownedfs.Root, name, role string, mode os.FileMode) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer pair.finish(role)
			defer func() {
				if value := recover(); value != nil {
					out.panicValue = value
				}
			}()
			out.file, out.id, out.image, out.err = expectedPairStreamNativeDescriptor(ctx, root, name, role, mode, fault, pair)
			out.returned = true
		}()
	}
	launch(&managed, t.file.root, t.file.name, "managed", 0755)
	launch(&pool, t.artifacts, name, "pool", 0555)
	workers.Wait()
	if managed.panicValue != nil {
		panic(managed.panicValue)
	}
	if pool.panicValue != nil {
		panic(pool.panicValue)
	}
	if !managed.returned || !pool.returned {
		return ErrUnavailable
	}
	if err := errors.Join(managed.err, pool.err); err != nil {
		return err
	}
	if pair.mismatch.Load() || pair.managedBytes != pair.poolBytes {
		return ErrConflict
	}
	// Fresh pool bytes are authenticated by exact streaming equality, never by the expected image.
	pool.image = managed.image
	if managed.id != managedID || pool.id != poolID || !equal(managed.image, expected) || !equal(pool.image, expected) {
		return ErrConflict
	}
	if err := artifactComparisonContext(ctx); err != nil {
		return err
	}
	if err := t.current(); err != nil {
		return err
	}
	if fault != nil {
		if err := fault("joined", "before-reopen"); err != nil {
			return err
		}
	}
	// Preserve the independent fresh pool reopen/owner comparison and its
	// Close ACK; this descriptor never replaces either actual hash reader.
	reopened, err := openReadOnly(t.artifacts, name)
	if err != nil {
		return err
	}
	held, statErr := reopened.Stat()
	heldID, idErr := artifactReadFingerprint(held)
	closeErr := reopened.Close()
	if statErr != nil || idErr != nil || closeErr != nil || heldID != pool.id || held.Size() != ref.Size || !existingOwner(held, false) {
		return errors.Join(ErrConflict, statErr, idErr, closeErr)
	}
	proof = &ArtifactSourceComparison{target: t, hashed: pool.file, managedHeld: managed.file, poolName: name, pool: pool.id, managed: managed.id, open: true}
	proof.self = proof
	proof.ctx = context.WithValue(ctx, artifactSourceComparisonKey{}, proof)
	if err := proof.currentLocked(); err != nil {
		return err
	}
	return read(proof.ctx, Image{Exists: true, Data: append([]byte(nil), managed.image.Data...)}, proof)
}

func expectedPairStreamNativeDescriptor(ctx context.Context, root *ownedfs.Root, name, role string, mode os.FileMode, fault func(string, string) error, pair *expectedPairStreamNative) (file *os.File, id artifactReadFileID, image Image, result error) {
	if err := artifactComparisonContext(ctx); err != nil {
		return nil, id, image, err
	}
	before, err := root.Stat(name)
	if err != nil || !before.Mode().IsRegular() || !existingOwner(before, false) || before.Mode().Perm() != mode || before.Size() < 1 || before.Size() > ownedfs.MaxAtomicArtifactBytes {
		return nil, id, image, ErrInvalid
	}
	wanted, err := artifactReadFingerprint(before)
	if err != nil {
		return nil, id, image, err
	}
	file, err = openReadOnly(root, name)
	if err != nil {
		return nil, id, image, err
	}
	returned := false
	defer func() {
		if !returned || result != nil {
			result = errors.Join(result, file.Close())
			file = nil
		}
	}()
	held, err := file.Stat()
	actual, fpErr := artifactReadFingerprint(held)
	if err != nil || fpErr != nil || actual != wanted {
		return file, id, image, errors.Join(ErrConflict, err, fpErr)
	}
	if fault != nil {
		if err := fault(role, "opened"); err != nil {
			return file, id, image, err
		}
	}
	hash := sha256.New()
	// SectionReader uses ReadAt on this retained FD; native MatchHeld and the
	// other hash stream can never alter its offset or replace its descriptor.
	writer := io.Writer(expectedPairStreamNativeWriter{pair: pair, role: role})
	if role == "managed" {
		writer = io.MultiWriter(hash, writer)
	}
	n, readErr := io.CopyBuffer(writer, artifactContextReader{ctx, io.NewSectionReader(file, 0, before.Size()+1)}, make([]byte, 64<<10))
	if fault != nil {
		if err := fault(role, "hashed"); err != nil {
			return file, id, image, err
		}
	}
	afterFD, fdErr := file.Stat()
	after, statErr := root.Stat(name)
	afterID, afterErr := artifactReadFingerprint(after)
	fdID, fdIDErr := artifactReadFingerprint(afterFD)
	if readErr != nil || fdErr != nil || statErr != nil || afterErr != nil || fdIDErr != nil || wanted != afterID || wanted != fdID || !existingOwner(after, false) || n != before.Size() {
		return file, id, image, errors.Join(ErrConflict, readErr, fdErr, statErr, afterErr, fdIDErr)
	}
	image, err = ArtifactImage(hex.EncodeToString(hash.Sum(nil)), n)
	if err != nil {
		return file, id, image, err
	}
	returned = true
	return file, wanted, image, nil
}

func expectedPairStreamNativeTestActualFDsAndRevocation(t *testing.T) {
	target, image, pool, _ := artifactComparisonFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	held, err := os.Open(pool)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	var late *ArtifactSourceComparison
	var lateCtx context.Context
	var poolFD, managedFD *os.File
	callbackErr := errors.New("expected reader callback error")
	err = target.expectedPairStreamNativeComparison(ctx, image, func(c context.Context, got Image, proof *ArtifactSourceComparison) error {
		late, lateCtx, poolFD, managedFD = proof, c, proof.hashed, proof.managedHeld
		if !equal(got, image) || proof.MatchHeld(c, held) != nil || managedFD == nil || poolFD == nil {
			t.Fatal("actual original hash descriptors not retained")
		}
		if proof.MatchHeld(c, managedFD) == nil {
			t.Fatal("same bytes different inode accepted as pool descriptor")
		}
		copyProof := &ArtifactSourceComparison{self: proof}
		if copyProof.MatchHeld(c, held) == nil || proof.MatchHeld(ctx, held) == nil {
			t.Fatal("copied/foreign proof accepted")
		}
		return callbackErr
	}, nil)
	if !errors.Is(err, callbackErr) {
		t.Fatal(err)
	}
	if late.MatchHeld(lateCtx, held) == nil {
		t.Fatal("late proof escaped")
	}
	for _, file := range []*os.File{poolFD, managedFD} {
		if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Fatal("actual hash descriptor escaped", err)
		}
	}
}

func expectedPairStreamNativeTestAlwaysJoinsBothReaders(t *testing.T) {
	for _, role := range []string{"managed", "pool"} {
		for _, step := range []string{"opened", "hashed"} {
			for _, kind := range []string{"error", "panic", "cancel"} {
				t.Run(role+"-"+step+"-"+kind, func(t *testing.T) {
					target, image, _, _ := artifactComparisonFixture(t)
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					cut := errors.New("original worker cut")
					var otherHashed atomic.Bool
					invoked := false
					var caught any
					var result error
					fault := func(current, phase string) error {
						if current != role && phase == "hashed" {
							otherHashed.Store(true)
						}
						if current == role && phase == step {
							switch kind {
							case "error":
								return cut
							case "panic":
								panic(cut)
							case "cancel":
								cancel()
							}
						}
						return nil
					}
					func() {
						defer func() { caught = recover() }()
						result = target.expectedPairStreamNativeComparison(ctx, image, func(context.Context, Image, *ArtifactSourceComparison) error { invoked = true; return nil }, fault)
					}()
					if invoked {
						t.Fatal("failed worker invoked callback")
					}
					if kind == "panic" && caught != cut {
						t.Fatal("panic changed", caught)
					}
					if kind == "error" && !errors.Is(result, cut) {
						t.Fatal("error lost", result)
					}
					if kind == "cancel" && !errors.Is(result, context.Canceled) {
						t.Fatal("cancel lost", result)
					}
					if kind != "cancel" && !otherHashed.Load() {
						t.Fatal("other complete fresh reader not joined")
					}
				})
			}
		}
	}
}

func expectedPairStreamNativeTestMutationBetweenReadersRefuses(t *testing.T) {
	for _, role := range []string{"managed", "pool"} {
		t.Run(role, func(t *testing.T) {
			target, image, pool, managed := artifactComparisonFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var changed atomic.Bool
			fault := func(current, step string) error {
				if current != role || step != "hashed" || !changed.CompareAndSwap(false, true) {
					return nil
				}
				path := managed
				if role == "pool" {
					path = pool
				}
				// Actual equal-size in-place write; ctime/byte/FD bookends must
				// reject even when the other hash has already completed.
				info, err := os.Stat(path)
				if err != nil {
					return err
				}
				if err := os.Chmod(path, info.Mode().Perm()|0200); err != nil {
					return err
				}
				file, err := os.OpenFile(path, os.O_WRONLY, 0)
				if err != nil {
					return err
				}
				_, writeErr := file.WriteAt([]byte{0}, 0)
				return errors.Join(writeErr, file.Close())
			}
			invoked := false
			err := target.expectedPairStreamNativeComparison(ctx, image, func(context.Context, Image, *ArtifactSourceComparison) error { invoked = true; return nil }, fault)
			if !changed.Load() || invoked || !errors.Is(err, ErrConflict) {
				t.Fatal("mutation during actual reads accepted", changed.Load(), invoked, err)
			}
		})
	}
}

func expectedPairStreamNativeTestFreshReopenRejectsEqualByteReplacement(t *testing.T) {
	target, image, pool, _ := artifactComparisonFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	data, err := os.ReadFile(pool)
	if err != nil {
		t.Fatal(err)
	}
	changed := false
	fault := func(role, step string) error {
		if role != "joined" || step != "before-reopen" {
			return nil
		}
		changed = true
		if err := os.Rename(pool, pool+".previous"); err != nil {
			return err
		}
		return os.WriteFile(pool, data, 0555)
	}
	invoked := false
	err = target.expectedPairStreamNativeComparison(ctx, image, func(context.Context, Image, *ArtifactSourceComparison) error { invoked = true; return nil }, fault)
	if !changed || invoked || !errors.Is(err, ErrConflict) {
		t.Fatal("same-byte foreign pool inode accepted", changed, invoked, err)
	}
}

func expectedPairStreamNativeTestExpectedImageNeverSubstitutesForManagedBytes(t *testing.T) {
	target, _, _, _ := artifactComparisonFixture(t)
	other := artifactFixtureImage(t, target.artifactPath, []byte("another actual owned pool member"))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	invoked := false
	err := target.expectedPairStreamNativeComparison(ctx, other, func(context.Context, Image, *ArtifactSourceComparison) error { invoked = true; return nil }, nil)
	if invoked || !errors.Is(err, ErrConflict) {
		t.Fatal("expected pin replaced actual managed hash", invoked, err)
	}
}

func expectedPairStreamNativeBody(t *testing.T, source, name string) string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "source.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == name {
			var b bytes.Buffer
			if err := format.Node(&b, fset, fn.Body); err != nil {
				t.Fatal(err)
			}
			return strings.ReplaceAll(b.String(), "\n\n", "\n")
		}
	}
	t.Fatal("missing exact function", name)
	return ""
}
func TestExpectedPairStreamNativeSourceParity(t *testing.T) {
	source := strings.ReplaceAll(expectedPairStreamNativeOriginal, "\r\n", "\n")
	sum := sha256.Sum256([]byte(source))
	if hex.EncodeToString(sum[:]) != "260c3cd013179b9ff60f7405a665820fbf8d9edeab66654c9fde6cf3a3a23de6" {
		t.Fatal("original source drift; review experiment before rerun")
	}
	expected := source
	substitutions := [][2]string{
		{"launch := func(", "pair := newExpectedPairStreamNative()\n\tlaunch := func("},
		{"defer workers.Done()", "defer workers.Done()\n\t\t\tdefer pair.finish(role)"},
		{"expectedArtifactHashDescriptor(ctx, root, name, role, mode, fault)", "expectedPairStreamNativeDescriptor(ctx, root, name, role, mode, fault, pair)"},
		{"if managed.id != managedID", "if pair.mismatch.Load() || pair.managedBytes != pair.poolBytes {\n\t\treturn ErrConflict\n\t}\n\tpool.image = managed.image\n\tif managed.id != managedID"},
		{"n, readErr := io.CopyBuffer(hash, artifactContextReader{ctx, io.NewSectionReader(file, 0, before.Size()+1)}, make([]byte, 64<<10))", "writer := io.Writer(expectedPairStreamNativeWriter{pair: pair, role: role})\n\tif role == \"managed\" {\n\t\twriter = io.MultiWriter(hash, writer)\n\t}\n\tn, readErr := io.CopyBuffer(writer, artifactContextReader{ctx, io.NewSectionReader(file, 0, before.Size()+1)}, make([]byte, 64<<10))"},
	}
	for _, sub := range substitutions {
		if strings.Count(expected, sub[0]) != 1 {
			t.Fatal("ambiguous seam", sub[0])
		}
		expected = strings.Replace(expected, sub[0], sub[1], 1)
	}
	for _, names := range [][2]string{{"withExpectedReadComparison", "expectedPairStreamNativeComparison"}, {"expectedArtifactHashDescriptor", "expectedPairStreamNativeDescriptor"}} {
		if expectedPairStreamNativeBody(t, expected, names[0]) != expectedPairStreamNativeBody(t, expectedPairStreamNativeCandidate, names[1]) {
			t.Fatal("body changed beyond reviewed streaming substitution", names)
		}
	}
	t.Logf("EXPECTED_PAIR_SOURCE original_sha256=%x io_workspace_bytes=131072 original_parallel_workers=2 candidate_parallel_workers=2", sum)
}
func TestExpectedPairStreamNativeActualFDsAndRevocation(t *testing.T) {
	expectedPairStreamNativeTestActualFDsAndRevocation(t)
	t.Run("close-error", func(t *testing.T) {
		target, image, _, _ := artifactComparisonFixture(t)
		err := target.expectedPairStreamNativeComparison(context.Background(), image, func(c context.Context, got Image, p *ArtifactSourceComparison) error { return p.hashed.Close() }, nil)
		if !errors.Is(err, os.ErrClosed) {
			t.Fatal("close/descriptor failure lost", err)
		}
	})
}
func TestExpectedPairStreamNativeRefusals(t *testing.T) {
	for name, run := range map[string]func(*testing.T){"join": expectedPairStreamNativeTestAlwaysJoinsBothReaders, "mutation": expectedPairStreamNativeTestMutationBetweenReadersRefuses, "reopen": expectedPairStreamNativeTestFreshReopenRejectsEqualByteReplacement, "expected-not-bytes": expectedPairStreamNativeTestExpectedImageNeverSubstitutesForManagedBytes} {
		t.Run(name, run)
	}
	for _, position := range []int{0, 65535, 65536, 131074} {
		t.Run("mismatch-"+fmt.Sprint(position), func(t *testing.T) {
			left := bytes.Repeat([]byte{23}, 131075)
			right := append([]byte(nil), left...)
			right[position] ^= 0xff
			pair := newExpectedPairStreamNative()
			var joined sync.WaitGroup
			for i, data := range [][]byte{left, right} {
				joined.Add(1)
				go func(i int, data []byte) {
					defer joined.Done()
					role := "managed"
					if i == 1 {
						role = "pool"
					}
					defer pair.finish(role)
					_, err := io.CopyBuffer(expectedPairStreamNativeWriter{pair, role}, io.LimitReader(bytes.NewReader(data), int64(len(data))), make([]byte, 64<<10))
					if err != nil {
						t.Error(err)
					}
				}(i, data)
			}
			joined.Wait()
			if !pair.mismatch.Load() || pair.managedBytes != int64(len(left)) || pair.poolBytes != int64(len(right)) {
				t.Fatal("mismatch stopped or skipped complete reads")
			}
		})
	}
	for _, role := range []string{"managed", "pool"} {
		for _, kind := range []string{"truncate", "grow"} {
			t.Run(role+"-"+kind, func(t *testing.T) {
				target, image, pool, managed := artifactComparisonFixture(t)
				path := managed
				if role == "pool" {
					path = pool
				}
				invoked := false
				changed := false
				fault := func(current, step string) error {
					if current != role || step != "opened" {
						return nil
					}
					changed = true
					info, err := os.Stat(path)
					if err != nil {
						return err
					}
					if err := os.Chmod(path, info.Mode().Perm()|0200); err != nil {
						return err
					}
					size := info.Size() - 1
					if kind == "grow" {
						size = info.Size() + 1
					}
					if err := os.Truncate(path, size); err != nil {
						return err
					}
					return os.Chmod(path, info.Mode().Perm())
				}
				err := target.expectedPairStreamNativeComparison(context.Background(), image, func(context.Context, Image, *ArtifactSourceComparison) error { invoked = true; return nil }, fault)
				if !changed || invoked || !errors.Is(err, ErrConflict) {
					t.Fatal("actual short/extra stream admitted", changed, invoked, err)
				}
			})
		}
	}

	// Two simultaneous observations own unrelated channels/buffers and join.
	var done sync.WaitGroup
	for i := 0; i < 2; i++ {
		target, image, _, _ := artifactComparisonFixture(t)
		done.Add(1)
		go func() {
			defer done.Done()
			if err := target.expectedPairStreamNativeComparison(context.Background(), image, func(_ context.Context, got Image, _ *ArtifactSourceComparison) error {
				if !equal(got, image) {
					return ErrConflict
				}
				return nil
			}, nil); err != nil {
				t.Error(err)
			}
		}()
	}
	done.Wait()
}

func expectedPairStreamNativeActualTarget(t *testing.T) (*ArtifactFileTarget, Image) {
	t.Helper()
	path := os.Getenv("RAZVILKA_MIHOMO_ARCHIVE")
	archiveFD, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	archive, readArchiveErr := io.ReadAll(io.LimitReader(archiveFD, (64<<20)+1))
	archiveCloseErr := archiveFD.Close()
	if readArchiveErr != nil || archiveCloseErr != nil || len(archive) > 64<<20 {
		t.Fatal("bounded gzip read", readArchiveErr, archiveCloseErr)
	}
	sum := sha256.Sum256(archive)
	if hex.EncodeToString(sum[:]) != "132f6f3edf9a65e62f04853aed3358472e0b2b7666daa8419edfa2ddf5bb6323" {
		t.Fatal("unreviewed Mihomo gzip")
	}
	zipped, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		t.Fatal(err)
	}
	data, readErr := io.ReadAll(io.LimitReader(zipped, 62017663))
	closeErr := zipped.Close()
	sum = sha256.Sum256(data)
	if readErr != nil || closeErr != nil || len(data) != 62017662 || hex.EncodeToString(sum[:]) != "09c2cb429cf45fb56884ceb91a0e5b17cc8b2c866c07811bcf75dfb59fef7662" {
		t.Fatal("unreviewed expanded Mihomo", readErr, closeErr)
	}
	base := t.TempDir()
	artifacts := filepath.Join(base, "artifacts")
	bin := filepath.Join(base, "bin")
	for _, dir := range []string{artifacts, bin} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	image := artifactFixtureImage(t, artifacts, data)
	clear(data)
	clear(archive)
	target, err := OpenArtifactExecutableTarget(filepath.Join(bin, "mihomo"), artifacts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := target.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := target.CompareAndSwap(context.Background(), Image{}, image); err != nil {
		t.Fatal(err)
	}
	ref, _ := artifactImageReference(image)
	a, errA := os.Stat(filepath.Join(bin, "mihomo"))
	b, errB := os.Stat(filepath.Join(artifacts, ref.SHA256+".bin"))
	if errA != nil || errB != nil || os.SameFile(a, b) {
		t.Fatal("requires two distinct actual inode copies", errA, errB)
	}
	return target, image
}
func expectedPairStreamNativeCPU(t *testing.T, who int) int64 {
	t.Helper()
	var u unix.Rusage
	if err := unix.Getrusage(who, &u); err != nil {
		t.Fatal(err)
	}
	return u.Utime.Nano() + u.Stime.Nano()
}
func TestExpectedPairStreamNativePairedMeasurement(t *testing.T) {
	if os.Getenv("RAZVILKA_EXPECTED_PAIR_STREAM_MEASURE") != "1" {
		t.Skip("explicit isolated paired stream measurement required")
	}
	target, image := expectedPairStreamNativeActualTarget(t)
	callback := func(_ context.Context, got Image, p *ArtifactSourceComparison) error {
		if !equal(got, image) || p == nil {
			return ErrConflict
		}
		return nil
	}
	variants := []struct {
		name string
		run  func(context.Context, Image, func(context.Context, Image, *ArtifactSourceComparison) error, func(string, string) error) error
	}{
		{"original-parallel-two-sha", target.withExpectedReadComparison}, {"paired-fresh-stream-one-sha", target.expectedPairStreamNativeComparison},
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	for _, v := range variants {
		if err := v.run(context.Background(), image, callback, nil); err != nil {
			t.Fatal("untimed warmup", v.name, err)
		}
	}
	const samples = 2
	for pair := 0; pair < 8; pair++ {
		order := []int{0, 1}
		if pair%2 == 1 {
			order = []int{1, 0}
		}
		for _, index := range order {
			v := variants[index]
			threadBefore := expectedPairStreamNativeCPU(t, unix.RUSAGE_THREAD)
			totalBefore := expectedPairStreamNativeCPU(t, unix.RUSAGE_SELF)
			start := time.Now()
			for sample := 0; sample < samples; sample++ {
				if err := v.run(context.Background(), image, callback, nil); err != nil {
					t.Fatal("actual comparison failed", v.name, pair, sample, err)
				}
			}
			elapsed := time.Since(start)
			totalAfter := expectedPairStreamNativeCPU(t, unix.RUSAGE_SELF)
			threadAfter := expectedPairStreamNativeCPU(t, unix.RUSAGE_THREAD)
			row := map[string]any{"pair": pair, "variant": v.name, "samples": samples, "file_bytes": 62017662, "fresh_streams_per_sample": 2, "io_workspace_bytes": 131072, "wall_ns": elapsed.Nanoseconds(), "thread_cpu_ns": threadAfter - threadBefore, "total_process_cpu_ns": totalAfter - totalBefore, "scope": "warm two distinct pinned Mihomo copies; complete comparison including descriptor closes and callback revocation; process CPU includes both workers/runtime; thread CPU excludes workers; not route timing"}
			raw, err := json.Marshal(row)
			if err != nil {
				t.Fatal(err)
			}
			t.Log("EXPECTED_PAIR_STREAM " + string(raw))
		}
	}
}
