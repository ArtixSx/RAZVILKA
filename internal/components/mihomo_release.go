package components

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

const MihomoReleaseReadVersion = 6
const ReviewedMihomoVersion = "1.19.33"

func mihomoPinnedRelease(arch string) (releaseInfo, error) {
	var digest string
	switch arch {
	case "amd64":
		digest = "132f6f3edf9a65e62f04853aed3358472e0b2b7666daa8419edfa2ddf5bb6323"
	case "arm64":
		digest = "ba408b317080ee265c46cb923a50018c1b82cbd708551cdd46a1e3e307396187"
	default:
		return releaseInfo{}, errors.New("Mihomo has no reviewed Linux asset for this architecture")
	}
	name := "mihomo-linux-" + arch + "-v" + ReviewedMihomoVersion + ".gz"
	return releaseInfo{Version: ReviewedMihomoVersion, PinnedSHA256: digest, Asset: releaseAsset{Name: name, URL: "https://github.com/MetaCubeX/mihomo/releases/download/v" + ReviewedMihomoVersion + "/" + name}}, nil
}

type mihomoArtifactReference struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

func mihomoArtifactReferenceOf(image restorejournal.Image) (mihomoArtifactReference, error) {
	var ref mihomoArtifactReference
	if !image.Exists || json.Unmarshal(image.Data, &ref) != nil {
		return ref, restorejournal.ErrInvalid
	}
	canonical, err := restorejournal.ArtifactImage(ref.SHA256, ref.Size)
	if err != nil || !bytes.Equal(canonical.Data, image.Data) {
		return ref, restorejournal.ErrInvalid
	}
	return ref, nil
}

// The compressed official asset is bounded independently of private journal
// images. Expanded executables are streamed and retained by content hash; the
// journal contains only closed references and small ownership receipts.
func (m *Manager) stageMihomoArtifact(ctx context.Context, compressed []byte, pin string, rename func(context.Context, func() error) error) (image restorejournal.Image, err error) {
	if ctx == nil || rename == nil || digest(compressed) != pin {
		return image, errors.New("Mihomo official pinned SHA-256 mismatch")
	}
	_, _, artifacts, _, err := m.mihomoReleaseLayout()
	if err != nil {
		return image, err
	}
	if err := os.MkdirAll(artifacts, 0700); err != nil {
		return image, err
	}
	root, err := ownedfs.Open(artifacts)
	if err != nil {
		return image, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	anchor, err := root.RootInfo()
	if _, ok := hevRetainedOwner(anchor, true); err != nil || !ok {
		return image, restorejournal.ErrInvalid
	}
	current := func() error {
		named, e := os.Lstat(artifacts)
		held, h := root.RootInfo()
		if e != nil || h != nil || !os.SameFile(anchor, named) || !os.SameFile(anchor, held) || anchor.Mode() != named.Mode() {
			return restorejournal.ErrConflict
		}
		return ctx.Err()
	}
	// A private temporary file is never an executable source until the complete
	// gzip stream and official compressed digest have both been verified.
	if err := current(); err != nil {
		return image, err
	}
	name := ".mihomo-stage-" + rand.Text()
	temp, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return image, err
	}
	identity, err := temp.Stat()
	if err != nil {
		_ = temp.Close()
		return image, err
	}
	defer func() {
		if info, e := root.Stat(name); e == nil && os.SameFile(identity, info) {
			err = errors.Join(err, root.Remove(name))
		} else if !errors.Is(e, os.ErrNotExist) {
			err = errors.Join(err, restorejournal.ErrConflict, e)
		}
	}()
	z, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		_ = temp.Close()
		return image, err
	}
	hash := sha256.New()
	n, copyErr := io.CopyBuffer(io.MultiWriter(temp, hash), io.LimitReader(mihomoContextReader{ctx, z}, ownedfs.MaxAtomicArtifactBytes+1), make([]byte, 64<<10))
	err = errors.Join(copyErr, z.Close(), temp.Sync(), temp.Close())
	if err != nil || n < 1 || n > ownedfs.MaxAtomicArtifactBytes {
		return image, errors.Join(err, restorejournal.ErrInvalid)
	}
	sum := hex.EncodeToString(hash.Sum(nil))
	image, err = restorejournal.ArtifactImage(sum, n)
	if err != nil {
		return image, err
	}
	if err := current(); err != nil {
		return image, err
	}
	source, err := root.OpenFile(name, hevRetainedReadFlags, 0)
	if err != nil {
		return image, err
	}
	defer func() { err = errors.Join(err, source.Close()) }()
	sourceInfo, err := source.Stat()
	if err != nil || !os.SameFile(identity, sourceInfo) {
		return image, restorejournal.ErrConflict
	}
	destination := sum + ".bin"
	if _, e := root.Stat(destination); e == nil {
		// An existing cache entry must be the complete immutable exact image.
		if err := verifyMihomoArtifact(ctx, root, destination, image); err != nil {
			return image, err
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return image, e
	} else {
		var expected [32]byte
		copy(expected[:], hash.Sum(nil))
		_, err = root.WriteAtomicStreamWithRenameAdmission(ctx, destination, source, n, expected, 0555, func(effect func() error) error { return rename(ctx, effect) }, func() error {
			if err := current(); err != nil {
				return err
			}
			if _, e := root.Stat(destination); !errors.Is(e, os.ErrNotExist) {
				return restorejournal.ErrConflict
			}
			held, e := source.Stat()
			named, ne := root.Stat(name)
			if e != nil || ne != nil || !os.SameFile(identity, held) || !os.SameFile(identity, named) {
				return restorejournal.ErrConflict
			}
			return nil
		})
		if err != nil {
			return image, err
		}
		if err := root.Sync(); err != nil {
			return image, err
		}
	}
	if err := current(); err != nil {
		return image, err
	}
	if err := verifyMihomoArtifact(ctx, root, destination, image); err != nil {
		return image, err
	}
	return image, nil
}

type mihomoContextReader struct {
	ctx    context.Context
	source io.Reader
}

func (r mihomoContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.source.Read(p)
}

func verifyMihomoArtifact(ctx context.Context, root *ownedfs.Root, name string, image restorejournal.Image) (err error) {
	ref, err := mihomoArtifactReferenceOf(image)
	if err != nil || name != ref.SHA256+".bin" {
		return restorejournal.ErrInvalid
	}
	before, err := root.Stat(name)
	if err != nil || !mihomoArtifactOwner(before) || before.Size() != ref.Size {
		return restorejournal.ErrConflict
	}
	f, err := root.OpenFile(name, hevRetainedReadFlags, 0)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	held, err := f.Stat()
	if err != nil || !os.SameFile(before, held) || !mihomoArtifactOwner(held) {
		return restorejournal.ErrConflict
	}
	h := sha256.New()
	n, err := io.CopyBuffer(h, io.LimitReader(mihomoContextReader{ctx, f}, ref.Size+1), make([]byte, 64<<10))
	if err != nil || n != ref.Size || hex.EncodeToString(h.Sum(nil)) != ref.SHA256 {
		return errors.Join(err, restorejournal.ErrConflict)
	}
	after, err := root.Stat(name)
	if err != nil || !os.SameFile(before, after) || !mihomoArtifactOwner(after) || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) || before.Size() != after.Size() {
		return restorejournal.ErrConflict
	}
	return ctx.Err()
}

func (m *Manager) ApplyMihomoGuarded(ctx context.Context, guard, rename, start func(context.Context, func() error) error) (result Result, err error) {
	result = Result{Component: "mihomo", Action: "install"}
	if m == nil || ctx == nil || guard == nil || rename == nil || start == nil {
		return result, NoMutation(ErrRecoveryAuthority)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := guard(ctx, func() error { return ctx.Err() }); err != nil {
		return result, NoMutation(err)
	}
	release, err := m.fencePackageMutation()
	if err != nil {
		return result, NoMutation(err)
	}
	defer release()
	info, err := mihomoPinnedRelease(m.Arch)
	if err != nil {
		return result, err
	}
	compressed, err := m.download(ctx, info.Asset.URL, 32<<20)
	if err != nil {
		return result, err
	}
	var image restorejournal.Image
	err = guard(ctx, func() error {
		image, err = m.stageMihomoArtifact(ctx, compressed, info.PinnedSHA256, rename)
		return err
	})
	clear(compressed)
	if err != nil {
		return result, err
	}
	_, _, artifacts, _, err := m.mihomoReleaseLayout()
	if err != nil {
		return result, err
	}
	if err := verifyMihomoArtifactRelease(ctx, artifacts, image, start); err != nil {
		return result, err
	}
	return m.installMihomoImage(ctx, info, image, guard, rename)
}
