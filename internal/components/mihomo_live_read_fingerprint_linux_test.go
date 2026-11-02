//go:build linux

package components

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/backendprofile"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"golang.org/x/sys/unix"
)

func TestMihomoLiveReadFingerprintIncludesActualIdentityAndCTime(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "fingerprint")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write([]byte("bounded file-only fingerprint fixture")); err != nil {
		t.Fatal(err)
	}
	original, err := mihomoLiveReadFileFingerprint(f)
	if err != nil {
		t.Fatal(err)
	}
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	if original.inode != uint64(stat.Ino) || original.ctimeSeconds != int64(stat.Ctim.Sec) || original.ctimeNanos != int64(stat.Ctim.Nsec) {
		t.Fatal("actual syscall identity/CTIM omitted")
	}
	changed := original
	changed.ctimeNanos ^= 1
	if changed == original {
		t.Fatal("CTIM absent from exact comparison")
	}
	if err := f.Chmod(0400); err != nil {
		t.Fatal(err)
	}
	after, err := mihomoLiveReadFileFingerprint(f)
	if err != nil || after == original {
		t.Fatal("actual mode/metadata mutation accepted", err)
	}
	if _, err := f.WriteAt([]byte("X"), 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(f.Name(), time.Unix(100, 0), time.Unix(100, 0)); err != nil {
		t.Fatal(err)
	}
	mutated, err := mihomoLiveReadFileFingerprint(f)
	if err != nil || mutated == after {
		t.Fatal("same-size byte/metadata mutation accepted", err)
	}
	foreign, err := os.CreateTemp(t.TempDir(), "same-bytes")
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Close()
	if _, err := io.Copy(foreign, io.NewSectionReader(f, 0, info.Size())); err != nil {
		t.Fatal(err)
	}
	copyID, err := mihomoLiveReadFileFingerprint(foreign)
	if err != nil || copyID == mutated || copyID.inode == mutated.inode && copyID.device == mutated.device {
		t.Fatal("foreign same-byte inode accepted", err)
	}
}

// Actual official child/held descriptor; no peer, service, TUN or routing
// success is inferred from these native process/file lifetime checks.
func TestMihomoLiveOriginalReadFingerprintNativeMutation(t *testing.T) {
	archive := os.Getenv("RAZVILKA_MIHOMO_ARCHIVE")
	if archive == "" || os.Geteuid() != 0 {
		t.Skip("root and official pinned native asset required")
	}
	compressed, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	m, info := mihomoReleaseFixture(t)
	image, err := m.stageMihomoArtifact(context.Background(), compressed, info.PinnedSHA256, mihomoFixtureAdmission)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := m.installMihomoImage(context.Background(), info, image, mihomoFixtureAdmission, mihomoFixtureAdmission); err != nil || !result.OK {
		t.Fatal(result, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	source, err := m.OpenMihomoLiveSource(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	gate := &operationgate.Gate{}
	root := filepath.Join(t.TempDir(), "control")
	if _, err := operationgate.InitializeSelfUpdateControl(ctx, root); err != nil {
		t.Fatal(err)
	}
	held, release, err := gate.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	control, err := gate.ReviewControlEpoch(held, root)
	if err != nil {
		t.Fatal(err)
	}
	cleanup, err := gate.ReviewExclusiveCleanup(held)
	if err != nil {
		control.Close()
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		control.Close()
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	raw := "vless://123e4567-e89b-12d3-a456-426614174000@edge.example:443?security=tls&sni=edge.example&type=tcp"
	options := backendprofile.MihomoOptions{SOCKSPort: port}
	compiled, err := backendprofile.Mihomo(raw, options)
	if err != nil {
		control.Close()
		t.Fatal(err)
	}
	profile, err := source.ReviewProfile(held, raw, options, digest([]byte(compiled.Config)), "edge.example", netip.MustParseAddr("1.1.1.2"))
	if err != nil {
		control.Close()
		t.Fatal(err)
	}
	child, err := source.ReserveLiveChild(held, profile, control, cleanup)
	if err != nil {
		control.Close()
		t.Fatal(err)
	}
	defer func() {
		c, done := context.WithTimeout(context.WithoutCancel(held), 5*time.Second)
		defer done()
		if err := child.Cleanup(c, cleanup); err != nil {
			t.Error("original child cleanup", err)
		}
	}()
	if err := child.StartAdmitted(held, mihomoFixtureAdmission); err != nil {
		t.Fatal(err)
	}
	native := child.native.(*mihomoLiveNativeLinux)
	// Linux protects the actual executing original image against writes.
	write, err := os.OpenFile("/proc/self/fd/"+strconv.Itoa(int(native.binary.Fd())), os.O_WRONLY, 0)
	if err == nil {
		write.Close()
		t.Fatal("executing original image became writable")
	}
	if !errors.Is(err, syscall.ETXTBSY) {
		t.Fatal("unexpected original image write refusal", err)
	}
	callbackErr := errors.New("actual native fingerprint callback failure")
	binaryInfo, err := native.binary.Stat()
	if err != nil {
		t.Fatal(err)
	}
	err = child.WithReadObservation(held, func(c context.Context, v *MihomoLiveObservation) error {
		if err := v.Current(c); err != nil {
			return err
		}
		if err := native.binary.Chmod(binaryInfo.Mode().Perm() ^ 0200); err != nil {
			return err
		}
		readErr := v.Current(c)
		restoreErr := native.binary.Chmod(binaryInfo.Mode().Perm())
		if readErr == nil {
			t.Error("original binary metadata mutation survived inner read")
		}
		// Deliberately do not return readErr: after restoring the same mode,
		// full closing still must reject the changed actual CTIM itself.
		return errors.Join(callbackErr, restoreErr)
	})
	if !errors.Is(err, callbackErr) || !errors.Is(err, ErrMihomoLiveOwner) {
		t.Fatal("metadata closing/callback cause lost", err)
	}
	if err := child.Current(held); err != nil {
		t.Fatal("restored original metadata", err)
	}
	foreign, err := os.CreateTemp(t.TempDir(), "foreign-original-bytes")
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Close()
	if _, err := io.Copy(foreign, io.NewSectionReader(native.binary, 0, binaryInfo.Size())); err != nil {
		t.Fatal(err)
	}
	backup, err := unix.FcntlInt(native.binary.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(backup)
	err = child.WithReadObservation(held, func(context.Context, *MihomoLiveObservation) error {
		if err := unix.Dup3(int(foreign.Fd()), int(native.binary.Fd()), unix.O_CLOEXEC); err != nil {
			return err
		}
		return callbackErr
	})
	restoreErr := unix.Dup3(backup, int(native.binary.Fd()), unix.O_CLOEXEC)
	if restoreErr != nil {
		t.Fatal("restore actual original descriptor", restoreErr)
	}
	if !errors.Is(err, callbackErr) || !errors.Is(err, ErrMihomoLiveOwner) {
		t.Fatal("same-byte foreign descriptor survived full closing", err)
	}
	if err := child.Current(held); err != nil {
		t.Fatal("restored held original descriptor", err)
	}
}
