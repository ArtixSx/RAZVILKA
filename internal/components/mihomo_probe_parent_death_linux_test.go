//go:build linux

package components

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/backendprofile"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"golang.org/x/sys/unix"
)

func TestMihomoOfficialProbeDiesWithOriginalParent(t *testing.T) {
	if os.Getenv("RAZVILKA_MIHOMO_ARCHIVE") == "" {
		t.Skip("official pinned native asset required")
	}
	if root := os.Getenv("RAZVILKA_MIHOMO_PARENT_FIXTURE"); root != "" {
		mihomoParentDeathChild(t, root)
		return
	}
	root := t.TempDir()
	log, err := os.Create(filepath.Join(root, "fixture.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	parent := exec.Command(os.Args[0], "-test.run=^TestMihomoOfficialProbeDiesWithOriginalParent$", "-test.timeout=45s")
	parent.Env = append(os.Environ(), "RAZVILKA_MIHOMO_PARENT_FIXTURE="+root, "TMPDIR="+root)
	parent.Stdout, parent.Stderr = log, log
	if err := parent.Start(); err != nil {
		t.Fatal(err)
	}
	joined := false
	defer func() {
		if !joined {
			_ = parent.Process.Kill()
			_ = parent.Wait()
		}
	}()
	deadline := time.Now().Add(35 * time.Second)
	pid := 0
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(filepath.Join(root, "child.pid"))
		if err == nil {
			pid, err = strconv.Atoi(string(data))
			if err != nil {
				t.Fatal(err)
			}
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if pid < 1 {
		data, _ := os.ReadFile(filepath.Join(root, "fixture.log"))
		t.Fatalf("actual child not reported: %s", data)
	}
	stat := func() string {
		raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			t.Fatal(err)
		}
		fields := strings.Fields(string(raw)[strings.LastIndexByte(string(raw), ')')+1:])
		if len(fields) < 20 || fields[1] != strconv.Itoa(parent.Process.Pid) || fields[0] == "Z" {
			t.Fatal("child no longer belongs to original live parent")
		}
		return fields[19]
	}
	birth := stat()
	childNS, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", pid))
	if err != nil {
		t.Fatal(err)
	}
	parentNS, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", parent.Process.Pid))
	if err != nil || childNS != parentNS {
		t.Fatal("child namespace differs", err)
	}
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		t.Fatal("native fixture requires pidfd to retain exact grandchild", err)
	}
	defer unix.Close(fd)
	if stat() != birth {
		t.Fatal("child birth changed during original pidfd capture")
	}
	// Compare the actual running image with the reviewed raw asset, not a PID
	// name or a serialized reference supplied by a caller.
	executable, err := os.Open(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(io.LimitReader(executable, 256<<20+1))
	_ = executable.Close()
	approved, pinErr := mihomoReviewedRawArtifact("amd64")
	if err != nil || pinErr != nil || int64(len(data)) != approved.Size || digest(data) != approved.SHA256 || stat() != birth {
		t.Fatal("actual child binary/birth changed", err, pinErr)
	}
	clear(data)
	// Fixture teardown may signal only the already associated, held pidfd.
	defer unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
	poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	if n, err := unix.Poll(poll, 0); err != nil || n != 0 {
		t.Fatal("child was already dead before parent kill", n, err)
	}
	if err := parent.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = parent.Wait() // Exactly one Wait for the original fixture controller.
	joined = true
	if n, err := unix.Poll(poll, 5000); err != nil || n != 1 || poll[0].Revents&unix.POLLIN == 0 {
		t.Fatal("finite native child survived original parent death", n, err)
	}
	t.Log("actual live reviewed child died with original parent; held pidfd observed exit; no cold journal adoption or process restart")
}

func mihomoParentDeathChild(t *testing.T, root string) {
	m, info := mihomoReleaseFixture(t)
	compressed, err := os.ReadFile(os.Getenv("RAZVILKA_MIHOMO_ARCHIVE"))
	if err != nil {
		t.Fatal(err)
	}
	image, err := m.stageMihomoArtifact(context.Background(), compressed, info.PinnedSHA256, mihomoFixtureAdmission)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.installMihomoImage(context.Background(), info, image, mihomoFixtureAdmission, mihomoFixtureAdmission); err != nil {
		t.Fatal(err)
	}
	controlRoot := filepath.Join(root, "control")
	if _, err := operationgate.InitializeSelfUpdateControl(context.Background(), controlRoot); err != nil {
		t.Fatal(err)
	}
	gate := &operationgate.Gate{}
	held, release, err := gate.ExclusiveContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithTimeout(held, 30*time.Second)
	defer cancel()
	control, err := gate.ReviewControlEpoch(ctx, controlRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	cleanup, err := control.ReviewExclusiveCleanup(ctx)
	if err != nil {
		t.Fatal(err)
	}
	reservation, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reservation.Addr().(*net.TCPAddr).Port
	_ = reservation.Close()
	options := backendprofile.MihomoOptions{SOCKSPort: port}
	raw := "vless://123e4567-e89b-12d3-a456-426614174000@edge.example:443?security=tls&sni=edge.example&type=tcp"
	profile, err := backendprofile.Mihomo(raw, options)
	if err != nil {
		t.Fatal(err)
	}
	source, err := m.ReviewMihomoProbe(ctx, raw, options, digest([]byte(profile.Config)), "edge.example", netip.MustParseAddr("1.1.1.2"), mihomoFixtureAdmission)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	_, err = source.RunProbe(ctx, control, cleanup, func(ctx context.Context, child *MihomoProbeProcess) error {
		for {
			connection, err := (&net.Dialer{Timeout: 100 * time.Millisecond}).DialContext(ctx, "tcp4", fmt.Sprintf("127.0.0.1:%d", port))
			if err == nil {
				_ = connection.Close()
				break
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(20 * time.Millisecond):
			}
		}
		if err := child.Current(ctx); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(root, "child.pid.tmp"), []byte(strconv.Itoa(child.PID())), 0600); err != nil {
			return err
		}
		if err := os.Rename(filepath.Join(root, "child.pid.tmp"), filepath.Join(root, "child.pid")); err != nil {
			return err
		}
		<-ctx.Done()
		return ctx.Err()
	})
	t.Fatal("original parent was not killed while native borrower was live", err)
}
