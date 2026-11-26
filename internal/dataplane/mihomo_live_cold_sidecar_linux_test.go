//go:build linux

package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/routeidentity"
	"golang.org/x/sys/unix"
)

const mihomoColdSidecarFixtureImage = `{"razvilka_native_cold_sidecar":1}`

func init() {
	// Dedicated actual OS child only. It implements no TUN/service and grants
	// no production runtime. No environment-dependent launcher is used.
	if len(os.Args) == 2 && os.Args[1] == "/proc/self/fd/4" {
		data, err := os.ReadFile(os.Args[1])
		if err == nil && string(data) == mihomoColdSidecarFixtureImage {
			for {
				syscall.Pause()
			}
		}
	}
}

func TestMihomoLiveColdSidecarSignalsOnlyObservedPidfdAndKeepsFiles(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("actual root-owned native receipt required")
	}
	for _, mode := range []string{"original", "wrong-receipt", "wrong-birth", "foreign-cleanup", "unsealed-profile"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			root := filepath.Join(t.TempDir(), "runtime")
			if err := os.Mkdir(root, 0700); err != nil {
				t.Fatal(err)
			}
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			image, info, err := mihomoColdFileHash(ctx, binary)
			if err != nil {
				t.Fatal(err)
			}
			config := []byte(mihomoColdSidecarFixtureImage)
			spec := ProcessSpec{ID: "mihomo-tun", Binary: binary, Args: []string{"/proc/self/fd/4"}, Dir: root, PIDPath: filepath.Join(root, "sidecar.pid"), LogPath: filepath.Join(root, "sidecar.log"), MatchArg: filepath.Join(root, "sidecar.json"), RouteProof: true}
			if err := os.WriteFile(spec.MatchArg, config, 0600); err != nil {
				t.Fatal(err)
			}
			executable, err := os.Open(binary)
			if err != nil {
				t.Fatal(err)
			}
			defer executable.Close()
			fd, err := unix.MemfdCreate("mihomo-cold-fixture", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
			if err != nil {
				t.Fatal(err)
			}
			profile := os.NewFile(uintptr(fd), "sealed-profile")
			defer profile.Close()
			if _, err := profile.Write(config); err != nil {
				t.Fatal(err)
			}
			if mode != "unsealed-profile" {
				if _, err := unix.FcntlInt(profile.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_SEAL|unix.F_SEAL_SHRINK|unix.F_SEAL_GROW|unix.F_SEAL_WRITE); err != nil {
					t.Fatal(err)
				}
			}
			command := exec.Command("/proc/self/fd/3", spec.Args...)
			command.Args[0] = binary
			command.Env = []string{}
			command.Dir = root
			command.ExtraFiles = []*os.File{executable, profile}
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() { _ = command.Wait(); close(done) }()
			defer func() {
				_ = command.Process.Kill()
				select {
				case <-done:
				case <-time.After(time.Second):
				}
			}()
			var raw []byte
			for end := time.Now().Add(2 * time.Second); time.Now().Before(end); {
				raw, err = routeidentity.RecordStart(command.Process.Pid, binary, spec.Args, spec.MatchArg, routeidentity.Hash(config))
				if err == nil {
					break
				}
				time.Sleep(time.Millisecond)
			}
			if err != nil {
				t.Fatal(err)
			}
			if mode == "wrong-birth" {
				var r routeidentity.Receipt
				if json.Unmarshal(raw, &r) != nil {
					t.Fatal("receipt")
				}
				r.StartTicks = "1"
				raw, _ = json.Marshal(r)
			}
			pidRaw := []byte(strconv.Itoa(command.Process.Pid) + "\n")
			if err := os.WriteFile(spec.PIDPath, pidRaw, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(spec.PIDPath+routeidentity.ReceiptSuffix, raw, 0600); err != nil {
				t.Fatal(err)
			}
			provider := netidentity.NewProcProvider()
			identity, err := provider.Observe(ctx)
			if err != nil {
				t.Fatal(err)
			}
			d := mihomoLiveDefinitionFixture(t)
			d.NetworkIdentity = identity
			d.Source.ParentOrigin.BootID = identity.BootID
			d.Sidecar = MihomoLiveSidecarReference{Kind: "hev", BinarySHA256: image, BinarySize: info.Size(), ConfigSHA256: routeidentity.Hash(config)}
			d.Observation = &MihomoLiveRuntimeObservation{Schema: 1, SidecarReceiptVersion: 1, SidecarReceiptSHA256: routeidentity.Hash(raw)}
			if mode == "wrong-receipt" {
				d.Observation.SidecarReceiptSHA256 = strings.Repeat("0", 64)
			}
			gate := &operationgate.Gate{}
			controlRoot := filepath.Join(t.TempDir(), "control")
			if _, err := operationgate.InitializeSelfUpdateControl(ctx, controlRoot); err != nil {
				t.Fatal(err)
			}
			held, release, err := gate.ExclusiveContext(ctx)
			if err != nil {
				t.Fatal(err)
			}
			control, err := gate.ReviewControlEpoch(held, controlRoot)
			if err != nil {
				release()
				t.Fatal(err)
			}
			defer control.Close()
			oldCleanup, err := gate.ReviewExclusiveCleanup(held)
			if err != nil {
				release()
				t.Fatal(err)
			}
			release()
			fresh, finish, err := gate.ExclusiveContext(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer finish()
			cleanup, err := gate.ReviewExclusiveCleanup(fresh)
			if err != nil {
				t.Fatal(err)
			}
			if err := stopMihomoLiveColdSidecar(ctx, provider, control, oldCleanup, spec, d); err == nil {
				t.Fatal("released operation signalled child")
			}
			if mode == "foreign-cleanup" {
				other := &operationgate.Gate{}
				c, close, err := other.ExclusiveContext(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer close()
				cleanup, err = other.ReviewExclusiveCleanup(c)
				if err != nil {
					t.Fatal(err)
				}
			}
			err = stopMihomoLiveColdSidecar(ctx, provider, control, cleanup, spec, d)
			if mode == "original" {
				if err != nil {
					t.Fatal(err)
				}
				select {
				case <-done:
				case <-ctx.Done():
					t.Fatal("original child not reaped")
				}
			} else {
				if err == nil {
					t.Fatal("changed ownership signalled")
				}
				if err := command.Process.Signal(syscall.Signal(0)); err != nil {
					t.Fatal("foreign child was affected", err)
				}
			}
			for path, want := range map[string][]byte{spec.PIDPath: pidRaw, spec.PIDPath + routeidentity.ReceiptSuffix: raw, spec.MatchArg: config} {
				got, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(got, want) {
					t.Fatal("cold signal erased history", path, err)
				}
			}
		})
	}
}
