//go:build linux

package components

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/backendprofile"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

func mihomoReleaseFixture(t *testing.T) (*Manager, releaseInfo) {
	t.Helper()
	base := t.TempDir()
	m := New()
	m.BinDir, m.StateDir, m.Arch = filepath.Join(base, "bin"), filepath.Join(base, "state"), "amd64"
	info, err := mihomoPinnedRelease(m.Arch)
	if err != nil {
		t.Fatal(err)
	}
	return m, info
}
func mihomoFixtureAdmission(ctx context.Context, effect func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return effect()
}
func mihomoFixtureStage(t *testing.T, m *Manager, data []byte) restorejournal.Image {
	t.Helper()
	var b bytes.Buffer
	z := gzip.NewWriter(&b)
	if _, err := z.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	image, err := m.stageMihomoArtifact(context.Background(), b.Bytes(), digest(b.Bytes()), mihomoFixtureAdmission)
	if err != nil {
		t.Fatal(err)
	}
	return image
}
func mihomoAssertInstalled(t *testing.T, m *Manager, data []byte) {
	t.Helper()
	got, err := os.ReadFile(filepath.Join(m.BinDir, "mihomo"))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("large binary differs", err)
	}
	raw, err := os.ReadFile(externalReceiptPath(filepath.Join(m.BinDir, "mihomo")))
	var receipt externalReceipt
	if err != nil || json.Unmarshal(raw, &receipt) != nil || receipt.Version != ReviewedMihomoVersion || receipt.SHA256 != digest(data) {
		t.Fatal("binary and receipt diverged", err)
	}
	if err := m.mihomoReleaseIdle(); err != nil {
		t.Fatal(err)
	}
}

func TestMihomoLargeArtifactInstallReinstallAndFailures(t *testing.T) {
	data := bytes.Repeat([]byte("Mihomo model binary data\n"), 240000)
	for _, fault := range []string{"", "mihomo:before:a_binary", "mihomo:after:a_binary", "mihomo:after:b_receipt", "mihomo:after:c_lifecycle"} {
		t.Run(fault, func(t *testing.T) {
			m, info := mihomoReleaseFixture(t)
			image := mihomoFixtureStage(t, m, data)
			fired := false
			m.updateFault = func(point string) error {
				if point == fault && !fired {
					fired = true
					return errors.New("fixture interruption")
				}
				return nil
			}
			result, err := m.installMihomoImage(context.Background(), info, image, mihomoFixtureAdmission, mihomoFixtureAdmission)
			if fault == "" {
				if err != nil || !result.OK {
					t.Fatal(result, err)
				}
				mihomoAssertInstalled(t, m, data)
				if again, err := m.installMihomoImage(context.Background(), info, image, mihomoFixtureAdmission, mihomoFixtureAdmission); err != nil || !again.OK {
					t.Fatal("identical reinstall", again, err)
				}
				mihomoAssertInstalled(t, m, data)
			} else {
				if err == nil || !fired || result.OK {
					t.Fatal("fault hidden", result, err)
				}
				for _, p := range []string{filepath.Join(m.BinDir, "mihomo"), externalReceiptPath(filepath.Join(m.BinDir, "mihomo")), filepath.Join(m.StateDir, "receipts", "mihomo.json")} {
					if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
						t.Fatal("partial install survived compensation", p, err)
					}
				}
				if err := m.mihomoReleaseIdle(); err != nil {
					t.Fatal("known compensation not settled", err)
				}
			}
		})
	}
}

func TestMihomoArtifactRefusesTamperingAndCancelledPublish(t *testing.T) {
	for _, change := range []string{"pin", "cancel", "artifact", "foreign-installed", "different-version"} {
		t.Run(change, func(t *testing.T) {
			m, info := mihomoReleaseFixture(t)
			data := bytes.Repeat([]byte("pinned-model"), 400000)
			if change == "pin" {
				if _, err := m.stageMihomoArtifact(context.Background(), data, "wrong", mihomoFixtureAdmission); err == nil {
					t.Fatal("wrong pin accepted")
				}
				return
			}
			image := mihomoFixtureStage(t, m, data)
			if change == "artifact" {
				ref, _ := mihomoArtifactReferenceOf(image)
				_, _, root, _, _ := m.mihomoReleaseLayout()
				path := filepath.Join(root, ref.SHA256+".bin")
				if err := os.Chmod(path, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("foreign"), 0755); err != nil {
					t.Fatal(err)
				}
			}
			if change == "foreign-installed" {
				if err := os.MkdirAll(m.BinDir, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(m.BinDir, "mihomo"), data, 0755); err != nil {
					t.Fatal(err)
				}
			}
			if change == "different-version" {
				if _, err := m.installMihomoImage(context.Background(), info, image, mihomoFixtureAdmission, mihomoFixtureAdmission); err != nil {
					t.Fatal(err)
				}
				image = mihomoFixtureStage(t, m, append(data, 'x'))
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if change == "cancel" {
				cancel()
			}
			if result, err := m.installMihomoImage(ctx, info, image, mihomoFixtureAdmission, mihomoFixtureAdmission); err == nil || result.OK {
				t.Fatal("invalid mutation accepted", result, err)
			}
			if change == "different-version" {
				mihomoAssertInstalled(t, m, data)
			}
		})
	}
}

func TestMihomoArtifactProcessCrashRecovery(t *testing.T) {
	if os.Getenv("RAZVILKA_MIHOMO_CRASH_CHILD") == "1" {
		m := New()
		m.BinDir, m.StateDir, m.Arch = os.Getenv("RAZVILKA_MIHOMO_TEST_BIN"), os.Getenv("RAZVILKA_MIHOMO_TEST_STATE"), "amd64"
		data := bytes.Repeat([]byte("durable-large-model"), 300000)
		image := mihomoFixtureStage(t, m, data)
		info, _ := mihomoPinnedRelease("amd64")
		m.updateFault = func(point string) error {
			if point == os.Getenv("RAZVILKA_MIHOMO_CRASH_AT") {
				os.Exit(109)
			}
			return nil
		}
		_, _ = m.installMihomoImage(context.Background(), info, image, mihomoFixtureAdmission, mihomoFixtureAdmission)
		t.Fatal("crash point not reached")
	}
	for _, point := range []string{"mihomo:after:a_binary", "mihomo:after:b_receipt", "mihomo:after:c_lifecycle"} {
		t.Run(point, func(t *testing.T) {
			m, _ := mihomoReleaseFixture(t)
			cmd := exec.Command(os.Args[0], "-test.run=^TestMihomoArtifactProcessCrashRecovery$")
			cmd.Env = append(os.Environ(), "RAZVILKA_MIHOMO_CRASH_CHILD=1", "RAZVILKA_MIHOMO_TEST_BIN="+m.BinDir, "RAZVILKA_MIHOMO_TEST_STATE="+m.StateDir, "RAZVILKA_MIHOMO_CRASH_AT="+point)
			out, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 109 {
				t.Fatalf("child did not crash: %v %s", err, out)
			}
			if err := m.mihomoReleaseIdle(); err == nil {
				t.Fatal("pending install not fenced")
			}
			if outcome, err := m.RecoverMihomoRelease(context.Background()); err != nil || outcome != restorejournal.RolledBack {
				t.Fatal("cold rollback", outcome, err)
			}
			if outcome, err := m.RecoverMihomoRelease(context.Background()); err != nil || outcome != restorejournal.Clean {
				t.Fatal("cold recovery retry", outcome, err)
			}
			if _, err := os.Stat(filepath.Join(m.BinDir, "mihomo")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("binary survived rollback", err)
			}
		})
	}
}

func TestMihomoOfficialPinnedNativeInstall(t *testing.T) {
	path := os.Getenv("RAZVILKA_MIHOMO_ARCHIVE")
	if path == "" {
		t.Skip("requires official pinned gzip asset")
	}
	compressed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	m, info := mihomoReleaseFixture(t)
	m.Client = &http.Client{Transport: hevReleaseTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != info.Asset.URL {
			t.Fatal("unreviewed release URL", r.URL)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(compressed)), Header: make(http.Header)}, nil
	})}
	for range 2 {
		result, err := m.ApplyMihomoGuarded(context.Background(), mihomoFixtureAdmission, mihomoFixtureAdmission, mihomoFixtureAdmission)
		if err != nil || !result.OK {
			t.Fatal(result, err)
		}
		s, err := m.openMihomoRelease(false)
		if err != nil {
			t.Fatal(err)
		}
		image, readErr := s.files["a_binary"].Read(context.Background())
		closeErr := s.close()
		if readErr != nil || closeErr != nil {
			t.Fatal(readErr, closeErr)
		}
		_, _, artifacts, _, _ := m.mihomoReleaseLayout()
		if err := verifyMihomoArtifactRelease(context.Background(), artifacts, image, mihomoFixtureAdmission); err != nil {
			t.Fatal(err)
		}
		if err := m.mihomoReleaseIdle(); err != nil {
			t.Fatal(err)
		}
	}
	// Hold the selected port while -t validates the compiled profile: config
	// validation must not require or start a SOCKS listener or a remote server.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	options := backendprofile.MihomoOptions{SOCKSPort: listener.Addr().(*net.TCPAddr).Port}
	source := "vless://123e4567-e89b-12d3-a456-426614174000@edge.example:443?security=tls&sni=edge.example&type=tcp"
	profile, err := backendprofile.Mihomo(source, options)
	if err != nil {
		t.Fatal(err)
	}
	review := digest([]byte(profile.Config))
	starts := 0
	start := func(ctx context.Context, begin func() error) error {
		starts++
		return mihomoFixtureAdmission(ctx, begin)
	}
	validation, err := m.ValidateMihomoProfileGuarded(context.Background(), source, options, review, mihomoFixtureAdmission, start)
	if err != nil || !validation.NativeValidated || validation.ServiceVerified || validation.LiveApplied || validation.ConfigSHA256 != review || starts != 1 {
		t.Fatal("native config validation lost exact scope", validation, starts, err)
	}
	if _, err := m.ValidateMihomoProfileGuarded(context.Background(), source, options, digest([]byte("other config")), mihomoFixtureAdmission, start); err == nil || starts != 1 {
		t.Fatal("changed preview executed native process", starts, err)
	}
}
