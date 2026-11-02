package components

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// Transaction tests model verified bytes, not HEV native acceptance. Production
// can call this transaction only after its pinned hash and version checks.
func hevReleaseFixture(t *testing.T) (*Manager, Spec, releaseInfo) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	m := New()
	m.StateDir = filepath.Join(root, "state")
	m.BinDir = filepath.Join(root, "bin")
	m.Arch = "amd64"
	spec, ok := lookup("hev-socks5-tunnel")
	if !ok {
		t.Fatal("HEV spec absent")
	}
	info, err := hevPinnedRelease(spec, m.Arch)
	if err != nil {
		t.Fatal(err)
	}
	return m, spec, info
}
func hevAssertPair(t *testing.T, m *Manager, want []byte) {
	t.Helper()
	p := filepath.Join(m.BinDir, "hev-socks5-tunnel")
	b, err := os.ReadFile(p)
	if want == nil {
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unexpected binary: %v", err)
		}
		if _, err := os.Stat(externalReceiptPath(p)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("receipt remains: %v", err)
		}
		return
	}
	if err != nil || !bytes.Equal(b, want) {
		t.Fatalf("binary mismatch: %v", err)
	}
	if externalReceiptVersion(p) != "2.17.1" {
		t.Fatal("ownership receipt does not bind actual bytes")
	}
}
func TestHEVReleaseTransactionFaultRollback(t *testing.T) {
	for _, phase := range []string{"hev:before:a_binary", "hev:after:a_binary", "hev:after:b_receipt", "hev:after:c_lifecycle"} {
		for _, existing := range []bool{false, true} {
			if existing && phase != "hev:after:c_lifecycle" {
				continue
			} // Identical reinstall never rewrites the binary/ownership receipt.
			t.Run(phase+map[bool]string{true: "/existing", false: "/absent"}[existing], func(t *testing.T) {
				m, spec, info := hevReleaseFixture(t)
				var before []byte
				if existing {
					before = []byte("model-new")
					if _, err := m.installHEVImage(context.Background(), spec, info, before); err != nil {
						t.Fatal(err)
					}
				}
				injected := errors.New("modeled write fault")
				fired := false
				m.updateFault = func(got string) error {
					if got == phase && !fired {
						fired = true
						return injected
					}
					return nil
				}
				if result, err := m.installHEVImage(context.Background(), spec, info, []byte("model-new")); err == nil || result.OK || !errors.Is(err, injected) {
					t.Fatalf("fault lost: %+v %v", result, err)
				}
				hevAssertPair(t, m, before)
				if err := m.hevReleaseIdle(); runtime.GOOS == "linux" && err != nil {
					t.Fatalf("rollback not idle: %v", err)
				}
			})
		}
	}
}
func TestHEVReleaseRollbackConflictRetainsRecovery(t *testing.T) {
	m, spec, info := hevReleaseFixture(t)
	foreign := []byte("foreign owner edit")
	fired := false
	m.updateFault = func(phase string) error {
		if phase == "hev:after:a_binary" && !fired {
			fired = true
			if err := os.WriteFile(filepath.Join(m.BinDir, spec.Binary), foreign, 0755); err != nil {
				return err
			}
			return errors.New("postwrite model fault")
		}
		return nil
	}
	_, err := m.installHEVImage(context.Background(), spec, info, []byte("model-new"))
	if !errors.Is(err, restorejournal.ErrRecovery) {
		t.Fatalf("rollback conflict lost: %v", err)
	}
	if err := m.hevReleaseIdle(); err == nil {
		t.Fatal("foreign state silently admitted")
	}
	m.updateFault = nil
	if out, err := m.RecoverHEVRelease(context.Background()); out != restorejournal.Blocked || err == nil {
		t.Fatalf("foreign recovery: %s %v", out, err)
	}
	got, _ := os.ReadFile(filepath.Join(m.BinDir, spec.Binary))
	if !bytes.Equal(got, foreign) {
		t.Fatal("foreign bytes overwritten")
	}
}
func TestHEVReleaseCrashRecovery(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("original-owner existing-lease recovery requires Linux ownership checks")
	}
	if root := os.Getenv("RAZVILKA_HEV_RELEASE_CRASH_CHILD"); root != "" {
		m := New()
		m.StateDir = filepath.Join(root, "state")
		m.BinDir = filepath.Join(root, "bin")
		spec, _ := lookup("hev-socks5-tunnel")
		info, _ := hevPinnedRelease(spec, "amd64")
		m.updateFault = func(phase string) error {
			if phase == os.Getenv("RAZVILKA_HEV_RELEASE_CRASH_PHASE") {
				os.Exit(91)
			}
			return nil
		}
		_, _ = m.installHEVImage(context.Background(), spec, info, []byte("model-new"))
		os.Exit(92)
	}
	for _, phase := range []string{"hev:after:a_binary", "hev:after:b_receipt", "hev:after:c_lifecycle"} {
		t.Run(phase, func(t *testing.T) {
			m, _, _ := hevReleaseFixture(t)
			cmd := exec.Command(os.Args[0], "-test.run=^TestHEVReleaseCrashRecovery$")
			cmd.Env = append(os.Environ(), "RAZVILKA_HEV_RELEASE_CRASH_CHILD="+filepath.Dir(m.StateDir), "RAZVILKA_HEV_RELEASE_CRASH_PHASE="+phase)
			err := cmd.Run()
			var exited *exec.ExitError
			if !errors.As(err, &exited) || exited.ExitCode() != 91 {
				t.Fatalf("child did not reach durable write: %v", err)
			}
			if err := m.hevReleaseIdle(); err == nil {
				t.Fatal("crash pending silently admitted")
			}
			fresh := New()
			fresh.StateDir = m.StateDir
			fresh.BinDir = m.BinDir
			if out, err := fresh.RecoverHEVRelease(context.Background()); out != restorejournal.RolledBack || err != nil {
				t.Fatalf("recover: %s %v", out, err)
			}
			hevAssertPair(t, fresh, nil)
			if out, err := fresh.RecoverHEVRelease(context.Background()); out != restorejournal.Clean || err != nil {
				t.Fatalf("repeated recover: %s %v", out, err)
			}
		})
	}
}

func TestHEVReleaseChangedOwnedBinaryRequiresInactivity(t *testing.T) {
	m, spec, info := hevReleaseFixture(t)
	before := []byte("model-original")
	if _, err := m.installHEVImage(context.Background(), spec, info, before); err != nil {
		t.Fatal(err)
	}
	if _, err := m.installHEVImage(context.Background(), spec, info, []byte("model-replacement")); err == nil || !strings.Contains(err.Error(), "inactivity") {
		t.Fatalf("replacement admitted without actual runtime owner: %v", err)
	}
	hevAssertPair(t, m, before)
}
func TestHEVReleaseOwnershipAndMissingRecovery(t *testing.T) {
	m, spec, info := hevReleaseFixture(t)
	if out, err := m.RecoverHEVRelease(context.Background()); out != restorejournal.Clean || err != nil {
		t.Fatal(out, err)
	}
	if _, err := os.Stat(m.StateDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing recovery created state")
	}
	if err := os.MkdirAll(m.BinDir, 0700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(m.BinDir, spec.Binary)
	if err := os.WriteFile(p, []byte("unowned"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := m.installHEVImage(context.Background(), spec, info, []byte("new")); err == nil {
		t.Fatal("unowned executable overwritten")
	}
	got, _ := os.ReadFile(p)
	if string(got) != "unowned" {
		t.Fatal("unowned bytes changed")
	}
}

type hevReleaseTransport func(*http.Request) (*http.Response, error)

func (f hevReleaseTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestHEVReleasePinnedDownloadRejectsBeforeExecution(t *testing.T) {
	m, spec, info := hevReleaseFixture(t)
	requests := 0
	m.Client = &http.Client{Transport: hevReleaseTransport(func(r *http.Request) (*http.Response, error) {
		requests++
		if r.URL.String() != info.Asset.URL {
			t.Fatal("unpinned request", r.URL)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("untrusted bytes")), Header: make(http.Header)}, nil
	})}
	if _, err := m.installHEVRelease(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("bad digest accepted: %v", err)
	}
	if requests != 1 {
		t.Fatal(requests)
	}
	if _, err := os.Stat(m.BinDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("bad digest touched binary directory")
	}
	if _, err := hevPinnedRelease(spec, "mipsle"); err == nil {
		t.Fatal("unreviewed architecture accepted")
	}
}
