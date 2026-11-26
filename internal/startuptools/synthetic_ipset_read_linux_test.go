//go:build linux && amd64

package startuptools

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"golang.org/x/sys/unix"
)

func TestSyntheticIPSetStartupNative(t *testing.T) {
	if os.Getenv("RAZVILKA_SYNTHETIC_IPSET_NATIVE") != "1" {
		t.Skip("explicit actual protected StartupTools fixture")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root required")
	}
	if os.Getenv("RAZVILKA_SYNTHETIC_IPSET_STARTUP_CHILD") != "1" {
		binary, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(binary, "-test.run=^TestSyntheticIPSetStartupNative$", "-test.v", "-test.count=1")
		cmd.Env = append(os.Environ(), "RAZVILKA_SYNTHETIC_IPSET_STARTUP_CHILD=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNET}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("private source fixture failed: %v\n%s", err, out)
		}
		t.Log(string(out))
		return
	}
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	initial, err := os.Readlink("/proc/1/ns/net")
	if err != nil || current == initial {
		t.Fatal("fixture refuses initial host namespace")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "/usr/sbin/ipset", "create", "rz_ipset_source", "hash:net", "family", "inet").CombinedOutput(); err != nil {
		t.Fatalf("isolated set creation failed: %v (%d bytes)", err, len(out))
	}
	lifetime, stop := context.WithCancel(context.Background())
	defer stop()
	lease, err := AcquireUbuntuLegacyPolicy(lifetime, netidentity.NewProcProvider())
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	reader, err := lease.SyntheticBaselineIPSetReader()
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.EquivalentDestinations(ctx, "rz_ipset_source", netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("198.18.0.1")); err != nil {
		t.Fatal("actual source refused empty pair", err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if err := reader.EquivalentDestinations(ctx, "rz_ipset_source", netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("198.18.0.1")); err == nil {
		t.Fatal("closed source still issued membership comparison")
	}
	t.Log("NATIVE_SOURCE_ONLY: actual held StartupTools source, namespace bookends, and close revocation; no DNS publication/forward grant")
}
