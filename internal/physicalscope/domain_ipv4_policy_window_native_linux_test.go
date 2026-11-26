//go:build linux

package physicalscope

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The complete add/delete cycle runs in a new namespace, with its identity
// independently compared to the parent's before any fixture command runs.
func TestNativeDomainIPv4PolicyWindowRejectsRestoredRule(t *testing.T) {
	if os.Getenv("RAZVILKA_DOMAIN_POLICY_WINDOW_NATIVE") != "1" {
		t.Skip("explicit disposable network namespace fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	namespace, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer namespace.Close()
	if os.Getenv("RAZVILKA_DOMAIN_POLICY_WINDOW_TEST_CHILD") != "1" {
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNativeDomainIPv4PolicyWindowRejectsRestoredRule$", "-test.v", "-test.count=1")
		cmd.Env = append(os.Environ(), "RAZVILKA_DOMAIN_POLICY_WINDOW_TEST_CHILD=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNET}
		cmd.ExtraFiles = []*os.File{namespace}
		out, err := cmd.CombinedOutput()
		if err != nil || !bytes.Contains(out, []byte("restored rule revoked the original read")) {
			t.Fatalf("isolated network notification check: %v\n%s", err, out)
		}
		t.Log(string(out))
		return
	}
	parent := os.NewFile(3, "parent namespace")
	defer parent.Close()
	var fs unix.Statfs_t
	if err := unix.Fstatfs(int(parent.Fd()), &fs); err != nil || fs.Type != unix.NSFS_MAGIC {
		t.Fatalf("fixture needs the inherited original namespace descriptor: %v", err)
	}
	parentInfo, parentErr := parent.Stat()
	currentInfo, currentErr := namespace.Stat()
	if err := errors.Join(parentErr, currentErr); err != nil || os.SameFile(parentInfo, currentInfo) {
		t.Fatalf("fixture cannot modify rules in its parent's network namespace: %v", err)
	}
	links, err := net.Interfaces()
	if err != nil || len(links) != 1 || links[0].Flags&net.FlagLoopback == 0 {
		t.Fatalf("fixture requires a fresh loopback-only namespace: %v", err)
	}
	runIP := func(args ...string) []byte {
		t.Helper()
		out, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("fixture ip %v: %v\n%s", args, err, out)
		}
		return out
	}
	before := runIP("-4", "rule", "show")
	monitor, err := platformOpenDomainIPv4PolicyWindow(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := monitor.close(); err != nil {
			t.Error(err)
		}
	}()
	if err := monitor.quiet(ctx); err != nil {
		t.Fatal("new subscription has no pending events", err)
	}
	runIP("-4", "rule", "add", "priority", "175", "fwmark", "0x77/0xff", "lookup", "10037")
	runIP("-4", "rule", "del", "priority", "175", "fwmark", "0x77/0xff", "lookup", "10037")
	if after := runIP("-4", "rule", "show"); !bytes.Equal(before, after) {
		t.Fatal("fixture did not restore the initial policy")
	}
	if err := monitor.quiet(ctx); !errors.Is(err, ErrDomainIPv4PolicyWindowChanged) {
		t.Fatal("identical final policy hid notifications of the intervening change", err)
	}
	t.Log("restored rule revoked the original read")
}
