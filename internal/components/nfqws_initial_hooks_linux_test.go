//go:build linux

package components

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

// Opt-in genuine pinned IPK preinst/postinst + native opkg/supervisor exercise.
// Only the test authority/runtime source is modeled. It does not prove the
// startup kernel inventory, router packet semantics, or physical power loss.
// The child MUST have distinct mount and network namespaces and private /opt.
func TestNFQWSInitialNativeIPK(t *testing.T) {
	if os.Getenv("RAZVILKA_NFQWS_INITIAL_NATIVE") != "1" {
		t.Skip("requires root, private mount/network namespaces, pinned IPK and native opkg")
	}
	if os.Getenv("RAZVILKA_NFQWS_INITIAL_CHILD") == "1" {
		nfqwsInitialNativeChild(t)
		return
	}
	if os.Geteuid() != 0 {
		t.Fatal("opt-in native test requires root; no hooks were run")
	}
	path := os.Getenv("RAZVILKA_NFQWS_INITIAL_IPK")
	source, err := os.ReadFile(path)
	if !filepath.IsAbs(path) || err != nil || len(source) != nfqwsInitialSourceSize || digest(source) != nfqwsInitialSourceSHA {
		t.Fatal("opt-in test requires the exact pinned source IPK at RAZVILKA_NFQWS_INITIAL_IPK", err)
	}
	if info, err := os.Stat("/opt"); err != nil || !info.IsDir() {
		t.Fatal("existing /opt mount target required; host path is never created by test", err)
	}
	work := t.TempDir()
	command := exec.Command(os.Args[0], "-test.run=^TestNFQWSInitialNativeIPK$", "-test.v", "-test.timeout=150s")
	command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNS | syscall.CLONE_NEWNET}
	command.Env = append(os.Environ(), "RAZVILKA_NFQWS_INITIAL_CHILD=1", "RAZVILKA_NFQWS_INITIAL_WORK="+work,
		"RAZVILKA_NFQWS_INITIAL_PARENT_MNT="+nfqwsInitialNS(t, "mnt"), "RAZVILKA_NFQWS_INITIAL_PARENT_NET="+nfqwsInitialNS(t, "net"))
	out, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated native IPK test failed: %v\n%s", err, out)
	}
	t.Log(string(out))
}

func nfqwsInitialNS(t *testing.T, name string) string {
	t.Helper()
	value, err := os.Readlink("/proc/self/ns/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func nfqwsInitialNativeChild(t *testing.T) {
	for _, name := range []string{"mnt", "net"} {
		if nfqwsInitialNS(t, name) == os.Getenv("RAZVILKA_NFQWS_INITIAL_PARENT_"+strings.ToUpper(name)) {
			t.Fatal("namespace isolation missing", name)
		}
	}
	work := os.Getenv("RAZVILKA_NFQWS_INITIAL_WORK")
	if !filepath.IsAbs(work) || work == "/" {
		t.Fatal("private absolute test workspace required")
	}
	opkg, err := exec.LookPath(os.Getenv("RAZVILKA_TEST_OPKG"))
	if err != nil || !filepath.IsAbs(opkg) {
		t.Fatal("RAZVILKA_TEST_OPKG must name the actual native opkg binary", err)
	}
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		t.Fatal(err)
	}
	offline := filepath.Join(work, "offline")
	prefix := filepath.Join(offline, "opt")
	for _, path := range []string{prefix, filepath.Join(prefix, "etc", "init.d"), filepath.Join(prefix, "usr", "bin"), filepath.Join(prefix, "bin"), filepath.Join(prefix, "var", "run"), filepath.Join(prefix, "lib", "opkg", "info"), filepath.Join(prefix, "tmp"), filepath.Join(offline, "usr", "lib", "opkg")} {
		if err := os.MkdirAll(path, 0755); err != nil {
			t.Fatal(err)
		}
	}
	// Native opkg's compiled metadata prefix is /usr/lib/opkg; expose the same
	// PRIVATE database under the production /opt/lib/opkg coordinates too.
	if err := syscall.Mount(filepath.Join(prefix, "lib", "opkg"), filepath.Join(offline, "usr", "lib", "opkg"), "", syscall.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mount(prefix, "/opt", "", syscall.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	privateInfo, err := os.Stat(prefix)
	if err != nil {
		t.Fatal(err)
	}
	mountedInfo, err := os.Stat("/opt")
	if err != nil || !os.SameFile(privateInfo, mountedInfo) {
		t.Fatal("/opt is not the private package root", err)
	}
	write := func(path, text string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, []byte(text), mode); err != nil {
			t.Fatal(err)
		}
	}
	// Existing dependencies are private package database records. No dependency
	// package, remote feed, upgrade, resolver, or host database is used.
	write("/opt/lib/opkg/status", "Package: iptables\nVersion: 1.4.21-6\nArchitecture: all\nStatus: install user installed\n\nPackage: busybox\nVersion: 1.37.0-6\nArchitecture: all\nStatus: install ok installed\n\n", 0644)
	for _, dependency := range []string{"busybox", "iptables"} {
		write("/opt/lib/opkg/info/"+dependency+".list", "", 0644)
	}
	arch := nfqwsInitialArchitectures[runtime.GOARCH]
	if arch == "" {
		t.Fatal("unsupported test architecture", runtime.GOARCH)
	}
	config := filepath.Join(work, "opkg.conf")
	write(config, "dest root /\nlists_dir ext /usr/lib/opkg/lists\narch all 1\narch "+arch+" 10\n", 0600)
	write("/opt/etc/opkg.conf", "arch "+arch+" 10\n", 0644)
	write("/opt/bin/route", "#!/bin/sh\nprintf 'default 0.0.0.0 0.0.0.0 UG 0 0 0 eth3\\n'\n", 0755)
	write("/opt/bin/ip", "#!/bin/sh\nprintf 'inet6 2001:db8::1/64 scope global\\n'\n", 0755)
	for _, tool := range []string{"iptables", "ip6tables", "modprobe", "insmod", "rmmod"} {
		write("/opt/bin/"+tool, "#!/bin/sh\necho invoked >> /opt/forbidden-effects.trace\nexit 97\n", 0755)
	}
	t.Setenv("PATH", "/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	m, _, authority := initialInstallFixture(t)
	m.InitDir, m.BinDir, m.InfoDir = "/opt/etc/init.d", "/opt/bin", "/opt/lib/opkg/info"
	m.Opkg = opkg
	m.Arch, m.StateDir, m.nfqwsFixture = runtime.GOARCH, filepath.Join(work, "state"), nil
	m.Runner = nativeOpkgRunner{config: config, root: offline}
	m.Timeout = 90 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	result, err := m.InstallInitialNFQWS(ctx, authority)
	if err != nil || !result.OK || !result.InstalledIdleAccepted {
		t.Fatalf("actual native --nodeps installation/readback: %+v %v", result, err)
	}
	state, pending, err := m.PendingManagedUpdate()
	if err != nil || pending || state.Phase != nfqwsInitialAccepted {
		t.Fatal("native hooks did not produce verified-idle evidence", state, pending, err)
	}
	init, err := os.ReadFile("/opt/etc/init.d/S51nfqws2")
	owner, ownerErr := engineconfig.NFQWSFirstStartInitOwner(init)
	if err != nil || ownerErr != nil || owner == "" {
		t.Fatal("actual opkg replaced the inert init", err)
	}
	// Poisoning occurs only AFTER the full install/readback assertion. Every
	// ordinary hook below must exit before source, so no config can run.
	conf, err := os.OpenFile("/opt/etc/nfqws2/nfqws2.conf", os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = conf.WriteString("\ntouch /opt/forbidden-source.trace\n")
	if closeErr := conf.Close(); err != nil || closeErr != nil {
		t.Fatal(err, closeErr)
	}
	for _, action := range []string{"start", "restart", "stop", "status", "firewall_iptables", "firewall_ip6tables", "kernel_modules", "unknown", ""} {
		args := []string{}
		if action != "" {
			args = append(args, action)
		}
		out, err := exec.CommandContext(ctx, "/opt/etc/init.d/S51nfqws2", args...).CombinedOutput()
		if action == "status" {
			if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 3 || !bytes.Contains(out, []byte("RAZVILKA")) {
				t.Fatal("ordinary status claimed running health", err, string(out))
			}
		} else if err != nil {
			t.Fatal("ordinary action was not inert", action, err, string(out))
		}
	}
	// Exercise the actual NDM hook's live-PID branch, without any NFQ process.
	write("/opt/var/run/nfqws2.pid", strconv.Itoa(os.Getpid())+"\n", 0600)
	ndm := exec.CommandContext(ctx, "/opt/etc/ndm/netfilter.d/100-nfqws2.sh")
	ndm.Env = append(os.Environ(), "table=mangle", "type=iptables")
	if out, err := ndm.CombinedOutput(); err != nil {
		t.Fatal("actual NDM hook failed", err, string(out))
	}
	if err := os.Remove("/opt/var/run/nfqws2.pid"); err != nil {
		t.Fatal(err)
	}
	for _, trace := range []string{"/opt/forbidden-effects.trace", "/opt/forbidden-source.trace", "/opt/tmp/nfqws2_install_type", "/opt/tmp/nfqws2_binary"} {
		if _, err := os.Lstat(trace); !os.IsNotExist(err) {
			t.Fatal("hook effects or incomplete genuine postinst", trace, err)
		}
	}
	t.Log(fmt.Sprintf("genuine pinned hooks + joined native opkg --nodeps verified in %s/%s; /opt=%s", nfqwsInitialNS(t, "mnt"), nfqwsInitialNS(t, "net"), prefix))
}
