//go:build linux

package dataplane

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/routeidentity"
	"golang.org/x/sys/unix"
)

func TestXrayRetirementNamespaceLinks(t *testing.T) {
	same := xrayRetirementNSLink{name: "net:[1]"}
	missing := xrayRetirementNSLink{err: os.ErrNotExist}
	for _, tc := range []struct {
		name  string
		allow bool
		links [3]xrayRetirementNSLink
		ok    bool
	}{
		{"standard", false, [3]xrayRetirementNSLink{same, same, same}, true},
		{"different", true, [3]xrayRetirementNSLink{same, same, {name: "net:[2]"}}, false},
		{"mixed", true, [3]xrayRetirementNSLink{missing, same, missing}, false},
		{"permission", true, [3]xrayRetirementNSLink{missing, missing, {err: os.ErrPermission}}, false},
		{"generic", false, [3]xrayRetirementNSLink{missing, missing, missing}, false},
		{"empty", true, [3]xrayRetirementNSLink{{}, {}, {}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id, err := xrayRetirementNamespace(t.Context(), tc.allow, tc.links)
			if tc.ok && (id != same.name || err != nil) || !tc.ok && (id != "" || !errors.Is(err, ErrProxyPolicyUnknown)) {
				t.Fatalf("unexpected identity %q, err %v", id, err)
			}
		})
	}
}

func TestXrayRetirementNetnsOriginalPair(t *testing.T) {
	if os.Getenv("RAZVILKA_RETIREMENT_CHILD") == "1" {
		time.Sleep(45 * time.Second)
		return
	}
	parentNS, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		t.Skip("mount namespaces unavailable")
	}
	inherited := os.Getenv("RAZVILKA_RETIREMENT_PARENT_MNT")
	if inherited == "" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestXrayRetirementNetnsOriginalPair$", "-test.v")
		cmd.Env = append(os.Environ(), "RAZVILKA_RETIREMENT_PARENT_MNT="+parentNS)
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS}
		raw, err := cmd.CombinedOutput()
		if errors.Is(err, unix.EPERM) {
			t.Skip("needs a private mount namespace")
		}
		if err != nil {
			t.Fatalf("private mount namespace: %v\n%s", err, raw)
		}
		t.Log(string(raw))
		return
	}
	if inherited == parentNS {
		t.Fatal("mount namespace not isolated")
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var specs [2]ProcessSpec
	var pids [2]int
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	for i := range specs {
		dir := t.TempDir()
		config := filepath.Join(dir, "config")
		spec := ProcessSpec{ID: "child", Binary: exe, Args: []string{"-test.run=^TestXrayRetirementNetnsOriginalPair$", "--", config}, Dir: dir, PIDPath: filepath.Join(dir, "pid"), LogPath: filepath.Join(dir, "log"), MatchArg: config, RouteProof: true}
		content := []byte("fixture")
		if err := os.WriteFile(config, content, 0600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(exe, spec.Args...)
		cmd.Env = append(os.Environ(), "RAZVILKA_RETIREMENT_CHILD=1")
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
		pid := cmd.Process.Pid
		var raw []byte
		for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
			raw, err = routeidentity.RecordStart(pid, exe, spec.Args, config, routeidentity.Hash(content))
			if err == nil {
				break
			}
			time.Sleep(time.Millisecond)
		}
		if err != nil {
			t.Fatal(err)
		}
		for path, data := range map[string][]byte{spec.PIDPath: []byte(strconv.Itoa(pid)), spec.PIDPath + routeidentity.ReceiptSuffix: raw} {
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
		}
		pids[i], specs[i] = pid, spec
	}
	pair, err := observeXrayRetirementPairLocal(ctx, specs, true)
	if err != nil || !strings.HasPrefix(pair[0].Namespace, "net:[") {
		t.Fatalf("regular namespace read: %v", err)
	}
	// A different real network namespace, even with similarly empty tables.
	foreign := exec.Command("sleep", "45")
	foreign.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNET}
	if err := foreign.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = foreign.Process.Kill(); _ = foreign.Wait() })
	if _, err := xrayRetirementProcTables(ctx, [2]int{pids[0], foreign.Process.Pid}, func() error { t.Fatal("accepted foreign netns"); return nil }); !errors.Is(err, ErrProxyPolicyUnknown) {
		t.Fatalf("foreign network namespace: %v", err)
	}
	// All three net namespace links are genuinely absent from these paths in
	// this isolated mount tree. The underlying network tables are untouched.
	empty := t.TempDir()
	for _, pid := range []int{os.Getpid(), pids[0], pids[1]} {
		target := filepath.Join("/proc", strconv.Itoa(pid), "ns")
		if err := unix.Mount(empty, target, "", unix.MS_BIND, ""); err != nil {
			t.Fatal(err)
		}
		defer unix.Unmount(target, 0)
	}
	pair, err = observeXrayRetirementPairLocal(ctx, specs, true)
	if err != nil || !strings.HasPrefix(pair[0].Namespace, "proc-net:") || pair[0].Namespace != pair[1].Namespace || pair[0].PID != pids[0] || pair[1].PID != pids[1] {
		t.Fatalf("original pair: %v", err)
	}
	if _, err := xrayRetirementProcTables(ctx, pids, func() error { return ErrProxyPolicyUnknown }); !errors.Is(err, ErrProxyPolicyUnknown) {
		t.Fatalf("lost closing owner: %v", err)
	}
	if _, err := observeXrayRetirementPairLocal(ctx, specs, false); !errors.Is(err, ErrProxyPolicyUnknown) {
		t.Fatalf("unsealed mode: %v", err)
	}
	// Binding a dynamic proc-net file as a mountpoint is rejected on Linux.
	// Bind the stable process directory. Its device and inode still match.
	target := filepath.Join("/proc", strconv.Itoa(pids[1]))
	original, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount(target, target, "", unix.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	bound, err := os.Stat(target)
	if err != nil || !os.SameFile(original, bound) {
		t.Fatalf("bind changed inode: %v", err)
	}
	if _, err := xrayRetirementProcTables(ctx, pids, func() error { t.Fatal("accepted different mount"); return nil }); !errors.Is(err, ErrProxyPolicyUnknown) {
		t.Fatalf("same inode via another mount: %v", err)
	}
	if err := unix.Unmount(target, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(specs[0].PIDPath+routeidentity.ReceiptSuffix, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := observeXrayRetirementPairLocal(ctx, specs, true); !errors.Is(err, ErrProxyPolicyUnknown) {
		t.Fatalf("changed launch receipt: %v", err)
	}
	cancel()
	if _, err := xrayRetirementProcTables(ctx, pids, func() error { return nil }); err == nil {
		t.Fatal("cancelled observation succeeded")
	}
}
