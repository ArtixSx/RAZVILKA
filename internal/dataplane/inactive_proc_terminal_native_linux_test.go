//go:build linux && razvilka_native_fixture

package dataplane

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type inactiveThreadgroupStat struct {
	state   byte
	threads int
	ticks   string
}

func inactiveThreadgroupReadStat(fd, pid int) (inactiveThreadgroupStat, error) {
	leaf, err := unix.Openat(fd, "stat", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return inactiveThreadgroupStat{}, err
	}
	file := os.NewFile(uintptr(leaf), "held-original-stat")
	data, readErr := io.ReadAll(io.LimitReader(file, 16385))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return inactiveThreadgroupStat{}, errors.Join(readErr, closeErr)
	}
	if len(data) > 16384 {
		return inactiveThreadgroupStat{}, ErrProxyRuntimeInactive
	}
	state, _, ticks, err := proxyInactiveProcStat(data, pid)
	if err != nil {
		return inactiveThreadgroupStat{}, err
	}
	fields := strings.Fields(string(data[strings.LastIndex(string(data), ")")+1:]))
	threads, err := strconv.Atoi(fields[17])
	if err != nil || threads < 1 || strconv.Itoa(threads) != fields[17] {
		return inactiveThreadgroupStat{}, ErrProxyRuntimeInactive
	}
	return inactiveThreadgroupStat{state, threads, ticks}, nil
}

// Actual thread-group regression: a zombie leader with a live worker is never terminal.
func TestInactiveProcNativeThreadGroupClassification(t *testing.T) {
	helper := os.Getenv("RAZVILKA_INACTIVE_THREADGROUP_HELPER")
	if helper == "" {
		t.Skip("explicit isolated pthread reproduction only")
	}
	if !filepath.IsAbs(helper) || os.Getpid() != 1 {
		t.Fatal("private PID1 and exact helper required")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	commandsR, commandsW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer commandsR.Close()
	defer commandsW.Close()
	repliesR, repliesW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer repliesR.Close()
	defer repliesW.Close()
	deadline, _ := ctx.Deadline()
	if commandsW.SetWriteDeadline(deadline) != nil || repliesR.SetReadDeadline(deadline) != nil {
		t.Fatal("bounded control pipes required")
	}
	stateRoot := filepath.Join(t.TempDir(), "state")
	cmd := exec.CommandContext(ctx, helper, "leader", helper, "--dataplane-state="+stateRoot)
	cmd.Args[0] = "mihomo"
	cmd.ExtraFiles = []*os.File{commandsR, repliesW}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	joined := false
	defer func() {
		if !joined {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	if err := commandsR.Close(); err != nil {
		t.Fatal(err)
	}
	if err := repliesW.Close(); err != nil {
		t.Fatal(err)
	}
	send := func(value byte) {
		t.Helper()
		if _, err := commandsW.Write([]byte{value}); err != nil {
			t.Fatal("pipe command", err)
		}
	}
	receive := func(want byte) {
		t.Helper()
		var data [1]byte
		if _, err := io.ReadFull(repliesR, data[:]); err != nil || data[0] != want {
			t.Fatal("pipe reply", want, data, err)
		}
	}
	receive('L')
	pid := cmd.Process.Pid
	root, err := unix.Open("/proc", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if root >= 0 {
			if err := unix.Close(root); err != nil {
				t.Error(err)
			}
		}
	}()
	fd, err := unix.Openat(root, strconv.Itoa(pid), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if fd >= 0 {
			if err := unix.Close(fd); err != nil {
				t.Error(err)
			}
		}
	}()
	var original unix.Stat_t
	if err := unix.Fstat(fd, &original); err != nil {
		t.Fatal(err)
	}
	opening, err := inactiveThreadgroupReadStat(fd, pid)
	if err != nil || opening.state == 'Z' {
		t.Fatal("original live child", err)
	}
	inactiveThreadgroupMountFences(t, ctx, pid)
	sameNamed := func() {
		t.Helper()
		var held, named unix.Stat_t
		if unix.Fstat(fd, &held) != nil || unix.Fstatat(root, strconv.Itoa(pid), &named, unix.AT_SYMLINK_NOFOLLOW) != nil || held.Dev != original.Dev || held.Ino != original.Ino || named.Dev != original.Dev || named.Ino != original.Ino {
			t.Fatal("original named PID directory changed")
		}
	}
	proxyProof, err := proxyInactivePlatformProof()
	if err != nil {
		t.Fatal(err)
	}
	dnsProof, err := scopedDNSInactivePlatformProof()
	if err != nil {
		t.Fatal(err)
	}
	adapter := &ProxyTunnelAdapter{EngineID: "mihomo", EngineBin: helper, SOCKSPort: 1080, StateRoot: filepath.Join(stateRoot, "mihomo")}
	observe := func(expectRefusal bool) {
		t.Helper()
		a := proxyInactiveProc(ctx, proxyProof, adapter)
		b := scopedDNSInactiveProc(ctx, dnsProof, filepath.Join(stateRoot, "mihomo"), filepath.Join(stateRoot, "config.json"), nil)
		if (a != nil) != expectRefusal || (b != nil) != expectRefusal {
			t.Fatal("actual observer result", expectRefusal, a, b)
		}
	}
	observe(true)
	send('Z')
	receive('W')
	var zombie inactiveThreadgroupStat
	for {
		if ctx.Err() != nil {
			t.Fatal(ctx.Err())
		}
		send('P')
		receive('P')
		zombie, err = inactiveThreadgroupReadStat(fd, pid)
		if err != nil {
			t.Fatal(err)
		}
		if zombie.state == 'Z' {
			break
		}
	}
	if zombie.threads < 2 || zombie.ticks != opening.ticks {
		t.Fatal("live worker zombie leader not proven", zombie)
	}
	sameNamed()
	observe(true)
	send('P')
	receive('P')
	sameNamed()
	t.Logf("INACTIVE_PROC_LIVE_WORKER_REFUSED state=Z threads=%d live_worker_ping=true observers=proxy,scoped-dns", zombie.threads)
	send('X')
	receive('E')
	afterExec, err := inactiveThreadgroupReadStat(fd, pid)
	if err != nil || afterExec.state == 'Z' || afterExec.ticks != opening.ticks {
		t.Fatal("worker exec same TGID/starttime", afterExec, err)
	}
	sameNamed()
	observe(true)
	t.Log("INACTIVE_PROC_WORKER_EXEC same_pid=true same_starttime=true live_observers_refuse=true")
	send('Q')
	var end [1]byte
	if n, err := repliesR.Read(end[:]); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatal("original group EOF", n, err)
	}
	for {
		if ctx.Err() != nil {
			t.Fatal(ctx.Err())
		}
		zombie, err = inactiveThreadgroupReadStat(fd, pid)
		if err != nil {
			t.Fatal(err)
		}
		if zombie.state == 'Z' && zombie.threads == 1 {
			break
		}
	}
	if zombie.ticks != opening.ticks {
		t.Fatal("terminal birth changed")
	}
	sameNamed()
	observe(false)
	waitErr := cmd.Wait()
	joined = true
	if waitErr != nil {
		t.Fatal("sole original Wait", waitErr)
	}
	_, statErr := inactiveThreadgroupReadStat(fd, pid)
	var named unix.Stat_t
	nameErr := unix.Fstatat(root, strconv.Itoa(pid), &named, unix.AT_SYMLINK_NOFOLLOW)
	if !(errors.Is(statErr, unix.ENOENT) || errors.Is(statErr, unix.ESRCH)) || !errors.Is(nameErr, unix.ENOENT) {
		t.Fatal("held and named original gone", statErr, nameErr)
	}
	closeErr := unix.Close(fd)
	fd = -1
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	closeErr = unix.Close(root)
	root = -1
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	t.Log("INACTIVE_PROC_Z1_THEN_GONE sole_wait=true held_and_named_gone=true; process leaf only, no socket/route acceptance")
}

func inactiveThreadgroupMountFences(t *testing.T, ctx context.Context, pid int) {
	t.Helper()
	for _, which := range []string{"pid-directory", "stat", "cmdline", "self-ns-directory", "self-fdinfo-directory"} {
		if !t.Run("mount-"+which, func(t *testing.T) {
			passValue, err := openLinuxInactiveProc(ctx, "/proc", os.Getpid())
			if err != nil {
				t.Fatal(err)
			}
			pass := passValue.(*linuxInactiveProcPass)
			defer func() {
				if !pass.closed {
					_ = pass.Close()
				}
			}()
			child, err := pass.OpenPID(pid)
			if err != nil {
				t.Fatal(err)
			}
			closedChild := false
			defer func() {
				if !closedChild {
					_ = child.Close()
				}
			}()
			if _, err := child.Stat(); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join("/proc", strconv.Itoa(pid))
			switch which {
			case "stat", "cmdline":
				target = filepath.Join(target, which)
			case "self-ns-directory":
				target = filepath.Join("/proc", strconv.Itoa(os.Getpid()), "ns")
			case "self-fdinfo-directory":
				target = filepath.Join("/proc", strconv.Itoa(os.Getpid()), "fdinfo")
			}
			before, err := unix.Open(target, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := unix.Close(before); err != nil {
					t.Error(err)
				}
			}()
			var beforeStat unix.Stat_t
			if err := unix.Fstat(before, &beforeStat); err != nil {
				t.Fatal(err)
			}
			beforeMount, err := pass.mountID(before)
			if err != nil {
				t.Fatal(err)
			}
			if err := unix.Mount(target, target, "", unix.MS_BIND, ""); err != nil {
				t.Fatal("owned mount fixture", err)
			}
			mounted := true
			defer func() {
				if mounted {
					if err := unix.Unmount(target, 0); err != nil {
						t.Error("fixture unmount", err)
					}
				}
			}()
			after, err := unix.Open(target, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			var afterStat unix.Stat_t
			statErr := unix.Fstat(after, &afterStat)
			afterMount, mountErr := pass.mountID(after)
			closeErr := unix.Close(after)
			if statErr != nil || mountErr != nil || closeErr != nil || !inactiveProcSame(beforeStat, afterStat) || beforeMount == afterMount {
				t.Fatal("same-inode different-mount fixture", statErr, mountErr, closeErr)
			}
			switch which {
			case "pid-directory":
				if child.Current() == nil {
					t.Fatal("late same-inode PID bind accepted")
				}
				fresh, err := pass.OpenPID(pid)
				if err == nil {
					_ = fresh.Close()
					t.Fatal("new same-inode PID bind accepted")
				}
			case "stat":
				if _, err := child.Stat(); err == nil {
					t.Fatal("stat bind accepted")
				}
			case "cmdline":
				if _, err := child.Command(); err == nil {
					t.Fatal("cmdline bind accepted")
				}
			default:
				if pass.currentRoot() == nil {
					t.Fatal("late self anchor bind accepted")
				}
				fresh, err := openLinuxInactiveProc(ctx, "/proc", os.Getpid())
				if err == nil {
					_ = fresh.Close()
					t.Fatal("new self anchor bind accepted")
				}
			}
			childCloseErr := child.Close()
			closedChild = true
			passCloseErr := pass.Close()
			if !inactiveThreadgroupOnlyGuardRefusal(childCloseErr) || !inactiveThreadgroupOnlyGuardRefusal(passCloseErr) {
				t.Fatal("unexpected cleanup failure", childCloseErr, passCloseErr)
			}
			if err := unix.Unmount(target, 0); err != nil {
				t.Fatal("fixture unmount", err)
			}
			mounted = false
			fresh, err := openLinuxInactiveProc(ctx, "/proc", os.Getpid())
			if err != nil {
				t.Fatal("restored root", err)
			}
			h, err := fresh.OpenPID(pid)
			if err != nil {
				_ = fresh.Close()
				t.Fatal(err)
			}
			_, readErr := h.Stat()
			closeErr = errors.Join(h.Close(), fresh.Close())
			if readErr != nil || closeErr != nil {
				t.Fatal("restored original PID", readErr, closeErr)
			}
		}) {
			t.Fatal("mount fence regression")
		}
	}
	t.Log("INACTIVE_PROC_MOUNT_FENCES same_inode_different_mount=true cases=5 restored=true")
}

func inactiveThreadgroupOnlyGuardRefusal(err error) bool {
	if err == nil || err == ErrProxyRuntimeInactive {
		return true
	}
	if many, ok := err.(interface{ Unwrap() []error }); ok {
		for _, child := range many.Unwrap() {
			if !inactiveThreadgroupOnlyGuardRefusal(child) {
				return false
			}
		}
		return true
	}
	return false
}
