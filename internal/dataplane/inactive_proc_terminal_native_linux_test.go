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

// Diagnostic baseline only: this test deliberately records the current false
// terminal skip. After the production fix the same physical case must refuse.
func TestInactiveProcNativeLeaderExitReproduction(t *testing.T) {
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
	observe(false)
	send('P')
	receive('P')
	sameNamed()
	t.Logf("INACTIVE_PROC_BASELINE_FALSE_PASS state=Z threads=%d live_worker_ping=true observers=proxy,scoped-dns; DIAGNOSTIC_NOT_ACCEPTANCE", zombie.threads)
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
