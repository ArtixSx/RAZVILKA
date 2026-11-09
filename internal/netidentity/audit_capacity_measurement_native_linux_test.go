//go:build linux && (amd64 || arm64) && razvilka_native_fixture

package netidentity

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"os"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The duplicated measurement body is mechanically checked against the real
// producer below. It retains the old backing allocation for a paired baseline.
//go:embed observe_linux.go
var auditCapacityProductionSource string

//go:embed audit_capacity_measurement_native_linux_test.go
var auditCapacityCandidateSource string

func captureProcBeforeReservation(ctx context.Context) observation {
	r := observation{}
	if ctx == nil || ctx.Err() != nil {
		return r
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	r.Checks.ThreadLocked = true
	pid, tid := syscall.Getpid(), syscall.Gettid()
	if pid <= 0 || tid <= 0 {
		return r
	}
	pidName, tidName := strconv.Itoa(pid), strconv.Itoa(tid)
	releaseBefore, machineBefore, ok := kernelTuple()
	if !ok {
		return r
	}
	r.KernelRelease, r.Machine = releaseBefore, machineBefore
	a := &audit{fdinfo: -1, ctx: ctx}
	defer a.close()
	rootFD, err := syscall.Open("/proc", dirFlags, 0)
	if err != nil {
		return r
	}
	root, ok := a.take(rootFD, true, false)
	if !ok {
		return r
	}
	if root.fs.Type != procMagic || root.stat.Ino != 1 {
		return r
	}
	a.root = root
	r.Checks.ProcRootVerified = true
	if !selfMatches(root.fd, pidName, tidName) {
		return r
	}
	pidFD, ok := a.openDir(root.fd, pidName)
	if !ok {
		return r
	}
	taskFD, ok := a.openDir(pidFD, "task")
	if !ok {
		return r
	}
	tidFD, ok := a.openDir(taskFD, tidName)
	if !ok {
		return r
	}
	nsFD, ok := a.openDir(tidFD, "ns")
	if !ok {
		return r
	}
	a.fdinfo, ok = a.openDir(pidFD, "fdinfo")
	if !ok {
		return r
	}
	sysFD, ok := a.openDir(root.fd, "sys")
	if !ok {
		return r
	}
	kernelFD, ok := a.openDir(sysFD, "kernel")
	if !ok {
		return r
	}
	randomFD, ok := a.openDir(kernelFD, "random")
	if !ok {
		return r
	}
	pidNSFD, ok := a.openDir(pidFD, "ns")
	if !ok {
		return r
	}
	r.Checks.AnchoredWalkVerified = true
	rootMount, ok := a.mountID(root.fd)
	if !ok {
		return r
	}
	if !a.mountsMatch(rootMount) {
		return r
	}
	// Reject submounts covering any audited path, including fdinfo children.
	paths := []string{"/proc/self", "/proc/thread-self", "/proc/" + pidName,
		"/proc/" + pidName + "/task/" + tidName + "/ns", "/proc/" + pidName + "/ns", "/proc/" + pidName + "/stat",
		"/proc/" + pidName + "/task/" + tidName + "/stat",
		"/proc/" + pidName + "/task/" + tidName + "/mountinfo",
		"/proc/" + pidName + "/fdinfo", "/proc/sys/kernel/random/boot_id"}
	mountBefore, ok := a.readFile(tidFD, "mountinfo", maxMountBytes, rootMount)
	if !ok || !mountLayoutOK(mountBefore, rootMount, paths) {
		return r
	}
	r.Checks.SameProcMount = true
	processStartBefore, ok := a.taskStart(pidFD, pid, rootMount)
	if !ok {
		return r
	}
	startBefore, ok := a.taskStart(tidFD, tid, rootMount)
	if !ok {
		return r
	}
	bootBefore, ok := a.bootID(randomFD, rootMount)
	if !ok {
		return r
	}
	position, err := syscall.Seek(nsFD, 0, 1)
	if err != nil || position != 0 {
		return r
	}
	r.Checks.FreshPositionZero = true
	r.Names, r.DTUnknownObserved, r.DirectoryComplete, ok = readNamespaceDirectory(ctx, func(buf []byte) (int, error) { return syscall.ReadDirent(nsFD, buf) })
	if !ok {
		return r
	}
	r.Checks.RawDirentsValid = true
	r.Checks.DotsPresent = true
	position, err = syscall.Seek(pidNSFD, 0, 1)
	if err != nil || position != 0 {
		return r
	}
	pidNames, _, complete, valid := readNamespaceDirectory(ctx, func(buf []byte) (int, error) { return syscall.ReadDirent(pidNSFD, buf) })
	if !complete || !valid {
		return r
	}
	r.PIDNames = pidNames
	for _, name := range r.Names {
		if name == "net" {
			r.NetPresent = true
		}
		if name == "mnt" {
			r.MntPresent = true
		}
	}
	r.BootID = string(bootBefore[:36])
	var net *netPair
	if r.NetPresent {
		var valid bool
		net, valid = holdNetPair(pidNSFD, nsFD)
		if !valid {
			return r
		}
		defer net.close()
		r.Inode = net.stats[0].Ino
	}
	// All postchecks run on the same locked thread and retained directory FDs.
	startAfter, ok := a.taskStart(tidFD, tid, rootMount)
	if !ok {
		return r
	}
	processStartAfter, ok := a.taskStart(pidFD, pid, rootMount)
	if !ok {
		return r
	}
	r.Checks.SameTaskStart = startBefore > 0 && processStartBefore > 0 && startBefore == startAfter && processStartBefore == processStartAfter
	bootAfter, ok := a.bootID(randomFD, rootMount)
	if !ok {
		return r
	}
	r.Checks.SameBoot = bytes.Equal(bootBefore, bootAfter)
	mountAfter, ok := a.readFile(tidFD, "mountinfo", maxMountBytes, rootMount)
	if !ok {
		return r
	}
	r.Checks.SameMountLayout = bytes.Equal(mountBefore, mountAfter) && mountLayoutOK(mountAfter, rootMount, paths)
	releaseAfter, machineAfter, ok := kernelTuple()
	if !ok {
		return r
	}
	r.Checks.SameKernelRelease = releaseBefore == releaseAfter && machineBefore == machineAfter
	r.Checks.SamePIDTID = syscall.Getpid() == pid && syscall.Gettid() == tid
	r.Checks.SelfLinksMatch = selfMatches(root.fd, pidName, tidName)
	r.Checks.HeldDescriptorsStable = a.stable() && a.mountsMatch(rootMount)
	r.Checks.ReopenedPathStable = a.reopenMatches(pidName, tidName, rootMount, pidNSFD, nsFD)
	if r.NetPresent {
		closing, valid := holdNetPair(pidNSFD, nsFD)
		if !valid {
			return r
		}
		same := closing.stats[0].Ino == r.Inode && net.stable()
		closing.close()
		if !same {
			return r
		}
	}
	if ctx.Err() != nil {
		return observation{}
	}
	c := r.Checks
	r.ObservationValid = r.DirectoryComplete && r.MntPresent && c.ThreadLocked &&
		c.ProcRootVerified && c.SelfLinksMatch && c.AnchoredWalkVerified && c.SameProcMount &&
		c.FreshPositionZero && c.RawDirentsValid && c.DotsPresent && c.SamePIDTID &&
		c.SameTaskStart && c.SameBoot && c.SameKernelRelease && c.SameMountLayout &&
		c.HeldDescriptorsStable && c.ReopenedPathStable
	return r
}

func TestAuditCapacityCandidateSourceParity(t *testing.T) {
	extract := func(source, start, end string) string {
		source = strings.ReplaceAll(source, "\r\n", "\n")
		from := strings.Index(source, start)
		if from < 0 {
			t.Fatal("capture function start absent")
		}
		to := strings.Index(source[from:], end)
		if to < 0 {
			t.Fatal("capture function end absent")
		}
		return strings.TrimSpace(source[from : from+to])
	}
	before := extract(auditCapacityProductionSource, "func captureProc(", "\nfunc (a *audit) close()")
	after := extract(auditCapacityCandidateSource, "func captureProcBeforeReservation(", "\nfunc TestAuditCapacityCandidateSourceParity(")
	before = strings.Replace(before, "func captureProc(", "func captureProcBeforeReservation(", 1)
	before = strings.Replace(before, "// Reserve common descriptor storage; append still grows without a new cap.\n\tvar retained [16]heldFD\n\ta := &audit{fds: retained[:0], fdinfo: -1, ctx: ctx}", "a := &audit{fdinfo: -1, ctx: ctx}", 1)
	if before != after {
		t.Fatal("measurement body drifted beyond backing storage initializer")
	}
}

type auditCapacityCancelContext struct {
	context.Context
	calls, at int
}

func (c *auditCapacityCancelContext) Err() error {
	c.calls++
	if c.calls >= c.at {
		return context.Canceled
	}
	return nil
}

func TestAuditCapacityCandidateActualCleanup(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	before := captureProcBeforeReservation(ctx)
	after := captureProc(ctx)
	if !before.ObservationValid || !reflect.DeepEqual(before, after) {
		t.Fatal("actual complete capture parity refused")
	}
	descriptors := func() int {
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		return len(entries)
	}
	count := descriptors()
	for i := 0; i < 16; i++ {
		canceled, stop := context.WithCancel(ctx)
		stop()
		for _, read := range []func(context.Context) observation{captureProcBeforeReservation, captureProc} {
			if read(canceled).ObservationValid {
				t.Fatal("canceled entry accepted")
			}
			late := &auditCapacityCancelContext{Context: ctx, at: 8}
			if read(late).ObservationValid || late.calls < late.at {
				t.Fatal("late cancellation accepted or not reached")
			}
		}
	}
	if descriptors() != count {
		t.Fatal("capture cancellation changed actual FD count")
	}
	// Reservation is capacity, never an admission cap: actual held FD ownership
	// still grows beyond sixteen and closes every adopted descriptor.
	var retained [16]heldFD
	a := &audit{fds: retained[:0], fdinfo: -1, ctx: ctx}
	defer func() {
		if a.fds != nil {
			a.close()
		}
	}()
	for i := 0; i < 20; i++ {
		fd, err := syscall.Open("/proc", dirFlags, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := a.take(fd, true, false); !ok {
			t.Fatal("actual additional held descriptor refused")
		}
	}
	if len(a.fds) != 20 || !a.stable() {
		t.Fatal("append fallback lost original descriptor ownership")
	}
	fds := append([]heldFD(nil), a.fds...)
	a.close()
	a.fds = nil
	for _, held := range fds {
		var st syscall.Stat_t
		if !errors.Is(syscall.Fstat(held.fd, &st), syscall.EBADF) {
			t.Fatal("adopted descriptor remained open")
		}
	}
	if descriptors() != count {
		t.Fatal("append fallback leaked actual descriptors")
	}
}

func BenchmarkProcAuditCapacityCandidate(b *testing.B) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	before, after := captureProcBeforeReservation(ctx), captureProc(ctx)
	if !before.ObservationValid || !reflect.DeepEqual(before, after) {
		b.Fatal("actual complete capture parity refused")
	}
	for _, sample := range []struct {
		name    string
		capture func(context.Context) observation
	}{{"before_append", captureProcBeforeReservation}, {"reserved_candidate", captureProc}} {
		b.Run(sample.name, func(b *testing.B) {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			// Subbenchmarks execute on their own pinned goroutine/thread. Re-establish
			// their complete reference before timing; no source observation is cached.
			reference := captureProc(ctx)
			if !reference.ObservationValid {
				b.Fatal("subbenchmark original capture refused")
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				actual := sample.capture(ctx)
				if !actual.ObservationValid || !auditCapacityObservationsEqual(actual, reference) {
					b.Fatal("fresh complete capture refused")
				}
			}
		})
	}
}

func auditCapacityObservationsEqual(a, b observation) bool {
	return a.KernelRelease == b.KernelRelease && a.Machine == b.Machine && a.BootID == b.BootID &&
		slices.Equal(a.Names, b.Names) && slices.Equal(a.PIDNames, b.PIDNames) && a.Inode == b.Inode &&
		a.NetPresent == b.NetPresent && a.MntPresent == b.MntPresent && a.DirectoryComplete == b.DirectoryComplete &&
		a.DTUnknownObserved == b.DTUnknownObserved && a.ObservationValid == b.ObservationValid && a.Checks == b.Checks
}
