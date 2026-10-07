//go:build linux && (amd64 || arm64)

package netidentity

// Extracted from reviewed procns90 helper SHA256
// 53eceab895ac42d28b4d7cc3198a7946cc4fb0b5a8148e1138f546efa9d1295e.
// Driver, stdout, exit watchdog and timers are deliberately absent.
import (
	"bytes"
	"context"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const (
	procMagic = 0x9fa0
	dirFlags  = syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
	fileFlags = syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC | syscall.O_NONBLOCK
)

type heldFD struct {
	fd   int
	stat syscall.Stat_t
	fs   syscall.Statfs_t
}
type audit struct {
	fds    []heldFD
	root   heldFD
	fdinfo int
	ctx    context.Context
}

func readObservation(ctx context.Context) (observation, error) {
	if ctx == nil {
		return observation{}, ErrUnknown
	}
	r := captureProc(ctx)
	if ctx.Err() != nil {
		return observation{}, ctx.Err()
	}
	if !r.ObservationValid {
		return observation{}, ErrUnknown
	}
	return r, nil
}
func captureProc(ctx context.Context) observation {
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

func (a *audit) close() {
	for i := len(a.fds) - 1; i >= 0; i-- {
		syscall.Close(a.fds[i].fd)
	}
}

func sameIdentity(a, b heldFD) bool {
	return a.stat.Dev == b.stat.Dev && a.stat.Ino == b.stat.Ino && a.stat.Mode == b.stat.Mode &&
		a.fs.Type == b.fs.Type && a.fs.Fsid == b.fs.Fsid
}

func (a *audit) take(fd int, directory, requireRoot bool) (heldFD, bool) {
	h := heldFD{fd: fd}
	if syscall.Fstat(fd, &h.stat) != nil || syscall.Fstatfs(fd, &h.fs) != nil {
		syscall.Close(fd)
		return heldFD{}, false
	}
	expectedType := uint32(syscall.S_IFREG)
	if directory {
		expectedType = syscall.S_IFDIR
	}
	if h.stat.Mode&syscall.S_IFMT != expectedType || h.fs.Type != procMagic ||
		(requireRoot && (h.stat.Dev != a.root.stat.Dev || h.fs.Fsid != a.root.fs.Fsid)) {
		syscall.Close(fd)
		return heldFD{}, false
	}
	a.fds = append(a.fds, h)
	return h, true
}

func (a *audit) openDir(parent int, name string) (int, bool) {
	if a.ctx.Err() != nil || !component(name) {
		return -1, false
	}
	fd, err := syscall.Openat(parent, name, dirFlags, 0)
	if err != nil {
		return -1, false
	}
	h, ok := a.take(fd, true, true)
	return h.fd, ok
}

func component(s string) bool {
	return len(s) > 0 && len(s) <= 64 && s != "." && s != ".." && !strings.ContainsAny(s, "/\x00")
}

// Temporary read FDs are closed immediately; no mutable file content is emitted.
func (a *audit) rawFile(parent int, name string, limit int) ([]byte, bool) {
	if a.ctx.Err() != nil || !component(name) || limit < 1 || limit > maxMountBytes {
		return nil, false
	}
	fd, err := syscall.Openat(parent, name, fileFlags, 0)
	if err != nil {
		return nil, false
	}
	defer syscall.Close(fd)
	var st syscall.Stat_t
	var fs syscall.Statfs_t
	if syscall.Fstat(fd, &st) != nil || syscall.Fstatfs(fd, &fs) != nil ||
		st.Mode&syscall.S_IFMT != syscall.S_IFREG || fs.Type != procMagic ||
		st.Dev != a.root.stat.Dev || fs.Fsid != a.root.fs.Fsid {
		return nil, false
	}
	return boundedRead(a.ctx, fd, limit)
}

func boundedRead(ctx context.Context, fd, limit int) ([]byte, bool) {
	data := make([]byte, 0, limit)
	buf := make([]byte, 4096)
	for calls := 0; calls < limit/len(buf)+3; calls++ {
		need := limit + 1 - len(data)
		if ctx.Err() != nil || need <= 0 {
			return nil, false
		}
		chunk := buf
		if need < len(chunk) {
			chunk = chunk[:need]
		}
		n, err := syscall.Read(fd, chunk)
		if err != nil || n < 0 || n > len(chunk) {
			return nil, false
		}
		if n == 0 {
			return data, true
		}
		data = append(data, chunk[:n]...)
		if len(data) > limit {
			return nil, false
		}
	}
	return nil, false
}

func (a *audit) mountID(fd int) (uint64, bool) {
	data, ok := a.rawFile(a.fdinfo, strconv.Itoa(fd), 4096)
	if !ok {
		return 0, false
	}
	var id uint64
	seen := false
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "mnt_id:") {
			continue
		}
		if seen {
			return 0, false
		}
		v, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "mnt_id:")), 10, 64)
		if err != nil || v == 0 {
			return 0, false
		}
		id, seen = v, true
	}
	return id, seen
}

func (a *audit) readFile(parent int, name string, limit int, rootMount uint64) ([]byte, bool) {
	// Check the actual opened content FD's mount ID, rather than only its parent.
	if a.ctx.Err() != nil || !component(name) {
		return nil, false
	}
	fd, err := syscall.Openat(parent, name, fileFlags, 0)
	if err != nil {
		return nil, false
	}
	defer syscall.Close(fd)
	var st syscall.Stat_t
	var fs syscall.Statfs_t
	if syscall.Fstat(fd, &st) != nil || syscall.Fstatfs(fd, &fs) != nil ||
		st.Mode&syscall.S_IFMT != syscall.S_IFREG || fs.Type != procMagic ||
		st.Dev != a.root.stat.Dev || fs.Fsid != a.root.fs.Fsid {
		return nil, false
	}
	id, ok := a.mountID(fd)
	if !ok || id != rootMount {
		return nil, false
	}
	return boundedRead(a.ctx, fd, limit)
}

func (a *audit) mountsMatch(rootMount uint64) bool {
	for _, h := range a.fds {
		id, ok := a.mountID(h.fd)
		if !ok || id != rootMount {
			return false
		}
	}
	return true
}

func (a *audit) stable() bool {
	for _, old := range a.fds {
		now := heldFD{fd: old.fd}
		if syscall.Fstat(old.fd, &now.stat) != nil || syscall.Fstatfs(old.fd, &now.fs) != nil ||
			!sameIdentity(old, now) {
			return false
		}
	}
	return true
}

func (a *audit) reopenMatches(pidName, tidName string, rootMount uint64, originalPIDNS, originalNS int) bool {
	fd, err := syscall.Open("/proc", dirFlags, 0)
	if err != nil {
		return false
	}
	h, ok := a.take(fd, true, true)
	if !ok || !sameIdentity(a.root, h) {
		return false
	}
	id, ok := a.mountID(fd)
	if !ok || id != rootMount {
		return false
	}
	pidFD, ok := a.openDir(fd, pidName)
	if !ok {
		return false
	}
	pidNS, ok := a.openDir(pidFD, "ns")
	if !ok {
		return false
	}
	id, ok = a.mountID(pidNS)
	var processOriginal, processReopened syscall.Stat_t
	if !ok || id != rootMount || syscall.Fstat(originalPIDNS, &processOriginal) != nil || syscall.Fstat(pidNS, &processReopened) != nil ||
		processOriginal.Dev != processReopened.Dev || processOriginal.Ino != processReopened.Ino || processOriginal.Mode != processReopened.Mode {
		return false
	}
	fd = pidFD
	for _, name := range []string{"task", tidName, "ns"} {
		fd, ok = a.openDir(fd, name)
		if !ok {
			return false
		}
		id, ok = a.mountID(fd)
		if !ok || id != rootMount {
			return false
		}
	}
	var original, reopened syscall.Stat_t
	return syscall.Fstat(originalNS, &original) == nil && syscall.Fstat(fd, &reopened) == nil &&
		original.Dev == reopened.Dev && original.Ino == reopened.Ino && original.Mode == reopened.Mode
}

func selfMatches(procFD int, pid, tid string) bool {
	self, ok := linkAt(procFD, "self")
	if !ok || self != pid {
		return false
	}
	thread, ok := linkAt(procFD, "thread-self")
	return ok && thread == pid+"/task/"+tid
}

// Read the two kernel-provided links for identity comparison; never follow them.
func linkAt(parent int, name string) (string, bool) {
	p, err := syscall.BytePtrFromString(name)
	if err != nil {
		return "", false
	}
	buf := make([]byte, 96)
	n, _, errno := syscall.Syscall6(syscall.SYS_READLINKAT, uintptr(parent),
		uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0, 0)
	runtime.KeepAlive(p)
	runtime.KeepAlive(buf)
	if errno != 0 || n == 0 || n >= uintptr(len(buf)) {
		return "", false
	}
	return string(buf[:int(n)]), true
}

func (a *audit) taskStart(tidFD, tid int, rootMount uint64) (uint64, bool) {
	data, ok := a.readFile(tidFD, "stat", 16384, rootMount)
	if !ok {
		return 0, false
	}
	text := string(data)
	left, right := strings.IndexByte(text, '('), strings.LastIndex(text, ") ")
	if left < 1 || right <= left {
		return 0, false
	}
	actual, err := strconv.Atoi(strings.TrimSpace(text[:left]))
	if err != nil || actual != tid {
		return 0, false
	}
	fields := strings.Fields(text[right+2:])
	if len(fields) < 20 {
		return 0, false
	}
	start, err := strconv.ParseUint(fields[19], 10, 64) // field 22; field 3 is index 0.
	return start, err == nil
}

func (a *audit) bootID(randomFD int, rootMount uint64) ([]byte, bool) {
	data, ok := a.readFile(randomFD, "boot_id", 64, rootMount)
	if !ok {
		return nil, false
	}
	if len(data) != 37 || data[36] != '\n' {
		return nil, false
	}
	for i := 0; i < 36; i++ {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if data[i] != '-' {
				return nil, false
			}
		} else if !((data[i] >= '0' && data[i] <= '9') || (data[i] >= 'a' && data[i] <= 'f')) {
			return nil, false
		}
	}
	return data, true
}
