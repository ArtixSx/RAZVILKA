//go:build linux && (amd64 || arm64)

package netidentity

import (
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

type netPair struct {
	fds   [2]int
	stats [2]syscall.Stat_t
	fs    [2]syscall.Statfs_t
}

func (p *netPair) close() {
	for _, fd := range p.fds {
		if fd >= 0 {
			_ = syscall.Close(fd)
		}
	}
}
func (p *netPair) stable() bool {
	for i, fd := range p.fds {
		var st syscall.Stat_t
		var fs syscall.Statfs_t
		if syscall.Fstat(fd, &st) != nil || syscall.Fstatfs(fd, &fs) != nil || st.Dev != p.stats[i].Dev || st.Ino != p.stats[i].Ino || st.Mode != p.stats[i].Mode || fs.Type != p.fs[i].Type || fs.Fsid != p.fs[i].Fsid {
			return false
		}
	}
	return true
}
func holdNetPair(processNS, threadNS int) (*netPair, bool) {
	p := &netPair{fds: [2]int{-1, -1}}
	fail := func() (*netPair, bool) { p.close(); return nil, false }
	for i, parent := range []int{processNS, threadNS} {
		link, ok := linkAt(parent, "net")
		if !ok || !strings.HasPrefix(link, "net:[") || !strings.HasSuffix(link, "]") {
			return fail()
		}
		number := strings.TrimSuffix(strings.TrimPrefix(link, "net:["), "]")
		inode, err := strconv.ParseUint(number, 10, 64)
		if err != nil || inode == 0 || strconv.FormatUint(inode, 10) != number {
			return fail()
		}
		// This single known procfs magic link is followed only after the complete
		// anchored directory/mount checks. The resulting FD must be real nsfs.
		fd, err := syscall.Openat(parent, "net", syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
		if err != nil {
			return fail()
		}
		p.fds[i] = fd
		if syscall.Fstat(fd, &p.stats[i]) != nil || syscall.Fstatfs(fd, &p.fs[i]) != nil || p.fs[i].Type != 0x6e736673 || p.stats[i].Mode&syscall.S_IFMT != syscall.S_IFREG || p.stats[i].Ino != inode {
			return fail()
		}
		closing, ok := linkAt(parent, "net")
		if !ok || closing != link {
			return fail()
		}
	}
	if p.stats[0].Dev != p.stats[1].Dev || p.stats[0].Ino != p.stats[1].Ino || p.fs[0].Fsid != p.fs[1].Fsid || !p.stable() {
		return fail()
	}
	return p, true
}
func kernelTuple() (string, string, bool) {
	var uts syscall.Utsname
	_, _, errno := syscall.Syscall(syscall.SYS_UNAME, uintptr(unsafe.Pointer(&uts)), 0, 0)
	runtime.KeepAlive(&uts)
	if errno != 0 {
		return "", "", false
	}
	var release, machine, system []byte
	for _, c := range uts.Release {
		release = append(release, byte(c))
	}
	for _, c := range uts.Machine {
		machine = append(machine, byte(c))
	}
	for _, c := range uts.Sysname {
		system = append(system, byte(c))
	}
	parse := func(raw []byte) (string, bool) {
		end := 0
		for end < len(raw) && raw[end] != 0 {
			end++
		}
		if end == 0 || end == len(raw) {
			return "", false
		}
		for _, b := range raw[:end] {
			if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || strings.ContainsRune("._+-", rune(b))) {
				return "", false
			}
		}
		return string(raw[:end]), true
	}
	r, a := parse(release)
	m, b := parse(machine)
	s, c := parse(system)
	return r, m, a && b && c && s == "Linux"
}
