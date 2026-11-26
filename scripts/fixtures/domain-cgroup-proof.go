//go:build linux && razvilka_cgroup_proof_fixture

// Read-only disposable-CI environment evidence. This does not create a cgroup,
// move a process, attach/detach BPF, or grant production baseline admission.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

type programQuery struct {
	FD, Attach, Flags, AttachFlags                         uint32
	IDs                                                    uint64
	Count, Pad                                             uint32
	ProgramAttachFlags, LinkIDs, LinkAttachFlags, Revision uint64
}

type queryEvidence struct {
	Depth  int    `json:"depth"`
	Attach uint32 `json:"attach"`
	Count  uint32 `json:"count"`
	Flags  uint32 `json:"attach_flags"`
	Errno  uint64 `json:"errno"`
}

type proof struct {
	Schema                  int             `json:"schema"`
	ReadOnly                bool            `json:"read_only_probe"`
	Depth                   int             `json:"own_depth"`
	MountRootSlash          bool            `json:"mount_root_slash"`
	MountReadOnly           bool            `json:"mount_read_only_indicator"`
	PID1CgroupNamespaceSame bool            `json:"pid1_cgroup_namespace_same"`
	RootEffectiveEmpty      bool            `json:"root_effective_empty"`
	Queries                 []queryEvidence `json:"queries"`
}

type anchor struct {
	fd   int
	stat unix.Stat_t
}

func limited(name string, limit int64) ([]byte, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	err = errors.Join(err, f.Close())
	if int64(len(b)) > limit {
		return nil, errors.New("bound")
	}
	return b, err
}

func fail(stage string) int {
	// Stages are literals at all callers. Never expose filesystem errors/paths.
	fmt.Fprintf(os.Stderr, "cgroup_proof_failed=%s\n", stage)
	return 3
}

func main() { os.Exit(run()) }

func run() int {
	if len(os.Args) != 1 || os.Geteuid() != 0 || unsafe.Sizeof(programQuery{}) != 64 {
		return fail("invocation")
	}
	end := time.Now().Add(6 * time.Second)
	membership, err := limited("/proc/self/cgroup", 16<<10)
	if err != nil {
		return fail("membership")
	}
	s := string(membership)
	if !strings.HasPrefix(s, "0::/") || !strings.HasSuffix(s, "\n") || strings.Count(s, "\n") != 1 {
		return fail("membership_format")
	}
	name := strings.TrimSuffix(strings.TrimPrefix(s, "0::"), "\n")
	if path.Clean(name) != name || strings.ContainsAny(name, "\x00\r\\ \t") {
		return fail("membership_canonical")
	}
	var components []string
	if name != "/" {
		components = strings.Split(name[1:], "/")
	}
	if len(components) > 32 {
		return fail("depth")
	}
	mountinfo, err := limited("/proc/self/mountinfo", 1<<20)
	if err != nil {
		return fail("mountinfo")
	}
	p := proof{Schema: 1, ReadOnly: true, Depth: len(components), RootEffectiveEmpty: true}
	matches := 0
	for _, line := range strings.Split(string(mountinfo), "\n") {
		f := strings.Fields(line)
		if len(f) < 10 || f[4] != "/sys/fs/cgroup" {
			continue
		}
		separator := -1
		for i := 6; i < len(f); i++ {
			if f[i] == "-" {
				separator = i
				break
			}
		}
		if separator < 0 || separator+3 >= len(f) || f[separator+1] != "cgroup2" {
			return fail("mount_kind")
		}
		matches++
		p.MountRootSlash = f[3] == "/"
		for _, option := range strings.Split(f[5], ",") {
			if option == "ro" {
				p.MountReadOnly = true
			}
		}
	}
	if matches != 1 {
		return fail("mount_ambiguity")
	}
	selfNS, err := os.Stat("/proc/self/ns/cgroup")
	if err != nil {
		return fail("self_namespace")
	}
	pid1NS, err := os.Stat("/proc/1/ns/cgroup")
	if err != nil {
		return fail("pid1_namespace")
	}
	p.PID1CgroupNamespaceSame = os.SameFile(selfNS, pid1NS)
	flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_DIRECTORY | unix.O_NONBLOCK
	root, err := unix.Open("/sys/fs/cgroup", flags, 0)
	if err != nil {
		return fail("root_open")
	}
	anchors := []anchor{{fd: root}}
	defer func() {
		for _, a := range anchors {
			_ = unix.Close(a.fd)
		}
	}()
	for _, component := range components {
		fd, e := unix.Openat(anchors[len(anchors)-1].fd, component, flags, 0)
		if e != nil {
			return fail("ancestor_open")
		}
		anchors = append(anchors, anchor{fd: fd})
	}
	for i := range anchors {
		a := &anchors[i]
		var fs unix.Statfs_t
		if unix.Fstat(a.fd, &a.stat) != nil || unix.Fstatfs(a.fd, &fs) != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
			return fail("anchor_identity")
		}
		if i == 0 && fs.Flags&unix.ST_RDONLY != 0 {
			p.MountReadOnly = true
		}
	}
	member := func() bool {
		fd, e := unix.Openat(anchors[len(anchors)-1].fd, "cgroup.procs", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if e != nil {
			return false
		}
		f := os.NewFile(uintptr(fd), "membership")
		b, e := io.ReadAll(io.LimitReader(f, 64<<10))
		ce := f.Close()
		if e != nil || ce != nil || len(b) >= 64<<10 {
			return false
		}
		for _, pid := range strings.Fields(string(b)) {
			if pid == strconv.Itoa(os.Getpid()) {
				return true
			}
		}
		return false
	}
	if !member() {
		return fail("actual_membership")
	}
	queryFailed := false
	for depth, a := range anchors {
		for _, attach := range []uint32{unix.BPF_CGROUP_INET_INGRESS, unix.BPF_CGROUP_INET_EGRESS, unix.BPF_CGROUP_INET_SOCK_CREATE, unix.BPF_CGROUP_SOCK_OPS, unix.BPF_CGROUP_INET4_BIND, unix.BPF_CGROUP_INET4_POST_BIND, unix.BPF_CGROUP_INET4_CONNECT, unix.BPF_CGROUP_GETSOCKOPT, unix.BPF_CGROUP_SETSOCKOPT, unix.BPF_CGROUP_INET4_GETSOCKNAME, unix.BPF_CGROUP_INET4_GETPEERNAME, unix.BPF_CGROUP_SYSCTL} {
			if time.Now().After(end) {
				return fail("deadline")
			}
			q := programQuery{FD: uint32(a.fd), Attach: attach, Flags: unix.BPF_F_QUERY_EFFECTIVE}
			_, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_PROG_QUERY, uintptr(unsafe.Pointer(&q)), unsafe.Sizeof(q))
			p.Queries = append(p.Queries, queryEvidence{depth, attach, q.Count, q.AttachFlags, uint64(errno)})
			if errno != 0 {
				queryFailed = true
			}
			if depth == 0 && (errno != 0 || q.Count != 0 || q.AttachFlags != 0) {
				p.RootEffectiveEmpty = false
			}
		}
	}
	// Retained FDs alone are insufficient: rewalk names and match their inodes.
	closingFD, err := unix.Open("/sys/fs/cgroup", flags, 0)
	if err != nil {
		return fail("closing_root")
	}
	for i, a := range anchors {
		var st unix.Stat_t
		if unix.Fstat(closingFD, &st) != nil || st.Dev != a.stat.Dev || st.Ino != a.stat.Ino || st.Mode != a.stat.Mode {
			_ = unix.Close(closingFD)
			return fail("closing_identity")
		}
		if i < len(components) {
			next, e := unix.Openat(closingFD, components[i], flags, 0)
			ce := unix.Close(closingFD)
			if e != nil || ce != nil {
				if e == nil {
					_ = unix.Close(next)
				}
				return fail("closing_ancestor")
			}
			closingFD = next
		}
	}
	if unix.Close(closingFD) != nil || !member() {
		return fail("closing_member")
	}
	closing, err := limited("/proc/self/cgroup", 16<<10)
	if err != nil || !bytes.Equal(membership, closing) {
		return fail("closing_membership")
	}
	closingMount, err := limited("/proc/self/mountinfo", 1<<20)
	if err != nil || !bytes.Equal(mountinfo, closingMount) || time.Now().After(end) {
		return fail("closing_mount")
	}
	if json.NewEncoder(os.Stdout).Encode(p) != nil {
		return fail("output")
	}
	if queryFailed {
		return fail("query_unknown")
	}
	return 0
}
