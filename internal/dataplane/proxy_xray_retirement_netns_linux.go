//go:build linux

package dataplane

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

// Linux resolves /proc/PID/net entries from that task's nsproxy->net_ns.
// IPv4 registers tcp and route independently under each net->proc_net.
// Equal contents (including empty tables) convey no identity. Require the
// same two live procfs objects, with all paths on the original proc mount.
func xrayRetirementProcTables(parent context.Context, pids [2]int, closeOriginal func() error) (string, error) {
	if closeOriginal == nil || parent == nil || pids[0] <= 1 || pids[1] <= 1 || pids[0] == pids[1] || pids[0] == os.Getpid() || pids[1] == os.Getpid() {
		return "", ErrProxyPolicyUnknown
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	type heldTable struct {
		proc *xraySelectedTCPProc
		name string
		stat unix.Stat_t
	}
	var held []heldTable
	var reference [2]unix.Stat_t
	var mount uint64
	for i, pid := range []int{os.Getpid(), pids[0], pids[1]} {
		proc, err := openXraySelectedTCPProc(ctx, pid)
		if err != nil {
			return "", errors.Join(ErrProxyPolicyUnknown, err)
		}
		defer proc.close()
		if i == 0 {
			mount = proc.mount
		} else if mount != proc.mount {
			return "", ErrProxyPolicyUnknown
		}
		dirs := []string{"net/"}
		if i == 0 {
			// Compare the thread that performs the observation as well as the
			// controller's leader against the two original children.
			dirs = append(dirs, "task/"+strconv.Itoa(unix.Gettid())+"/net/")
		}
		for k, dir := range dirs {
			for j, leaf := range []string{"tcp", "route"} {
				name := dir + leaf
				fd, err := proc.open(ctx, proc.child, name, false)
				if err != nil {
					return "", errors.Join(ErrProxyPolicyUnknown, err)
				}
				defer unix.Close(fd)
				var st unix.Stat_t
				if unix.Fstat(fd, &st) != nil || st.Ino == 0 {
					return "", ErrProxyPolicyUnknown
				}
				if i == 0 && k == 0 {
					reference[j] = st
				} else if st.Dev != reference[j].Dev || st.Ino != reference[j].Ino {
					return "", ErrProxyPolicyUnknown
				}
				held = append(held, heldTable{proc: proc, name: name, stat: st})
			}
		}
	}
	if reference[0].Ino == reference[1].Ino {
		return "", ErrProxyPolicyUnknown
	}
	// All initial descriptors stay open through the last re-lookup. Unlink,
	// exit, replacement and mount changes cannot supply the original inode.
	for _, t := range held {
		if err := t.proc.current(ctx); err != nil {
			return "", errors.Join(ErrProxyPolicyUnknown, err)
		}
		fd, err := t.proc.open(ctx, t.proc.child, t.name, false)
		if err != nil {
			return "", errors.Join(ErrProxyPolicyUnknown, err)
		}
		var now unix.Stat_t
		err = unix.Fstat(fd, &now)
		closeErr := unix.Close(fd)
		if err != nil || closeErr != nil || now.Dev != t.stat.Dev || now.Ino != t.stat.Ino {
			return "", ErrProxyPolicyUnknown
		}
	}
	if err := closeOriginal(); err != nil {
		return "", errors.Join(ErrProxyPolicyUnknown, err)
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return fmt.Sprintf("proc-net:%d:%d:%d:%d", mount, reference[0].Dev, reference[0].Ino, reference[1].Ino), nil
}
