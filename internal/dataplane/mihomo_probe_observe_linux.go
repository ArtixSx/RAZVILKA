//go:build linux

package dataplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"os"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"golang.org/x/sys/unix"
)

var errMihomoProbeObservation = errors.New("original Mihomo process and listener association is unconfirmed")

// Comparison data only. These values cannot grant Start, kill, journal
// settlement, service success or adoption of a cold process.
type mihomoProbeObservation struct {
	pid, parent, group        int
	start                     string
	network                   netidentity.Identity
	executable, profile, home os.FileInfo
	listener                  uint64
}

func (a mihomoProbeObservation) same(b mihomoProbeObservation) bool {
	return a.pid == b.pid && a.parent == b.parent && a.group == b.group && a.start == b.start && a.network == b.network && a.listener == b.listener &&
		sameXrayDomainTCPFile(a.executable, b.executable) && sameXrayDomainTCPFile(a.profile, b.profile) &&
		a.home != nil && b.home != nil && os.SameFile(a.home, b.home) && a.home.Mode() == b.home.Mode()
}

func observeMihomoProbeProcess(ctx context.Context, child *components.MihomoProbeProcess, ref components.MihomoProbeReference, provider *netidentity.Provider, expected netidentity.Identity) (result mihomoProbeObservation, err error) {
	return observeOriginalMihomoProcess(ctx, child, ref, provider, expected)
}

type originalMihomoObservedChild interface {
	Current(context.Context) error
	PID() int
	MatchesFile(string, os.FileInfo) bool
}

// Only original concrete component owners reach the comparison reader. An
// arbitrary interface implementation or serialized PID cannot mint an owner.
func originalMihomoObservedOwner(child originalMihomoObservedChild) bool {
	switch owner := child.(type) {
	case *components.MihomoProbeProcess:
		return owner != nil
	case *components.MihomoLiveProcess:
		return owner != nil
	case *components.MihomoLiveObservation:
		return owner != nil
	case *mihomoLiveCleanupObservedChild:
		return owner != nil && owner.child != nil && owner.cleanup != nil
	default:
		return false
	}
}

func observeOriginalMihomoProcess(ctx context.Context, child originalMihomoObservedChild, ref components.MihomoProbeReference, provider *netidentity.Provider, expected netidentity.Identity) (result mihomoProbeObservation, err error) {
	if xraySelectedTCPFinite(ctx) != nil || child == nil || provider == nil || expected.Validate() != nil || ref.SOCKSPort < 1024 || ref.SOCKSPort > 65535 || ref.SOCKSPort == 8787 {
		return result, errMihomoProbeObservation
	}
	if !originalMihomoObservedOwner(child) {
		return result, errMihomoProbeObservation
	}
	err = provider.WithCurrent(ctx, func(held context.Context, current netidentity.Identity) error {
		if current != expected || child.Current(held) != nil {
			return errMihomoProbeObservation
		}
		proc, err := openXraySelectedTCPProc(held, child.PID())
		if err != nil {
			return err
		}
		defer proc.close()
		before, err := readMihomoProbeProcess(held, proc, child, ref, current)
		if err != nil {
			return err
		}
		endpoint := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(ref.SOCKSPort))
		inode, err := proc.domainListener(held, endpoint)
		if err != nil || proc.socketFD(held, inode) != nil {
			return errMihomoProbeObservation
		}
		after, err := readMihomoProbeProcess(held, proc, child, ref, current)
		if err != nil || !before.same(after) {
			return errMihomoProbeObservation
		}
		closing, err := proc.domainListener(held, endpoint)
		if err != nil || inode != closing || proc.socketFD(held, closing) != nil || proc.current(held) != nil || child.Current(held) != nil {
			return errMihomoProbeObservation
		}
		after.listener = closing
		result = after
		return nil
	})
	if err != nil {
		return mihomoProbeObservation{}, err
	}
	return result, nil
}

func readMihomoProbeProcess(ctx context.Context, proc *xraySelectedTCPProc, child originalMihomoObservedChild, ref components.MihomoProbeReference, network netidentity.Identity) (mihomoProbeObservation, error) {
	var result mihomoProbeObservation
	if proc == nil || proc.pid != child.PID() || proc.current(ctx) != nil {
		return result, errMihomoProbeObservation
	}
	stat, err := proc.read(ctx, proc.child, "stat", 8192)
	start, parent, group, parseErr := xraySelectedTCPStat(stat, proc.pid)
	if err != nil || parseErr != nil || parent != os.Getpid() {
		return result, errMihomoProbeObservation
	}
	image, err := proc.domainKernelImage(ctx, network)
	if err != nil || !bytes.Equal(image.argv, []byte("mihomo\x00-f\x00/proc/self/fd/4\x00-d\x00/proc/self/fd/5\x00")) || !child.MatchesFile("binary", image.executable) {
		return result, errMihomoProbeObservation
	}
	environment, err := proc.read(ctx, proc.child, "environ", 1)
	if err != nil || len(environment) != 0 {
		return result, errMihomoProbeObservation
	}
	config, err := readMihomoProbeFile(ctx, proc, child, "4", "profile", ref.ConfigSHA256)
	if err != nil {
		return result, err
	}
	home, err := readMihomoProbeFile(ctx, proc, child, "5", "home", "")
	if err != nil {
		return result, err
	}
	closing, err := proc.domainKernelImage(ctx, network)
	if err != nil || !image.same(closing) || !child.MatchesFile("binary", closing.executable) {
		return result, errMihomoProbeObservation
	}
	last, err := proc.read(ctx, proc.child, "stat", 8192)
	lastStart, lastParent, lastGroup, lastErr := xraySelectedTCPStat(last, proc.pid)
	if err != nil || lastErr != nil || start != lastStart || parent != lastParent || group != lastGroup || proc.current(ctx) != nil {
		return result, errMihomoProbeObservation
	}
	return mihomoProbeObservation{pid: proc.pid, parent: parent, group: group, start: start, network: network, executable: closing.executable, profile: config, home: home}, nil
}

func readMihomoProbeFile(ctx context.Context, proc *xraySelectedTCPProc, child originalMihomoObservedChild, number, kind, digest string) (os.FileInfo, error) {
	if number != "4" || kind != "profile" {
		if number != "5" || kind != "home" {
			return nil, errMihomoProbeObservation
		}
	}
	dir, err := proc.open(ctx, proc.child, "fd", true)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dir)
	flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK
	if kind == "home" {
		flags |= unix.O_DIRECTORY
	}
	fd, err := unix.Openat(dir, number, flags, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "[original Mihomo child file association]")
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !child.MatchesFile(kind, before) {
		return nil, errMihomoProbeObservation
	}
	if kind == "profile" {
		seals, err := unix.FcntlInt(f.Fd(), unix.F_GET_SEALS, 0)
		if err != nil || seals != unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL {
			return nil, errMihomoProbeObservation
		}
		data, err := xraySelectedTCPReadFD(ctx, fd, 1<<20)
		hash := sha256.Sum256(data)
		clear(data)
		if err != nil || hex.EncodeToString(hash[:]) != digest {
			return nil, errMihomoProbeObservation
		}
	}
	after, err := f.Stat()
	if err != nil || !child.MatchesFile(kind, after) || !os.SameFile(before, after) || !proc.procFile(dir, unix.S_IFDIR) || !proc.sameMount(ctx, dir) || proc.current(ctx) != nil {
		return nil, errMihomoProbeObservation
	}
	return after, nil
}

func observeMihomoProbeListenerAbsent(ctx context.Context, provider *netidentity.Provider, expected netidentity.Identity, port int) error {
	if xraySelectedTCPFinite(ctx) != nil || provider == nil || expected.Validate() != nil || port < 1024 || port > 65535 {
		return errMihomoProbeObservation
	}
	return provider.WithCurrent(ctx, func(held context.Context, current netidentity.Identity) error {
		if current != expected {
			return errMihomoProbeObservation
		}
		proc, err := openXraySelectedTCPProc(held, os.Getpid())
		if err != nil {
			return err
		}
		defer proc.close()
		for i := 0; i < 2; i++ {
			if proc.network(held, expected) != nil {
				return errMihomoProbeObservation
			}
			v4, err := proc.read(held, proc.child, "net/tcp", 8<<20)
			if err != nil {
				return err
			}
			v6, err := proc.read(held, proc.child, "net/tcp6", 8<<20)
			if err != nil {
				return err
			}
			rows4, err := xraySelectedTCPSockets(v4, false)
			if err != nil {
				return err
			}
			rows6, err := xraySelectedTCPSockets(v6, true)
			if err != nil {
				return err
			}
			if xrayDomainTCPListenerAbsent(rows4, rows6, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port))) != nil || proc.network(held, expected) != nil || proc.current(held) != nil {
				return errMihomoProbeObservation
			}
		}
		return nil
	})
}
