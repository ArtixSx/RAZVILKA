//go:build linux && razvilka_native_fixture

package startuptools

// CI-only platform classification: actual native protected ELF closure,
// dependency hashes, held descriptors, --version, namespace and every real
// Start/Wait still use the ordinary producer. Not included in production.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func AcquireNativeFixturePolicy(ctx context.Context, provider *netidentity.Provider, reviewPath string) (*Lease, error) {
	ns, err := os.Readlink("/proc/self/ns/net")
	initial, e2 := os.Readlink("/proc/1/ns/net")
	if os.Geteuid() != 0 || err != nil || e2 != nil || ns == initial || provider == nil {
		return nil, ErrUnknown
	}
	return acquireNativeFixturePolicy(ctx, provider, reviewPath)
}

var errNativeFixtureOuterNamespace = errors.New("native fixture requires a different genuine outer network namespace descriptor")

// AcquireNativeFixturePolicyWithOuterNetFD preserves the same actual tool
// producer for a private PID namespace, where /proc/1 is already local. The
// caller retains a genuine outer network namespace descriptor opened before
// unshare. Namespace comparison is fixture isolation, never runtime absence.
func AcquireNativeFixturePolicyWithOuterNetFD(ctx context.Context, provider *netidentity.Provider, reviewPath string, outer *os.File) (*Lease, error) {
	if ctx == nil || ctx.Err() != nil || provider == nil {
		return nil, ErrUnknown
	}
	if outer == nil || os.Geteuid() != 0 {
		return nil, errors.Join(ErrUnknown, errNativeFixtureOuterNamespace)
	}
	var opening unix.Stat_t
	var fs unix.Statfs_t
	fd := int(outer.Fd())
	if unix.Fstat(fd, &opening) != nil || unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.NSFS_MAGIC {
		return nil, errors.Join(ErrUnknown, errNativeFixtureOuterNamespace)
	}
	kind, err := unix.IoctlRetInt(fd, unix.NS_GET_NSTYPE)
	if err != nil || kind != unix.CLONE_NEWNET {
		return nil, errors.Join(ErrUnknown, errNativeFixtureOuterNamespace)
	}
	current, err := os.Open("/proc/self/ns/net")
	if err != nil {
		return nil, err
	}
	defer current.Close()
	var inner unix.Stat_t
	var innerFS unix.Statfs_t
	innerKind, innerErr := unix.IoctlRetInt(int(current.Fd()), unix.NS_GET_NSTYPE)
	if innerErr != nil || innerKind != unix.CLONE_NEWNET || unix.Fstatfs(int(current.Fd()), &innerFS) != nil || innerFS.Type != unix.NSFS_MAGIC || unix.Fstat(int(current.Fd()), &inner) != nil || opening.Dev == inner.Dev && opening.Ino == inner.Ino {
		return nil, errors.Join(ErrUnknown, errNativeFixtureOuterNamespace)
	}
	lease, err := acquireNativeFixturePolicy(ctx, provider, reviewPath)
	if err != nil {
		return nil, err
	}
	var closing, namedInner unix.Stat_t
	if unix.Fstat(fd, &closing) != nil || unix.Stat("/proc/self/ns/net", &namedInner) != nil || opening != closing || inner.Dev != namedInner.Dev || inner.Ino != namedInner.Ino {
		return nil, errors.Join(ErrUnknown, errNativeFixtureOuterNamespace, lease.Close())
	}
	return lease, nil
}

func acquireNativeFixturePolicy(ctx context.Context, provider *netidentity.Provider, reviewPath string) (*Lease, error) {
	p, err := nativeFixturePolicyProfile(reviewPath)
	if err != nil {
		return nil, err
	}
	return acquire(ctx, provider, p)
}

func nativeFixturePolicyProfile(reviewPath string) (profile, error) {
	data, err := os.ReadFile(reviewPath)
	if err != nil || len(data) > 4096 {
		return profile{}, ErrUnknown
	}
	var review struct{ XTablesSHA256, IPToolSHA256, Version, IPVersion string }
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&review) != nil || d.Decode(new(any)) != io.EOF || len(review.XTablesSHA256) != 64 || strings.Trim(review.XTablesSHA256, "0123456789abcdef") != "" || len(review.IPToolSHA256) != 64 || strings.Trim(review.IPToolSHA256, "0123456789abcdef") != "" || !strings.HasPrefix(review.Version, "1.8.") || !strings.HasSuffix(review.Version, " (legacy)") || len(review.Version) > 64 || len(review.IPVersion) > 256 || !strings.HasPrefix(review.IPVersion, "ip utility, iproute2-") {
		return profile{}, ErrUnknown
	}
	p := ubuntuPolicyProfile()
	p.id = "ci-only-native-platform-classification-modeled"
	p.mainSHA = review.XTablesSHA256
	p.ipSHA = review.IPToolSHA256
	p.version = review.Version
	// Only these separately researched save ABIs participate in native parity.
	// This tagged classification never enables another production profile.
	p.classicSaveABI = review.Version == "1.8.10 (legacy)" || review.Version == "1.8.11 (legacy)"
	p.ipVersion = review.IPVersion
	return p, nil
}
