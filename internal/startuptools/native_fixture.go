//go:build linux && razvilka_native_fixture

package startuptools

// CI-only platform classification: actual native protected ELF closure,
// dependency hashes, held descriptors, --version, namespace and every real
// Start/Wait still use the ordinary producer. Not included in production.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func AcquireNativeFixturePolicy(ctx context.Context, provider *netidentity.Provider, reviewPath string) (*Lease, error) {
	ns, err := os.Readlink("/proc/self/ns/net")
	initial, e2 := os.Readlink("/proc/1/ns/net")
	if os.Geteuid() != 0 || err != nil || e2 != nil || ns == initial || provider == nil {
		return nil, ErrUnknown
	}
	data, err := os.ReadFile(reviewPath)
	if err != nil || len(data) > 4096 {
		return nil, ErrUnknown
	}
	var review struct{ XTablesSHA256, IPToolSHA256, Version, IPVersion string }
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&review) != nil || d.Decode(new(any)) != io.EOF || len(review.XTablesSHA256) != 64 || strings.Trim(review.XTablesSHA256, "0123456789abcdef") != "" || len(review.IPToolSHA256) != 64 || strings.Trim(review.IPToolSHA256, "0123456789abcdef") != "" || !strings.HasPrefix(review.Version, "1.8.") || !strings.HasSuffix(review.Version, " (legacy)") || len(review.Version) > 64 || len(review.IPVersion) > 256 || !strings.HasPrefix(review.IPVersion, "ip utility, iproute2-") {
		return nil, ErrUnknown
	}
	p := ubuntuPolicyProfile()
	p.id = "ci-only-native-platform-classification-modeled"
	p.mainSHA = review.XTablesSHA256
	p.ipSHA = review.IPToolSHA256
	p.version = review.Version
	p.ipVersion = review.IPVersion
	return acquire(ctx, provider, p)
}
