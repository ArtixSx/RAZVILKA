package startuptools

import (
	"context"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// NFQWSProbeCounterProtocol describes the fixed numeric-list output of this
// same protected tool owner. It is read-only formatting metadata, never a
// counter observation or permission to execute a command. Both actual version
// commands and the complete held graph are freshly checked before returning.
func (l *Lease) NFQWSProbeCounterProtocol(ctx context.Context, expected netidentity.Identity, review string) (string, error) {
	if ctx == nil || expected.Validate() != nil {
		return "", at("COUNTER_FORMAT_SCOPE", nil)
	}
	c, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	if err := l.lock(c); err != nil {
		return "", err
	}
	defer l.unlock()
	stop := context.AfterFunc(l.lifetime, cancel)
	defer stop()
	if review == "" || review != l.digest || l.review == nil || expected != l.identity {
		return "", at("COUNTER_FORMAT_SCOPE", nil)
	}
	if err := l.current(c, expected, true); err != nil {
		return "", err
	}
	protocol := reviewedCounterProtocol(l.profile.version)
	if protocol == "" || l.closed.Load() || c.Err() != nil || l.lifetime.Err() != nil {
		return "", at("COUNTER_FORMAT_UNKNOWN", c.Err())
	}
	return protocol, nil
}

func reviewedCounterProtocol(version string) string {
	// Upstream 1.8.10 xshared.c print_rule_details prints numeric protocols
	// with -n -L. 1.8.11 reverted that change; reviewed stock 1.4.21 likewise
	// prints known protocol names. Unknown versions get no inferred grammar.
	switch version {
	case "1.8.10 (legacy)":
		return "6"
	case "1.8.11 (legacy)", "1.4.21":
		return "tcp"
	default:
		return ""
	}
}
