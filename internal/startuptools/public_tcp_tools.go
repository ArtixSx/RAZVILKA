package startuptools

import (
	"context"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/publicfetch"
)

type publicTCPRunner struct{ lease *Lease }

// Projection of the SAME held policy source. No path/hash/callback factory
// accepts a substitute source; original COMMON admission remains mandatory.
func (l *Lease) PublicTCPCommandTools() (dataplane.PublicTCPCommandTools, error) {
	if l == nil || l.lifetime == nil {
		return dataplane.PublicTCPCommandTools{}, at("PUBLIC_TCP_UNISSUED", nil)
	}
	ctx, cancel := context.WithTimeout(l.lifetime, operationTimeout)
	defer cancel()
	if err := l.lock(ctx); err != nil {
		return dataplane.PublicTCPCommandTools{}, err
	}
	defer l.unlock()
	if !l.publicTCPIssued() {
		return dataplane.PublicTCPCommandTools{}, at("PUBLIC_TCP_UNISSUED", nil)
	}
	return dataplane.PublicTCPCommandTools{IP: l.profile.ipAlias, IPTables: l.profile.aliases[0], IP6Tables: l.profile.aliases[1], ReviewSHA256: l.digest, Identity: l.identity, Provider: l.provider, Runner: &publicTCPRunner{l}}, nil
}
func (l *Lease) publicTCPIssued() bool {
	return l.syntheticDNSIssued() && l.review.entry[1] != nil && l.review.entry[1].file != nil && l.profile.aliases[1] != "" && l.profile.aliases[0] != l.profile.aliases[1]
}
func (r *publicTCPRunner) CheckPublicTCP(ctx context.Context, identity netidentity.Identity) error {
	if r == nil || r.lease == nil {
		return at("PUBLIC_TCP_UNISSUED", nil)
	}
	return r.lease.Check(ctx, identity)
}
func (r *publicTCPRunner) RunPublicTCP(ctx context.Context, admission dataplane.PublicTCPCommandAdmission, name string, args ...string) ([]byte, error) {
	if r == nil || r.lease == nil || ctx == nil || admission == nil {
		return nil, at("PUBLIC_TCP_UNISSUED", nil)
	}
	return r.lease.runPublicTCP(WithCommandAdmission(ctx, admission), name, args...)
}

var publicTCPComment = regexp.MustCompile(`^rzp[cb]:[0-9a-f]{20}$`)
var publicTCPMark = regexp.MustCompile(`^0x52[0-9a-f]{6}/0xffffffff$`)

func publicTCPNumber(value string, min, max uint64) bool {
	n, err := strconv.ParseUint(value, 10, 32)
	return err == nil && n >= min && n <= max && strconv.FormatUint(n, 10) == value
}
func publicTCPClient(value string) bool {
	p, err := netip.ParsePrefix(value)
	return err == nil && p.Bits() == 32 && p.Addr().Is4() && p.Addr().IsPrivate() && p.String() == value
}
func publicTCPDestination(value string) bool {
	p, err := netip.ParsePrefix(value)
	return err == nil && p.Bits() == 32 && p.Addr().Is4() && publicfetch.PublicAddress(p.Addr()) && p.String() == value
}
func publicTCPMAC(value string) bool {
	m, err := net.ParseMAC(value)
	return err == nil && len(m) == 6 && m[0]&1 == 0 && m.String() == value && value != "00:00:00:00:00:00"
}

// Closed compiler ABI only. The original resource must also compare every
// argv byte, held tool/source, generation and one-shot command reservation.
func publicTCPArguments(index int, args []string) bool {
	if !boundedArguments(args) {
		return false
	}
	if index == 2 {
		if len(args) != 9 || args[0] != "-4" || (args[2] != "add" && args[2] != "del") {
			return false
		}
		switch args[1] {
		case "rule":
			return args[3] == "priority" && publicTCPNumber(args[4], 10000, 19999) && args[5] == "fwmark" && publicTCPMark.MatchString(args[6]) && args[7] == "lookup" && publicTCPNumber(args[8], 16000, 16999)
		case "route":
			return args[3] == "local" && publicTCPClient(args[4]) && slices.Equal(args[5:8], []string{"dev", "lo", "table"}) && publicTCPNumber(args[8], 16000, 16999)
		default:
			return false
		}
	}
	if index != 0 || len(args) < 4 || args[0] != "-t" || (args[2] != "-A" && args[2] != "-D") || args[3] != "PREROUTING" {
		return false
	}
	// Exact MAC/iif/source/destination TCP80/443 capture to one nonprivileged listener.
	if len(args) == 26 && args[1] == "nat" && args[4] == "-i" && syntheticDNSIngress(args[5]) && args[6] == "-s" && publicTCPClient(args[7]) && args[8] == "-d" && publicTCPDestination(args[9]) && slices.Equal(args[10:13], []string{"-m", "mac", "--mac-source"}) && publicTCPMAC(args[13]) && slices.Equal(args[14:17], []string{"-p", "tcp", "--dport"}) && (args[17] == "80" || args[17] == "443") && slices.Equal(args[18:21], []string{"-m", "comment", "--comment"}) && publicTCPComment.MatchString(args[21]) && strings.HasPrefix(args[21], "rzpc:") && slices.Equal(args[22:25], []string{"-j", "REDIRECT", "--to-ports"}) && publicTCPNumber(args[25], 1024, 65535) {
		return true
	}
	// Return diversion is per actual transparent socket port, not a whole client.
	return len(args) == 28 && args[1] == "mangle" && args[4] == "-i" && syntheticDNSIngress(args[5]) && args[6] == "-s" && publicTCPDestination(args[7]) && args[8] == "-d" && publicTCPClient(args[9]) && slices.Equal(args[10:13], []string{"-p", "tcp", "--sport"}) && (args[13] == "80" || args[13] == "443") && args[14] == "--dport" && publicTCPNumber(args[15], 1024, 65535) && slices.Equal(args[16:23], []string{"-m", "socket", "--transparent", "--nowildcard", "-m", "comment", "--comment"}) && publicTCPComment.MatchString(args[23]) && strings.HasPrefix(args[23], "rzpb:") && slices.Equal(args[24:27], []string{"-j", "MARK", "--set-xmark"}) && publicTCPMark.MatchString(args[27])
}
