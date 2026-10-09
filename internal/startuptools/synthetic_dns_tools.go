package startuptools

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/publicfetch"
)

type syntheticDNSRunner struct{ lease *Lease }

// SyntheticDNSCommandTools retains the SAME original policy tool source. The
// descriptor and Check compare that source; only sealed Manager admission can
// issue an exact command at the existing held-image Start boundary.
func (l *Lease) SyntheticDNSCommandTools() (dataplane.SyntheticDNSCommandTools, error) {
	if l == nil || l.lifetime == nil {
		return dataplane.SyntheticDNSCommandTools{}, at("SYNTHETIC_DNS_UNISSUED", nil)
	}
	c, cancel := context.WithTimeout(l.lifetime, operationTimeout)
	defer cancel()
	if err := l.lock(c); err != nil {
		return dataplane.SyntheticDNSCommandTools{}, err
	}
	defer l.unlock()
	if !l.syntheticDNSIssued() {
		return dataplane.SyntheticDNSCommandTools{}, at("SYNTHETIC_DNS_UNISSUED", nil)
	}
	return dataplane.SyntheticDNSCommandTools{IPTables: l.profile.aliases[0], ReviewSHA256: l.digest, Identity: l.identity, Provider: l.provider, Runner: &syntheticDNSRunner{l}}, nil
}

func (l *Lease) syntheticDNSIssued() bool {
	return l != nil && l.review != nil && l.review.ipEntry != nil && l.review.ipEntry.file != nil &&
		l.review.entry[0] != nil && l.review.entry[0].file != nil && l.profile.ipAlias != "" &&
		l.profile.aliases[0] != "" && len(l.digest) == 64 && strings.Trim(l.digest, "0123456789abcdef") == "" &&
		l.provider != nil && l.identity.Validate() == nil
}

func (r *syntheticDNSRunner) CheckSyntheticDNS(ctx context.Context, expected netidentity.Identity) error {
	if r == nil || r.lease == nil {
		return at("SYNTHETIC_DNS_UNISSUED", nil)
	}
	return r.lease.Check(ctx, expected)
}

func (r *syntheticDNSRunner) RunSyntheticDNS(ctx context.Context, admission dataplane.SyntheticDNSCommandAdmission, name string, args ...string) ([]byte, error) {
	if r == nil || r.lease == nil || ctx == nil || admission == nil {
		return nil, at("SYNTHETIC_DNS_UNISSUED", nil)
	}
	return r.lease.runSyntheticDNS(WithCommandAdmission(ctx, admission), name, args...)
}

// These are only the three current standby compiler shapes. Syntax, paths and
// hashes never replace the original owner's exact reviewed command comparison.
// Capture or any additional native ABI needs its own reviewed extension.
func syntheticDNSArguments(args []string) bool {
	if !boundedArguments(args) || len(args) < 4 || args[0] != "-t" || args[1] != "nat" {
		return false
	}
	if args[2] == "-N" || args[2] == "-X" {
		return len(args) == 4 && syntheticDNSChain(args[3])
	}
	if args[2] != "-A" && args[2] != "-D" {
		return false
	}
	if len(args) == 10 && syntheticDNSChain(args[3]) && slices.Equal(args[4:9], []string{"-p", "tcp", "-j", "DNAT", "--to-destination"}) {
		address, err := netip.ParseAddr(args[9])
		return err == nil && address.Is4() && address.String() == args[9] && publicfetch.PublicAddress(address)
	}
	if len(args) != 22 || args[3] != "PREROUTING" || args[4] != "-i" || !syntheticDNSIngress(args[5]) ||
		args[6] != "-s" || args[8] != "-d" || !slices.Equal(args[10:13], []string{"-m", "mac", "--mac-source"}) ||
		!slices.Equal(args[14:19], []string{"-p", "tcp", "-m", "tcp", "--dport"}) ||
		(args[19] != "80" && args[19] != "443") || args[20] != "-j" || !syntheticDNSChain(args[21]) {
		return false
	}
	client, clientErr := netip.ParsePrefix(args[7])
	synthetic, syntheticErr := netip.ParsePrefix(args[9])
	mac, macErr := net.ParseMAC(args[13])
	return clientErr == nil && client.Bits() == 32 && client.Addr().Is4() && client.Addr().IsPrivate() && client.String() == args[7] &&
		syntheticErr == nil && synthetic.Bits() == 32 && synthetic.Addr().Is4() && synthetic.String() == args[9] && netip.MustParsePrefix("198.18.0.0/15").Contains(synthetic.Addr()) &&
		macErr == nil && len(mac) == 6 && mac[0]&1 == 0 && mac.String() == args[13] && args[13] != "00:00:00:00:00:00"
}

func syntheticDNSChain(value string) bool {
	return len(value) == 25 && strings.HasPrefix(value, "RZSB_") && strings.Trim(value[5:], "0123456789abcdef") == ""
}

func syntheticDNSIngress(value string) bool {
	if value == "" || value == "lo" || len(value) > 15 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("_.:-", c)) {
			return false
		}
	}
	return true
}
