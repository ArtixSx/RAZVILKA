package startuptools

import (
	"net/netip"
	"slices"
	"strconv"

	"github.com/ArtixSx/razvilka/internal/publicfetch"
)

func domainBaselineClient(value string) bool {
	p, err := netip.ParsePrefix(value)
	return err == nil && p.String() == value && p.Bits() == 32 && p.Addr().Is4() && p.Addr().IsPrivate()
}
func syntheticDomainBaselineIPArguments(args []string) bool {
	if !boundedArguments(args) || len(args) < 4 || args[0] != "-4" || args[2] != "add" && args[2] != "del" {
		return false
	}
	if args[1] == "route" {
		return len(args) == 11 && args[3] == "local" && domainBaselineClient(args[4]) && slices.Equal(args[5:], []string{"dev", "lo", "table", "31000", "proto", "static"})
	}
	return args[1] == "rule" && len(args) == 13 && slices.Equal(args[3:6], []string{"priority", "31000", "to"}) && domainBaselineClient(args[6]) && args[7] == "iif" && syntheticDNSIngress(args[8]) && slices.Equal(args[9:], []string{"fwmark", "0x525a0001/0xffffffff", "lookup", "31000"})
}

func syntheticDomainBaselinePacketArguments(args []string) bool {
	if !boundedArguments(args) || len(args) < 5 || args[0] != "-t" || args[1] != "raw" && args[1] != "mangle" {
		return false
	}
	if args[2] == "-I" {
		if args[4] != "1" {
			return false
		}
		args = append(slices.Clone(args[:4]), args[5:]...)
	} else if args[2] != "-D" {
		return false
	}
	if len(args) != 21 && len(args) != 22 {
		return false
	}
	if args[4] != "-i" && args[4] != "-o" || !syntheticDNSIngress(args[5]) || args[6] != "-s" || args[8] != "-d" || !slices.Equal(args[10:15], []string{"-p", "tcp", "-m", "tcp", "--sport"}) || args[16] != "--dport" || args[18] != "-j" {
		return false
	}
	source, e1 := netip.ParsePrefix(args[7])
	target, e2 := netip.ParsePrefix(args[9])
	if e1 != nil || e2 != nil || source.String() != args[7] || target.String() != args[9] || source.Bits() != 32 || target.Bits() != 32 || !source.Addr().Is4() || !target.Addr().Is4() {
		return false
	}
	sport, e1 := strconv.ParseUint(args[15], 10, 16)
	dport, e2 := strconv.ParseUint(args[17], 10, 16)
	if e1 != nil || e2 != nil || sport == 0 || dport == 0 || strconv.FormatUint(sport, 10) != args[15] || strconv.FormatUint(dport, 10) != args[17] {
		return false
	}
	if args[3] == "OUTPUT" {
		return args[4] == "-o" && args[1] == "raw" && source.Addr().IsPrivate() && publicfetch.PublicAddress(target.Addr()) && (dport == 80 || dport == 443) && len(args) == 21 && slices.Equal(args[19:], []string{"CT", "--notrack"})
	}
	if args[3] != "PREROUTING" || args[4] != "-i" || !publicfetch.PublicAddress(source.Addr()) || !target.Addr().IsPrivate() || sport != 80 && sport != 443 {
		return false
	}
	if args[1] == "raw" {
		return len(args) == 21 && slices.Equal(args[19:], []string{"CT", "--notrack"})
	}
	return len(args) == 22 && slices.Equal(args[19:], []string{"MARK", "--set-xmark", "0x525a0001/0xffffffff"})
}
