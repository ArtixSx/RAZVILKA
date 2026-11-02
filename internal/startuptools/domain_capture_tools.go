package startuptools

import (
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// Closed syntax for the domain capture compiler only. This grants no Start:
// the original sealed Manager admission still compares the exact plan/index,
// authored COMMON intent and actual opened process/listener at Cmd.Start.
func syntheticDomainCaptureArguments(args []string) bool {
	if !boundedArguments(args) || len(args) < 4 || args[0] != "-t" || args[1] != "nat" && args[1] != "filter" {
		return false
	}
	table, operation := args[1], args[2]
	inserted := false
	prefix := "RZDC_"
	hook := "PREROUTING"
	if table == "filter" {
		prefix = "RZDI_"
		hook = "INPUT"
	}
	chain := func(value string) bool {
		return len(value) == 25 && strings.HasPrefix(value, prefix) && strings.Trim(value[5:], "0123456789abcdef") == ""
	}
	if operation == "-N" || operation == "-X" {
		return len(args) == 4 && chain(args[3])
	}
	if operation == "-I" {
		if len(args) != 23 || args[3] != hook || args[4] != "1" {
			return false
		}
		args = append([]string{"-t", table, "-A", hook}, args[5:]...)
		operation = "-A"
		inserted = true
	}
	if operation != "-A" && operation != "-D" {
		return false
	}
	if chain(args[3]) {
		if table == "filter" {
			return len(args) == 6 && slices.Equal(args[4:], []string{"-j", "ACCEPT"})
		}
		if len(args) != 10 || !slices.Equal(args[4:9], []string{"-p", "tcp", "-j", "DNAT", "--to-destination"}) {
			return false
		}
		endpoint, err := netip.ParseAddrPort(args[9])
		return err == nil && endpoint.String() == args[9] && endpoint.Addr().Is4() && endpoint.Addr().IsPrivate() && endpoint.Port() > 0
	}
	if !inserted && operation != "-D" {
		return false
	}
	if len(args) != 22 || args[3] != hook || args[4] != "-i" || !syntheticDNSIngress(args[5]) || args[6] != "-s" || args[8] != "-d" || !slices.Equal(args[10:13], []string{"-m", "mac", "--mac-source"}) || !slices.Equal(args[14:19], []string{"-p", "tcp", "-m", "tcp", "--dport"}) || args[20] != "-j" || !chain(args[21]) {
		return false
	}
	client, e1 := netip.ParsePrefix(args[7])
	destination, e2 := netip.ParsePrefix(args[9])
	mac, e3 := net.ParseMAC(args[13])
	port, e4 := strconv.ParseUint(args[19], 10, 16)
	if e1 != nil || !client.Addr().Is4() || !client.Addr().IsPrivate() || client.Bits() != 32 || client.String() != args[7] || e2 != nil || !destination.Addr().Is4() || destination.Bits() != 32 || destination.String() != args[9] || e3 != nil || len(mac) != 6 || mac[0]&1 != 0 || mac.String() != args[13] || args[13] == "00:00:00:00:00:00" || e4 != nil || port == 0 || strconv.FormatUint(port, 10) != args[19] {
		return false
	}
	if table == "nat" {
		return netip.MustParsePrefix("198.18.0.0/15").Contains(destination.Addr()) && (port == 80 || port == 443)
	}
	return destination.Addr().IsPrivate()
}
