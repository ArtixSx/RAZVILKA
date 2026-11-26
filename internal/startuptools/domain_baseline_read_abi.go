package startuptools

import (
	"net/netip"
	"slices"

	"github.com/ArtixSx/razvilka/internal/publicfetch"
)

func domainBaselineQueryValid(client, real netip.Addr, ingress string) bool {
	return client.Is4() && client.IsPrivate() && real.Is4() && publicfetch.PublicAddress(real) && syntheticDNSIngress(ingress)
}

func domainDirectQueryValid(source, real netip.Addr) bool {
	return source.Is4() && source.IsGlobalUnicast() && !source.IsLoopback() && real.Is4() && publicfetch.PublicAddress(real) && source != real
}

// The exact baseline queries and the separately typed local DIRECT lookup. This is
// not a generic IP grammar: no effects, namespace selection or batch input.
func domainBaselineObservedRead(args []string) bool {
	if len(args) == 7 && slices.Equal(args[:4], []string{"-4", "-j", "route", "get"}) && args[5] == "from" {
		real, realErr := netip.ParseAddr(args[4])
		source, sourceErr := netip.ParseAddr(args[6])
		return realErr == nil && sourceErr == nil && real.String() == args[4] && source.String() == args[6] && domainDirectQueryValid(source, real)
	}
	if slices.Equal(args, []string{"-4", "-j", "rule", "show"}) ||
		slices.Equal(args, []string{"-4", "-j", "route", "show", "table", "all"}) ||
		slices.Equal(args, []string{"-j", "-details", "link", "show"}) {
		return true
	}
	if len(args) != 9 || !slices.Equal(args[:4], []string{"-4", "-j", "route", "get"}) || args[5] != "from" || args[7] != "iif" {
		return false
	}
	real, realErr := netip.ParseAddr(args[4])
	client, clientErr := netip.ParseAddr(args[6])
	return realErr == nil && clientErr == nil && real.String() == args[4] && client.String() == args[6] && domainBaselineQueryValid(client, real, args[8])
}
