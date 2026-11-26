//go:build !linux

package physicalscope

import "context"

func platformDomainIPv4RouteLookup(context.Context, domainIPv4RouteQuery) (DomainIPv4RouteLookup, error) {
	return DomainIPv4RouteLookup{}, ErrUnknown
}
