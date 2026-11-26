//go:build !linux

package physicalscope

import "context"

func platformDomainIPv4PolicyDump(context.Context, uint16, byte) ([]message, error) {
	return nil, ErrUnknown
}

func platformDomainIPv4PolicyRoute(context.Context, DomainIPv4PolicyLookupQuery) (DomainIPv4PolicyLookup, error) {
	return DomainIPv4PolicyLookup{}, ErrUnknown
}

func platformOpenDomainIPv4PolicyWindow(context.Context) (domainIPv4PolicyWindowMonitor, error) {
	return nil, ErrUnknown
}
