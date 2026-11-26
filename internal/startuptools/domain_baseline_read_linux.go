//go:build linux && (amd64 || arm64)

package startuptools

import (
	"context"
	"errors"
	"net/netip"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/physicalscope"
)

// Local output lookup on the same held source. The consumer independently
// proves whole RPDB/packet policy; this query alone grants no Connect.
func (r *syntheticDNSRunner) ReadDomainTCPDirectRoute(ctx context.Context, source, real netip.Addr) (dataplane.DomainTCPDirectRouteRead, error) {
	var zero dataplane.DomainTCPDirectRouteRead
	if r == nil || r.lease == nil || ctx == nil || ctx.Err() != nil || !domainDirectQueryValid(source, real) {
		return zero, at("DOMAIN_BASELINE_READ", nil)
	}
	if _, finite := ctx.Deadline(); !finite {
		return zero, at("DOMAIN_BASELINE_READ", nil)
	}
	l := r.lease
	if err := l.retain(ctx); err != nil {
		return zero, err
	}
	defer l.retained.Done()
	if !l.syntheticDNSIssued() || l.profile.stock {
		return zero, at("DOMAIN_BASELINE_READ", nil)
	}
	read, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(l.lifetime, cancel)
	defer stop()
	// Keep the held IP command, including its tool/namespace readback.
	raw, err := l.domainBaselineRead(read, []string{"-4", "-j", "route", "get", real.String(), "from", source.String()})
	if err != nil {
		return zero, err
	}
	// The kernel lookup checks the same source and destination without
	// selecting an output device. It checks the actually selected table
	// and actual egress index separately from the command's JSON text.
	kernel, err := physicalscope.ReadDomainIPv4LocalRoute(read, l.provider, l.identity, source, real)
	if err != nil || read.Err() != nil || l.closed.Load() || l.lifetime.Err() != nil {
		return zero, at("DOMAIN_DIRECT_KERNEL_READ", errors.Join(err, read.Err(), l.lifetime.Err()))
	}
	return dataplane.DomainTCPDirectRouteRead{JSON: raw, Kernel: kernel}, nil
}

// Fixed bounded read ABI on the SAME original held IP source. This is not
// generic Run and grants no route, TPROXY, socket or flow effect. Old BusyBox
// dialects remain unsupported by the initial JSON comparison contract.
func (r *syntheticDNSRunner) ReadDomainTCPBaseline(ctx context.Context, client, real netip.Addr, ingress string) (dataplane.DomainTCPBaselineReadImage, error) {
	var image dataplane.DomainTCPBaselineReadImage
	if r == nil || r.lease == nil || ctx == nil || ctx.Err() != nil || !domainBaselineQueryValid(client, real, ingress) {
		return image, at("DOMAIN_BASELINE_READ", nil)
	}
	if _, finite := ctx.Deadline(); !finite {
		return image, at("DOMAIN_BASELINE_READ", nil)
	}
	l := r.lease
	if err := l.retain(ctx); err != nil {
		return image, err
	}
	defer l.retained.Done()
	if !l.syntheticDNSIssued() || l.profile.stock {
		return image, at("DOMAIN_BASELINE_READ", nil)
	}
	commands := []struct {
		args   []string
		output *[]byte
	}{
		{[]string{"-4", "-j", "rule", "show"}, &image.Rules},
		{[]string{"-4", "-j", "route", "show", "table", "all"}, &image.Routes},
		{[]string{"-j", "-details", "link", "show"}, &image.Links},
		{[]string{"-4", "-j", "route", "get", real.String(), "from", client.String(), "iif", ingress}, &image.Lookup},
	}
	for _, command := range commands {
		data, err := l.domainBaselineRead(ctx, command.args)
		if err != nil {
			return dataplane.DomainTCPBaselineReadImage{}, err
		}
		*command.output = data
	}
	return image, nil
}
