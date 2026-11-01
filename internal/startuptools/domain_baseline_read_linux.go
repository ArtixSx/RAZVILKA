//go:build linux && (amd64 || arm64)

package startuptools

import (
	"context"
	"net/netip"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/publicfetch"
)

// Fixed bounded read ABI on the SAME original held IP source. This is not
// generic Run and grants no route, TPROXY, socket or flow effect. Old BusyBox
// dialects remain unsupported by the initial JSON comparison contract.
func (r *syntheticDNSRunner) ReadDomainTCPBaseline(ctx context.Context, client, real netip.Addr, ingress string) (dataplane.DomainTCPBaselineReadImage, error) {
	var image dataplane.DomainTCPBaselineReadImage
	if r == nil || r.lease == nil || ctx == nil || ctx.Err() != nil || !client.Is4() || !client.IsPrivate() || !real.Is4() || !publicfetch.PublicAddress(real) || !syntheticDNSIngress(ingress) {
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
		data, err := l.policyRead(ctx, 2, command.args)
		if err != nil {
			return dataplane.DomainTCPBaselineReadImage{}, err
		}
		*command.output = data
	}
	return image, nil
}
