package usquediag

import (
	"context"
	"errors"
	"net/netip"
	"slices"

	"github.com/ArtixSx/razvilka/internal/defaultconsent"
	"golang.org/x/net/dns/dnsmessage"
)

var errOwnedNetworkTarget = errors.New("owned-network-target-unapproved")

type ownedProbeTargetReviewKey struct{}

// WithOwnedProbeTargetReview carries the original retained CORE review to the
// network leaves. It issues no authority: the concrete review checks its own
// owner, original Gate context, saved config and control epoch on every use.
// The caller must separately review actual primary/auxiliary service IDs and
// positive client/path eligibility using its real retained catalog.
func WithOwnedProbeTargetReview(ctx context.Context, review *defaultconsent.Review) context.Context {
	if ctx == nil {
		return nil
	}
	return context.WithValue(ctx, ownedProbeTargetReviewKey{}, review)
}

func checkOwnedProbeTarget(ctx context.Context, hostname string, pins []netip.Addr) error {
	if ctx == nil || ctx.Err() != nil {
		return ownedProbeTargetFailure(errOwnedNetworkTarget, defaultconsent.ErrProbeTargetUnknown)
	}
	review, _ := ctx.Value(ownedProbeTargetReviewKey{}).(*defaultconsent.Review)
	if err := review.CheckProbeTarget(ctx, hostname, slices.Clone(pins)); err != nil {
		return ownedProbeTargetFailure(errOwnedNetworkTarget, err)
	}
	return nil
}

// Preserve a static exclusion/unknown classification through HTTP/DNS error
// wrappers without exposing URLs, resolver replies or original owner errors.
// An excluded auxiliary target leaves the diagnostic inconclusive.
func ownedProbeTargetFailure(otherwise, cause error) error {
	var classification error
	if errors.Is(cause, defaultconsent.ErrProbeTargetExcluded) {
		classification = defaultconsent.ErrProbeTargetExcluded
	} else if errors.Is(cause, errOwnedNetworkTarget) || errors.Is(cause, defaultconsent.ErrProbeTargetUnknown) || otherwise == errOwnedNetworkTarget {
		classification = defaultconsent.ErrProbeTargetUnknown
	} else {
		return otherwise
	}
	if otherwise == errOwnedNetworkTarget {
		return errors.Join(otherwise, classification)
	}
	return errors.Join(otherwise, errOwnedNetworkTarget, classification)
}

func checkOwnedProbeURL(ctx context.Context, raw string) error {
	u, err := validateOwnedNetworkHTTPS(raw)
	if err != nil {
		return errOwnedNetworkRequest
	}
	if literal, err := netip.ParseAddr(u.Hostname()); err == nil {
		return checkOwnedProbeTarget(ctx, "", []netip.Addr{literal})
	}
	return checkOwnedProbeTarget(ctx, u.Hostname(), nil)
}

func checkOwnedNetworkTargets(ctx context.Context, request OwnedNetworkRequest) error {
	if err := checkOwnedProbeURL(ctx, ownedWarpTraceURL); err != nil {
		return err
	}
	if err := checkOwnedProbeTarget(ctx, "cloudflare-dns.com", []netip.Addr{netip.MustParseAddr("1.1.1.1")}); err != nil {
		return err
	}
	for _, service := range request.Services {
		if err := checkOwnedProbeURL(ctx, service.URL); err != nil {
			return err
		}
	}
	if request.UDP != nil {
		return checkOwnedProbeTarget(ctx, "", []netip.Addr{request.UDP.Target.Addr()})
	}
	return nil
}

// Validate the complete packet before observing its aliases and every address
// RR, including the nonselected family and glue. The resolver still returns
// only terminal A/AAAA pins; negative checks cannot choose a different peer.
func checkOwnedDNSProbeAnswer(ctx context.Context, query, response []byte) error {
	if _, _, err := parseOwnedDNSAnswerDetails(query, response); err != nil {
		return errOwnedNetworkDNS
	}
	message, err := unpackOwnedDNSMessage(response)
	if err != nil {
		return errOwnedNetworkDNS
	}
	var pins []netip.Addr
	var aliases []string
	for _, records := range [][]dnsmessage.Resource{message.Answers, message.Authorities, message.Additionals} {
		for _, record := range records {
			switch body := record.Body.(type) {
			case *dnsmessage.AResource:
				pins = append(pins, netip.AddrFrom4(body.A))
			case *dnsmessage.AAAAResource:
				pins = append(pins, netip.AddrFrom16(body.AAAA))
			case *dnsmessage.CNAMEResource:
				aliases = append(aliases, body.CNAME.String())
			}
		}
	}
	if err := checkOwnedProbeTarget(ctx, message.Questions[0].Name.String(), pins); err != nil {
		return ownedProbeTargetFailure(errOwnedNetworkDNS, err)
	}
	for _, alias := range aliases {
		if err := checkOwnedProbeTarget(ctx, alias, nil); err != nil {
			return ownedProbeTargetFailure(errOwnedNetworkDNS, err)
		}
	}
	return nil
}
