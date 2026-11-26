package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/ArtixSx/razvilka/internal/app"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/physicalscope"
)

// The diagnostic consumes kernel facts without granting route readiness or
// creating a manager, installer, DNS listener, connection, or packet effect.
// Dumps are sequential: even a successful report is not an atomic policy fence.
type networkPolicyDiagnostic struct {
	OK           bool                                     `json:"ok"`
	Version      string                                   `json:"version"`
	ReadOnly     bool                                     `json:"read_only"`
	Atomic       bool                                     `json:"atomic"`
	RouteReady   bool                                     `json:"route_ready"`
	IPv6Covered  bool                                     `json:"ipv6_covered"`
	Source       string                                   `json:"source"`
	IdentityKind netidentity.Kind                         `json:"identity_kind,omitempty"`
	ObservedAt   time.Time                                `json:"observed_at"`
	Inventory    *physicalscope.DomainIPv4PolicyInventory `json:"inventory,omitempty"`
	Issue        string                                   `json:"issue,omitempty"`
}

var errNetworkPolicyIdentity = errors.New("network policy diagnostic identity unavailable")

func collectNetworkPolicyDiagnostic(ctx context.Context) (physicalscope.DomainIPv4PolicyInventory, netidentity.Kind, error) {
	var zero physicalscope.DomainIPv4PolicyInventory
	if ctx == nil || ctx.Err() != nil {
		return zero, "", context.Canceled
	}
	provider := netidentity.NewProcProvider()
	identity, err := provider.Observe(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return zero, "", ctx.Err()
		}
		// The stock factory verifies the actual NC-1812 tuple itself. A
		// failed generic observation does not grant a guessed stock identity.
		provider, err = netidentity.NewReviewedStockNC1812Provider(ctx)
		if err != nil {
			return zero, "", errors.Join(errNetworkPolicyIdentity, err)
		}
		identity, err = provider.Observe(ctx)
		if err != nil {
			return zero, "", errors.Join(errNetworkPolicyIdentity, err)
		}
	}
	inventory, err := physicalscope.ReadDomainIPv4PolicySnapshot(ctx, provider, identity)
	if err != nil {
		return zero, identity.Kind, err
	}
	return inventory, identity.Kind, nil
}

func writeNetworkPolicyDiagnostic(ctx context.Context, output io.Writer, collect func(context.Context) (physicalscope.DomainIPv4PolicyInventory, netidentity.Kind, error)) int {
	report := networkPolicyDiagnostic{Version: app.Version, ReadOnly: true, Source: "NETLINK_ROUTE"}
	if ctx == nil || output == nil || collect == nil {
		return 2
	}
	inventory, kind, err := collect(ctx)
	report.ObservedAt = time.Now().UTC()
	report.IdentityKind = kind
	if err != nil || ctx.Err() != nil {
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded), ctx.Err() != nil:
			report.Issue = "network-policy-read-interrupted"
		case errors.Is(err, errNetworkPolicyIdentity):
			report.Issue = "network-identity-unavailable"
		default:
			report.Issue = "network-policy-read-unavailable"
		}
	} else {
		report.OK = true
		report.Inventory = &inventory
	}
	if json.NewEncoder(output).Encode(report) != nil {
		return 3
	}
	if !report.OK {
		return 3
	}
	return 0
}
