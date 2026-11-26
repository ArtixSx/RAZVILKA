package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/physicalscope"
)

func TestNetworkPolicyDiagnosticRetainsNonstandardFactsWithoutReadiness(t *testing.T) {
	var output bytes.Buffer
	code := writeNetworkPolicyDiagnostic(context.Background(), &output, func(context.Context) (physicalscope.DomainIPv4PolicyInventory, netidentity.Kind, error) {
		return physicalscope.DomainIPv4PolicyInventory{
			Rules: []physicalscope.DomainIPv4PolicyRule{{Priority: 100, Table: 1001, Source: netip.MustParsePrefix("192.168.1.0/24"), Mark: 7, Mask: 255, MarkPresent: true, MaskPresent: true}},
			Links: []physicalscope.DomainIPv4PolicyLink{{Index: 4, Name: "br0", Kind: "bridge"}},
		}, netidentity.ReviewedSingleInitNet, nil
	})
	var report networkPolicyDiagnostic
	if err := json.Unmarshal(output.Bytes(), &report); err != nil || code != 0 || !report.OK || !report.ReadOnly || report.Atomic || report.RouteReady || report.IPv6Covered {
		t.Fatal("read facts became an atomic or route-ready claim", code, output.String(), err)
	}
	if report.Inventory == nil || len(report.Inventory.Rules) != 1 || report.Inventory.Rules[0].Table != 1001 || report.Inventory.Rules[0].Mark != 7 || report.Inventory.Links[0].Kind != "bridge" || report.IdentityKind != netidentity.ReviewedSingleInitNet {
		t.Fatal("native policy facts lost", output.String())
	}
}

func TestNetworkPolicyDiagnosticFailureDropsPartialSnapshotAndPrivateCause(t *testing.T) {
	for _, cause := range []error{errors.New("private-provider-token"), errors.Join(errNetworkPolicyIdentity, errors.New("private-provider-token")), context.Canceled} {
		var output bytes.Buffer
		code := writeNetworkPolicyDiagnostic(context.Background(), &output, func(context.Context) (physicalscope.DomainIPv4PolicyInventory, netidentity.Kind, error) {
			return physicalscope.DomainIPv4PolicyInventory{Rules: []physicalscope.DomainIPv4PolicyRule{{Table: 1001}}}, netidentity.ProcNetInode, cause
		})
		var report networkPolicyDiagnostic
		if json.Unmarshal(output.Bytes(), &report) != nil || code != 3 || report.OK || report.Inventory != nil || !report.ReadOnly || report.RouteReady || strings.Contains(output.String(), "private-provider-token") {
			t.Fatal("failed read published partial or private evidence", code, output.String())
		}
	}
}

func TestNetworkPolicyDiagnosticClosingCancellationDiscardsSuccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var output bytes.Buffer
	code := writeNetworkPolicyDiagnostic(ctx, &output, func(context.Context) (physicalscope.DomainIPv4PolicyInventory, netidentity.Kind, error) {
		cancel()
		return physicalscope.DomainIPv4PolicyInventory{Rules: []physicalscope.DomainIPv4PolicyRule{{Table: 254}}}, netidentity.ProcNetInode, nil
	})
	var report networkPolicyDiagnostic
	if json.Unmarshal(output.Bytes(), &report) != nil || code != 3 || report.OK || report.Inventory != nil || report.Issue != "network-policy-read-interrupted" {
		t.Fatal("canceled read published facts", code, output.String())
	}
}
