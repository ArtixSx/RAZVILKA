//go:build linux && razvilka_native_fixture

package app

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/dnscontrol"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
	"golang.org/x/net/dns/dnsmessage"
)

// No source/runtime callback is fabricated: this receives the first genuine
// closed source's opaque handoff and uses public original Manager factories.
// Native clocks are per-operation, matching the unchanged finite producer.
func runDomainOriginalSuccessor(t *testing.T, ctx context.Context, peers *domainOriginalNativePeers, manager *dataplane.Manager, dnsAdapter *dataplane.ScopedDNSAdapter, backend *dataplane.BackendInventory, xray *dataplane.ProxyTunnelAdapter, nodeSource *dataplane.NodeDefaultSourceReview, resolver *dnscontrol.NetworkPolicyDNSResolver, control *operationgate.ControlEpochReview, history *updatecheck.ExecutionHistoryAdmission, plan dataplane.Plan, service catalog.Service, nodeID string, prior *dataplane.DomainTCPDetachedStandby, oldAlias string) (resultErr error) {
	t.Helper()
	binding, err := manager.BindSyntheticDNSExecution(ctx, dnsAdapter, plan)
	if err != nil {
		return fmt.Errorf("successor original DNS binding: %w", err)
	}
	owner, err := manager.NewDomainTCPOriginalScope(ctx, binding, backend)
	if err != nil {
		return fmt.Errorf("successor original owner: %w", err)
	}
	if err := owner.StartDNSContinuing(ctx, resolver, control, prior); err != nil {
		return fmt.Errorf("successor original source lineage: %w", err)
	}
	query := dnsmessage.Message{Header: dnsmessage.Header{ID: 9, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("service.example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	wire, err := query.Pack()
	if err != nil {
		return err
	}
	transport := plan.SyntheticDNS
	mapping, err := owner.Reserve(ctx, transport.Definition.Client, wire)
	if err != nil {
		return fmt.Errorf("successor original Reserve: %w", err)
	}
	observed, err := mapping.Observation(ctx)
	if err != nil || observed.Synthetic.String() == oldAlias || observed.PossiblyIssued || observed.RealIPv4.String() != domainOriginalServer {
		return errors.Join(errors.New("successor reused old alias or invented original answer"), err)
	}
	spec := dataplane.DomainPolicyTCPCaptureSpec{Xray: dataplane.DomainPolicyTCPXraySpec{Generation: plan.DomainPolicy.Generation, NetworkProfile: plan.NetworkProfileID, ServiceID: service.ID, NodeID: nodeID, Name: "service.example.com", RealIP: observed.RealIPv4}, Client: autonomy.ClientPacket{Address: transport.Definition.Client, MAC: transport.Definition.MAC, Interface: "br0", SegmentID: "home"}, DeviceID: "selected", Listen: netip.MustParseAddrPort(transport.CaptureEndpoint), Limits: dataplane.DomainPolicySniffLimits{Bytes: 16 << 10, Timeout: time.Second}}
	material, err := dataplane.ReviewXrayDomainTCPOperationMaterial(ctx, binding, xray, nodeSource, mapping, service, spec)
	if err != nil {
		return fmt.Errorf("successor genuine material: %w", err)
	}
	resource, err := dataplane.AcquireXrayDomainTCPExecutionResource(ctx, material)
	if err != nil {
		return fmt.Errorf("successor original COMMON issuer: %w", err)
	}
	stopMetrics := dataplane.StartDomainTCPNativeMeasurement()
	defer func() {
		t.Logf("successor original Run/join observations %+v; overlapping durations, not default12 performance", stopMetrics())
	}()
	runCtx, stopRun := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- owner.Run(runCtx, resource) }()
	joined := false
	defer func() {
		stopRun()
		if !joined {
			select {
			case runErr := <-done:
				if !domainOriginalExpectedStopError(runErr) {
					resultErr = errors.Join(resultErr, runErr)
				}
			case <-time.After(15 * time.Second):
				resultErr = errors.Join(resultErr, errors.New("successor original process/capture did not join"))
			}
		}
	}()
	deadline := time.Now().Add(30 * time.Second)
	published := peers.clientRequest(t, ctx, "dns-wait", deadline.UTC().Format(time.RFC3339Nano))
	if published.Answer != observed.Synthetic.String() {
		domainOriginalPublicationDiagnostics(t, manager.StateRoot)
		return errors.New("actual successor DNS publication unavailable or returned prior alias")
	}
	lookup, err := owner.LookupPublished(ctx, transport.Definition.Client, observed.Synthetic)
	if err != nil || lookup != mapping {
		return errors.Join(errors.New("successor response lacks original published mapping"), err)
	}
	old := peers.clientRequest(t, ctx, "selected", oldAlias)
	if old.Source != domainOriginalClient || old.SourcePort == "" || old.SourcePort != old.ClientPort || old.Marker != "native-domain-service" {
		return fmt.Errorf("new capture changed old cached-alias tuple: %+v", old)
	}
	selected := peers.clientRequest(t, ctx, "selected", published.Answer)
	if selected.Source != domainOriginalServer || selected.Marker != "native-domain-service" {
		return fmt.Errorf("successor selected TLS did not use genuine native VLESS: %+v", selected)
	}
	for _, mode := range []string{"mismatch", "opaque"} {
		flow := peers.clientRequest(t, ctx, mode, published.Answer)
		marker := "native-domain-service"
		if mode == "opaque" {
			marker = "opaque-native-baseline"
		}
		if flow.Source != domainOriginalClient || flow.SourcePort == "" || flow.SourcePort != flow.ClientPort || flow.Marker != marker {
			return fmt.Errorf("successor %s changed original baseline tuple: %+v", mode, flow)
		}
	}
	stopRun()
	select {
	case runErr := <-done:
		joined = true
		if !domainOriginalExpectedStopError(runErr) {
			return runErr
		}
	case <-time.After(15 * time.Second):
		return errors.New("successor original Stop/join timeout")
	}
	if len(domainOriginalRuntimeChildren(t, manager.StateRoot)) != 0 {
		return errors.New("successor Stop retained native child")
	}
	for _, alias := range []string{oldAlias, published.Answer} {
		late := peers.clientRequest(t, ctx, "selected", alias)
		if late.Source != domainOriginalClient || late.SourcePort == "" || late.SourcePort != late.ClientPort || late.Marker != "native-domain-service" {
			return fmt.Errorf("cached alias %s lost original late-SYN tuple: %+v", alias, late)
		}
	}
	if err := owner.RetainStandby(ctx, history); err != nil {
		return fmt.Errorf("successor same-owner standby handoff: %w", err)
	}
	return nil
}
