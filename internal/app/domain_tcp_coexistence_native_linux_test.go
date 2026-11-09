//go:build linux && razvilka_native_fixture

package app

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
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

var errDomainOriginalJoinedFailure = errors.New("native fixture callback failed after actual original Run and join")

type domainOriginalCancelAfterStartKey struct{}
type domainOriginalCanceledAliasKey struct{}

func domainOriginalOnlyJoinedFailure(err error) bool {
	if err == errDomainOriginalJoinedFailure {
		return true
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		all := joined.Unwrap()
		if len(all) == 0 {
			return false
		}
		for _, e := range all {
			if !domainOriginalOnlyJoinedFailure(e) {
				return false
			}
		}
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return domainOriginalOnlyJoinedFailure(wrapped.Unwrap())
	}
	return false
}

// No source/runtime callback is fabricated: this receives the first genuine
// closed source's opaque handoff and uses public original Manager factories.
// Native clocks are per-operation, matching the unchanged finite producer.
func runDomainOriginalSuccessor(t *testing.T, ctx context.Context, peers *domainOriginalNativePeers, manager *dataplane.Manager, dnsAdapter *dataplane.ScopedDNSAdapter, backend *dataplane.BackendInventory, xray *dataplane.ProxyTunnelAdapter, nodeSource *dataplane.NodeDefaultSourceReview, resolver *dnscontrol.NetworkPolicyDNSResolver, control *operationgate.ControlEpochReview, history *updatecheck.ExecutionHistoryAdmission, plan dataplane.Plan, service catalog.Service, nodeID string, prior *dataplane.DomainTCPDetachedStandby, oldAlias string, unpublished bool, captured **dataplane.DomainTCPOriginalScope) (resultErr error) {
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
	deadline := time.Now().Add(domainOriginalPublicationBudget(t))
	if cancelOriginal, ok := ctx.Value(domainOriginalCancelAfterStartKey{}).(context.CancelFunc); ok {
		if captured != nil {
			*captured = owner
		}
		// Observe the genuine issued child before canceling its ORIGINAL
		// forward request. No ready bit or process observation is fabricated.
		for {
			var ready error
			if os.Getenv("RAZVILKA_DOMAIN_CANCELED_READY") == "1" {
				ready = owner.CurrentSyntheticMapping(ctx, mapping)
			} else {
				ready = resource.Current(ctx)
			}
			if ready == nil {
				if os.Getenv("RAZVILKA_DOMAIN_CANCELED_PUBLISHED") == "1" {
					actual := peers.clientRequest(t, ctx, "dns-wait", deadline.UTC().Format(time.RFC3339Nano))
					if actual.Answer != observed.Synthetic.String() {
						return errors.New("canceled published case lacks actual client answer")
					}
					if current, err := owner.LookupPublished(ctx, transport.Definition.Client, observed.Synthetic); err != nil || current != mapping {
						return errors.Join(errors.New("canceled published case lacks original LookupPublished"), err)
					}
					if held, ok := ctx.Value(domainOriginalCanceledAliasKey{}).(*string); ok {
						*held = actual.Answer
					} else {
						return errors.New("canceled published alias custody missing")
					}
				}
				t.Log("actual original successor child/listener observed; canceling original request before native cleanup publication")
				cancelOriginal()
				return context.Canceled
			}
			select {
			case err := <-done:
				joined = true
				return errors.Join(errors.New("native child ended before cancellation witness"), err)
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
			if time.Now().After(deadline) {
				return errors.New("actual child/listener cancellation witness unavailable")
			}
		}
	}
	newAlias := observed.Synthetic.String()
	if unpublished {
		readinessCtx, cancelReadiness := context.WithDeadline(ctx, deadline)
		defer cancelReadiness()
		for {
			if err := owner.CurrentSyntheticMapping(readinessCtx, mapping); err == nil {
				break
			}
			if time.Now().After(deadline) {
				return errors.New("actual never-issued successor readiness unavailable")
			}
			select {
			case err := <-done:
				joined = true
				return errors.Join(errors.New("never-issued successor ended before readiness"), err)
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(250 * time.Millisecond):
			}
		}
		actual, err := mapping.Observation(ctx)
		if err != nil || actual.PossiblyIssued {
			return errors.Join(errors.New("never-issued successor acquired publication"), err)
		}
	} else {
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
	lateAliases := []string{oldAlias}
	if !unpublished {
		lateAliases = append(lateAliases, newAlias)
	}
	for _, alias := range lateAliases {
		late := peers.clientRequest(t, ctx, "selected", alias)
		if late.Source != domainOriginalClient || late.SourcePort == "" || late.SourcePort != late.ClientPort || late.Marker != "native-domain-service" {
			return fmt.Errorf("cached alias %s lost original late-SYN tuple: %+v", alias, late)
		}
	}
	if captured != nil {
		*captured = owner
	}
	if unpublished && os.Getenv("RAZVILKA_DOMAIN_JOINED_FAILURE") == "1" {
		return errDomainOriginalJoinedFailure
	}
	if err := owner.RetainStandby(ctx, history); err != nil {
		return fmt.Errorf("successor same-owner standby handoff: %w", err)
	}
	return nil
}

func TestDomainOriginalJoinedFailureCannotMaskOtherErrors(t *testing.T) {
	if !domainOriginalOnlyJoinedFailure(errors.Join(errDomainOriginalJoinedFailure)) {
		t.Fatal("actual cause lost")
	}
	for _, err := range []error{nil, context.Canceled, errors.Join(errDomainOriginalJoinedFailure, context.Canceled), errors.Join(errDomainOriginalJoinedFailure, dataplane.ErrPolicyAdditionUnknown)} {
		if domainOriginalOnlyJoinedFailure(err) {
			t.Fatal("unrelated failure masked", err)
		}
	}
}
