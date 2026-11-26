package app

import (
	"context"
	"errors"
	"net/netip"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/dnscontrol"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/systemprobe"
	"golang.org/x/net/dns/dnsmessage"
)

var (
	errDomainProofIntent = errors.New("DOMAIN_PROOF_INTENT_UNAVAILABLE")
	errDomainProofScope  = errors.New("DOMAIN_PROOF_CLIENT_OUTSIDE_SCOPE")
)

type domainTCPProofRequest struct {
	ServiceID, DeviceID, NetworkProfile   string
	BaselineDNSProfile, ServiceDNSProfile string
	Client                                netip.Addr
	DNSListen, CaptureListen              netip.AddrPort
	Host                                  dataplane.HostState
	Engine                                dataplane.Engine
}

type domainTCPDNSIdentity struct {
	Baseline, Service string
}

type domainTCPProofPlan struct {
	plan    dataplane.Plan
	service catalog.Service
	source  *dataplane.NodeDefaultSourceReview
	capture dataplane.DomainPolicyTCPCaptureSpec
}

// prepareDomainTCPProofPlan compiles finite, single-client DNS and TCP intent
// for the original Manager proof. The Store, DNS exclusions, and node review
// remain owned by their issuers. The result cannot authorize an ordinary Apply.
func prepareDomainTCPProofPlan(ctx context.Context, store *config.Store, dns *dnscontrol.Manager, exclusions *dnscontrol.NetworkPolicyDNSExclusions, source *dataplane.NodeDefaultSourceReview, observed DefaultRouteSnapshot, services catalog.Catalog, request domainTCPProofRequest, now time.Time) (domainTCPProofPlan, error) {
	if ctx == nil || store == nil || dns == nil || exclusions == nil || source == nil {
		return domainTCPProofPlan{}, errDomainProofIntent
	}
	deadline, bounded := ctx.Deadline()
	if !bounded || time.Until(deadline) > 2*time.Minute {
		return domainTCPProofPlan{}, errDomainProofIntent
	}
	if err := source.Current(ctx); err != nil {
		return domainTCPProofPlan{}, err
	}
	cfg := store.Get()
	if err := exclusions.CheckOriginalStore(ctx, store, cfg); err != nil {
		return domainTCPProofPlan{}, err
	}
	ref := source.Reference()
	baseline, err := dns.ScopedProfileIdentity(request.BaselineDNSProfile)
	if err != nil {
		return domainTCPProofPlan{}, err
	}
	identity := domainTCPDNSIdentity{Baseline: baseline, Service: baseline}
	if request.ServiceDNSProfile != request.BaselineDNSProfile {
		identity.Service, err = dns.ScopedProfileIdentity(request.ServiceDNSProfile)
		if err != nil {
			return domainTCPProofPlan{}, err
		}
	}
	definition, route, client, err := domainTCPProofDefinition(cfg, observed, services, request, ref, identity, now)
	if err != nil {
		return domainTCPProofPlan{}, err
	}
	name := route.Domains[0]
	frozenDNS, err := dns.FreezeNetworkPolicyDNSPlan(ctx, definition.Generation, request.BaselineDNSProfile, []dnscontrol.ClientDNSBinding{{Client: client.Address, Domain: name, ProfileID: request.ServiceDNSProfile}}, exclusions)
	if err != nil {
		return domainTCPProofPlan{}, err
	}
	if frozenDNS.DefaultProfileDigest != identity.Baseline || len(frozenDNS.Bindings) != 1 ||
		frozenDNS.Bindings[0].ProfileDigest != identity.Service {
		return domainTCPProofPlan{}, dnscontrol.ErrServiceDNSChanged
	}
	transport := &dataplane.SyntheticDNSTransportPlan{
		Listener: request.DNSListen.String(), CaptureEndpoint: request.CaptureListen.String(),
		DomainPolicyDigest: definition.Digest, DNS: frozenDNS,
		Definition: dnscontrol.SyntheticDNSDefinition{Client: client.Address, DeviceID: request.DeviceID, MAC: client.MAC, Ingress: client.Interface, ExactNames: []string{name}},
	}
	plan, err := dataplane.BuildAt(dataplane.Input{
		Revision: cfg.Revision, DomainPolicy: definition, SyntheticDNS: transport, NetworkProfileID: request.NetworkProfile,
		Routes: []dataplane.Route{route}, Engines: []dataplane.Engine{request.Engine}, Host: request.Host,
	}, now)
	if err != nil {
		return domainTCPProofPlan{}, err
	}
	if plan.Ready || len(plan.Blockers) != 2 ||
		!slices.ContainsFunc(plan.Blockers, func(blocker dataplane.Blocker) bool { return blocker.Code == "DOMAIN_POLICY_RUNTIME_UNAVAILABLE" }) ||
		!slices.ContainsFunc(plan.Blockers, func(blocker dataplane.Blocker) bool { return blocker.Code == "DOMAIN_FLOW_AUTHORITY_REQUIRED" }) {
		return domainTCPProofPlan{}, dataplane.ErrDomainTransportRuntime
	}
	if err := source.Current(ctx); err != nil {
		return domainTCPProofPlan{}, err
	}
	if err := dns.CheckNetworkPolicyDNSPlan(ctx, frozenDNS, exclusions); err != nil {
		return domainTCPProofPlan{}, err
	}
	if !reflect.DeepEqual(store.Get(), cfg) {
		return domainTCPProofPlan{}, config.ErrRevisionChanged
	}
	return domainTCPProofPlan{
		plan: plan, service: *route.ProbeService, source: source,
		capture: dataplane.DomainPolicyTCPCaptureSpec{
			Xray:   dataplane.DomainPolicyTCPXraySpec{Generation: definition.Generation, NetworkProfile: request.NetworkProfile, ServiceID: request.ServiceID, NodeID: ref.NodeID, Name: name},
			Client: client, DeviceID: request.DeviceID, Listen: request.CaptureListen,
			Limits: dataplane.DomainPolicySniffLimits{Bytes: 16 << 10, Timeout: time.Second},
		},
	}, nil
}

func domainTCPProofDefinition(cfg config.Config, observed DefaultRouteSnapshot, services catalog.Catalog, request domainTCPProofRequest, ref dataplane.NodeDefaultSourceReference, dnsIdentity domainTCPDNSIdentity, now time.Time) (*dataplane.DomainPolicyRuntimePlan, dataplane.Route, autonomy.ClientPacket, error) {
	deny := func(err error) (*dataplane.DomainPolicyRuntimePlan, dataplane.Route, autonomy.ClientPacket, error) {
		return nil, dataplane.Route{}, autonomy.ClientPacket{}, err
	}
	state := cfg.Services[request.ServiceID]
	selected := selectedRoute(state)
	if cfg.Revision == 0 || cfg.SafeMode || cfg.ServiceControl.Stopped || cfg.ServiceControl.EffectiveMode() != "auto" || observed.Stopped || cfg.NetworkPolicy == nil ||
		config.ValidateListNetworkPolicy(cfg.NetworkPolicy) != nil || !state.Enabled || !systemprobe.ValidWANProfileID(request.NetworkProfile) ||
		request.Engine.ID != "xray" || ref.EngineID != "xray" || ref.Resolved != "xray:"+ref.NodeID || ref.NodeID == "" ||
		selected != "auto" && selected != ref.EngineID && selected != ref.Resolved || catalog.Validate(services) != nil {
		return deny(errDomainProofIntent)
	}
	// The finite proof cannot compose with unrelated committed assignments.
	for _, applied := range cfg.AppliedServices {
		if applied.Enabled {
			return deny(errDomainProofIntent)
		}
	}
	client, err := domainTCPProofClient(observed, request.DeviceID, request.Client)
	if err != nil {
		return deny(err)
	}
	definitions := make([]dataplane.DomainPolicyService, 0, len(services.Services))
	var service catalog.Service
	for _, item := range services.Services {
		if item.ID == request.ServiceID {
			service = item
			continue
		}
		// The complete catalog contributes negative identities, including
		// disabled services and service names overlapping the selected name.
		definitions = append(definitions, dataplane.DomainPolicyService{ID: item.ID, DomainSuffixes: item.Domains, CIDRs: item.CIDRs})
	}
	if len(service.Domains) != 1 || len(service.CIDRs) != 0 || !domainTCPProofProbesMatch(service, service.Domains[0]) {
		return deny(errDomainProofIntent)
	}
	name := service.Domains[0]
	canonical, err := config.PolicyDomain(name)
	if err != nil || canonical != name {
		return deny(errDomainProofIntent)
	}
	question := autonomy.TrafficQuestion{Client: client, Domain: name, ServiceID: service.ID, ServiceSelected: true, ServiceSources: state.Sources}
	if decision := autonomy.DecideNetworkPolicy(cfg.NetworkPolicy, observed.Scope, question, now); decision.Action != "bypass" || decision.DeviceID != request.DeviceID {
		return deny(errDomainProofScope)
	}
	exclusions, err := config.EffectiveResourceExclusions(cfg.NetworkPolicy)
	if err != nil {
		return deny(err)
	}
	for _, identity := range definitions {
		if slices.ContainsFunc(identity.DomainSuffixes, func(suffix string) bool { return name == suffix || strings.HasSuffix(name, "."+suffix) }) {
			excluded, err := exclusions.Matches(config.ResourceTarget{ServiceID: identity.ID, Domain: name, DeviceID: request.DeviceID})
			if err != nil || excluded {
				return deny(errors.Join(errDomainProofScope, err))
			}
		}
	}
	sources := []string{netip.PrefixFrom(client.Address, 32).String()}
	definitions = append(definitions, dataplane.DomainPolicyService{ID: service.ID, Route: ref.Resolved, Selected: true, Domains: []string{name}, Sources: sources})
	// Include the reviewed settings and node, while allowing a scope observation
	// to renew its timestamps without changing the underlying generation.
	scopeIdentity := observed.Scope
	scopeIdentity.ObservedAt, scopeIdentity.FreshUntil = time.Time{}, time.Time{}
	generation := defaultRouteDigest(struct {
		Revision uint64
		Policy   *config.NetworkPolicy
		Scope    autonomy.ScopeObservation
		Catalog  string
		Client   autonomy.ClientPacket
		Source   dataplane.NodeDefaultSourceReference
		Request  domainTCPProofRequest
		DNS      domainTCPDNSIdentity
		Guests   []string
	}{cfg.Revision, cfg.NetworkPolicy, scopeIdentity, defaultRouteDigest(services), client, ref, request, dnsIdentity, observed.GuestSegmentIDs})
	definition, err := dataplane.FreezeDomainPolicyRuntimePlan(generation, cfg.NetworkPolicy, observed.Scope, observed.GuestSegmentIDs, definitions, now)
	if err != nil {
		return deny(err)
	}
	route := dataplane.Route{ServiceID: service.ID, LogicalServiceID: service.ID, Selected: ref.Resolved, Resolved: ref.Resolved, Domains: []string{name}, Sources: sources, Ingress: []string{client.Interface}, ProbeURL: service.ProbeURL, ProbeService: &service}
	frozenService, err := dataplane.FrozenProbeService(route)
	if err != nil {
		return deny(err)
	}
	route.ProbeService = &frozenService
	return definition, route, client, nil
}

func domainTCPProofClient(observed DefaultRouteSnapshot, deviceID string, address netip.Addr) (autonomy.ClientPacket, error) {
	if deviceID == "" || !address.Is4() {
		return autonomy.ClientPacket{}, errDomainProofScope
	}
	owners := 0
	for _, device := range observed.Devices {
		if !slices.Contains(device.Addresses, address) {
			continue
		}
		if device.ID != deviceID {
			return autonomy.ClientPacket{}, errDomainProofScope
		}
		owners++
	}
	if owners != 1 {
		return autonomy.ClientPacket{}, errDomainProofScope
	}
	var binding autonomy.DeviceBinding
	for _, device := range observed.Scope.Devices {
		if device.ID == deviceID {
			if binding.ID != "" || !device.Confirmed {
				return autonomy.ClientPacket{}, errDomainProofScope
			}
			binding = device
		}
	}
	if binding.ID == "" {
		return autonomy.ClientPacket{}, errDomainProofScope
	}
	return autonomy.ClientPacket{Address: address, MAC: binding.MAC, Interface: binding.Interface, SegmentID: binding.SegmentID}, nil
}

func domainTCPProofProbesMatch(service catalog.Service, exactName string) bool {
	matches := func(value string) bool {
		probe, err := url.Parse(value)
		return err == nil && probe.Scheme == "https" && strings.EqualFold(probe.Hostname(), exactName) && (probe.Port() == "" || probe.Port() == "443")
	}
	if service.ProbeURL == "" || !matches(service.ProbeURL) {
		return false
	}
	return !slices.ContainsFunc(service.Probes, func(probe catalog.Probe) bool { return probe.Required && !matches(probe.URL) })
}

// bindExecution assembles the original unpublished DNS and capture scope
// inside the Manager's existing proof execution. Its caller retains that
// execution until teardown and any earlier DNS publication is settled.
func (p domainTCPProofPlan) bindExecution(ctx context.Context, manager *dataplane.Manager, adapter *dataplane.ScopedDNSAdapter, backend *dataplane.BackendInventory, resolver *dnscontrol.NetworkPolicyDNSResolver, control *operationgate.ControlEpochReview) (*dataplane.DomainTCPOriginalScope, *dataplane.SyntheticDNSExecutionBinding, error) {
	if err := p.source.Current(ctx); err != nil {
		return nil, nil, err
	}
	binding, err := manager.BindSyntheticDNSExecution(ctx, adapter, p.plan)
	if err != nil {
		return nil, nil, err
	}
	owner, err := manager.NewDomainTCPOriginalScope(ctx, binding, backend)
	if err != nil {
		return nil, nil, err
	}
	if err := owner.StartDNS(ctx, resolver, control); err != nil {
		return nil, nil, err
	}
	return owner, binding, nil
}

// reserveDestination requests the chosen exact name through the owned DNS
// resolver. No synthetic answer may leave before its capture is prepared.
func (p domainTCPProofPlan) reserveDestination(ctx context.Context, owner *dataplane.DomainTCPOriginalScope) (*dnscontrol.SyntheticDNSMapping, netip.Addr, error) {
	name, err := dnsmessage.NewName(p.capture.Xray.Name + ".")
	if err != nil {
		return nil, netip.Addr{}, err
	}
	query := dnsmessage.Message{
		Header:    dnsmessage.Header{RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}
	wire, err := query.Pack()
	if err != nil {
		return nil, netip.Addr{}, err
	}
	mapping, err := owner.Reserve(ctx, p.capture.Client.Address, wire)
	if err != nil {
		return nil, netip.Addr{}, err
	}
	observation, err := mapping.Observation(ctx)
	if err != nil {
		return nil, netip.Addr{}, err
	}
	if observation.PossiblyIssued || !observation.RealIPv4.Is4() {
		return nil, netip.Addr{}, dataplane.ErrDomainTransportRuntime
	}
	return mapping, observation.RealIPv4, nil
}

func (p domainTCPProofPlan) acquireXray(ctx context.Context, binding *dataplane.SyntheticDNSExecutionBinding, xray *dataplane.ProxyTunnelAdapter, mapping *dnscontrol.SyntheticDNSMapping, realIP netip.Addr) (*dataplane.XrayDomainTCPExecutionResource, error) {
	spec := p.capture
	spec.Xray.RealIP = realIP
	material, err := dataplane.ReviewXrayDomainTCPOperationMaterial(ctx, binding, xray, p.source, mapping, p.service, spec)
	if err != nil {
		return nil, err
	}
	return dataplane.AcquireXrayDomainTCPExecutionResource(ctx, material)
}
