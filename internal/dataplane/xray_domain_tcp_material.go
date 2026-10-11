package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"path/filepath"
	"reflect"
	"slices"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/dnscontrol"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// Preparation derived from the SAME original DNS session and NodeStore. No
// public config, argv, listener-ready callback or literal-mode material can
// construct it. It grants no Start; only the Manager resource issuer may bind
// the actual publication, original FDs and one-shot child reservation later.
type XrayDomainTCPOperationMaterial struct {
	self         *XrayDomainTCPOperationMaterial
	mu           sync.Mutex
	closed       bool
	ctx          context.Context
	cancel       context.CancelFunc
	manager      *Manager
	managerRoot  string
	adapter      *ProxyTunnelAdapter
	adapterRoot  string
	binaryField  string
	binary       string
	processes    ProcessController
	resource     *XrayDomainTCPExecutionResource
	registration *XrayRegistrationReview
	binding      *SyntheticDNSExecutionBinding
	session      *scopedDNSSession
	dnsSource    *dnscontrol.NetworkPolicyDNSSyntheticResolver
	mapping      *dnscontrol.SyntheticDNSMapping
	retirement   *dnscontrol.SyntheticDNSRetirementReview
	control      *operationgate.ControlEpochReview
	cleanup      *operationgate.ExclusiveCleanupReview
	nodeSource   *NodeDefaultSourceReview
	service      catalog.Service
	plan         Plan
	spec         DomainPolicyTCPCaptureSpec
	observation  dnscontrol.SyntheticDNSMappingObservation
	proof        nodeServiceProofState
	config       []byte
	private      netip.AddrPort
	nodePin      netip.AddrPort
	nodeHost     string
}

func (*XrayDomainTCPOperationMaterial) String() string {
	return "[original domain Xray TCP preparation]"
}
func (*XrayDomainTCPOperationMaterial) GoString() string {
	return "[original domain Xray TCP preparation]"
}

// A genuine Reserve result is mandatory. ReviewRetirement authenticates that
// mapping's private source against this actual registered DNS session before
// any process/config/capture effects; Observation alone could not do that.
func ReviewXrayDomainTCPOperationMaterial(ctx context.Context, binding *SyntheticDNSExecutionBinding, original *ProxyTunnelAdapter, source *NodeDefaultSourceReview, mapping *dnscontrol.SyntheticDNSMapping, service catalog.Service, spec DomainPolicyTCPCaptureSpec) (*XrayDomainTCPOperationMaterial, error) {
	if xraySelectedTCPFinite(ctx) != nil || binding == nil || binding.self != binding || binding.scope == nil || binding.scope.manager == nil || original == nil || !original.xrayPlanDispatch || !original.nodeRouterVerifier || original.scopedXray || original.xrayOperation || source == nil || !source.valid() || mapping == nil {
		return nil, ErrXrayDomainTCPOriginal
	}
	if err := binding.Current(ctx); err != nil {
		return nil, err
	}
	frozen, err := FrozenProbeService(Route{LogicalServiceID: service.ID, ProbeService: &service, ProbeURL: service.ProbeURL})
	if err != nil || validateXrayDomainTCPService(frozen, spec.Xray) != nil || validateXrayDomainTCPCaptureIntent(binding.domain, binding.transport, binding.plan.NetworkProfileID, spec) != nil || source.ref.EngineID != "xray" || source.ref.NodeID != spec.Xray.NodeID {
		return nil, errors.Join(ErrXrayDomainTCPOriginal, err)
	}
	matched := 0
	for _, route := range binding.plan.Routes {
		if route.LogicalServiceID != frozen.ID || route.Resolved != "xray:"+source.ref.NodeID {
			continue
		}
		probe, err := FrozenProbeService(route)
		if err != nil || !reflect.DeepEqual(probe, frozen) {
			return nil, ErrXrayDomainTCPOriginal
		}
		matched++
	}
	if matched != 1 || !filepath.IsAbs(original.StateRoot) || filepath.Clean(original.StateRoot) != original.StateRoot || original.SOCKSPort < 1024 || original.SOCKSPort > 65535 || original.SOCKSPort == 8787 || original.Processes == nil {
		return nil, ErrXrayDomainTCPOriginal
	}
	control, err := binding.baselineControl()
	if err != nil {
		return nil, err
	}
	session, err := binding.originalSyntheticSession(control)
	if err != nil || session == nil || session.synthetic == nil || session.synthetic.source == nil {
		return nil, errors.Join(ErrXrayDomainTCPOriginal, err)
	}
	retirement, err := mapping.ReviewRetirement(ctx, session.synthetic.source, binding.dns, binding.transport.DNS, control, binding.root, binding.transport.Definition)
	if err != nil {
		return nil, err
	}
	observation, err := mapping.Observation(ctx)
	if err != nil || observation.PossiblyIssued || !domainPolicyTCPMappingMatchesCapture(observation, spec) || observation.Authority.ControlEpoch != control.Reference().Sequence || observation.Authority.BindingRevision == 0 || observation.Authority.Exclusions != binding.transport.DNS.Exclusions {
		return nil, errors.Join(ErrXrayDomainTCPOriginal, err)
	}
	registration, err := binding.scope.manager.ReviewXrayRegistration(ctx, original)
	if err != nil {
		return nil, err
	}
	cleanup, err := control.ReviewExclusiveCleanup(ctx)
	if err != nil {
		_ = registration.Close()
		return nil, err
	}
	life, cancel := context.WithCancel(ctx)
	m := &XrayDomainTCPOperationMaterial{ctx: life, cancel: cancel, manager: binding.scope.manager, managerRoot: binding.scope.managerRoot,
		adapter: original, adapterRoot: original.StateRoot, binaryField: original.EngineBin, binary: original.engineBinary(), processes: original.Processes,
		registration: registration, binding: binding, session: session, dnsSource: session.synthetic.source, mapping: mapping, retirement: retirement,
		control: control, cleanup: cleanup, nodeSource: source, service: frozen, plan: cloneExecutionResourcePlan(binding.plan), spec: spec,
		observation: observation, private: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(original.SOCKSPort))}
	m.self = m
	if !filepath.IsAbs(m.binary) || filepath.Clean(m.binary) != m.binary {
		_ = m.Close()
		return nil, ErrXrayDomainTCPOriginal
	}
	material, proof, err := m.readNodeAdmission(ctx)
	if err == nil {
		defer clear(material)
		m.proof = proof
		m.config, err = m.compile(ctx, material)
	}
	if err == nil {
		err = m.Current(ctx)
	}
	if err != nil {
		_ = m.Close()
		return nil, errors.Join(ErrXrayDomainTCPOriginal, err)
	}
	return m, nil
}

func (m *XrayDomainTCPOperationMaterial) readNodeAdmission(ctx context.Context) ([]byte, nodeServiceProofState, error) {
	if err := m.nodeSource.Current(ctx); err != nil {
		return nil, nodeServiceProofState{}, err
	}
	now := time.Now().UTC()
	snapshot, err := m.nodeSource.store.Snapshot(ctx, now)
	if err != nil || snapshot.Generation != m.nodeSource.ref.NodeGeneration {
		return nil, nodeServiceProofState{}, errors.Join(ErrXrayDomainTCPOriginal, err)
	}
	var check nodestore.CheckRecord
	found := false
	for _, node := range snapshot.Nodes {
		if node.ID != m.nodeSource.ref.NodeID {
			continue
		}
		for _, candidate := range node.Health.History {
			if candidate.ServiceID == m.service.ID && candidate.NetworkProfile == m.plan.NetworkProfileID && candidate.RoutePathID == m.nodeSource.ref.Resolved {
				check, found = candidate, true
				break
			}
		}
		break
	}
	if !found || !routeNodeServiceCheckUsable(check, m.nodeSource.ref, m.service.ID, m.plan.NetworkProfileID, now) {
		return nil, nodeServiceProofState{}, ErrXrayDomainTCPOriginal
	}
	material, err := m.nodeSource.store.MaterializeXray(ctx, []nodestore.RouteBinding{{ServiceID: m.service.ID, NodeID: m.nodeSource.ref.NodeID, NetworkProfile: m.plan.NetworkProfileID, Domains: []string{m.spec.Xray.Name}}}, now)
	if err != nil || material.EngineID != "xray" {
		clear(material.Config)
		return nil, nodeServiceProofState{}, errors.Join(ErrXrayDomainTCPOriginal, err)
	}
	proof := nodeServiceProofState{check: check, ref: NodeServiceProofReference{Schema: 1, EngineID: "xray", NodeID: m.nodeSource.ref.NodeID, ServiceID: m.service.ID,
		WANProfile: m.plan.NetworkProfileID, NodeGeneration: snapshot.Generation, CompiledMaterialSHA256: nodeDefaultSourceMaterialHash(material.Config),
		ServiceSHA256: nodeServiceProofDigest(m.service), CheckedAt: check.CheckedAt, ExpiresAt: check.ExpiresAt}}
	proof.ref.ProofSHA256 = nodeServiceProofDigest(struct {
		Source  NodeDefaultSourceReference
		Service catalog.Service
		Check   nodestore.CheckRecord
	}{m.nodeSource.ref, m.service, check})
	if m.nodeSource.Current(ctx) != nil {
		clear(material.Config)
		return nil, nodeServiceProofState{}, ErrXrayDomainTCPOriginal
	}
	return material.Config, proof, nil
}

func (m *XrayDomainTCPOperationMaterial) compile(ctx context.Context, material []byte) ([]byte, error) {
	requests := []NodeRouteRequest{{ServiceID: m.service.ID, NodeID: m.nodeSource.ref.NodeID, Domains: []string{m.spec.Xray.Name}}}
	if validateScopedXrayConfig(material, requests, 0) != nil {
		return nil, ErrXrayDomainTCPOriginal
	}
	var doc map[string]any
	if json.Unmarshal(material, &doc) != nil {
		return nil, ErrXrayDomainTCPOriginal
	}
	server := doc["outbounds"].([]any)[1].(map[string]any)["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)
	m.nodeHost = server["address"].(string)
	addresses, err := m.adapter.resolveNodeEndpoint(ctx, m.nodeHost)
	if err != nil {
		return nil, err
	}
	for _, address := range addresses {
		if address.Is4() && domainPolicyTCPPublicIPv4(address) {
			m.nodePin = netip.AddrPortFrom(address, uint16(server["port"].(float64)))
			break
		}
	}
	return compileXrayDomainTCPConfig(material, m.spec.Xray, m.private, m.nodePin)
}

func (m *XrayDomainTCPOperationMaterial) Current(ctx context.Context) error {
	if m == nil || m.self != m || xraySelectedTCPFinite(ctx) != nil {
		return ErrXrayDomainTCPOriginal
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.ctx.Err() != nil || m.manager.StateRoot != m.managerRoot || m.adapter.StateRoot != m.adapterRoot || m.adapter.EngineBin != m.binaryField || m.adapter.engineBinary() != m.binary || !sameNetworkPolicyDependency(m.processes, m.adapter.Processes) || m.adapter.SOCKSPort != int(m.private.Port()) {
		return ErrXrayDomainTCPOriginal
	}
	deadline, _ := m.ctx.Deadline()
	c, cancel := context.WithDeadline(ctx, deadline)
	stop := context.AfterFunc(m.ctx, cancel)
	defer func() { stop(); cancel() }()
	if err := m.control.Current(c); err != nil {
		return err
	}
	if err := m.registration.Current(c); err != nil {
		return err
	}
	if err := m.binding.Current(c); err != nil {
		return err
	}
	session, err := m.binding.originalSyntheticSession(m.control)
	if err != nil || session != m.session || session.synthetic == nil || session.synthetic.source != m.dnsSource || !reflect.DeepEqual(m.binding.plan, m.plan) {
		return errors.Join(ErrXrayDomainTCPOriginal, err)
	}
	if err := m.dnsSource.CheckAdapterBinding(c, m.binding.dns, m.binding.transport.DNS, m.control, m.binding.root, m.binding.transport.Definition); err != nil {
		return err
	}
	observation, err := m.mapping.Observation(c)
	if err != nil || !syntheticSettlementCoordinatesEqual(observation, m.observation) {
		return errors.Join(ErrXrayDomainTCPOriginal, err)
	}
	material, proof, err := m.readNodeAdmission(c)
	defer clear(material)
	if err != nil || !reflect.DeepEqual(proof, m.proof) {
		return errors.Join(ErrXrayDomainTCPOriginal, err)
	}
	addresses, err := m.adapter.resolveNodeEndpoint(c, m.nodeHost)
	if err != nil || !slices.Contains(addresses, m.nodePin.Addr()) {
		return errors.Join(ErrXrayDomainTCPOriginal, err)
	}
	config, err := compileXrayDomainTCPConfig(material, m.spec.Xray, m.private, m.nodePin)
	defer clear(config)
	if err != nil || !slices.Equal(config, m.config) {
		return errors.Join(ErrXrayDomainTCPOriginal, err)
	}
	return errors.Join(m.control.Current(c), m.mapping.Current(c))
}

// This unpublished preparation owns no child, resource, mapping or DNS source;
// closing it only revokes its private input and registration review.
func (m *XrayDomainTCPOperationMaterial) Close() error {
	if m == nil || m.self != m {
		return ErrXrayDomainTCPOriginal
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	if m.resource != nil && !m.resource.descriptorsClosed.Load() {
		return ErrXrayDomainTCPOriginal
	}
	m.closed = true
	m.cancel()
	clear(m.config)
	m.config = nil
	return m.registration.Close()
}
