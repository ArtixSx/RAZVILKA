package dataplane

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

type domainCaptureReadComparisonFixture struct {
	ctx      context.Context
	cancel   context.CancelFunc
	capture  *DomainPolicyTCPCapture
	owner    *DomainTCPOriginalScope
	xray     *DomainPolicyTCPXray
	process  *XrayDomainTCPExecutionResource
	material *XrayDomainTCPOperationMaterial
	binding  *SyntheticDNSExecutionBinding
	listener *net.TCPListener
}

// Actual socket, comparison-only associations: no source, process or Current
// success is fabricated. Native acceptance exercises the complete producer.
func domainCaptureReadComparison(t *testing.T) *domainCaptureReadComparisonFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	binding := &SyntheticDNSExecutionBinding{scope: &executionResourceScope{}}
	binding.self = binding
	adapter := &ProxyTunnelAdapter{}
	material := &XrayDomainTCPOperationMaterial{binding: binding, adapter: adapter}
	material.self = material
	process := &XrayDomainTCPExecutionResource{material: material, scope: binding.scope}
	process.self, material.resource = process, process
	process.definition.Capture.Listen = listener.Addr().(*net.TCPAddr).AddrPort()
	process.definition.PrivateEndpoint = netip.MustParseAddrPort("127.0.0.1:19877")
	xray := &DomainPolicyTCPXray{ctx: ctx, resource: process, a: adapter, spec: process.definition.Capture.Xray, address: process.definition.PrivateEndpoint.String()}
	owner := &DomainTCPOriginalScope{binding: binding, process: process}
	owner.self = owner
	capture := &DomainPolicyTCPCapture{ctx: ctx, xray: xray, owner: owner, listener: listener, spec: process.definition.Capture}
	capture.self, owner.capture = capture, capture
	return &domainCaptureReadComparisonFixture{ctx, cancel, capture, owner, xray, process, material, binding, listener}
}

func (f *domainCaptureReadComparisonFixture) compare() error {
	return f.capture.originalReadAssociation(f.ctx, f.owner, f.xray, f.process, f.material, f.binding, f.listener)
}

func TestDomainOriginalCaptureReadClosesOriginalAssociations(t *testing.T) {
	for _, name := range []string{"owner", "owner-copy", "owner-process", "owner-capture", "owner-closed", "capture-self", "capture-closed", "xray", "xray-resource", "xray-adapter", "xray-spec", "xray-address", "material", "material-resource", "binding", "scope", "listener-closed", "listener-replaced", "cancel"} {
		t.Run(name, func(t *testing.T) {
			f := domainCaptureReadComparison(t)
			if err := f.compare(); err != nil {
				t.Fatal("initial local comparison", err)
			}
			// An external callback can mutate these between opening and closing;
			// the comparison must retain the ORIGINAL pointers.
			switch name {
			case "owner":
				f.capture.owner = &DomainTCPOriginalScope{}
			case "owner-copy":
				f.owner.self = &DomainTCPOriginalScope{}
			case "owner-process":
				f.owner.process = &XrayDomainTCPExecutionResource{}
			case "owner-capture":
				f.owner.capture = &DomainPolicyTCPCapture{}
			case "owner-closed":
				f.owner.closed = true
			case "capture-self":
				f.capture.self = &DomainPolicyTCPCapture{}
			case "capture-closed":
				f.capture.closed = true
			case "xray":
				f.capture.xray = &DomainPolicyTCPXray{}
			case "xray-resource":
				f.xray.resource = &XrayDomainTCPExecutionResource{}
			case "xray-adapter":
				f.xray.a = &ProxyTunnelAdapter{}
			case "xray-spec":
				f.xray.spec.ServiceID = "foreign"
			case "xray-address":
				f.xray.address = "127.0.0.1:19878"
			case "material":
				f.process.material = &XrayDomainTCPOperationMaterial{}
			case "material-resource":
				f.material.resource = &XrayDomainTCPExecutionResource{}
			case "binding":
				f.owner.binding = &SyntheticDNSExecutionBinding{}
			case "scope":
				f.process.scope = &executionResourceScope{}
			case "listener-closed":
				_ = f.listener.Close()
			case "listener-replaced":
				other, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = other.Close() })
				f.capture.listener = other
			case "cancel":
				f.cancel()
			}
			if err := f.compare(); err == nil {
				t.Fatal("changed original association accepted")
			}
		})
	}
}

func TestDomainOriginalCaptureReadComparisonCannotMintCurrent(t *testing.T) {
	f := domainCaptureReadComparison(t)
	if err := f.compare(); err != nil {
		t.Fatal(err)
	}
	if err := f.capture.Current(f.ctx); err == nil {
		t.Fatal("comparison-only handles minted resource Current")
	}
	f.capture.owner = (*DomainTCPOriginalScope)(nil)
	if err := f.capture.Current(f.ctx); !errors.Is(err, ErrDomainPolicyTCPConsumer) {
		t.Fatal("typed nil owner not refused", err)
	}
}

type domainCaptureReadCustomOwner struct {
	*syntheticTCPModelOwner
	calls int
	err   error
}

func (o *domainCaptureReadCustomOwner) CheckCapture(context.Context, *DomainPolicyTCPCapture) error {
	o.calls++
	return o.err
}

func TestDomainOriginalCaptureReadKeepsCustomOwnerError(t *testing.T) {
	f := domainCaptureReadComparison(t)
	witness := errors.New("custom capture owner refused original source")
	owner := &domainCaptureReadCustomOwner{syntheticTCPModelOwner: &syntheticTCPModelOwner{}, err: witness}
	f.capture.owner = owner
	if err := f.capture.Current(f.ctx); !errors.Is(err, witness) || owner.calls != 1 {
		t.Fatal("custom owner path or exception changed", owner.calls, err)
	}
}
