package dataplane

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// Refusal models: the socket factory must never be entered. Actual listener
// acceptance and worker joins are reserved for ROOT native/network checks.
func TestSyntheticDNSAdapterModeRefusesMetadataBeforeSocketFactory(t *testing.T) {
	m, a, plan, scope, ctx := syntheticExecutionModel(t)
	binding, err := m.BindSyntheticDNSExecution(withSyntheticExecutionRegistrar(scope.contextWith(ctx), scope), a, plan)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	a.listen = func(netip.AddrPort) (*net.UDPConn, *net.TCPListener, error) {
		calls++
		t.Fatal("unissued mode reached socket factory")
		return nil, nil, nil
	}
	for _, b := range []*SyntheticDNSExecutionBinding{nil, new(SyntheticDNSExecutionBinding), binding} {
		if err := a.startSyntheticDNSLocked(ctx, b, new(dnscontrol.NetworkPolicyDNSResolver), new(operationgate.ControlEpochReview), nil); err == nil {
			t.Fatal("metadata-only source accepted")
		}
	}
	if calls != 0 || a.live != nil {
		t.Fatal("refused mode published a local session")
	}
	if err := syntheticDNSListenerAddress(nil, nil, netip.MustParseAddrPort("192.168.1.1:10553")); err == nil {
		t.Fatal("missing original listeners accepted")
	}
	if err := a.stopSyntheticDNSLocked(context.Background()); err == nil {
		t.Fatal("absent original session granted settlement")
	}
}
