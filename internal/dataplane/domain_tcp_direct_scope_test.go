package dataplane

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/physicalscope"
)

func TestDomainTCPDirectRouteIsExactLocalPath(t *testing.T) {
	source := netip.MustParseAddr("1.1.1.1")
	target := netip.MustParseAddrPort("1.1.1.2:443")
	path := domainTCPBaselinePath{Egress: "wan0", Gateway: netip.MustParseAddr("1.1.1.254")}
	valid := `[{"dst":"1.1.1.2","from":"1.1.1.1","gateway":"1.1.1.254","dev":"wan0","uid":0,"cache":[]}]`
	if err := domainTCPDirectRouteMatches([]byte(valid), source, target, path); err != nil {
		t.Fatal(err)
	}
	for _, cut := range []struct{ name, from, to string }{
		{"other-source", "1.1.1.1\"", "1.1.1.3\""},
		{"other-target", "1.1.1.2\"", "1.1.1.3\""},
		{"other-gateway", "1.1.1.254", "1.1.1.253"},
		{"other-egress", "wan0", "vpn0"},
		{"other-user", "\"uid\":0", "\"uid\":1000"},
		{"foreign-table", "\"uid\":0", "\"table\":100,\"uid\":0"},
		{"forwarded-not-local", "\"uid\":0", "\"iif\":\"br0\",\"uid\":0"},
		{"unknown-field", "\"uid\":0", "\"nhid\":2,\"uid\":0"},
		{"foreign-prefsrc", "\"uid\":0", "\"prefsrc\":\"1.1.1.3\",\"uid\":0"},
		{"blackhole", "\"uid\":0", "\"type\":\"blackhole\",\"uid\":0"},
		{"nonempty-cache", "\"cache\":[]", "\"cache\":[\"local\"]"},
		{"duplicate", "\"uid\":0", "\"uid\":1,\"uid\":0"},
	} {
		t.Run(cut.name, func(t *testing.T) {
			if domainTCPDirectRouteMatches([]byte(strings.Replace(valid, cut.from, cut.to, 1)), source, target, path) == nil {
				t.Fatal("foreign local route accepted")
			}
		})
	}
	for _, raw := range []string{"[]", valid + " []", strings.Repeat(" ", 2<<20) + valid} {
		if domainTCPDirectRouteMatches([]byte(raw), source, target, path) == nil {
			t.Fatal("unbounded/ambiguous response")
		}
	}
}

func TestDomainTCPDirectRequiresMatchingKernelLookupAndOriginalJSON(t *testing.T) {
	source := netip.MustParseAddr("1.1.1.1")
	target := netip.MustParseAddrPort("1.1.1.2:443")
	gateway := netip.MustParseAddr("1.1.1.254")
	path := domainTCPBaselinePath{Egress: "wan0", EgressIndex: 12, Gateway: gateway}
	valid := DomainTCPDirectRouteRead{
		JSON:   []byte(`[{"dst":"1.1.1.2","from":"1.1.1.1","gateway":"1.1.1.254","dev":"wan0","uid":0,"cache":[]}]`),
		Kernel: physicalscope.DomainIPv4RouteLookup{Source: source, Destination: target.Addr(), Gateway: gateway, EgressIndex: 12},
	}
	if err := domainTCPDirectRouteReadMatches(valid, source, target, path); err != nil {
		t.Fatal(err)
	}
	for _, edit := range []struct {
		name   string
		mutate func(*DomainTCPDirectRouteRead)
	}{
		{"missing-kernel", func(r *DomainTCPDirectRouteRead) { r.Kernel = physicalscope.DomainIPv4RouteLookup{} }},
		{"missing-json", func(r *DomainTCPDirectRouteRead) { r.JSON = nil }},
		{"changed-source", func(r *DomainTCPDirectRouteRead) { r.Kernel.Source = netip.MustParseAddr("1.1.1.4") }},
		{"changed-target", func(r *DomainTCPDirectRouteRead) { r.Kernel.Destination = netip.MustParseAddr("1.1.1.4") }},
		{"changed-gateway", func(r *DomainTCPDirectRouteRead) { r.Kernel.Gateway = netip.MustParseAddr("1.1.1.4") }},
		{"changed-index", func(r *DomainTCPDirectRouteRead) { r.Kernel.EgressIndex = 13 }},
		{"forwarded-result", func(r *DomainTCPDirectRouteRead) { r.Kernel.IngressIndex = 11 }},
		{"foreign-json", func(r *DomainTCPDirectRouteRead) {
			r.JSON = []byte(strings.Replace(string(r.JSON), `"wan0"`, `"vpn0"`, 1))
		}},
	} {
		t.Run(edit.name, func(t *testing.T) {
			read := valid
			edit.mutate(&read)
			if err := domainTCPDirectRouteReadMatches(read, source, target, path); !errors.Is(err, ErrDomainTCPBaselineKernel) {
				t.Fatalf("one reader overrode the other's refusal: %v", err)
			}
		})
	}
}

func TestDomainTCPDirectRefusesUnownedEntry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, d := range []*domainTCPDirectScope{nil, {}, {self: &domainTCPDirectScope{}}} {
		if d.registered(ctx) == nil {
			t.Fatal("unissued scope")
		}
	}
	if c, err := dialDomainTCPDirect(ctx, nil, nil, DomainPolicyTCPSocket{}, DomainPolicyTCPFlow{}, DomainPolicyDecision{}); c != nil || err == nil {
		t.Fatal("unowned dial")
	}
}

type domainDirectNoCallbackReader struct{ calls atomic.Int32 }

func (r *domainDirectNoCallbackReader) ReadDomainTCPBaseline(context.Context, netip.Addr, netip.Addr, string) (DomainTCPBaselineReadImage, error) {
	r.calls.Add(1)
	return DomainTCPBaselineReadImage{}, errors.New("unexpected kernel callback")
}
func (r *domainDirectNoCallbackReader) ReadDomainTCPDirectRoute(context.Context, netip.Addr, netip.Addr) (DomainTCPDirectRouteRead, error) {
	r.calls.Add(1)
	return DomainTCPDirectRouteRead{}, errors.New("unexpected route callback")
}

func TestDomainTCPDirectRejectsReadOnlyCarriersBeforeCallbacks(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := domainTCPDirectForwardContext(ctx); err != nil {
		t.Fatal("ordinary finite context refused", err)
	}
	reader := &domainDirectNoCallbackReader{}
	kernel := &domainTCPBaselineKernelOwner{reader: reader, capture: &domainTCPCaptureExecutionResource{}}
	kernel.self = kernel
	d := &domainTCPDirectScope{kernel: kernel}
	d.self = d
	for _, key := range []any{domainTCPBaselineCleanupKey{}, domainTCPCaptureCleanupKey{}, domainTCPFailureCleanupKey{}, domainTCPPreAddKey{}, domainTCPGuardReadKey{}, domainTCPPriorReadKey{}} {
		for _, value := range []any{true, "malformed", (*domainTCPGuardReadLoan)(nil)} {
			marked := context.WithValue(ctx, key, value)
			if err := d.current(marked); !errors.Is(err, errDomainTCPDirectReadOnlyContext) {
				t.Fatal("marker did not cause entry refusal", err)
			}
			conn, err := dialDomainTCPDirect(marked, nil, kernel, DomainPolicyTCPSocket{}, DomainPolicyTCPFlow{}, DomainPolicyDecision{})
			if conn != nil || !errors.Is(err, errDomainTCPDirectReadOnlyContext) {
				t.Fatal("dial marker did not cause entry refusal", err)
			}
		}
	}
	if reader.calls.Load() != 0 {
		t.Fatal("read-only carrier reached kernel callbacks")
	}
}

func TestDomainTCPDirectCloseJoinsCancellationAndRetainsFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	failure := errors.New("owned close failure")
	captureCtx, captureCancel := context.WithCancel(context.Background())
	defer captureCancel()
	capture := &DomainPolicyTCPCapture{ctx: captureCtx, cancel: captureCancel}
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	c := &domainTCPDirectConn{capture: capture, ctx: ctx, callbackDone: make(chan struct{}), closeOwned: func() error { calls.Add(1); close(entered); <-release; return failure }}
	c.self = c
	c.stop = context.AfterFunc(ctx, func() { defer close(c.callbackDone); c.closeLocal() })
	cancel()
	<-entered
	returned := make(chan error, 1)
	go func() { returned <- c.Close() }()
	select {
	case <-returned:
		t.Fatal("Close did not join original callback")
	default:
	}
	close(release)
	if err := <-returned; !errors.Is(err, failure) {
		t.Fatal(err)
	}
	select {
	case <-c.callbackDone:
	default:
		t.Fatal("callback escaped Close")
	}
	var joined sync.WaitGroup
	for range 16 {
		joined.Go(func() {
			if err := c.Close(); !errors.Is(err, failure) {
				t.Error(err)
			}
		})
	}
	joined.Wait()
	if calls.Load() != 1 || !errors.Is(capture.directFailure(), failure) {
		t.Fatal("close failure lost or original descriptors closed repeatedly")
	}
	if captureCtx.Err() != context.Canceled {
		t.Fatal("ambiguous socket left sibling capture flows running")
	}
}

func TestDomainTCPDirectCloseStopsUnusedCancellationCallback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	c := &domainTCPDirectConn{capture: &DomainPolicyTCPCapture{}, ctx: ctx, callbackDone: make(chan struct{}), closeOwned: func() error { calls.Add(1); return nil }}
	c.self = c
	c.stop = context.AfterFunc(ctx, func() { defer close(c.callbackDone); c.closeLocal() })
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := c.Close(); err != nil || calls.Load() != 1 {
		t.Fatal(err, calls.Load())
	}
}

func TestDomainTCPDirectCopiedOrCanceledTransportCannotUseConnection(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	original := &domainTCPDirectConn{conn: left, ctx: ctx}
	original.self = original
	foreign := &domainTCPDirectConn{conn: left, ctx: ctx, self: original}
	for _, c := range []*domainTCPDirectConn{nil, foreign} {
		if _, err := c.Read(make([]byte, 1)); err == nil {
			t.Fatal("foreign read")
		}
		if _, err := c.Write([]byte("x")); err == nil {
			t.Fatal("foreign write")
		}
		if c.CloseWrite() == nil || c.SetDeadline(time.Now()) == nil || c.SetReadDeadline(time.Now()) == nil || c.SetWriteDeadline(time.Now()) == nil || c.LocalAddr() != nil || c.RemoteAddr() != nil {
			t.Fatal("foreign transport exposed")
		}
	}
	cancel()
	if _, err := original.Read(make([]byte, 1)); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := original.Write([]byte("x")); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
