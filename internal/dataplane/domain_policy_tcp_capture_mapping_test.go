package dataplane

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

// Actual listener/FD and TCP connections; backend/process/physical ownership
// remain explicit models. No private NET source is reconstructed here. NET's
// original factory tests exercise valid reservations; this consumer tests that
// empty objects, copies and missing original associations cannot replace them.
func syntheticCaptureObjectModel(t *testing.T, ctx context.Context, p *DomainPolicy, spec DomainPolicyTCPCaptureSpec, owner *syntheticTCPModelOwner, xray *DomainPolicyTCPXray) *DomainPolicyTCPCapture {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", net.TCPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	spec.Listen = listener.Addr().(*net.TCPAddr).AddrPort()
	capture, err := newDomainPolicyTCPCapture(ctx, p, spec, owner, xray, listener)
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = capture.Close() })
	return capture
}

func TestDomainPolicySyntheticTCPCaptureOriginalObjectsCannotBeCopiedOrHydrated(t *testing.T) {
	f, p, spec, owner := syntheticTCPModelFixture(t)
	err := f.a.WithDomainPolicyTCPXray(context.Background(), spec.Xray, owner, func(ctx context.Context, xray *DomainPolicyTCPXray) error {
		capture := syntheticCaptureObjectModel(t, ctx, p, spec, owner, xray)
		if err := capture.Current(ctx); err != nil {
			t.Fatal(err)
		}
		// Copy only the original comparison/source references. Copying the
		// synchronization primitives themselves would be invalid Go usage.
		copy := &DomainPolicyTCPCapture{self: capture, policy: capture.policy, spec: capture.spec, owner: capture.owner, xray: capture.xray, listener: capture.listener, ctx: capture.ctx}
		if err := copy.Current(ctx); !errors.Is(err, ErrDomainPolicyTCPConsumer) {
			t.Fatal("copy became original capture", err)
		}
		if err := copy.Close(); !errors.Is(err, ErrDomainPolicyTCPConsumer) {
			t.Fatal("copy closed original capture", err)
		}
		if err := capture.Current(ctx); err != nil {
			t.Fatal("copy invalidated original", err)
		}
		for _, source := range []*dnscontrol.SyntheticDNSMapping{nil, {}} {
			prepared, err := capture.PrepareSyntheticMapping(ctx, source)
			if prepared != nil || !errors.Is(err, dnscontrol.ErrSyntheticDNSMapping) {
				t.Fatal("empty original mapping prepared capture", err)
			}
		}
		if owner.prepared.Load() != 0 || len(capture.mappings) != 0 {
			t.Fatal("non-original source reached selector preparation")
		}
		if err := capture.Close(); err != nil {
			t.Fatal(err)
		}
		if err := capture.Current(ctx); !errors.Is(err, ErrDomainPolicyTCPConsumer) {
			t.Fatal("closed capture revived", err)
		}
		if !f.processes.Running(f.a.engineProcess()) {
			t.Fatal("capture Close independently retired backend")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDomainPolicySyntheticTCPCaptureRejectsUnpublishedOrUnpreparedOriginalAssociation(t *testing.T) {
	for _, kind := range []string{"missing source", "unprepared object", "forged prepared object"} {
		t.Run(kind, func(t *testing.T) {
			f, p, spec, owner := syntheticTCPModelFixture(t)
			err := f.a.WithDomainPolicyTCPXray(context.Background(), spec.Xray, owner, func(ctx context.Context, xray *DomainPolicyTCPXray) error {
				capture := syntheticCaptureObjectModel(t, ctx, p, spec, owner, xray)
				if kind != "missing source" {
					owner.lookup = &dnscontrol.SyntheticDNSMapping{}
				}
				if kind == "forged prepared object" {
					// A matching pointer and detached shape STILL lack NET's seal.
					life, cancel := context.WithCancel(capture.ctx)
					watchDone := make(chan struct{})
					close(watchDone)
					mapping := &DomainPolicyTCPCaptureMapping{capture: capture, source: owner.lookup, ctx: life, cancel: cancel, connections: make(map[*net.TCPConn]struct{}), watchDone: watchDone, closeDone: make(chan struct{})}
					mapping.self = mapping
					capture.mappings[owner.lookup] = mapping
				}
				client, conn := domainPolicyTCPPair(t)
				socket := syntheticTCPModelSocket(spec, owner.lease.mapping, 443)
				socket.Listener = capture.spec.Listen
				d, err := capture.handleTCP(ctx, conn, func(*net.TCPConn) (DomainPolicyTCPSocket, error) { return socket, nil })
				if d.Kind != "refused" || err == nil || owner.admitted.Load() != 0 || owner.lease.calls.Load() != 0 {
					t.Fatal("non-original mapping became flow authority", d, err)
				}
				_ = client.Close()
				return capture.Close()
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDomainPolicySyntheticTCPCaptureMappingCloseModelCancelsAndJoinsSocket(t *testing.T) {
	client, conn := domainPolicyTCPPair(t)
	life, cancel := context.WithCancel(context.Background())
	watchDone := make(chan struct{})
	close(watchDone)
	m := &DomainPolicyTCPCaptureMapping{ctx: life, cancel: cancel, connections: make(map[*net.TCPConn]struct{}), watchDone: watchDone, closeDone: make(chan struct{})}
	m.self = m
	flowCtx, release, err := m.enterFlow(context.Background(), conn)
	if err != nil {
		t.Fatal(err)
	}
	readDone, allowJoin := make(chan struct{}), make(chan struct{})
	go func() { var data [1]byte; _, _ = conn.Read(data[:]); close(readDone); <-allowJoin; release() }()
	closed := make(chan error, 1)
	go func() { closed <- m.Close() }()
	select {
	case <-readDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not release socket reader")
	}
	if flowCtx.Err() == nil {
		t.Fatal("Close did not revoke flow")
	}
	select {
	case err := <-closed:
		t.Fatal("Close returned before flow joined", err)
	default:
	}
	close(allowJoin)
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not join flow")
	}
	copy := &DomainPolicyTCPCaptureMapping{self: m, ctx: m.ctx}
	if err := copy.Close(); !errors.Is(err, ErrDomainPolicyTCPConsumer) {
		t.Fatal("copy replaced mapping lifetime", err)
	}
	if _, _, err := m.enterFlow(context.Background(), client); !errors.Is(err, ErrDomainPolicyTCPConsumer) {
		t.Fatal("closed mapping admitted new flow", err)
	}
}
