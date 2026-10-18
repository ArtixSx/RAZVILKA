//go:build linux

package dataplane

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestPublicTCPBaselineSocketRequiresActualFiniteAcceptedSource(t *testing.T) {
	finite, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	canceled, stop := context.WithCancel(finite)
	stop()
	for _, tc := range []struct {
		ctx  context.Context
		conn *net.TCPConn
	}{{nil, nil}, {context.Background(), new(net.TCPConn)}, {finite, nil}, {finite, new(net.TCPConn)}, {canceled, new(net.TCPConn)}} {
		prepared, err := preparePublicTCPBaselineSocket(tc.ctx, tc.conn)
		if prepared != nil || !errors.Is(err, errPublicTCPBaselineSocket) {
			t.Fatal("unissued tuple produced descriptor", err)
		}
		if tc.ctx == canceled && !errors.Is(err, context.Canceled) {
			t.Fatal("original cancellation lost", err)
		}
	}
	for _, owner := range []*publicTCPBaselineSocket{nil, {}} {
		if owner.close() == nil || owner.current(finite) == nil {
			t.Fatal("unissued owner accepted")
		}
	}
}
