package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func pingOutbound(host string) []byte {
	raw, _ := json.Marshal(map[string]any{"type": "vless", "server": host, "server_port": 443, "uuid": "private-credential"})
	return raw
}

func TestNodePingPinsOnlyValidatedPublicAddressAndMeasuresConnect(t *testing.T) {
	var resolutions, dials atomic.Int32
	var peer net.Conn
	p := &TCPNodePinger{
		resolve: func(ctx context.Context, network, host string) ([]netip.Addr, error) {
			resolutions.Add(1)
			if host != "node.example" || network != "ip" {
				t.Fatal("unexpected resolver input")
			}
			return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
		},
		dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dials.Add(1)
			if network != "tcp" || address != "8.8.8.8:443" {
				t.Fatalf("unvalidated dial: %s %s", network, address)
			}
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) > 3*time.Second {
				t.Fatal("missing bounded deadline")
			}
			client, server := net.Pipe()
			peer = server
			return client, nil
		},
	}
	result := p.Ping(context.Background(), pingOutbound("node.example"))
	defer peer.Close()
	if !result.Reachable || result.LatencyMS < 1 || resolutions.Load() != 1 || dials.Load() != 1 {
		t.Fatalf("bad result: %+v", result)
	}
	if _, err := peer.Write([]byte("must-be-closed")); err == nil {
		t.Fatal("TCP socket was retained after measurement")
	}
	raw, _ := json.Marshal(result)
	for _, private := range []string{"node.example", "8.8.8.8", "private-credential"} {
		if strings.Contains(string(raw), private) {
			t.Fatal("result disclosed endpoint or credentials")
		}
	}
}

func TestNodePingRejectsPrivateMixedMappedReservedAndOversizedAnswers(t *testing.T) {
	for _, bad := range []string{"192.168.1.1", "127.0.0.1", "100.64.0.1", "169.254.169.254", "198.18.0.1", "203.0.113.1", "::1", "::ffff:8.8.8.8", "fc00::1", "2001:db8::1", "fe80::1%eth0"} {
		t.Run(bad, func(t *testing.T) {
			p := &TCPNodePinger{resolve: func(context.Context, string, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr(bad)}, nil
			}, dial: func(context.Context, string, string) (net.Conn, error) {
				t.Fatal("dialed mixed private/public answers")
				return nil, nil
			}}
			if p.Ping(context.Background(), pingOutbound("node.example")).Reachable {
				t.Fatal("unsafe answer accepted")
			}
		})
	}
	for _, count := range []int{0, 17} {
		p := &TCPNodePinger{resolve: func(context.Context, string, string) ([]netip.Addr, error) {
			addresses := make([]netip.Addr, count)
			for i := range addresses {
				addresses[i] = netip.MustParseAddr("8.8.8.8")
			}
			return addresses, nil
		}, dial: func(context.Context, string, string) (net.Conn, error) {
			t.Fatal("bad answer count dialed")
			return nil, nil
		}}
		if p.Ping(context.Background(), pingOutbound("node.example")).Reachable {
			t.Fatal("bad answer count accepted")
		}
	}
}

func TestNodePingLiteralAndLocalHostnameNeverResolve(t *testing.T) {
	p := &TCPNodePinger{resolve: func(context.Context, string, string) ([]netip.Addr, error) {
		t.Fatal("unexpected lookup")
		return nil, nil
	}, dial: func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("raw-private-network-error")
	}}
	for _, host := range []string{"8.8.8.8", "127.0.0.1", "localhost", "router.local", "router.lan", "router.home.arpa"} {
		result := p.Ping(context.Background(), pingOutbound(host))
		if result.Reachable || strings.Contains(result.Message, "raw-private") {
			t.Fatal("unsafe result")
		}
	}
}

func TestNodePingCancellationAndUDPDoNotProduceReachability(t *testing.T) {
	p := &TCPNodePinger{resolve: net.DefaultResolver.LookupNetIP, dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	if p.Ping(ctx, pingOutbound("8.8.8.8")).Reachable || time.Since(start) > time.Second {
		t.Fatal("canceled ping continued or passed")
	}
	p.dial = func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("UDP was TCP tested")
		return nil, nil
	}
	for _, protocol := range []string{"hysteria2", "tuic"} {
		if p.Ping(context.Background(), []byte(`{"type":"`+protocol+`","server":"8.8.8.8","server_port":443}`)).Reachable {
			t.Fatal("UDP protocol reported TCP availability")
		}
	}
}
