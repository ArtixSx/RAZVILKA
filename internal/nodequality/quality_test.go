package nodequality

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

func int64p(v int64) *int64 { return &v }
func observation(now time.Time) Observation {
	return Observation{Version: 1, NodeID: "node-abc", ServiceID: "telegram", NetworkProfile: "wan-one", RoutePathID: "sing-box:node-abc", ProbeID: "node-check-one", CheckedAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute), TCPConnectMS: int64p(12), ProxyResponseMS: int64p(75), TotalCheckMS: int64p(4500)}
}
func TestCacheNoAuthorityOrSecrets(t *testing.T) {
	o := observation(time.Now())
	b, e := json.Marshal(o)
	if e != nil {
		t.Fatal(e)
	}
	for _, s := range []string{"available", "verdict", "password", "endpoint", "uuid", "egress_ip"} {
		if strings.Contains(string(b), s) {
			t.Fatal(s)
		}
	}
}
func TestCacheDefensiveCopies(t *testing.T) {
	now := time.Now()
	o := observation(now)
	var c Cache
	if !c.Put(o, now) {
		t.Fatal("not stored")
	}
	*o.ProxyResponseMS = 999
	s := c.Snapshot(now)
	if *s[0].ProxyResponseMS != 75 {
		t.Fatal("input aliased")
	}
	*s[0].TCPConnectMS = 100
	s[0].NodeID = "changed"
	if *c.Snapshot(now)[0].TCPConnectMS != 12 {
		t.Fatal("output aliased")
	}
}
func TestCacheBoundAndRetention(t *testing.T) {
	now := time.Now()
	var c Cache
	for i := 0; i < MaxObservations+20; i++ {
		o := observation(now)
		o.NodeID = fmt.Sprintf("node-%d", i)
		o.CheckedAt = now.Add(-time.Duration(MaxObservations+20-i) * time.Second)
		o.ExpiresAt = o.CheckedAt.Add(time.Hour)
		if !c.Put(o, now) {
			t.Fatal(i)
		}
	}
	if len(c.Snapshot(now)) != MaxObservations {
		t.Fatal("unbounded")
	}
	if len(c.Snapshot(now.Add(Retention+time.Hour))) != 0 {
		t.Fatal("not pruned")
	}
}
func TestCacheRejectsInvalidObservations(t *testing.T) {
	now := time.Now()
	tests := []func(*Observation){func(o *Observation) { o.Version = 2 }, func(o *Observation) { o.NodeID = "https://secret" }, func(o *Observation) { o.ProbeID = "" }, func(o *Observation) { o.ServiceID = "bad\n" }, func(o *Observation) { o.CheckedAt = now.Add(time.Second) }, func(o *Observation) { o.ExpiresAt = o.CheckedAt }, func(o *Observation) { o.ExpiresAt = o.CheckedAt.Add(25 * time.Hour) }, func(o *Observation) { o.ProxyResponseMS = int64p(-1) }, func(o *Observation) { o.TotalCheckMS = int64p(600001) }}
	for i, mutate := range tests {
		o := observation(now)
		mutate(&o)
		var c Cache
		if c.Put(o, now) {
			t.Fatal(i)
		}
	}
}
func TestCacheDoesNotReplaceNewer(t *testing.T) {
	now := time.Now()
	var c Cache
	o := observation(now)
	c.Put(o, now)
	older := o
	older.CheckedAt = o.CheckedAt.Add(-time.Minute)
	older.ProxyResponseMS = int64p(7)
	if c.Put(older, now) {
		t.Fatal("old result overwrote")
	}
}
func TestCacheConcurrent(t *testing.T) {
	now := time.Now()
	var c Cache
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 60; j++ {
				o := observation(now)
				o.NodeID = fmt.Sprintf("node-%d-%d", i, j)
				c.Put(o, now)
				c.Snapshot(now)
			}
		}(i)
	}
	wg.Wait()
	if len(c.Snapshot(now)) != 480 {
		t.Fatal("lost records")
	}
}
func TestNilCache(t *testing.T) {
	var c *Cache
	if c.Put(observation(time.Now()), time.Now()) || len(c.Snapshot(time.Now())) != 0 {
		t.Fatal("nil behavior")
	}
}
func TestResponseTimingRequiresExactFreshCheck(t *testing.T) {
	now := time.Now()
	o := observation(now)
	get := func(m Observation) (int64, bool) {
		return ResponseMS(m, o.NodeID, o.ServiceID, o.NetworkProfile, o.RoutePathID, o.ProbeID, now)
	}
	if n, ok := get(o); !ok || n != 75 {
		t.Fatal(n, ok)
	}
	for _, mutate := range []func(*Observation){func(m *Observation) { m.Version = 2 }, func(m *Observation) { m.NodeID += "x" }, func(m *Observation) { m.ProbeID += "x" }, func(m *Observation) { m.ServiceID = "youtube" }, func(m *Observation) { m.NetworkProfile = "wan-two" }, func(m *Observation) { m.RoutePathID = "xray:node-abc" }, func(m *Observation) { m.ExpiresAt = now }, func(m *Observation) { m.ProxyResponseMS = nil }} {
		m := o
		mutate(&m)
		if _, ok := get(m); ok {
			t.Fatalf("accepted %+v", m)
		}
	}
	o.ProxyResponseMS = int64p(0)
	if n, ok := get(o); !ok || n != 0 {
		t.Fatal("zero is a real measurement")
	}
}
func TestLocalErrorsNeverPoisonReputation(t *testing.T) {
	for _, v := range []string{"ERROR", "PARTIAL", "INCONCLUSIVE", "MISROUTED", "FAIL", ""} {
		for _, stage := range []string{"service", "configuration", "cleanup", "dns", "transport"} {
			if ServiceFailure(v, "service", stage, "", false) {
				t.Fatal(v, stage)
			}
		}
	}
	if !ServiceFailure("BLOCKED", "service", "service", "http-status-blocked", false) {
		t.Fatal("lost attributable rejection")
	}
	for _, code := range []string{"node-cleanup-failed", "node-direct-control-unavailable", "route-identity-failed"} {
		if ServiceFailure("BLOCKED", "service", "service", code, false) {
			t.Fatal(code)
		}
	}
	if ServiceFailure("BLOCKED", "service", "service", "", true) {
		t.Fatal("misroute != node reputation")
	}
}
func TestEndpointSelectedMatchesSuccessfulDial(t *testing.T) {
	a := netip.MustParseAddr("192.0.2.1")
	b := netip.MustParseAddr("192.0.2.2")
	calls := []netip.Addr{}
	now := time.Now()
	clock := func() time.Time { now = now.Add(2 * time.Millisecond); return now }
	r, e := SelectEndpoint(context.Background(), []netip.Addr{a, b}, true, func(_ context.Context, ip netip.Addr) (bool, error) {
		calls = append(calls, ip)
		if ip == a {
			return true, errors.New("no path")
		}
		return true, nil
	}, clock)
	if e != nil || r.Address != b || r.TCPConnectMS == nil || *r.TCPConnectMS != 2 || len(calls) != 2 {
		t.Fatalf("%+v %v %v", r, e, calls)
	}
}
func TestEndpointCancellationBeforeAndAfterSuccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	f := func(context.Context, netip.Addr) (bool, error) { called = true; return true, nil }
	_, e := SelectEndpoint(ctx, []netip.Addr{netip.MustParseAddr("192.0.2.1")}, true, f, time.Now)
	if !errors.Is(e, context.Canceled) || called {
		t.Fatal("late call")
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	_, e = SelectEndpoint(ctx, []netip.Addr{netip.MustParseAddr("192.0.2.1")}, true, func(context.Context, netip.Addr) (bool, error) { cancel(); return true, nil }, time.Now)
	if !errors.Is(e, context.Canceled) {
		t.Fatal("late success accepted")
	}
}
func TestEndpointUDPDoesNotInventTCPPing(t *testing.T) {
	a := netip.MustParseAddr("2001:db8::1")
	r, e := SelectEndpoint(context.Background(), []netip.Addr{a}, false, nil, time.Now)
	if e != nil || r.Checked || r.TCPConnectMS != nil || r.Address != a {
		t.Fatal(r, e)
	}
}
func TestEndpointLimitsAndNoFalsePositive(t *testing.T) {
	f := func(context.Context, netip.Addr) (bool, error) { return false, nil }
	for _, ips := range [][]netip.Addr{nil, {netip.Addr{}}, make([]netip.Addr, 17), {netip.MustParseAddr("fe80::1%eth0")}, {netip.MustParseAddr("192.0.2.1")}} {
		if _, e := SelectEndpoint(context.Background(), ips, true, f, time.Now); e == nil {
			t.Fatal("bad set", ips)
		}
	}
}
func TestEndpointDuplicateAndClockJump(t *testing.T) {
	a := netip.MustParseAddr("192.0.2.1")
	b := netip.MustParseAddr("192.0.2.2")
	calls := 0
	now := time.Now()
	clock := func() time.Time { now = now.Add(-time.Second); return now }
	r, e := SelectEndpoint(context.Background(), []netip.Addr{a, a, b}, true, func(_ context.Context, ip netip.Addr) (bool, error) {
		calls++
		if ip == a {
			return true, errors.New("refused")
		}
		return true, nil
	}, clock)
	if e != nil || calls != 2 || r.TCPConnectMS != nil || r.Address != b {
		t.Fatal(r, e, calls)
	}
}

// Native local TCP only; not a VPN/HIL test. No public endpoint is contacted.
func TestEndpointRealLoopbackTCP(t *testing.T) {
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, e := SelectEndpoint(ctx, []netip.Addr{netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("127.0.0.1")}, true, func(ctx context.Context, ip netip.Addr) (bool, error) {
		c, e := (&net.Dialer{Timeout: 150 * time.Millisecond}).DialContext(ctx, "tcp4", net.JoinHostPort(ip.String(), fmt.Sprint(port)))
		if c != nil {
			c.Close()
		}
		return true, e
	}, time.Now)
	if e != nil || r.Address.String() != "127.0.0.1" || r.TCPConnectMS == nil {
		t.Fatal(r, e)
	}
}
