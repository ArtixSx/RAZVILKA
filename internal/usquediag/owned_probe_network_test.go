package usquediag

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestOwnedNetworkPreflightHasNoNetworkEffect(t *testing.T) {
	good := OwnedNetworkRequest{SOCKSAddress: "127.0.0.1:18080", Services: []OwnedServiceProbe{{ID: "service-1", URL: "https://example.com/proof", Challenge: true}}, UDP: &OwnedUDPProbe{Target: netip.MustParseAddrPort("1.1.1.1:443")}}
	if err := validateOwnedNetworkRequest(good); err != nil {
		t.Fatal("valid trusted request rejected", err)
	}
	mutations := map[string]func(*OwnedNetworkRequest){
		"proxy-domain":       func(r *OwnedNetworkRequest) { r.SOCKSAddress = "localhost:18080" },
		"proxy-private":      func(r *OwnedNetworkRequest) { r.SOCKSAddress = "192.168.1.1:18080" },
		"proxy-wildcard":     func(r *OwnedNetworkRequest) { r.SOCKSAddress = "0.0.0.0:18080" },
		"proxy-zero":         func(r *OwnedNetworkRequest) { r.SOCKSAddress = "127.0.0.1:0" },
		"proxy-mapped":       func(r *OwnedNetworkRequest) { r.SOCKSAddress = "[::ffff:127.0.0.1]:18080" },
		"proxy-zone":         func(r *OwnedNetworkRequest) { r.SOCKSAddress = "[::1%private-marker]:18080" },
		"proxy-noncanonical": func(r *OwnedNetworkRequest) { r.SOCKSAddress = "127.0.0.1:018080" },
		"http":               func(r *OwnedNetworkRequest) { r.Services[0].URL = "http://example.com/" },
		"userinfo":           func(r *OwnedNetworkRequest) { r.Services[0].URL = "https://private-marker@example.com/" },
		"query":              func(r *OwnedNetworkRequest) { r.Services[0].URL += "?private-marker=secret" },
		"empty-query":        func(r *OwnedNetworkRequest) { r.Services[0].URL += "?" },
		"fragment":           func(r *OwnedNetworkRequest) { r.Services[0].URL += "#private-marker" },
		"private-url":        func(r *OwnedNetworkRequest) { r.Services[0].URL = "https://192.168.1.1/" },
		"mapped-url":         func(r *OwnedNetworkRequest) { r.Services[0].URL = "https://[::ffff:1.1.1.1]/" },
		"local-host":         func(r *OwnedNetworkRequest) { r.Services[0].URL = "https://private-marker.local/" },
		"internal-host":      func(r *OwnedNetworkRequest) { r.Services[0].URL = "https://private-marker.internal/" },
		"port":               func(r *OwnedNetworkRequest) { r.Services[0].URL = "https://example.com:8443/" },
		"id":                 func(r *OwnedNetworkRequest) { r.Services[0].ID = "private-marker\nsecret" },
		"duplicate-id":       func(r *OwnedNetworkRequest) { r.Services = append(r.Services, r.Services[0]) },
		"too-many-services":  func(r *OwnedNetworkRequest) { r.Services = make([]OwnedServiceProbe, 9) },
		"timeout":            func(r *OwnedNetworkRequest) { r.Timeout = 21 * time.Second },
		"negative-timeout":   func(r *OwnedNetworkRequest) { r.Timeout = -time.Second },
		"private-udp":        func(r *OwnedNetworkRequest) { r.UDP.Target = netip.MustParseAddrPort("192.168.1.1:443") },
		"mapped-udp":         func(r *OwnedNetworkRequest) { r.UDP.Target = netip.MustParseAddrPort("[::ffff:1.1.1.1]:443") },
		"zero-udp":           func(r *OwnedNetworkRequest) { r.UDP.Target = netip.MustParseAddrPort("1.1.1.1:0") },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			request := good
			request.Services = append([]OwnedServiceProbe(nil), good.Services...)
			udp := *good.UDP
			request.UDP = &udp
			mutate(&request)
			err := validateOwnedNetworkRequest(request)
			if !errors.Is(err, errOwnedNetworkRequest) || strings.Contains(err.Error(), "private-marker") {
				t.Fatal("invalid request accepted or private text exposed", err)
			}
			proof, err := probeOwnedNetwork(context.Background(), request)
			if !errors.Is(err, errOwnedNetworkRequest) || !reflect.DeepEqual(proof, OwnedApplicationProof{}) {
				t.Fatal("preflight failed to fence execution", err)
			}
		})
	}
	good.Services = nil
	for i := 0; i < 8; i++ {
		good.Services = append(good.Services, OwnedServiceProbe{ID: fmt.Sprintf("service-%d", i), URL: "https://example.com/"})
	}
	good.SOCKSAddress = "[::1]:18080"
	if err := validateOwnedNetworkRequest(good); err != nil {
		t.Fatal("valid bounded IPv6 loopback request rejected", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if proof, err := probeOwnedNetwork(ctx, good); !errors.Is(err, errOwnedNetworkStopped) || !reflect.DeepEqual(proof, OwnedApplicationProof{}) {
		t.Fatal("canceled request reached network", err)
	}
	if _, err := probeOwnedNetwork(nil, good); !errors.Is(err, errOwnedNetworkRequest) {
		t.Fatal("missing context accepted", err)
	}
}

func TestOwnedWarpTraceParserKeepsOnlySafeBoundedFields(t *testing.T) {
	proof, err := parseOwnedWarpTrace([]byte("fl=private-marker\nwarp=plus\ncolo=AMS\nloc=NL\nip=1.1.1.1\n"))
	if err != nil || proof.Warp != "plus" || proof.Colo != "AMS" || proof.Loc != "NL" || proof.EgressIP != "1.1.1.1" || proof.UDPConfirmed || len(proof.ConfirmedRoutes) != 0 {
		t.Fatal("safe trace not parsed", proof, err)
	}
	for _, raw := range []string{"", "warp=off\n", "warp=unknown\n", "warp=on\nwarp=plus\n", "warp=on\nip=1.1.1.1\nip=8.8.8.8\n", "private-marker", strings.Repeat("x", ownedTraceBodyLimit+1)} {
		if proof, err := parseOwnedWarpTrace([]byte(raw)); !errors.Is(err, errOwnedNetworkTrace) || !reflect.DeepEqual(proof, OwnedApplicationProof{}) || strings.Contains(err.Error(), "private-marker") {
			t.Fatal("invalid trace accepted or leaked", err)
		}
	}
	for _, ip := range []string{"127.0.0.1", "192.168.1.1", "::ffff:1.1.1.1", "private-marker", "fe80::1%private-marker"} {
		proof, err := parseOwnedWarpTrace([]byte("warp=on\ncolo=private-marker\nloc=private-marker\nip=" + ip + "\n"))
		if err != nil || proof.EgressIP != "" || proof.Colo != "" || proof.Loc != "" {
			t.Fatal("unsafe metadata retained", proof, err)
		}
	}
}

func TestOwnedSOCKSRepliesAndUDPRelayPin(t *testing.T) {
	proxy := netip.MustParseAddrPort("127.0.0.1:18080")
	good, _ := ownedSOCKSAddress(proxy.Addr().String(), proxy.Port())
	raw := append([]byte{5, 0, 0}, good...)
	reply, err := readOwnedSOCKSReply(bytes.NewReader(raw))
	if err != nil || !bytes.Equal(reply, good) {
		t.Fatal("literal SOCKS reply rejected", err)
	}
	if relay, err := validateOwnedUDPRelay(reply, proxy); err != nil || relay != proxy {
		t.Fatal("exact owned UDP relay rejected", err)
	}
	for _, endpoint := range []string{"0.0.0.0:18080", "127.0.0.1:0", "127.0.0.2:18080", "127.0.0.1:18081", "192.168.1.1:18080", "1.1.1.1:18080", "[::1]:18080", "[::ffff:127.0.0.1]:18080"} {
		address := netip.MustParseAddrPort(endpoint)
		encoded, _ := ownedSOCKSAddress(address.Addr().String(), address.Port())
		if _, err := validateOwnedUDPRelay(encoded, proxy); !errors.Is(err, errOwnedNetworkUDP) {
			t.Fatal("UDP relay mismatch accepted", endpoint, err)
		}
	}
	domain := append([]byte{3, 9}, []byte("localhost")...)
	domain = append(domain, 0x46, 0xa0)
	if _, err := validateOwnedUDPRelay(domain, proxy); !errors.Is(err, errOwnedNetworkUDP) {
		t.Fatal("domain relay accepted", err)
	}
	for _, raw := range [][]byte{{}, {5}, {4, 0, 0, 1}, {5, 1, 0, 1}, {5, 0, 1, 1}, {5, 0, 0, 9}, {5, 0, 0, 3, 0}, {5, 0, 0, 1, 127, 0, 0}} {
		if _, err := readOwnedSOCKSReply(bytes.NewReader(raw)); !errors.Is(err, errOwnedNetworkHTTP) {
			t.Fatal("malformed SOCKS reply accepted", err)
		}
	}
}

func TestOwnedDoHBootstrapRefusesUnapprovedTargetsBeforeSockets(t *testing.T) {
	transport := ownedDoHTransport(netip.MustParseAddrPort("127.0.0.1:18080"), &probeSockets{}, time.Second)
	defer transport.CloseIdleConnections()
	if transport.Proxy != nil || transport.TLSClientConfig.InsecureSkipVerify || transport.TLSClientConfig.ServerName != "cloudflare-dns.com" {
		t.Fatal("DoH TLS/proxy profile changed")
	}
	for _, target := range []string{"1.1.1.1:443", "cloudflare-dns.com:80", "private.example:443"} {
		if conn, err := transport.DialContext(context.Background(), "tcp", target); conn != nil || !errors.Is(err, errOwnedNetworkDNS) {
			t.Fatal("unapproved DoH target accepted", target, err)
		}
	}
}

func TestOwnedUDPDatagramsRequireExactTargetAndChallenge(t *testing.T) {
	expected := []byte(TransportChallengeResponse(strings.Repeat("a", 64)))
	for _, rawTarget := range []string{"1.1.1.1:443", "[2606:4700:4700::1111]:443"} {
		target := netip.MustParseAddrPort(rawTarget)
		address, _ := ownedSOCKSAddress(target.Addr().String(), target.Port())
		good := append(append([]byte{0, 0, 0}, address...), expected...)
		if err := validateOwnedUDPReply(good, target, expected); err != nil {
			t.Fatal("exact datagram rejected", err)
		}
		for name, mutate := range map[string]func([]byte) []byte{
			"reserved":     func(p []byte) []byte { p[0] = 1; return p },
			"fragment":     func(p []byte) []byte { p[2] = 1; return p },
			"address-type": func(p []byte) []byte { p[3] = 3; return p },
			"wrong-target": func(p []byte) []byte { p[4] ^= 1; return p },
			"wrong-port":   func(p []byte) []byte { p[2+len(address)] ^= 1; return p },
			"challenge":    func(p []byte) []byte { p[len(p)-1] ^= 1; return p },
			"short":        func(p []byte) []byte { return p[:len(p)-1] },
			"trailing":     func(p []byte) []byte { return append(p, 0) },
		} {
			t.Run(rawTarget+"/"+name, func(t *testing.T) {
				if err := validateOwnedUDPReply(mutate(append([]byte(nil), good...)), target, expected); !errors.Is(err, errOwnedNetworkUDP) {
					t.Fatal("invalid datagram accepted", err)
				}
			})
		}
	}
	if err := validateOwnedUDPReply([]byte{0, 0, 0}, netip.AddrPort{}, expected); !errors.Is(err, errOwnedNetworkUDP) {
		t.Fatal("missing target accepted", err)
	}
}

type ownedMemoryRoundTripper func(*http.Request) (*http.Response, error)

func (f ownedMemoryRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type ownedTrackedBody struct {
	io.Reader
	closed bool
	read   int
}

func (b *ownedTrackedBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	b.read += n
	return n, err
}
func (b *ownedTrackedBody) Close() error { b.closed = true; return nil }

func TestOwnedHTTPSResponseBoundsAndCleanupWithoutSockets(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		length int64
		tls    bool
		ok     bool
	}{
		{"ok", 200, "proof", 5, true, true},
		{"redirect", 302, "private-marker", 14, true, false},
		{"failed", 500, "private-marker", 14, true, false},
		{"oversized-length", 200, "private-marker", 257, true, false},
		{"oversized-stream", 200, strings.Repeat("x", 4096), -1, true, false},
		{"unverified-tls", 200, "private-marker", 14, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := &ownedTrackedBody{Reader: strings.NewReader(tc.body)}
			client := &http.Client{Transport: ownedMemoryRoundTripper(func(request *http.Request) (*http.Response, error) {
				if request.URL.String() != "https://example.com/proof" || request.Header.Get(TransportChallengeHeader) != strings.Repeat("a", 64) || !request.Close {
					t.Fatal("request changed")
				}
				response := &http.Response{StatusCode: tc.status, Header: http.Header{}, Body: body, ContentLength: tc.length, Request: request}
				if tc.tls {
					response.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{}}}}
				}
				return response, nil
			})}
			got, err := ownedHTTPSBody(context.Background(), client, "https://example.com/proof", strings.Repeat("a", 64), 256, true)
			if (err == nil) != tc.ok || !body.closed || body.read > 257 || err != nil && (len(got) != 0 || strings.Contains(err.Error(), "private-marker")) {
				t.Fatal("bounded HTTP handling failed", err, body.closed, body.read)
			}
		})
	}
}
