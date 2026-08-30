package routeprobe

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/evidence"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func TestClassifyProbeStream(t *testing.T) {
	response := &http.Response{ContentLength: 65536}
	if got := classifyProbeStream(response, 16384, errors.New("timeout")); got != "interrupted" {
		t.Fatalf("got %q", got)
	}
	if got := classifyProbeStream(response, 32768, nil); got != "sampled" {
		t.Fatalf("got %q", got)
	}
	if got := classifyProbeStream(&http.Response{ContentLength: 120}, 120, nil); got != "complete" {
		t.Fatalf("got %q", got)
	}
}

func TestEndpointFromJSONUsesOnlyLoopbackSocksInbound(t *testing.T) {
	endpoint, username, password := endpointFromJSON("sing-box", []byte(`{
  "inbounds": [{"type":"socks","listen":"0.0.0.0","listen_port":2080,"users":[{"username":"u","password":"p"}]}]
}`))
	if endpoint != "127.0.0.1:2080" || username != "u" || password != "p" {
		t.Fatalf("unexpected endpoint: %q %q %q", endpoint, username, password)
	}
	endpoint, _, _ = endpointFromJSON("xray", []byte(`{"inbounds":[{"protocol":"socks","listen":"192.168.1.1","port":1080}]}`))
	if endpoint != "" {
		t.Fatalf("non-loopback endpoint must be rejected: %q", endpoint)
	}
}

func TestManagedSOCKSEndpointMatchesDataplaneRuntime(t *testing.T) {
	root := t.TempDir()
	runtimeRoot := filepath.Join(root, "sing-box", "runtime")
	if err := os.MkdirAll(runtimeRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	config := []byte(`{"inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":18081}]}`)
	if err := os.WriteFile(filepath.Join(runtimeRoot, "engine.json"), config, 0o600); err != nil {
		t.Fatal(err)
	}
	manager := New(nil)
	manager.DataplaneRoot = root
	if endpoint := manager.managedSOCKSEndpoint("sing-box"); endpoint != "127.0.0.1:18081" {
		t.Fatalf("endpoint=%q", endpoint)
	}
}

func TestUSQUENativeInterfaceParserRejectsShellSyntax(t *testing.T) {
	if got := usqueInterfaceName("SNI=ozon.ru\nIFACE='opkgtun0'\n"); got != "opkgtun0" {
		t.Fatalf("interface=%q", got)
	}
	for _, value := range []string{"IFACE=$(touch /tmp/bad)\n", "IFACE=opkgtun0 extra\n", "IFACE=\n"} {
		if got := usqueInterfaceName(value); got != "" {
			t.Fatalf("unsafe interface accepted from %q: %q", value, got)
		}
	}
}

func TestFailedSOCKSRequestIsNotRouteConfirmed(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("connect local SOCKS5 proxy: connection refused")
	})}
	result := probeHTTP(context.Background(), client, catalog.Service{ID: "telegram", Name: "Telegram", ProbeURL: "https://telegram.org/"}, "usque", "explicit-socks5:usque@127.0.0.1:1080", true)
	if result.RouteConfirmed {
		t.Fatalf("failed SOCKS request must not confirm a route: %+v", result)
	}
}

func TestIsolatedProbeRejectsBlockPageAndInvalidJSON(t *testing.T) {
	for _, test := range []struct {
		body, contentType string
		expect            catalog.ProbeExpectation
		verdict           evidence.Verdict
	}{
		{"<html>Доступ к запрашиваемому ресурсу ограничен</html>", "text/html", catalog.ProbeExpectation{}, evidence.VerdictBlocked},
		{"<html>portal</html>", "application/json", catalog.ProbeExpectation{JSON: true}, evidence.VerdictError},
	} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", test.contentType)
			_, _ = w.Write([]byte(test.body))
		}))
		service := catalog.Service{ID: "test", ProbeURL: server.URL, Probes: []catalog.Probe{{URL: server.URL, Expect: test.expect}}}
		result := probeHTTP(context.Background(), server.Client(), service, "sing-box", "explicit-socks5:test", true)
		result.NormalizeEvidence()
		if result.Verdict != test.verdict || result.AssuranceLevel().AtLeast(evidence.Service) {
			t.Errorf("unsafe result: %+v", result)
		}
		server.Close()
	}
}

func TestIsolatedProbeDoesNotIgnoreTLSVerification(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer server.Close()
	result := probeHTTP(context.Background(), &http.Client{Timeout: time.Second}, catalog.Service{ID: "test", ProbeURL: server.URL}, "sing-box", "explicit-socks5:test", true)
	result.NormalizeEvidence()
	if result.Verdict != evidence.VerdictBlocked || result.RouteConfirmed || result.AssuranceLevel().AtLeast(evidence.Service) {
		t.Fatalf("untrusted TLS became proof: %+v", result)
	}
}

func TestParseScopedNFQueuePackets(t *testing.T) {
	output := "Chain RZRP1234 (1 references)\n pkts bytes target prot opt in out source destination\n 7 420 NFQUEUE tcp -- * * 0.0.0.0/0 0.0.0.0/0 NFQUEUE num 300\n"
	if packets := parseScopedNFQueuePackets(output); packets != 7 {
		t.Fatalf("packets=%d", packets)
	}
}

func TestParseNFQWSQueueArgs(t *testing.T) {
	for _, test := range []struct {
		args  []string
		queue int
		ok    bool
	}{
		{[]string{"--daemon", "--qnum=300", "--filter-tcp=443"}, 300, true},
		{[]string{"--qnum", "64610"}, 64610, true},
		{[]string{"--qnum=70000"}, 0, false},
		{[]string{"--filter-tcp=443"}, 0, false},
	} {
		queue, ok := parseNFQWSQueueArgs(test.args)
		if queue != test.queue || ok != test.ok {
			t.Fatalf("args=%v queue=%d ok=%v", test.args, queue, ok)
		}
	}
}

func TestProfileAddress(t *testing.T) {
	ip, err := profileAddress("[Interface]\nAddress = 172.16.0.2/32, 2606:4700:110::2/128\n")
	if err != nil || ip.String() != "172.16.0.2" {
		t.Fatalf("unexpected address %v, err=%v", ip, err)
	}
}

func TestProbeURLRejectsLocalDestinations(t *testing.T) {
	for _, value := range []string{"http://example.com", "https://127.0.0.1/", "https://192.168.1.1/", "https://[::1]/"} {
		if validateProbeURL(value) == nil {
			t.Fatalf("expected rejection for %s", value)
		}
	}
	if err := validateProbeURL("https://example.com/status"); err != nil {
		t.Fatal(err)
	}
}

func TestSafeDialRejectsDNSResolvedLoopback(t *testing.T) {
	called := false
	dial := safeDial(func(context.Context, string, string) (net.Conn, error) {
		called = true
		return nil, nil
	})
	_, err := dial(context.Background(), "tcp", "localhost:443")
	if err == nil || !strings.Contains(err.Error(), "private or local") {
		t.Fatalf("unexpected error: %v", err)
	}
	if called {
		t.Fatal("underlying dialer must not receive a local destination")
	}
}

func TestSocksDialerHandshake(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			done <- acceptErr
			return
		}
		defer connection.Close()
		greeting := make([]byte, 3)
		if _, acceptErr = io.ReadFull(connection, greeting); acceptErr != nil {
			done <- acceptErr
			return
		}
		_, _ = connection.Write([]byte{0x05, 0x00})
		header := make([]byte, 4)
		if _, acceptErr = io.ReadFull(connection, header); acceptErr != nil {
			done <- acceptErr
			return
		}
		addressLength := 4
		if header[3] == 0x03 {
			length := []byte{0}
			_, _ = io.ReadFull(connection, length)
			addressLength = int(length[0])
		} else if header[3] == 0x04 {
			addressLength = 16
		}
		_, _ = io.CopyN(io.Discard, connection, int64(addressLength+2))
		_, _ = connection.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 1})
		done <- nil
	}()

	dialer := socksDialer{ProxyAddress: listener.Addr().String(), Timeout: time.Second}
	connection, err := dialer.DialContext(context.Background(), "tcp", "93.184.216.34:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
