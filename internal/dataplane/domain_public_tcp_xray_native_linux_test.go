//go:build linux

package dataplane

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/config"
)

// The policy is explicit namespace test intent. Its flow tuple and LAN MAC
// are obtained from the real captured FD and kernel observation, never filled
// with destination constants as proof. This is NOT Manager/firmware admission.
func TestPublicTCPDomainXrayNative(t *testing.T) {
	if os.Getenv(publicTCPBaselineNative) != "1" {
		t.Skip("explicit root-only owned namespace experiment")
	}
	binary := os.Getenv("RAZVILKA_XRAY_NATIVE")
	if !filepath.IsAbs(binary) {
		t.Fatal("actual absolute Xray binary required")
	}
	t.Setenv("RAZVILKA_PUBLIC_TCP_DOMAIN", "1")
	for _, scenario := range []string{"selected", "unlisted-shared-ip", "excluded-domain", "opaque", "ech", "half-closed"} {
		t.Run(scenario, func(t *testing.T) {
			t.Setenv("RAZVILKA_PUBLIC_TCP_DOMAIN_CASE", scenario)
			TestPublicTCPBaselineNative(t)
		})
	}
}

func publicTCPDomainPayload() string {
	switch os.Getenv("RAZVILKA_PUBLIC_TCP_DOMAIN_CASE") {
	case "selected":
		return "GET / HTTP/1.1\r\nHost: service.example\r\nConnection: close\r\n\r\n"
	case "unlisted-shared-ip", "half-closed":
		return "GET / HTTP/1.1\r\nHost: unlisted.example\r\nConnection: close\r\n\r\n"
	case "excluded-domain":
		return "GET / HTTP/1.1\r\nHost: excluded.example\r\nConnection: close\r\n\r\n"
	case "opaque":
		return "opaque-original-payload\n"
	default:
		return ""
	}
}
func publicTCPDomainExpectedSource() string {
	if os.Getenv("RAZVILKA_PUBLIC_TCP_DOMAIN_CASE") == "selected" {
		return "93.184.216.14"
	}
	return "192.0.2.2"
}

func publicTCPDomainXrayProcess(t *testing.T, doc any) *nativeXrayProcess {
	t.Helper()
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "owned-xray.json")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	p := &nativeXrayProcess{t: t, binary: os.Getenv("RAZVILKA_XRAY_NATIVE"), config: path}
	p.start()
	return p
}
func publicTCPDomainXrayServer(t *testing.T) {
	p := publicTCPDomainXrayProcess(t, map[string]any{
		"log":       map[string]any{"loglevel": "warning"},
		"inbounds":  []any{map[string]any{"listen": "93.184.216.11", "port": 18100, "protocol": "vless", "settings": map[string]any{"clients": []any{map[string]any{"id": nativeXrayUUID}}, "decryption": "none"}}},
		"outbounds": []any{map[string]any{"protocol": "freedom", "sendThrough": "93.184.216.14"}},
	})
	defer p.stop()
	nativeXrayAwait(t, "93.184.216.11:18100")
	l, err := net.ListenTCP("tcp4", net.TCPAddrFromAddrPort(netip.MustParseAddrPort(publicTCPBaselineTarget)))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	_ = l.SetDeadline(time.Now().Add(12 * time.Second))
	fmt.Println("BASELINE_SERVER_READY")
	c, err := l.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(8 * time.Second))
	var payload []byte
	if os.Getenv("RAZVILKA_PUBLIC_TCP_DOMAIN_CASE") == "ech" {
		header := make([]byte, 5)
		if _, err = io.ReadFull(c, header); err != nil {
			t.Fatal(err)
		}
		size := int(binary.BigEndian.Uint16(header[3:]))
		if header[0] != 22 || size > 16<<10 {
			t.Fatal("invalid actual TLS test record")
		}
		body := make([]byte, size)
		if _, err = io.ReadFull(c, body); err != nil {
			t.Fatal(err)
		}
		payload = append(header, body...)
		if evidence, done := parseDomainPolicyName(payload); !done || evidence.State != DomainPolicyNameEncrypted || evidence.Name != "" {
			t.Fatal("ECH fixture was not actually encrypted-name evidence")
		}
	} else {
		payload = make([]byte, len(publicTCPDomainPayload()))
		_, err = io.ReadFull(c, payload)
		if err != nil || string(payload) != publicTCPDomainPayload() {
			t.Fatal("captured payload changed", err)
		}
	}
	source := c.RemoteAddr().(*net.TCPAddr).AddrPort().Addr().String()
	if source != publicTCPDomainExpectedSource() {
		t.Fatalf("wrong actual outbound source: got %s want %s", source, publicTCPDomainExpectedSource())
	}
	if _, err = io.WriteString(c, fmt.Sprintf("observed-source=%s digest=%x\n", source, sha256.Sum256(payload))); err != nil {
		t.Fatal(err)
	}
	if _, err = io.Copy(io.Discard, c); err != nil {
		t.Fatal("original client did not drain", err)
	}
	_ = c.CloseWrite()
}
func publicTCPDomainXrayClient(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	base, err := (&net.Dialer{}).DialContext(ctx, "tcp4", publicTCPBaselineTarget)
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	c := base.(*net.TCPConn)
	_ = c.SetDeadline(time.Now().Add(9 * time.Second))
	payload := []byte(publicTCPDomainPayload())
	if os.Getenv("RAZVILKA_PUBLIC_TCP_DOMAIN_CASE") == "ech" {
		payload = domainPolicyTLSExtension(t, domainPolicyHello(t, "service.example"), 0xfe0d, []byte{0, 0, 1, 0})
	}
	if _, err = c.Write(payload); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("RAZVILKA_PUBLIC_TCP_DOMAIN_CASE") == "half-closed" {
		if err = c.CloseWrite(); err != nil {
			t.Fatal(err)
		}
	}
	response, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || response != fmt.Sprintf("observed-source=%s digest=%x\n", publicTCPDomainExpectedSource(), sha256.Sum256(payload)) {
		t.Fatal("original client received wrong flow", err, response)
	}
	if err = c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
}

func publicTCPDomainXrayCaptured(t *testing.T, ctx context.Context, accepted *net.TCPConn, socket DomainPolicyTCPSocket, mac string, currentLAN func() bool, baseline *net.Dialer) {
	t.Helper()
	p := publicTCPDomainXrayProcess(t, map[string]any{
		"log":       map[string]any{"loglevel": "warning"},
		"inbounds":  []any{map[string]any{"listen": "127.0.0.1", "port": 18082, "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": false}}},
		"outbounds": []any{map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": "93.184.216.11", "port": 18100, "users": []any{map[string]any{"id": nativeXrayUUID, "encryption": "none"}}}}}}},
	})
	defer p.stop()
	nativeXrayAwait(t, "127.0.0.1:18082")
	now := time.Now()
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	namespace, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	scope := autonomy.ScopeObservation{BootID: strings.TrimSpace(string(boot)), NetworkID: namespace, Revision: 1, ObservedAt: now, FreshUntil: now.Add(20 * time.Second), Segments: []autonomy.HomeSegment{{ID: "owned-lan", Interface: "lan0", Home: true, Prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}}, Devices: []autonomy.DeviceBinding{{ID: "owned-client", MAC: mac, Interface: "lan0", SegmentID: "owned-lan", Confirmed: true}}}
	intent := &config.NetworkPolicy{Schema: 2, Revision: 1, Clients: config.ClientScope{Mode: "lan_except", SegmentIDs: []string{"owned-lan"}, NewDevices: "inherit"}, Traffic: config.TrafficSelection{Mode: "selected_services", Unavailable: "block"}, Rules: []config.NetworkRule{{ID: "explicit-test-exclusion", Revision: 1, Kind: "exact", Value: "excluded.example", Action: "direct", Mandatory: true}}}
	policy, err := CompileDomainPolicy(strings.Repeat("b", 64), intent, scope, nil, []DomainPolicyService{{ID: "owned-service", Route: "xray", Selected: true, Domains: []string{"service.example", "excluded.example"}}}, now)
	if err != nil {
		t.Fatal(err)
	}
	// These values originate from the actual accepted socket and kernel bookend.
	flow := DomainPolicyTCPFlow{Generation: policy.generation, FlowID: socket.Source.String() + ">" + socket.OriginalDestination.String(), Source: socket.Source, Destination: socket.OriginalDestination, Client: autonomy.ClientPacket{Address: socket.Source.Addr(), MAC: mac, Interface: "lan0", SegmentID: "owned-lan"}, DefaultCoverage: "supported"}
	check := func(c context.Context, f DomainPolicyTCPFlow) (autonomy.ScopeObservation, error) {
		if c.Err() != nil || !currentLAN() || f.Source != socket.Source || f.Destination != socket.OriginalDestination {
			return autonomy.ScopeObservation{}, ErrDomainPolicyTCPConsumer
		}
		actual, err := observeDomainPolicyTCPSocket(accepted)
		if err != nil || actual != socket {
			return autonomy.ScopeObservation{}, ErrDomainPolicyTCPConsumer
		}
		return scope, nil
	}
	entered := false
	positive, negative := 0, 0
	runtime := DomainPolicyTCPRuntime{Limits: DomainPolicySniffLimits{Bytes: 16 << 10, Timeout: time.Second}, Guard: check,
		Lease: func(c context.Context, f DomainPolicyTCPFlow, _ DomainPolicyDecision, forward func(context.Context) error) error {
			if entered {
				return ErrDomainPolicyTCPConsumer
			}
			entered = true
			if _, err := check(c, f); err != nil {
				return err
			}
			return forward(c)
		},
		Dial: func(c context.Context, f DomainPolicyTCPFlow, _ DomainPolicyDecision) (net.Conn, error) {
			positive++
			if _, err := check(c, f); err != nil {
				return nil, err
			}
			return domainPolicyTCPNumericSOCKS(c, "127.0.0.1:18082", socket.OriginalDestination)
		},
		BaselineDial: func(c context.Context, f DomainPolicyTCPFlow, _ DomainPolicyDecision) (net.Conn, error) {
			negative++
			if _, err := check(c, f); err != nil {
				return nil, err
			}
			return baseline.DialContext(c, "tcp4", socket.OriginalDestination.String())
		},
	}
	decision, err := policy.HandleTCP(ctx, accepted, flow, runtime)
	if err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatal("actual captured domain flow failed", decision.Kind, decision.Reason, err)
	}
	selected := os.Getenv("RAZVILKA_PUBLIC_TCP_DOMAIN_CASE") == "selected"
	if !entered || selected && (decision.Kind != "service" || positive != 1 || negative != 0) || !selected && (decision.Kind != "baseline" || positive != 0 || negative != 1) {
		t.Fatalf("wrong domain isolation: kind=%s positive=%d baseline=%d", decision.Kind, positive, negative)
	}
}
