//go:build linux

// Package nativecheckfixture is imported only by opt-in tests. It supplies
// actual local DNS/TLS and a genuine VLESS XHTTP server, never runtime proofs,
// admission grants, a mock process controller or a replacement NodeChecker.
package nativecheckfixture

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const ServerIP = "93.184.216.11"
const HTTPSIP = "93.184.216.12"
const ExitIP = "93.184.216.13"
const Profile = "wan-0123456789ab" // Explicit fixture identity; no WAN acceptance.
const UUID = "123e4567-e89b-12d3-a456-426614174000"
const ServerPort = 10443

type Fixture struct {
	Binary, Root, NodeURL, ProbeURL       string
	Outbound                              []byte
	Entered                               chan struct{}
	ServiceCalls, DirectCalls, ProxyCalls atomic.Int64
	mode                                  atomic.Int32
	delay                                 atomic.Int64
	mu                                    sync.Mutex
	server                                *exec.Cmd
	serverConfig                          string
}

func Start(t *testing.T) *Fixture {
	t.Helper()
	self, e1 := os.Readlink("/proc/self/ns/net")
	host, e2 := os.Readlink("/proc/1/ns/net")
	if os.Getenv("RAZVILKA_XRAY_NETNS") != "1" || self == host || e1 != nil || e2 != nil {
		t.Fatal("native measurements require disposable loopback-only network namespace")
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		t.Fatal("native fixture namespace must have only loopback")
	}
	binary := os.Getenv("RAZVILKA_XRAY_NATIVE")
	if !filepath.IsAbs(binary) || filepath.Base(binary) != "xray" {
		t.Fatal("verified absolute Xray binary required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	version, err := exec.CommandContext(ctx, binary, "version").Output()
	cancel()
	if err != nil || !strings.Contains(string(version), "26.10.31") {
		t.Fatal("native measurement requires reviewed Xray26.10.31")
	}
	f := &Fixture{Binary: binary, Root: t.TempDir(), Entered: make(chan struct{}, 1024), ProbeURL: "https://service.example/generate_204"}
	cert, key := certificate(t, f.Root)
	t.Setenv("SSL_CERT_FILE", cert)
	t.Setenv("SSL_CERT_DIR", filepath.Join(f.Root, "empty-roots"))
	f.startDNS(t)
	listener, err := net.Listen("tcp", net.JoinHostPort(HTTPSIP, "443"))
	if err != nil {
		t.Fatal(err)
	}
	https := &http.Server{Handler: http.HandlerFunc(f.serve), TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13}, ReadHeaderTimeout: 5 * time.Second}
	t.Cleanup(func() { _ = https.Close(); _ = listener.Close() })
	go func() { _ = https.ServeTLS(listener, cert, key) }()
	server := map[string]any{"log": map[string]any{"loglevel": "warning", "access": "none"}, "dns": map[string]any{"hosts": map[string]any{"service.example": HTTPSIP, "api.ipify.org": HTTPSIP, "www.cloudflare.com": HTTPSIP}}, "inbounds": []any{map[string]any{"listen": ServerIP, "port": ServerPort, "protocol": "vless", "settings": map[string]any{"clients": []any{map[string]any{"id": UUID}}, "decryption": "none"}, "streamSettings": map[string]any{"network": "xhttp", "security": "tls", "tlsSettings": map[string]any{"certificates": []any{map[string]any{"certificateFile": cert, "keyFile": key}}, "alpn": []string{"h2", "http/1.1"}}, "xhttpSettings": map[string]any{"host": "front.example", "path": "/native-perf", "mode": "packet-up"}}}}, "outbounds": []any{map[string]any{"protocol": "freedom", "sendThrough": ExitIP, "settings": map[string]any{"domainStrategy": "UseIPv4"}}}}
	raw, err := json.Marshal(server)
	if err != nil {
		t.Fatal(err)
	}
	f.serverConfig = filepath.Join(f.Root, "server.json")
	if err := os.WriteFile(f.serverConfig, raw, 0600); err != nil {
		t.Fatal(err)
	}
	f.Outbound, err = json.Marshal(map[string]any{"type": "vless", "server": ServerIP, "server_port": ServerPort, "uuid": UUID, "tls": map[string]any{"enabled": true, "server_name": "front.example", "alpn": []string{"h2"}}, "transport": map[string]any{"type": "xhttp", "host": "front.example", "path": "/native-perf", "mode": "packet-up"}})
	if err != nil {
		t.Fatal(err)
	}
	f.NodeURL = fmt.Sprintf("vless://%s@%s:%d?security=tls&sni=front.example&alpn=h2&type=xhttp&host=front.example&path=%%2Fnative-perf&mode=packet-up", UUID, ServerIP, ServerPort)
	f.StartServer(t)
	t.Cleanup(func() { f.StopServer(t) })
	return f
}

func (f *Fixture) SetService(mode string, delay time.Duration) {
	v := int32(0)
	if mode == "dead-service" {
		v = 1
	}
	if mode == "cancel" {
		v = 2
	}
	f.mode.Store(v)
	f.delay.Store(int64(delay))
	for {
		select {
		case <-f.Entered:
		default:
			return
		}
	}
}
func (f *Fixture) serve(w http.ResponseWriter, r *http.Request) {
	source, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		http.Error(w, "source", 500)
		return
	}
	if source == ExitIP {
		f.ProxyCalls.Add(1)
	} else {
		f.DirectCalls.Add(1)
	}
	if r.Host == "service.example" && r.URL.Path == "/generate_204" {
		f.ServiceCalls.Add(1)
		select {
		case f.Entered <- struct{}{}:
		default:
		}
		delay := time.Duration(f.delay.Load())
		if f.mode.Load() == 2 {
			delay = 3 * time.Second
		}
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return
		}
		if f.mode.Load() == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusNoContent)
		}
		return
	}
	if r.URL.Path == "/cdn-cgi/trace" {
		_, _ = fmt.Fprintf(w, "ip=%s\nwarp=off\n", source)
	} else {
		_, _ = fmt.Fprint(w, source)
	}
}

func (f *Fixture) StartServer(t *testing.T) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.server != nil {
		t.Fatal("native server already running")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	out, err := exec.CommandContext(ctx, f.Binary, "run", "-test", "-config", f.serverConfig).CombinedOutput()
	cancel()
	clear(out)
	if err != nil {
		t.Fatal("native VLESS server validation failed", err)
	}
	log, err := os.OpenFile(filepath.Join(f.Root, "server.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(f.Binary, "run", "-config", f.serverConfig)
	cmd.Stdout, cmd.Stderr = log, log
	err = cmd.Start()
	_ = log.Close()
	if err != nil {
		t.Fatal(err)
	}
	f.server = cmd
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(ServerIP, fmt.Sprint(ServerPort)), 50*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("native server did not listen")
}
func (f *Fixture) StopServer(t *testing.T) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.server == nil {
		return
	}
	_ = f.server.Process.Kill()
	_ = f.server.Wait()
	f.server = nil
}

func certificate(t *testing.T, root string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cert := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: "RAZVILKA isolated measurement CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true, DNSNames: []string{"front.example", "service.example", "api.ipify.org", "www.cloudflare.com"}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cp, kp := filepath.Join(root, "ca.pem"), filepath.Join(root, "key.pem")
	if err := os.WriteFile(cp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kp, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	return cp, kp
}
func (f *Fixture) startDNS(t *testing.T) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:1053")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	original := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", conn.LocalAddr().String())
	}}
	t.Cleanup(func() { net.DefaultResolver = original })
	go func() {
		buffer := make([]byte, 4096)
		for {
			n, peer, err := conn.ReadFrom(buffer)
			if err != nil {
				return
			}
			var query dnsmessage.Message
			if query.Unpack(buffer[:n]) != nil {
				continue
			}
			answer := dnsmessage.Message{Header: dnsmessage.Header{ID: query.ID, Response: true, RecursionDesired: query.RecursionDesired, RecursionAvailable: true}, Questions: query.Questions}
			for _, q := range query.Questions {
				host := strings.TrimSuffix(q.Name.String(), ".")
				ip := HTTPSIP
				if host == "node.example" {
					ip = ServerIP
				}
				if q.Type == dnsmessage.TypeA {
					answer.Answers = append(answer.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.AResource{A: netip.MustParseAddr(ip).As4()}})
				}
			}
			wire, err := answer.Pack()
			if err == nil {
				_, _ = conn.WriteTo(wire, peer)
			}
		}
	}()
}
