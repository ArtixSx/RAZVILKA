//go:build linux && razvilka_native_fixture

package app

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const domainOriginalNativeEnv = "RAZVILKA_DOMAIN_ORIGINAL_NATIVE"
const domainOriginalClient = "192.168.1.42"
const domainOriginalServer = "1.1.1.2"
const domainOriginalWAN = "1.1.1.254"
const domainOriginalUUID = "123e4567-e89b-12d3-a456-426614174000"

type domainOriginalNativePeers struct{ root, client, server, binary string }
type domainOriginalPeerResult struct {
	Source, Marker, Answer string
	RCode                  int
}

// Physical test peers only: no runtime authority, source, Current callback,
// admission or accepted-FD is fabricated by these helpers.
func domainOriginalPeers(t *testing.T, ctx context.Context) *domainOriginalNativePeers {
	t.Helper()
	self, e1 := os.Readlink("/proc/self/ns/net")
	initial, e2 := os.Readlink("/proc/1/ns/net")
	if os.Geteuid() != 0 || e1 != nil || e2 != nil || self == initial {
		t.Fatal("disposable root network namespace required")
	}
	selfMount, m1 := os.Readlink("/proc/self/ns/mnt")
	initialMount, m2 := os.Readlink("/proc/1/ns/mnt")
	if m1 != nil || m2 != nil || selfMount == initialMount {
		t.Fatal("private mount namespace required for fixture trust store")
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		t.Fatal("refuse existing network interfaces")
	}
	binary := os.Getenv("RAZVILKA_XRAY_NATIVE")
	if !filepath.IsAbs(binary) {
		t.Fatal("pinned official Xray required")
	}
	p := &domainOriginalNativePeers{root: t.TempDir(), binary: binary}
	var nonce [5]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	prefix := "rzdom" + hex.EncodeToString(nonce[:])
	p.client = prefix + "c"
	p.server = prefix + "s"
	run := func(args ...string) {
		t.Helper()
		command := exec.CommandContext(ctx, "ip", args...)
		out, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("owned topology %v: %v %s", args, err, out)
		}
	}
	run("link", "set", "lo", "up")
	created := []string{}
	t.Cleanup(func() {
		for i := len(created) - 1; i >= 0; i-- {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			out, err := exec.CommandContext(cleanup, "ip", "netns", "delete", created[i]).CombinedOutput()
			cancel()
			if err != nil {
				t.Errorf("owned namespace cleanup %s: %v %s", created[i], err, out)
			}
		}
	})
	for _, ns := range []string{p.client, p.server} {
		run("netns", "add", ns)
		created = append(created, ns)
		run("-n", ns, "link", "set", "lo", "up")
	}
	for _, pair := range []struct{ inside, peer, ns string }{{"br0", "client0", p.client}, {"wan0", "server0", p.server}} {
		run("link", "add", pair.inside, "type", "veth", "peer", "name", pair.peer)
		run("link", "set", pair.peer, "netns", pair.ns)
		run("link", "set", pair.inside, "up")
		run("-n", pair.ns, "link", "set", pair.peer, "up")
	}
	run("-n", p.client, "link", "set", "client0", "address", "02:00:00:00:00:02")
	run("addr", "add", "192.168.1.1/24", "dev", "br0")
	run("-n", p.client, "addr", "add", domainOriginalClient+"/24", "dev", "client0")
	run("-n", p.client, "addr", "add", "192.168.1.43/24", "dev", "client0")
	run("addr", "add", domainOriginalWAN+"/24", "dev", "wan0")
	run("-n", p.server, "addr", "add", domainOriginalServer+"/24", "dev", "server0")
	run("-n", p.client, "route", "add", "default", "via", "192.168.1.1")
	run("-n", p.server, "route", "add", "default", "via", domainOriginalWAN)
	run("addr", "add", "1.1.1.1/32", "dev", "lo")
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"all", "default", "br0", "wan0"} {
		if err := os.WriteFile("/proc/sys/net/ipv4/conf/"+name+"/rp_filter", []byte("0\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	p.certificate(t)
	// The original held-FD Xray process correctly uses a closed environment
	// without SSL_CERT_FILE. Supply its real OS trust store ONLY in this private
	// mount namespace, preserving certificate verification and native argv/env.
	trustTarget := "/etc/ssl/certs/ca-certificates.crt"
	if err := syscall.Mount(filepath.Join(p.root, "ca.pem"), trustTarget, "", syscall.MS_BIND, ""); err != nil {
		t.Fatal("private fixture trust mount", err)
	}
	t.Cleanup(func() {
		if err := syscall.Unmount(trustTarget, 0); err != nil {
			t.Error("private trust mount cleanup", err)
		}
	})
	t.Setenv("SSL_CERT_FILE", filepath.Join(p.root, "ca.pem"))
	t.Setenv("SSL_CERT_DIR", filepath.Join(p.root, "empty-roots"))
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("ALL_PROXY", "")
	p.localDoH(t)
	command := exec.Command("ip", "netns", "exec", p.server, os.Args[0], "-test.run=^TestDomainTCPOriginalNativePeer$", "-test.v", "-test.timeout=4m")
	command.Env = append(os.Environ(), "RAZVILKA_DOMAIN_NATIVE_PEER=server", "RAZVILKA_DOMAIN_NATIVE_ROOT="+p.root)
	log, err := os.OpenFile(filepath.Join(p.root, "peer.log"), os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	command.Stdout, command.Stderr = log, log
	if err := command.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	log.Close()
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	t.Cleanup(func() {
		_ = command.Process.Signal(syscall.SIGTERM)
		select {
		case err := <-done:
			if err != nil {
				data, _ := os.ReadFile(filepath.Join(p.root, "peer.log"))
				t.Errorf("physical peer exit: %v %s", err, data)
			}
		case <-time.After(8 * time.Second):
			_ = command.Process.Kill()
			<-done
			t.Error("physical server did not join")
		}
	})
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filepath.Join(p.root, "server.ready")); err == nil {
			return p
		}
		time.Sleep(20 * time.Millisecond)
	}
	data, _ := os.ReadFile(filepath.Join(p.root, "peer.log"))
	t.Fatalf("physical server not ready: %s", data)
	return nil
}

func (p *domainOriginalNativePeers) certificate(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	certificate := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: "isolated original domain fixture"}, DNSNames: []string{"front.example", "service.example.com", "unknown.example.com", "cloudflare-dns.com", "www.cloudflare.com", "api.ipify.org"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"ca.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), "key.pem": pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: private})} {
		if err := os.WriteFile(filepath.Join(p.root, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func domainOriginalDNSAnswer(wire []byte, address [4]byte) ([]byte, error) {
	var query dnsmessage.Message
	if err := query.Unpack(wire); err != nil {
		return nil, err
	}
	answer := dnsmessage.Message{Header: dnsmessage.Header{ID: query.ID, Response: true, RecursionDesired: query.RecursionDesired, RecursionAvailable: true}, Questions: query.Questions}
	for _, question := range query.Questions {
		if question.Type == dnsmessage.TypeA {
			answer.Answers = append(answer.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: address}})
		}
	}
	return answer.Pack()
}

func (p *domainOriginalNativePeers) localDoH(t *testing.T) {
	udp, err := net.ListenPacket("udp4", "127.0.0.1:1053")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udp.Close() })
	original := net.DefaultResolver
	preferGo, dial := original.PreferGo, original.Dial
	original.PreferGo = true
	original.Dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp4", udp.LocalAddr().String())
	}
	t.Cleanup(func() { original.PreferGo, original.Dial = preferGo, dial })
	go func() {
		buffer := make([]byte, 4096)
		for {
			n, peer, err := udp.ReadFrom(buffer)
			if err != nil {
				return
			}
			address := [4]byte{1, 1, 1, 2}
			var q dnsmessage.Message
			if q.Unpack(buffer[:n]) == nil && len(q.Questions) > 0 && q.Questions[0].Name.String() == "cloudflare-dns.com." {
				address = [4]byte{1, 1, 1, 1}
			}
			answer, err := domainOriginalDNSAnswer(buffer[:n], address)
			if err == nil {
				_, _ = udp.WriteTo(answer, peer)
			}
		}
	}()
	listener, err := net.Listen("tcp4", "1.1.1.1:443")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{ReadHeaderTimeout: 3 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query, err := io.ReadAll(io.LimitReader(r.Body, 4097))
		if err != nil || len(query) > 4096 {
			w.WriteHeader(400)
			return
		}
		answer, err := domainOriginalDNSAnswer(query, [4]byte{1, 1, 1, 2})
		if err != nil {
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(answer)
	})}
	t.Cleanup(func() { server.Close(); listener.Close() })
	go func() {
		_ = server.ServeTLS(listener, filepath.Join(p.root, "ca.pem"), filepath.Join(p.root, "key.pem"))
	}()
}

func (p *domainOriginalNativePeers) clientRequest(t *testing.T, ctx context.Context, mode, target string) domainOriginalPeerResult {
	t.Helper()
	resultPath := filepath.Join(p.root, fmt.Sprintf("result-%d.json", time.Now().UnixNano()))
	command := exec.CommandContext(ctx, "ip", "netns", "exec", p.client, os.Args[0], "-test.run=^TestDomainTCPOriginalNativePeer$", "-test.v", "-test.timeout=10s")
	command.Env = append(os.Environ(), "RAZVILKA_DOMAIN_NATIVE_PEER="+mode, "RAZVILKA_DOMAIN_NATIVE_ROOT="+p.root, "RAZVILKA_DOMAIN_NATIVE_TARGET="+target, "RAZVILKA_DOMAIN_NATIVE_RESULT="+resultPath)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("actual client %s: %v %s", mode, err, output)
	}
	data, err := os.ReadFile(resultPath)
	if err != nil {
		t.Fatal(err)
	}
	var result domainOriginalPeerResult
	if json.Unmarshal(data, &result) != nil {
		t.Fatal("invalid actual client result")
	}
	return result
}

func TestDomainTCPOriginalNativePeer(t *testing.T) {
	if os.Getenv(domainOriginalNativeEnv) != "1" {
		t.Skip("native original domain fixture only")
	}
	mode := os.Getenv("RAZVILKA_DOMAIN_NATIVE_PEER")
	if mode == "" {
		t.Skip("physical peer role only")
	}
	root := os.Getenv("RAZVILKA_DOMAIN_NATIVE_ROOT")
	if mode == "server" {
		domainOriginalServePeer(t, root)
		return
	}
	result := domainOriginalPeerResult{}
	target := os.Getenv("RAZVILKA_DOMAIN_NATIVE_TARGET")
	if strings.HasPrefix(mode, "dns") {
		source := domainOriginalClient
		if mode == "dns-other-client" {
			source = "192.168.1.43"
		}
		socket, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.ParseIP(source)}, &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 10553})
		if err != nil {
			t.Fatal(err)
		}
		defer socket.Close()
		socket.SetDeadline(time.Now().Add(time.Second))
		query := dnsmessage.Message{Header: dnsmessage.Header{ID: 7, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("service.example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
		wire, _ := query.Pack()
		if _, err = socket.Write(wire); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 4096)
		n, err := socket.Read(buffer)
		if err != nil {
			t.Fatal(err)
		}
		var answer dnsmessage.Message
		if answer.Unpack(buffer[:n]) != nil {
			t.Fatal("actual DNS reply invalid")
		}
		result.RCode = int(answer.RCode)
		for _, a := range answer.Answers {
			if body, ok := a.Body.(*dnsmessage.AResource); ok {
				result.Answer = net.IP(body.A[:]).String()
			}
		}
	} else if mode == "opaque" {
		conn, err := net.DialTimeout("tcp4", net.JoinHostPort(target, "80"), 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(4 * time.Second))
		if _, err = io.WriteString(conn, "opaque-native-baseline\n"); err != nil {
			t.Fatal(err)
		}
		if json.NewDecoder(conn).Decode(&result) != nil {
			t.Fatal("opaque original baseline result missing")
		}
	} else {
		ca, err := os.ReadFile(filepath.Join(root, "ca.pem"))
		if err != nil {
			t.Fatal(err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(ca) {
			t.Fatal("physical CA invalid")
		}
		name := "service.example.com"
		if mode == "mismatch" {
			name = "unknown.example.com"
		}
		transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: name, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp4", net.JoinHostPort(target, "443"))
		}}
		defer transport.CloseIdleConnections()
		client := http.Client{Transport: transport, Timeout: 4 * time.Second}
		response, err := client.Get("https://" + name + "/")
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != 200 || json.NewDecoder(response.Body).Decode(&result) != nil {
			t.Fatal("actual TLS service response missing")
		}
	}
	data, _ := json.Marshal(result)
	if err := os.WriteFile(os.Getenv("RAZVILKA_DOMAIN_NATIVE_RESULT"), data, 0600); err != nil {
		t.Fatal(err)
	}
}

func domainOriginalServePeer(t *testing.T, root string) {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer cancel()
	listener, err := net.Listen("tcp4", domainOriginalServer+":443")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{ReadHeaderTimeout: 3 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		source, _, _ := net.SplitHostPort(r.RemoteAddr)
		if r.URL.Path == "/cdn-cgi/trace" {
			fmt.Fprintf(w, "ip=%s\nwarp=off\n", source)
			return
		}
		if r.Host == "api.ipify.org" {
			io.WriteString(w, source)
			return
		}
		_ = json.NewEncoder(w).Encode(domainOriginalPeerResult{Source: source, Marker: "native-domain-service"})
	})}
	go func() { _ = server.ServeTLS(listener, filepath.Join(root, "ca.pem"), filepath.Join(root, "key.pem")) }()
	defer server.Close()
	opaque, err := net.Listen("tcp4", domainOriginalServer+":80")
	if err != nil {
		t.Fatal(err)
	}
	defer opaque.Close()
	go func() {
		for {
			conn, err := opaque.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(4 * time.Second))
				line, err := bufio.NewReader(io.LimitReader(conn, 1024)).ReadString('\n')
				if err != nil {
					return
				}
				source, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
				_ = json.NewEncoder(conn).Encode(domainOriginalPeerResult{Source: source, Marker: strings.TrimSpace(line)})
			}()
		}
	}()
	config := map[string]any{"log": map[string]any{"loglevel": "debug", "access": "none"}, "inbounds": []any{map[string]any{"listen": domainOriginalServer, "port": 10443, "protocol": "vless", "settings": map[string]any{"clients": []any{map[string]any{"id": domainOriginalUUID}}, "decryption": "none"}, "streamSettings": map[string]any{"network": "tcp", "security": "tls", "tlsSettings": map[string]any{"certificates": []any{map[string]any{"certificateFile": filepath.Join(root, "ca.pem"), "keyFile": filepath.Join(root, "key.pem")}}}}}}, "outbounds": []any{map[string]any{"protocol": "freedom", "sendThrough": domainOriginalServer}}}
	raw, _ := json.Marshal(config)
	path := filepath.Join(root, "server.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	check, cancelCheck := context.WithTimeout(ctx, 5*time.Second)
	output, checkErr := exec.CommandContext(check, os.Getenv("RAZVILKA_XRAY_NATIVE"), "run", "-test", "-config", path).CombinedOutput()
	cancelCheck()
	if checkErr != nil {
		t.Fatalf("physical native server config invalid: %v %s", checkErr, output)
	}
	command := exec.Command(os.Getenv("RAZVILKA_XRAY_NATIVE"), "run", "-config", path)
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = command.Process.Kill(); _ = command.Wait() }()
	deadline := time.Now().Add(5 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp4", domainOriginalServer+":10443", 50*time.Millisecond)
		if err == nil {
			conn.Close()
			ready = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ready {
		t.Fatal("actual native server did not listen")
	}
	if err := os.WriteFile(filepath.Join(root, "server.ready"), []byte("physical-listeners-only\n"), 0600); err != nil {
		t.Fatal(err)
	}
	<-ctx.Done()
}
