package dataplane

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
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
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/evidence"
)

// This is an opt-in native server/client test, run only by the owner of the
// isolated network namespace. Its public-format addresses are local fixtures,
// not Internet exits. No mock process, SOCKS proxy or NodeChecker proof is used.
const (
	nativeXrayServerIP = "93.184.216.11"
	nativeXrayHTTPSIP  = "93.184.216.12"
	nativeXrayExitIP   = "93.184.216.13"
	nativeXrayUUID     = "123e4567-e89b-12d3-a456-426614174000"
)

type nativeXrayProcess struct {
	t      *testing.T
	binary string
	config string
	cmd    *exec.Cmd
}

func (p *nativeXrayProcess) start() {
	p.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, p.binary, "run", "-test", "-config", p.config).CombinedOutput()
	clear(output)
	if err != nil {
		p.t.Fatalf("native server config rejected: %v", err)
	}
	log, err := os.OpenFile(p.config+".log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		p.t.Fatal(err)
	}
	p.cmd = exec.Command(p.binary, "run", "-config", p.config)
	p.cmd.Stdout, p.cmd.Stderr = log, log
	err = p.cmd.Start()
	_ = log.Close()
	if err != nil {
		p.t.Fatal(err)
	}
}

func (p *nativeXrayProcess) stop() {
	if p.cmd != nil {
		_ = p.cmd.Process.Kill()
		_ = p.cmd.Wait()
		p.cmd = nil
	}
}

func nativeXrayCertificate(t *testing.T, root string) (string, string, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: "RAZVILKA isolated native fixture"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true,
		DNSNames: []string{"front.example", "service.example", "www.cloudflare.com", "api.ipify.org"},
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(root, "ca.pem"), filepath.Join(root, "key.pem")
	if err := os.WriteFile(certPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(encoded) {
		t.Fatal("fixture certificate invalid")
	}
	return certPath, keyPath, roots
}

func nativeXrayListen(t *testing.T, address, cert, key string, handler http.Handler) {
	t.Helper()
	l, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal("native fixture listener:", err)
	}
	s := &http.Server{Handler: handler, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13}, ReadHeaderTimeout: 15 * time.Second}
	t.Cleanup(func() { _ = s.Close(); _ = l.Close() })
	go func() { _ = s.ServeTLS(l, cert, key) }()
}

func nativeXrayAwait(t *testing.T, address string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("native server did not become ready")
}

func nativeXrayServerReady(t *testing.T, address, security string) {
	nativeXrayAwait(t, address)
	if security == "reality" {
		// Xray v26.3.27 starts REALITY's asynchronous target-record detector
		// when the listener opens. It deliberately reads for five seconds and
		// probes ignored CCS records. TCP readiness alone precedes that work.
		// Give the test server time to finish its target discovery; the real
		// checker's HTTP timeouts and certificate verification stay unchanged.
		time.Sleep(6 * time.Second)
	}
}

func TestNativeXrayExactNode(t *testing.T) {
	if nativeXrayIsolatedFixture(t) {
		return
	}
	nativeXrayExactNodeMatrix(t, []nativeXrayCase{{security: "tls", lifecycle: true}, {security: "reality", lifecycle: true}})
}

// Each matrix creates a fresh CA. Go's system roots are process-cached, so a
// second matrix cannot replace the first CA merely by changing SSL_CERT_FILE.
// Re-execute the selected test in the SAME isolated namespace, with a fresh
// Go trust store. The production service/TLS probes and genuine Xray processes
// stay unchanged; explicit fixture roots still verify both paired egress paths.
func nativeXrayIsolatedFixture(t *testing.T) bool {
	t.Helper()
	if os.Getenv("RAZVILKA_XRAY_NATIVE") == "" {
		t.Skip("requires scripts/check-xray-native.sh and a verified Xray binary")
	}
	const marker = "RAZVILKA_XRAY_FIXTURE_CHILD"
	if selected := os.Getenv(marker); selected != "" {
		if selected != t.Name() {
			t.Fatal("native fixture child selected a different matrix")
		}
		return false
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(11 * time.Minute)
	if parentDeadline, ok := t.Deadline(); ok && parentDeadline.Add(-5*time.Second).Before(deadline) {
		deadline = parentDeadline.Add(-5 * time.Second)
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "-test.run", "^"+regexp.QuoteMeta(t.Name())+"$", "-test.v", "-test.count=1", "-test.timeout", time.Until(deadline).String())
	command.Env = append(os.Environ(), marker+"="+t.Name())
	output, err := command.CombinedOutput()
	defer clear(output)
	t.Logf("isolated native matrix:\n%s", output)
	if err != nil {
		t.Fatalf("isolated native matrix failed: %v", err)
	}
	return true
}

type nativeXrayCase struct {
	security  string
	mode      string
	extra     bool
	lifecycle bool
}

// Separate opt-in test: genuine Xray server/client for each XHTTP mode,
// preserving the accepted RAW/TCP fixture and its independently recorded runs.
func TestNativeXrayXHTTPExactNode(t *testing.T) {
	if nativeXrayIsolatedFixture(t) {
		return
	}
	var cases []nativeXrayCase
	for _, security := range []string{"tls", "reality"} {
		for _, mode := range []string{"auto", "packet-up", "stream-up", "stream-one"} {
			cases = append(cases, nativeXrayCase{security: security, mode: mode, extra: mode == "packet-up", lifecycle: security == "tls" && mode == "packet-up" || security == "reality" && mode == "stream-one"})
		}
	}
	nativeXrayExactNodeMatrix(t, cases)
}

func nativeXrayExactNodeMatrix(t *testing.T, cases []nativeXrayCase) {
	binary := os.Getenv("RAZVILKA_XRAY_NATIVE")
	if binary == "" {
		t.Skip("requires scripts/check-xray-native.sh and a verified Xray binary")
	}
	selfNS, e1 := os.Readlink("/proc/self/ns/net")
	ownerNS, e2 := os.Readlink("/proc/1/ns/net")
	if os.Getenv("RAZVILKA_XRAY_NETNS") != "1" || e1 != nil || e2 != nil || selfNS == ownerNS {
		t.Fatal("native test requires its own isolated network namespace")
	}
	for _, fixture := range cases {
		if fixture.mode != "" {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			version, err := exec.CommandContext(ctx, binary, "version").Output()
			cancel()
			pinned := exactXHTTPVersionOutput(version)
			clear(version)
			if err != nil || !pinned {
				t.Fatal("XHTTP schema harness requires the reviewed Xray 26.3.27 binary")
			}
			break
		}
	}
	root := t.TempDir()
	cert, key, roots := nativeXrayCertificate(t, root)
	// Both Go service probes and the child Xray verify the generated CA.
	// The isolated fixture process runs only this matrix. Production never
	// supplies these roots; the wrapper prevents Go system-root cache reuse.
	t.Setenv("SSL_CERT_FILE", cert)
	t.Setenv("SSL_CERT_DIR", filepath.Join(root, "empty-roots"))
	var directRequests, proxyRequests, serviceRequests atomic.Int64
	nativeXrayListen(t, net.JoinHostPort(nativeXrayHTTPSIP, "443"), cert, key, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		source, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "bad source", 500)
			return
		}
		if source == nativeXrayExitIP {
			proxyRequests.Add(1)
		} else {
			directRequests.Add(1)
		}
		if r.Host == "service.example" && r.URL.Path == "/generate_204" {
			serviceRequests.Add(1)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		if r.URL.Path == "/cdn-cgi/trace" {
			_, _ = fmt.Fprintf(w, "ip=%s\nwarp=off\n", source)
		} else {
			_, _ = fmt.Fprint(w, source)
		}
	}))
	// REALITY uses a real local TLS 1.3/H2 target, with its own certificate.
	nativeXrayListen(t, net.JoinHostPort(nativeXrayHTTPSIP, "9443"), cert, key, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	xkey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := base64.RawURLEncoding.EncodeToString(xkey.PublicKey().Bytes())
	privateKey := base64.RawURLEncoding.EncodeToString(xkey.Bytes())
	for index, fixture := range cases {
		security := fixture.security
		name := security
		if fixture.mode != "" {
			name += "-xhttp-" + fixture.mode
		}
		t.Run(name, func(t *testing.T) {
			serverPort := 10443 + index
			stream := map[string]any{"network": "tcp", "security": security}
			tlsOptions := map[string]any{"enabled": true, "server_name": "front.example"}
			user := map[string]any{"id": nativeXrayUUID}
			outbound := map[string]any{"type": "vless", "server": "node.example", "server_port": serverPort, "uuid": nativeXrayUUID, "tls": tlsOptions}
			if fixture.mode != "" {
				xsettings := map[string]any{"host": "front.example", "path": "/exact-xhttp?fixture=1", "mode": fixture.mode}
				if fixture.extra {
					xsettings["extra"] = map[string]any{
						"xPaddingBytes": "64-128", "xPaddingObfsMode": true, "xPaddingPlacement": "header", "xPaddingHeader": "X-Fixture-Pad",
						"sessionPlacement": "query", "sessionKey": "fixture-session", "seqPlacement": "query", "seqKey": "fixture-seq",
						"noGRPCHeader": true, "noSSEHeader": true, "scMaxEachPostBytes": 8192, "scMinPostsIntervalMs": 0,
						"xmux": map[string]any{"maxConcurrency": 2, "hMaxRequestTimes": "10-20", "hMaxReusableSecs": 30},
					}
				}
				stream["network"], stream["xhttpSettings"] = "xhttp", xsettings
				transport := map[string]any{"type": "xhttp"}
				for field, value := range xsettings {
					transport[field] = value
				}
				outbound["transport"] = transport
				if security == "tls" {
					tlsOptions["alpn"] = []string{"h2"}
				}
			}
			if security == "tls" {
				stream["tlsSettings"] = map[string]any{"certificates": []any{map[string]any{"certificateFile": cert, "keyFile": key}}, "alpn": []string{"h2", "http/1.1"}}
			} else {
				stream["realitySettings"] = map[string]any{"target": net.JoinHostPort(nativeXrayHTTPSIP, "9443"), "serverNames": []string{"front.example"}, "privateKey": privateKey, "shortIds": []string{"abcd"}}
				tlsOptions["utls"] = map[string]any{"enabled": true, "fingerprint": "chrome"}
				tlsOptions["reality"] = map[string]any{"enabled": true, "public_key": publicKey, "short_id": "abcd"}
				if fixture.mode == "" {
					user["flow"], outbound["flow"] = "xtls-rprx-vision", "xtls-rprx-vision"
				}
			}
			serverConfig := map[string]any{
				"log":       map[string]any{"loglevel": "warning", "access": "none"},
				"dns":       map[string]any{"hosts": map[string]any{"service.example": nativeXrayHTTPSIP}},
				"inbounds":  []any{map[string]any{"listen": nativeXrayServerIP, "port": serverPort, "protocol": "vless", "settings": map[string]any{"clients": []any{user}, "decryption": "none"}, "streamSettings": stream}},
				"outbounds": []any{map[string]any{"protocol": "freedom", "sendThrough": nativeXrayExitIP, "settings": map[string]any{"domainStrategy": "UseIPv4"}}},
			}
			serverPath := filepath.Join(root, "server-"+name+".json")
			data, err := json.Marshal(serverConfig)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(serverPath, data, 0o600); err != nil {
				t.Fatal(err)
			}
			clear(data)
			server := &nativeXrayProcess{t: t, binary: binary, config: serverPath}
			server.start()
			t.Cleanup(server.stop)
			serverAddress := net.JoinHostPort(nativeXrayServerIP, fmt.Sprint(serverPort))
			nativeXrayServerReady(t, serverAddress, security)
			checker := NewExactXrayNodeCheckerSlots(filepath.Join(root, "client-"+name), 2)
			checker.Binary, checker.Port = binary, 29185+index*MaxExactNodeSlots
			checker.FreshProfile = func(context.Context) (string, error) { return "wan-0123456789ab", nil }
			checker.resolve = func(_ context.Context, host string) ([]netip.Addr, error) {
				if host == "node.example" {
					return []netip.Addr{netip.MustParseAddr(nativeXrayServerIP)}, nil
				}
				return []netip.Addr{netip.MustParseAddr(nativeXrayHTTPSIP)}, nil
			}
			getter := nodeEgressHTTP{roots: roots, resolve: func(context.Context, string, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr(nativeXrayHTTPSIP)}, nil
			}}
			checker.egressPair = func(ctx context.Context, address string) nodeEgressPair {
				return probeNodeEgressPair(ctx, address, func(ctx context.Context, endpoint nodeEgressEndpoint, address string) (string, error) {
					endpoint.pinned = netip.MustParseAddr(nativeXrayHTTPSIP)
					return getter.get(ctx, endpoint, address)
				})
			}
			material, err := json.Marshal(outbound)
			if err != nil {
				t.Fatal(err)
			}
			r := NodeCheckRequest{NodeID: checkedNodeID, Outbound: material, NetworkProfile: "wan-0123456789ab", Service: catalog.Service{ID: "telegram", ProbeURL: "https://service.example/generate_204", Strategy: []string{"xray"}}}
			run := func() NodeCheckResult {
				t.Helper()
				ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
				defer cancel()
				result, err := checker.Check(ctx, r)
				if err != nil {
					t.Fatalf("native checker error: %v", err)
				}
				return result
			}
			assertPass := func(result NodeCheckResult) {
				t.Helper()
				if !result.Available || result.RoutePathID != "xray:"+checkedNodeID || result.EgressIP != nativeXrayExitIP || result.Evidence.Engine != "xray" || result.DirectControl != "measured" {
					t.Fatalf("native path not confirmed: %+v", result)
				}
				for slot := range checker.Capacity() {
					if checker.Processes.Running(checker.session(slot).Spec) {
						t.Fatal("native client leaked after check")
					}
				}
			}
			assertPass(run())
			t.Log("native exact path passed: owned client, TLS-verified paired egress, service hostname and literal-IP path")
			if !fixture.lifecycle {
				return
			}
			if fixture.mode != "" {
				// A real server requires the correct transport, TLS name, path
				// and mode. SOCKS readiness or TCP connect cannot substitute.
				for _, mutation := range []struct {
					name     string
					material []byte
				}{
					{"wrong-path", []byte(strings.Replace(string(material), "/exact-xhttp?fixture=1", "/wrong-xhttp", 1))},
					{"wrong-tls-name", []byte(strings.Replace(string(material), `"server_name":"front.example"`, `"server_name":"wrong.example"`, 1))},
					{"wrong-mode", []byte(strings.Replace(string(material), `"mode":"`+fixture.mode+`"`, `"mode":"stream-up"`, 1))},
				} {
					r.Outbound = mutation.material
					if failed := run(); failed.Available || failed.Verdict == evidence.VerdictPass || failed.Evidence.Verdict == evidence.VerdictPass || failed.ErrorCode != "node-egress-failed" || failed.Stage != "egress" {
						t.Fatalf("%s was not rejected by the real path: %+v", mutation.name, failed)
					}
				}
				var wrongTransport map[string]any
				if json.Unmarshal(material, &wrongTransport) != nil {
					t.Fatal("invalid fixture")
				}
				delete(wrongTransport, "transport")
				r.Outbound, err = json.Marshal(wrongTransport)
				if err != nil {
					t.Fatal(err)
				}
				if failed := run(); failed.Available || failed.ErrorCode != "node-egress-failed" || failed.Stage != "egress" {
					t.Fatalf("RAW client was accepted by XHTTP server: %+v", failed)
				}
				r.Outbound = material
				assertPass(run())
				t.Log("native XHTTP mismatch rejection: actual wrong path/TLS name/mode/transport failed, correct material recovered")
			}
			// Real server restart: a stopped endpoint cannot produce a PASS;
			// the same material works again only after the real server returns.
			server.stop()
			if failed := run(); failed.Available || failed.ErrorCode != "node-transport-failed" {
				t.Fatalf("stopped server accepted: %+v", failed)
			}
			server.start()
			nativeXrayServerReady(t, serverAddress, security)
			assertPass(run())
			// Wrong credentials must fail after local SOCKS readiness succeeds.
			r.Outbound = []byte(strings.Replace(string(material), nativeXrayUUID, "223e4567-e89b-12d3-a456-426614174000", 1))
			if failed := run(); failed.Available || failed.ErrorCode != "node-egress-failed" {
				t.Fatalf("wrong UUID accepted or misclassified: %+v", failed)
			}
			r.Outbound = material
			// A mid-check kill reaches the actual managed PID and cannot leave
			// cached response evidence usable. Ownership is checked after probes.
			baseProbe := checker.serviceProbe
			checker.serviceProbe = func(ctx context.Context, address, route, egress string, svc catalog.Service) (evidence.ProbeEvidence, error) {
				proof, err := baseProbe(ctx, address, route, egress, svc)
				for slot := range checker.Capacity() {
					s := checker.session(slot)
					if s.Address == address {
						pid, readErr := readManagedPID(s.Spec)
						if readErr != nil {
							t.Fatal(readErr)
						}
						p, findErr := os.FindProcess(pid)
						if findErr != nil {
							t.Fatal(findErr)
						}
						if err := p.Kill(); err != nil {
							t.Fatal(err)
						}
					}
				}
				return proof, err
			}
			failed := run()
			// A just-killed child may still be a zombie until the launcher's
			// wait goroutine reaps it. Cleanup correctly fences that unknown
			// process state rather than assuming that a PID is safe to remove.
			if failed.Available || failed.Verdict == evidence.VerdictPass || failed.Evidence.Verdict == evidence.VerdictPass || failed.Evidence.ErrorCode != "node-route-runtime-changed" || failed.ErrorCode != "node-route-runtime-changed" && failed.ErrorCode != "node-cleanup-failed" {
				t.Fatalf("killed client retained proof: %+v", failed)
			}
			if failed.ErrorCode == "node-cleanup-failed" && !checker.poisoned.Load() {
				t.Fatal("uncertain cleanup did not fence the checker")
			}
			checker.serviceProbe = baseProbe
			deadline := time.Now().Add(2 * time.Second)
			for {
				err := checker.Recover(context.Background())
				if err == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal(err)
				}
				time.Sleep(20 * time.Millisecond)
			}
			assertPass(run())
			t.Log("native failure/recovery passed: stopped/restarted server, wrong UUID, killed/recovered client")
		})
	}
	if directRequests.Load() == 0 || proxyRequests.Load() == 0 || serviceRequests.Load() < 4 {
		t.Fatal("native fixtures did not observe real direct, proxy and service traffic")
	}
	t.Logf("native fixture observations: direct=%d proxy=%d service=%d; not router TUN/HIL evidence", directRequests.Load(), proxyRequests.Load(), serviceRequests.Load())
}
