package usquediag

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
)

func localTransportCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "cloud-harness.invalid"}, DNSNames: []string{"cloud-harness.invalid"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, roots
}

func nativeProofHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || r.URL.Path != "/proof" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	proof := TransportChallengeResponse(r.Header.Get(TransportChallengeHeader))
	if proof == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	_, _ = io.WriteString(w, proof)
}

// This opt-in fixture exercises real localhost TCP/TLS/H2 and UDP/QUIC/H3 with
// an ephemeral trusted certificate. It never calls a WARP API or starts USQUE.
func TestNativeLocalCloudTransportHarness(t *testing.T) {
	if os.Getenv("RAZVILKA_NATIVE_CLOUD_TRANSPORT") != "1" {
		t.Skip("requires explicit localhost native transport opt-in")
	}
	certificate, roots := localTransportCertificate(t)
	environmentID := strings.Repeat("a", 64)
	environment := func(context.Context) (string, error) { return environmentID, nil }
	h2 := httptest.NewUnstartedServer(http.HandlerFunc(nativeProofHandler))
	h2.EnableHTTP2 = true
	h2.Config.ErrorLog = log.New(io.Discard, "", 0)
	h2.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
	h2.StartTLS()
	t.Cleanup(h2.Close)
	h2Endpoint, err := netip.ParseAddrPort(h2.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	options := TransportProbeOptions{Enabled: true, AllowLoopback: true, URL: "https://cloud-harness.invalid:" + strconv.Itoa(int(h2Endpoint.Port())) + "/proof", Endpoint: h2Endpoint, Transport: "HTTP/2", RootCAs: roots, Environment: environment, Timeout: time.Second}
	t.Run("H2-success-without-UDP-proof", func(t *testing.T) {
		proof, err := ProbeNativeTransport(context.Background(), options)
		if err != nil || !proof.HTTP2 || proof.HTTP3 || proof.QUICUDP || !proof.Fresh(time.Now(), h2Endpoint, environmentID) {
			t.Fatal("H2 proof", proof, err)
		}
		if proof.Fresh(time.Now(), h2Endpoint, strings.Repeat("b", 64)) || proof.Fresh(proof.ValidUntil, h2Endpoint, environmentID) {
			t.Fatal("stale/environment proof accepted")
		}
		mutated := proof
		mutated.HTTP3, mutated.QUICUDP = true, true
		if mutated.Fresh(time.Now(), h2Endpoint, environmentID) {
			t.Fatal("modified result became H3 proof")
		}
		encoded, _ := json.Marshal(proof)
		var restored TransportProbeEvidence
		if err := json.Unmarshal(encoded, &restored); err != nil {
			t.Fatal(err)
		}
		if restored.Fresh(time.Now(), h2Endpoint, environmentID) {
			t.Fatal("serialized diagnostics gained native authority")
		}
	})
	t.Run("H2-available-H3-UDP-blackhole", func(t *testing.T) {
		// Reserve UDP on the same loopback tuple as the H2 TCP server; no QUIC
		// server reads it. A successful TCP socket cannot complete HTTP/3 here.
		blackhole, err := net.ListenPacket("udp4", h2Endpoint.String())
		if err != nil {
			t.Fatal(err)
		}
		defer blackhole.Close()
		probe := options
		probe.Transport, probe.Timeout = "HTTP/3", 300*time.Millisecond
		proof, err := ProbeNativeTransport(context.Background(), probe)
		if err == nil || proof.HTTP3 || proof.QUICUDP || proof.verified {
			t.Fatal("TCP promoted to H3/UDP", proof, err)
		}
	})
	t.Run("TLS-trust-and-name-enforced", func(t *testing.T) {
		for _, mismatch := range []string{"trust", "name"} {
			probe := options
			if mismatch == "trust" {
				probe.RootCAs = x509.NewCertPool()
			} else {
				probe.URL = strings.Replace(probe.URL, "cloud-harness.invalid", "wrong.invalid", 1)
			}
			if proof, err := ProbeNativeTransport(context.Background(), probe); err == nil || proof.verified {
				t.Fatal("TLS mismatch accepted", mismatch)
			}
		}
	})
	t.Run("generic-H1-does-not-confirm-H2", func(t *testing.T) {
		server := httptest.NewUnstartedServer(http.HandlerFunc(nativeProofHandler))
		server.Config.ErrorLog = log.New(io.Discard, "", 0)
		server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: []string{"http/1.1"}}
		server.StartTLS()
		defer server.Close()
		endpoint, _ := netip.ParseAddrPort(server.Listener.Addr().String())
		probe := options
		probe.Endpoint = endpoint
		probe.URL = "https://cloud-harness.invalid:" + strconv.Itoa(int(endpoint.Port())) + "/proof"
		if proof, err := ProbeNativeTransport(context.Background(), probe); err == nil || proof.verified {
			t.Fatal("HTTP/1 promoted to HTTP/2")
		}
	})
	t.Run("H3-native-proof-and-env-change", func(t *testing.T) {
		packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		server := &http3.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13}, Handler: http.HandlerFunc(nativeProofHandler)}
		done := make(chan error, 1)
		go func() { done <- server.Serve(packet) }()
		defer func() {
			server.Close()
			packet.Close()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("H3 server did not stop")
			}
		}()
		endpoint, _ := netip.ParseAddrPort(packet.LocalAddr().String())
		probe := options
		probe.Transport, probe.Endpoint = "HTTP/3", endpoint
		probe.URL = "https://cloud-harness.invalid:" + strconv.Itoa(int(endpoint.Port())) + "/proof"
		proof, err := ProbeNativeTransport(context.Background(), probe)
		if err != nil || proof.HTTP2 || !proof.HTTP3 || !proof.QUICUDP || !proof.Fresh(time.Now(), endpoint, environmentID) {
			t.Fatal("H3 proof", proof, err)
		}
		calls := 0
		probe.Environment = func(context.Context) (string, error) {
			calls++
			if calls == 1 {
				return environmentID, nil
			}
			return strings.Repeat("b", 64), nil
		}
		if changed, err := ProbeNativeTransport(context.Background(), probe); err == nil || changed.verified {
			t.Fatal("environment changed during proof")
		}
	})
	t.Run("wrong-body-redirect-errors-withhold-secrets", func(t *testing.T) {
		for _, redirect := range []bool{false, true} {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if redirect {
					w.Header().Set("Location", "https://private-token-marker.invalid/")
					w.WriteHeader(http.StatusFound)
					return
				}
				_, _ = io.WriteString(w, "private-token-marker")
			}))
			server.EnableHTTP2 = true
			server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}}
			server.StartTLS()
			endpoint, _ := netip.ParseAddrPort(server.Listener.Addr().String())
			probe := options
			probe.Endpoint, probe.URL = endpoint, "https://cloud-harness.invalid:"+strconv.Itoa(int(endpoint.Port()))+"/proof"
			result, err := ProbeNativeTransport(context.Background(), probe)
			server.Close()
			if err == nil || result.verified || strings.Contains(err.Error(), "private-") {
				t.Fatal("untrusted body/redirect became proof or leaked")
			}
		}
	})
	t.Run("oversized-proof-and-cancelled-stream-cleanup", func(t *testing.T) {
		for _, streaming := range []bool{false, true} {
			closed := make(chan struct{}, 1)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !streaming {
					_, _ = io.WriteString(w, TransportChallengeResponse(r.Header.Get(TransportChallengeHeader))+strings.Repeat(" ", 512))
					return
				}
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				<-r.Context().Done()
			}))
			server.EnableHTTP2 = true
			server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}}
			server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateClosed {
					select {
					case closed <- struct{}{}:
					default:
					}
				}
			}
			server.StartTLS()
			endpoint, _ := netip.ParseAddrPort(server.Listener.Addr().String())
			probe := options
			probe.Endpoint, probe.URL, probe.Timeout = endpoint, "https://cloud-harness.invalid:"+strconv.Itoa(int(endpoint.Port()))+"/proof", 250*time.Millisecond
			result, err := ProbeNativeTransport(context.Background(), probe)
			if err == nil || result.verified {
				server.Close()
				t.Fatal("oversized/unfinished response accepted")
			}
			select {
			case <-closed:
			case <-time.After(2 * time.Second):
				server.Close()
				t.Fatal("cancelled H2 socket was retained")
			}
			server.Close()
		}
	})
}
