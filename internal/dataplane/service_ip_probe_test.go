package dataplane

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type pinnedSOCKSRequest struct {
	AddressType byte
	Host        string
	Port        int
}

type pinnedSOCKSFixture struct {
	address  string
	requests chan pinnedSOCKSRequest
}

// All sockets are local. The real SOCKS handshake records a public literal
// CONNECT target, then the fixture maps it to its private TLS test server.
func newPinnedSOCKSFixture(t *testing.T, backend string, reject bool) pinnedSOCKSFixture {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	requests := make(chan pinnedSOCKSRequest, 16)
	var mu sync.Mutex
	connections := map[net.Conn]bool{}
	closed := false
	track := func(conn net.Conn) bool {
		mu.Lock()
		defer mu.Unlock()
		if closed {
			_ = conn.Close()
			return false
		}
		connections[conn] = true
		return true
	}
	t.Cleanup(func() {
		_ = listener.Close()
		mu.Lock()
		defer mu.Unlock()
		closed = true
		for conn := range connections {
			_ = conn.Close()
		}
	})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			if !track(conn) {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				greeting := make([]byte, 2)
				if _, err := io.ReadFull(conn, greeting); err != nil || greeting[0] != 5 {
					return
				}
				if _, err := io.CopyN(io.Discard, conn, int64(greeting[1])); err != nil {
					return
				}
				if _, err := conn.Write([]byte{5, 0}); err != nil {
					return
				}
				header := make([]byte, 4)
				if _, err := io.ReadFull(conn, header); err != nil || header[0] != 5 || header[1] != 1 {
					return
				}
				var host string
				switch header[3] {
				case 1, 4:
					length := 4
					if header[3] == 4 {
						length = 16
					}
					data := make([]byte, length)
					if _, err := io.ReadFull(conn, data); err != nil {
						return
					}
					host = net.IP(data).String()
				case 3:
					length := make([]byte, 1)
					if _, err := io.ReadFull(conn, length); err != nil {
						return
					}
					data := make([]byte, int(length[0]))
					if _, err := io.ReadFull(conn, data); err != nil {
						return
					}
					host = string(data)
				default:
					return
				}
				port := make([]byte, 2)
				if _, err := io.ReadFull(conn, port); err != nil {
					return
				}
				requests <- pinnedSOCKSRequest{header[3], host, int(binary.BigEndian.Uint16(port))}
				if reject {
					_, _ = conn.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				upstream, err := net.DialTimeout("tcp", backend, time.Second)
				if err != nil || !track(upstream) {
					return
				}
				defer upstream.Close()
				if _, err := conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
					return
				}
				_ = conn.SetDeadline(time.Time{})
				go func() { _, _ = io.Copy(upstream, conn); _ = upstream.Close() }()
				_, _ = io.Copy(conn, upstream)
			}()
		}
	}()
	return pinnedSOCKSFixture{listener.Addr().String(), requests}
}

func newPinnedTLSFixture(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *tls.Config, <-chan string) {
	t.Helper()
	serverNames := make(chan string, 16)
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		serverNames <- hello.ServerName
		return nil, nil
	}}
	server.StartTLS()
	t.Cleanup(server.Close)
	if err := server.Certificate().VerifyHostname("example.com"); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	return server, &tls.Config{RootCAs: roots}, serverNames
}

func TestPinnedServiceSOCKSUsesLiteralIPv4WithOriginalTLSAndHost(t *testing.T) {
	hosts := make(chan string, 1)
	backend, roots, serverNames := newPinnedTLSFixture(t, func(w http.ResponseWriter, r *http.Request) {
		hosts <- r.Host
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "service reached")
	})
	socks := newPinnedSOCKSFixture(t, backend.Listener.Addr().String(), false)
	response, cleanup, err := socksHTTPGetPinnedTLS(context.Background(), "https://example.com/health?q=original", socks.address, netip.MustParseAddr("1.1.1.1"), roots)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	defer response.Body.Close()
	if _, err := strictServiceResponse("https://example.com/health?q=original", response); err != nil {
		t.Fatal(err)
	}
	request := <-socks.requests
	if request.AddressType != 1 || request.Host != "1.1.1.1" || request.Port != 443 {
		t.Fatalf("SOCKS CONNECT did not pin IP: %+v", request)
	}
	if host, sni := <-hosts, <-serverNames; host != "example.com" || sni != "example.com" {
		t.Fatalf("Host=%q SNI=%q", host, sni)
	}
	if response.Request.URL.String() != "https://example.com/health?q=original" {
		t.Fatal("request URL was replaced by its transport IP")
	}
}

func TestPinnedServiceFailureCannotFallbackToHostnameOrDirect(t *testing.T) {
	socks := newPinnedSOCKSFixture(t, "", true)
	response, cleanup, err := socksHTTPGetPinned(context.Background(), "https://example.com/?token=private-fixture", socks.address, netip.MustParseAddr("1.1.1.1"))
	if err == nil || response != nil || cleanup != nil {
		t.Fatalf("failed literal CONNECT was accepted: response=%v err=%v", response, err)
	}
	if strings.Contains(err.Error(), "private-fixture") {
		t.Fatal("request query leaked in the error")
	}
	request := <-socks.requests
	if request.AddressType != 1 || request.Host != "1.1.1.1" || len(socks.requests) != 0 {
		t.Fatalf("literal failure caused another target attempt: %+v", request)
	}
}

func TestPinnedServiceRejectsUnknownPrivateMappedAndIPv6Pins(t *testing.T) {
	for _, value := range []string{"", "127.0.0.1", "10.0.0.1", "100.64.0.1", "169.254.1.1", "192.0.2.1", "::ffff:1.1.1.1", "2606:4700::1111"} {
		t.Run(value, func(t *testing.T) {
			pin, _ := netip.ParseAddr(value)
			if _, _, err := socksHTTPGetPinned(context.Background(), "https://example.com", "127.0.0.1:1", pin); err == nil {
				t.Fatal("unsupported or unsafe pin accepted")
			}
		})
	}
	for _, raw := range []string{"http://example.com", "https://user:secret@example.com", "https://example.com:8443", "https://localhost", "https://127.0.0.1", "https://8.8.8.8"} {
		if _, _, err := socksHTTPGetPinned(context.Background(), raw, "127.0.0.1:1", netip.MustParseAddr("1.1.1.1")); err == nil {
			t.Fatalf("unsafe URL accepted: %s", raw)
		}
	}
}

func TestPinnedServiceKeepsCertificateVerification(t *testing.T) {
	backend, _, names := newPinnedTLSFixture(t, func(http.ResponseWriter, *http.Request) { t.Error("untrusted certificate reached HTTP") })
	socks := newPinnedSOCKSFixture(t, backend.Listener.Addr().String(), false)
	_, _, err := socksHTTPGetPinned(context.Background(), "https://example.com", socks.address, netip.MustParseAddr("1.1.1.1"))
	var certificate *tls.CertificateVerificationError
	if !errors.As(err, &certificate) {
		t.Fatalf("TLS verification failure was not preserved: %v", err)
	}
	if name := <-names; name != "example.com" {
		t.Fatalf("untrusted handshake used wrong SNI: %q", name)
	}
}

func TestPinnedServiceRedirectCannotChangeHostOrAddressForm(t *testing.T) {
	for _, location := range []string{"https://sub.example.com/final", "https://1.1.1.1/final", "http://example.com/final", "https://example.com:8443/final"} {
		t.Run(location, func(t *testing.T) {
			backend, roots, _ := newPinnedTLSFixture(t, func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, location, http.StatusFound) })
			socks := newPinnedSOCKSFixture(t, backend.Listener.Addr().String(), false)
			if _, _, err := socksHTTPGetPinnedTLS(context.Background(), "https://example.com", socks.address, netip.MustParseAddr("1.1.1.1"), roots); err == nil {
				t.Fatal("cross-origin redirect accepted")
			}
			request := <-socks.requests
			if request.AddressType != 1 || len(socks.requests) != 0 {
				t.Fatal("redirect triggered a different SOCKS destination")
			}
		})
	}
}

func TestPinnedServiceSameOriginRedirectRetainsPinAndResponseSemantics(t *testing.T) {
	backend, roots, _ := newPinnedTLSFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusForbidden)
	})
	socks := newPinnedSOCKSFixture(t, backend.Listener.Addr().String(), false)
	response, cleanup, err := socksHTTPGetPinnedTLS(context.Background(), "https://example.com", socks.address, netip.MustParseAddr("1.1.1.1"), roots)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	defer response.Body.Close()
	if response.Request.URL.String() != "https://example.com/final" || response.StatusCode != http.StatusForbidden {
		t.Fatal("response semantics were replaced")
	}
	if _, err := strictServiceResponse("https://example.com", response); err == nil {
		t.Fatal("a pinned transport was treated as accepted blocked content")
	}
	for len(socks.requests) > 0 {
		if request := <-socks.requests; request.AddressType != 1 || request.Host != "1.1.1.1" {
			t.Fatalf("redirect changed pin: %+v", request)
		}
	}
}

func TestPinnedServiceCancellationClosesStalledSOCKSHandshake(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	closed := make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, _ = io.Copy(io.Discard, conn) // Never acknowledge the SOCKS greeting.
		close(closed)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, _, err = socksHTTPGetPinned(ctx, "https://example.com", listener.Addr().String(), netip.MustParseAddr("1.1.1.1"))
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > time.Second {
		t.Fatalf("cancellation was not bounded: %v", err)
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("cancelled handshake retained its socket")
	}
}

func TestPinnedServiceRejectsNonlocalProxyAndDisabledTLSVerification(t *testing.T) {
	for _, address := range []string{"example.com:1080", "1.1.1.1:1080", "127.0.0.1:0", "127.0.0.1:" + strconv.Itoa(65536)} {
		if _, _, err := socksHTTPGetPinned(context.Background(), "https://example.com", address, netip.MustParseAddr("1.1.1.1")); err == nil {
			t.Fatalf("nonlocal/invalid proxy endpoint accepted: %s", address)
		}
	}
	if _, _, err := socksHTTPGetPinnedTLS(context.Background(), "https://example.com", "127.0.0.1:1080", netip.MustParseAddr("1.1.1.1"), &tls.Config{InsecureSkipVerify: true}); err == nil {
		t.Fatal("certificate verification could be disabled")
	}
}
