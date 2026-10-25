package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math/big"
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

func fixtureTLS(t *testing.T, name string, handler http.HandlerFunc, local ...string) (*httptest.Server, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	server := httptest.NewUnstartedServer(handler)
	if len(local) == 1 {
		listener, err := net.Listen("tcp4", local[0])
		if err != nil {
			server.Close()
			t.Fatal(err)
		}
		_ = server.Listener.Close()
		server.Listener = listener
	}
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, &tls.Config{RootCAs: pool}
}

type socksFixture struct {
	address       string
	commands      chan string
	connected     chan struct{}
	disconnect    chan struct{}
	finalGreeting chan struct{}
	mu            sync.Mutex
	conns         map[net.Conn]bool
	wg            sync.WaitGroup
}

// No target supplied by the probe is dialed. Every CONNECT is mapped to one
// local TLS fixture, or deliberately stalled to test cancellation.
func fixtureSOCKS(t *testing.T, backend, stall string, mtBackend ...string) *socksFixture {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &socksFixture{address: listener.Addr().String(), commands: make(chan string, 32), connected: make(chan struct{}, 16), disconnect: make(chan struct{}, 16), finalGreeting: make(chan struct{}), conns: map[net.Conn]bool{}}
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		connections := 0
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			connections++
			connectionNumber := connections
			f.mu.Lock()
			f.conns[conn] = true
			f.mu.Unlock()
			f.wg.Add(1)
			go func() {
				defer f.wg.Done()
				defer conn.Close()
				defer func() { f.mu.Lock(); delete(f.conns, conn); f.mu.Unlock() }()
				var greeting [3]byte
				if _, err := io.ReadFull(conn, greeting[:]); err != nil || greeting != [3]byte{5, 1, 0} {
					return
				}
				// A single HTTPS cycle has initial, request, then final greetings.
				if stall == "greeting" || stall == "final_greeting" && connectionNumber == 3 {
					if stall == "final_greeting" {
						close(f.finalGreeting)
					}
					_, _ = io.Copy(io.Discard, conn)
					f.disconnect <- struct{}{}
					return
				}
				if _, err := conn.Write([]byte{5, 0}); err != nil {
					return
				}
				var head [4]byte
				if _, err := io.ReadFull(conn, head[:]); err != nil {
					return // A greeting-only endpoint control.
				}
				if head[0] != 5 || head[1] != 1 || head[2] != 0 {
					return
				}
				var host string
				if head[3] == 3 {
					var length [1]byte
					if _, err := io.ReadFull(conn, length[:]); err != nil {
						return
					}
					name := make([]byte, int(length[0]))
					if _, err := io.ReadFull(conn, name); err != nil {
						return
					}
					host = string(name)
				} else if head[3] == 1 {
					var ip [4]byte
					if _, err := io.ReadFull(conn, ip[:]); err != nil {
						return
					}
					host = netip.AddrFrom4(ip).String()
				} else {
					return
				}
				var port [2]byte
				if _, err := io.ReadFull(conn, port[:]); err != nil {
					return
				}
				f.commands <- net.JoinHostPort(host, strconvPort(port))
				f.connected <- struct{}{}
				if stall == "connect" {
					_, _ = io.Copy(io.Discard, conn)
					f.disconnect <- struct{}{}
					return
				}
				destination := backend
				if len(mtBackend) == 1 && net.JoinHostPort(host, strconvPort(port)) == qaMTEndpoint {
					destination = mtBackend[0]
				}
				remote, err := net.DialTimeout("tcp", destination, time.Second)
				if err != nil {
					return
				}
				defer remote.Close()
				if _, err := conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
					return
				}
				done := make(chan struct{})
				go func() { _, _ = io.Copy(remote, conn); _ = remote.Close(); close(done) }()
				_, _ = io.Copy(conn, remote)
				_ = conn.Close()
				<-done
				f.disconnect <- struct{}{}
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		f.mu.Lock()
		for conn := range f.conns {
			_ = conn.Close()
		}
		f.mu.Unlock()
		f.wg.Wait()
	})
	return f
}

func strconvPort(port [2]byte) string {
	return strconv.Itoa(int(binary.BigEndian.Uint16(port[:])))
}

func fixtureOptions(endpoint string) options {
	o := defaults()
	o.SOCKS, o.Duration, o.ProbeTimeout, o.ControlTimeout = endpoint, 200*time.Millisecond, 100*time.Millisecond, 100*time.Millisecond
	o.Interval = time.Second
	return o
}

func TestHTTPSWindowRetainsSOCKSAndOriginalVerifiedHost(t *testing.T) {
	for _, pinned := range []bool{false, true} {
		hosts := make(chan string, 1)
		server, roots := fixtureTLS(t, telegramHost, func(w http.ResponseWriter, r *http.Request) {
			if r.TLS == nil || r.TLS.ServerName != telegramHost || r.URL.Path != "/" || r.Header.Get("User-Agent") != "RAZVILKA-Telegram-Soak/1" {
				t.Error("original HTTPS identity changed")
			}
			hosts <- r.Host
			_, _ = io.WriteString(w, "Telegram fixture")
		})
		socks := fixtureSOCKS(t, server.Listener.Addr().String(), "")
		o := fixtureOptions(socks.address)
		want := telegramHost + ":443"
		if pinned {
			o.Pin, want = netip.MustParseAddr("8.8.8.8"), "8.8.8.8:443"
		}
		r, err := observe(context.Background(), o, roots)
		if err != nil || r.ExitCode != 0 || !r.WindowCompleted || !r.Initial.OK || !r.Final.OK || r.Attempts != 1 || r.Accepted != 1 || r.Failures != 0 || r.AllLatency.Count != 1 || r.AcceptedLatency.Count != 1 || r.SamplingElapsedSeconds < o.Duration.Seconds() || r.ElapsedSeconds > 1 {
			t.Fatal("bounded HTTPS window failed", r, err)
		}
		select {
		case command := <-socks.commands:
			if command != want {
				t.Fatal("CONNECT target changed", command)
			}
		default:
			t.Fatal("HTTPS bypassed the supplied SOCKS")
		}
		select {
		case host := <-hosts:
			if host != telegramHost {
				t.Fatal("Host changed", host)
			}
		default:
			t.Fatal("verified TLS fixture not reached")
		}
	}
}

func TestHTTPSFailuresRedirectTLSAndBodyAreBoundedAndSanitized(t *testing.T) {
	secret := "vless://UUID:PRIVATE-KEY@private.invalid/"
	for _, mode := range []string{"status", "redirect", "tls", "body", "headers"} {
		t.Run(mode, func(t *testing.T) {
			name := telegramHost
			if mode == "tls" {
				name = "wrong.example"
			}
			server, roots := fixtureTLS(t, name, func(w http.ResponseWriter, _ *http.Request) {
				switch mode {
				case "status":
					w.WriteHeader(http.StatusForbidden)
				case "redirect":
					w.Header().Set("Location", "https://UUID:PRIVATE-KEY@private.invalid/")
					w.WriteHeader(http.StatusFound)
				case "body":
					_, _ = w.Write(bytes.Repeat([]byte("x"), maxBody+1))
				case "headers":
					w.Header().Set("X-Oversize", strings.Repeat("x", 64<<10))
				}
				_, _ = io.WriteString(w, secret)
			})
			socks := fixtureSOCKS(t, server.Listener.Addr().String(), "")
			o := fixtureOptions(socks.address)
			// These cases verify response semantics and sanitization, including
			// transferring maxBody+1 bytes through TLS/SOCKS under the race
			// detector. The short request/control timers are tested separately;
			// they must not win the race against a valid oversized response.
			o.ProbeTimeout, o.ControlTimeout = 2*time.Second, time.Second
			o.Duration, o.Interval = 2200*time.Millisecond, 5*time.Second
			r, err := observe(context.Background(), o, roots)
			wantCode := map[string]string{"status": "http_status", "redirect": "http_status", "tls": "tls_verification", "body": "body_limit", "headers": "transport_failed"}[mode]
			if err != nil || r.ExitCode != 2 || !r.WindowCompleted || r.Accepted != 0 || r.Failures != 1 || r.FailureCodes[wantCode] != 1 || len(socks.commands) != 1 || !r.Final.OK {
				t.Fatal("failure or redirect acquired success", r, err)
			}
			data, err := json.Marshal(r)
			if err != nil || bytes.Contains(data, []byte("UUID")) || bytes.Contains(data, []byte("PRIVATE-KEY")) || bytes.Contains(data, []byte("vless://")) || bytes.Contains(data, []byte("https://")) || r.MTProto != "not_tested_not_requested" || r.Protocol != nil {
				t.Fatal("report leaked raw material or overstated protocol coverage")
			}
		})
	}
}

func TestSOCKSStallCancellationClosesRequestAndSkipsFinalIO(t *testing.T) {
	socks := fixtureSOCKS(t, "", "connect")
	o := fixtureOptions(socks.address)
	o.Duration, o.ProbeTimeout = time.Second, 500*time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type observed struct {
		r report
		e error
	}
	result := make(chan observed, 1)
	go func() { r, err := observe(ctx, o, nil); result <- observed{r, err} }()
	select {
	case <-socks.connected:
	case <-time.After(time.Second):
		t.Fatal("request never reached SOCKS")
	}
	started := time.Now()
	cancel()
	select {
	case got := <-result:
		if got.e != nil || got.r.ExitCode != 130 || got.r.WindowCompleted || got.r.Outcome != "canceled" || got.r.Final.Code != "not_attempted_parent_cancellation" || got.r.FailureCodes["canceled"] != 1 || got.r.Accepted != 0 || len(socks.commands) != 1 {
			t.Fatal("cancellation continued work or claimed completion", got)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("SOCKS cancellation exceeded its local bound")
	}
	select {
	case <-socks.disconnect:
	case <-time.After(300 * time.Millisecond):
		t.Fatal("cancellation left its SOCKS connection open")
	}
	if time.Since(started) > 500*time.Millisecond {
		t.Fatal("cancellation was not bounded")
	}
}

func TestEndpointGreetingTimeoutAndShorterParentDeadline(t *testing.T) {
	socks := fixtureSOCKS(t, "", "greeting")
	o := fixtureOptions(socks.address)
	o.ControlTimeout = 30 * time.Millisecond
	r, err := observe(context.Background(), o, nil)
	if err != nil || r.ExitCode != 1 || r.Initial.OK || r.Initial.Code != "timeout" || r.Attempts != 0 || r.WindowCompleted || r.ElapsedSeconds > 0.3 {
		t.Fatal("endpoint stall escaped its budget", r, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	r, err = observe(ctx, o, nil)
	if err != nil || r.Outcome != "parent_deadline" || r.ExitCode != 1 || r.Attempts != 0 || r.ElapsedSeconds > 0.3 || r.Final.Code != "not_attempted_parent_cancellation" {
		t.Fatal("short parent deadline was extended", r, err)
	}
}

// Models the interval after the absolute deadline but before a context timer
// delivers Done/Err. The socket still observes Deadline independently.
type pendingDeadlineContext struct {
	context.Context
	deadline time.Time
}

func (c pendingDeadlineContext) Deadline() (time.Time, bool) { return c.deadline, true }

func TestEndpointParentDeadlinePrecedesContextTimerDelivery(t *testing.T) {
	socks := fixtureSOCKS(t, "", "greeting")
	o := fixtureOptions(socks.address)
	o.ControlTimeout = 100 * time.Millisecond
	parent := pendingDeadlineContext{context.Background(), time.Now().Add(10 * time.Millisecond)}
	r, err := observe(parent, o, nil)
	if parent.Err() != nil || parent.Done() != nil || time.Now().Before(parent.deadline) {
		t.Fatal("fixture did not retain the pending context notification")
	}
	if err != nil || r.Initial.OK || r.Initial.Code != "timeout" || r.Outcome != "parent_deadline" || r.ExitCode != 1 || r.Attempts != 0 || r.WindowCompleted || r.Final.Code != "not_attempted_parent_cancellation" || r.ElapsedSeconds > 0.3 || len(socks.commands) != 0 {
		t.Fatal("expired parent deadline became an endpoint refusal", r, err)
	}
}

func TestPendingParentDeadlineDoesNotReplaceLocalControlTimeout(t *testing.T) {
	socks := fixtureSOCKS(t, "", "greeting")
	o := fixtureOptions(socks.address)
	o.ControlTimeout = 10 * time.Millisecond
	parent := pendingDeadlineContext{context.Background(), time.Now().Add(time.Hour)}
	r, err := observe(parent, o, nil)
	if err != nil || r.Initial.OK || r.Initial.Code != "timeout" || r.Outcome != "refused" || r.ExitCode != 1 || r.Attempts != 0 || r.WindowCompleted || r.Final.Code != "not_attempted" {
		t.Fatal("local control timeout became a parent deadline", r, err)
	}
}

func TestSamplingWaitHonorsDeadlineBeforeContextTimerDelivery(t *testing.T) {
	parent := pendingDeadlineContext{context.Background(), time.Now()}
	if err := waitUntil(parent, time.Now().Add(time.Hour)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("expired deadline permitted scheduled work", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	parent.Context = canceled
	if err := waitUntil(parent, time.Now()); !errors.Is(err, context.Canceled) {
		t.Fatal("expired deadline replaced explicit cancellation", err)
	}
}

func TestCancellationDuringFinalGreetingPreservesAttemptedControl(t *testing.T) {
	server, roots := fixtureTLS(t, telegramHost, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "Telegram fixture")
	})
	socks := fixtureSOCKS(t, server.Listener.Addr().String(), "final_greeting")
	o := fixtureOptions(socks.address)
	o.ControlTimeout = 500 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type observed struct {
		r   report
		err error
	}
	result := make(chan observed, 1)
	go func() {
		r, err := observe(ctx, o, roots)
		result <- observed{r, err}
	}()
	select {
	case <-socks.finalGreeting:
	case <-time.After(time.Second):
		t.Fatal("final SOCKS greeting never started")
	}
	cancel()
	select {
	case got := <-result:
		r := got.r
		if got.err != nil || r.Outcome != "canceled" || r.ExitCode != 130 || !r.WindowCompleted || !r.Initial.OK || r.Attempts != 1 || r.Accepted != 1 || r.Failures != 0 || r.Final.OK || r.Final.Code != "canceled" || len(socks.commands) != 1 {
			t.Fatal("attempted final control became not attempted", got)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("final SOCKS greeting ignored cancellation")
	}
}

func TestCancellationOfPendingHTTPSNeverCompletesOrStartsAnotherRequest(t *testing.T) {
	requestReceived := make(chan struct{})
	server, roots := fixtureTLS(t, telegramHost, func(_ http.ResponseWriter, r *http.Request) {
		close(requestReceived)
		<-r.Context().Done() // No response: cancellation is strictly in the request.
	})
	socks := fixtureSOCKS(t, server.Listener.Addr().String(), "")
	o := fixtureOptions(socks.address)
	o.Duration = time.Second
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan report, 1)
	go func() {
		r, err := observe(ctx, o, roots)
		if err != nil {
			t.Error(err)
		}
		result <- r
	}()
	select {
	case <-requestReceived:
	case <-time.After(time.Second):
		t.Fatal("HTTPS fixture never received the request")
	}
	cancel()
	select {
	case r := <-result:
		if r.ExitCode != 130 || r.Outcome != "canceled" || r.WindowCompleted || r.Accepted != 0 || r.Attempts != 1 || r.Failures != 1 || r.FailureCodes["canceled"] != 1 || r.Final.OK || len(socks.commands) != 1 {
			t.Fatal("an unfinished canceled request became a completed window", r)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("pending HTTPS ignored cancellation")
	}
}

func TestSamplingWaitReturnsCancellationInsteadOfScheduledWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		close(entered)
		result <- waitUntil(ctx, time.Now().Add(time.Hour))
	}()
	<-entered
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("canceled interval permitted its next scheduled operation", err)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("sampling wait ignored cancellation")
	}
}

func TestHTTPSStallUsesWholeRequestBudget(t *testing.T) {
	server, roots := fixtureTLS(t, telegramHost, func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	socks := fixtureSOCKS(t, server.Listener.Addr().String(), "")
	r, err := observe(context.Background(), fixtureOptions(socks.address), roots)
	if err != nil || r.ExitCode != 2 || !r.WindowCompleted || r.Attempts != 1 || r.FailureCodes["timeout"] != 1 || r.Accepted != 0 || !r.Final.OK || r.ElapsedSeconds > 0.8 {
		t.Fatal("HTTPS response stall escaped request/window budgets", r, err)
	}
}

func TestOptionsRefuseRemoteAuthUnboundedValuesAndSecretEcho(t *testing.T) {
	for _, args := range [][]string{
		{"-socks", "vless://UUID:PRIVATE-KEY@private.invalid/"}, {"-socks", "localhost:1080"}, {"-socks", "192.168.1.1:1080"},
		{"-socks", "127.0.0.1:1080", "-duration", "2h"}, {"-socks", "127.0.0.1:1080", "-interval", "0s"},
		{"-socks", "127.0.0.1:1080", "-probe-timeout", "0s"}, {"-socks", "127.0.0.1:1080", "-control-timeout", "1h"},
		{"-socks", "127.0.0.1:1080", "-telegram-ip", "127.0.0.1"}, {"-socks", "127.0.0.1:1080", "-duration", "PRIVATE-KEY"},
		{"-socks", "127.0.0.1:1080", "-duration", "10s"}, {"-socks", "127.0.0.1:1080", "-duration", "13s", "-mtproto"},
	} {
		_, help, err := parseOptions(args)
		if err == nil || help || err.Error() != "invalid options" {
			t.Fatal("invalid option accepted or echoed", err)
		}
	}
	o, help, err := parseOptions([]string{"-socks", "[::1]:1080"})
	if err != nil || help || o.Duration != time.Hour || o.Interval != 30*time.Second {
		t.Fatal("finite defaults changed", o, err)
	}
	_, help, err = parseOptions([]string{"-help"})
	if err != nil || !help {
		t.Fatal("help unavailable")
	}
	var text bytes.Buffer
	usage(&text)
	if !strings.Contains(text.String(), "MTProto") || !strings.Contains(text.String(), "Exit 2") {
		t.Fatal("scope or exit semantics missing from instructions")
	}
}

func TestLatencyNearestRankAndEmptyAggregate(t *testing.T) {
	got := summarize([]float64{50, 10, 30, 20, 40})
	if got.Count != 5 || got.MinMS != 10 || got.MeanMS != 30 || got.P50MS != 30 || got.P95MS != 50 || got.MaxMS != 50 || summarize(nil) != (latency{}) {
		t.Fatal("latency aggregates incorrect", got)
	}
}
