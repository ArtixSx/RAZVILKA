package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/evidence"
)

// holdingListener serves every accepted connection with serve and closes
// whatever is still open when the test ends. Everything stays on loopback.
func holdingListener(t *testing.T, serve func(net.Conn)) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	closed := false
	connections := []net.Conn{}
	t.Cleanup(func() {
		_ = listener.Close()
		mu.Lock()
		defer mu.Unlock()
		closed = true
		for _, conn := range connections {
			_ = conn.Close()
		}
	})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			if closed {
				mu.Unlock()
				_ = conn.Close()
				return
			}
			connections = append(connections, conn)
			mu.Unlock()
			go serve(conn)
		}
	}()
	return listener.Addr().String()
}

// A peer that accepts TCP and never answers a byte.
func silentPeer(conn net.Conn) { _, _ = io.Copy(io.Discard, conn) }

// stalledSOCKS answers the SOCKS greeting and reads CONNECT, then relays
// nothing. With ack it reports success first, as Xray does before it dials
// the node; without, it never answers, as Sing-box 1.11+ does while its own
// connection to the node hangs.
func stalledSOCKS(ack bool) func(net.Conn) {
	return func(conn net.Conn) {
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
		if _, err := io.ReadFull(conn, header); err != nil || header[3] != 1 {
			return
		}
		if _, err := io.CopyN(io.Discard, conn, 4+2); err != nil {
			return
		}
		if ack {
			if _, err := conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
				return
			}
		}
		silentPeer(conn)
	}
}

type privateTimeoutError struct{}

func (privateTimeoutError) Error() string   { return "private-profile-marker i/o timeout" }
func (privateTimeoutError) Timeout() bool   { return true }
func (privateTimeoutError) Temporary() bool { return true }

func directProbe(address string) nodeEgressHTTP {
	return nodeEgressHTTP{dial: func(ctx context.Context, network, target string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", address)
	}}
}

var stageEndpoint = nodeEgressEndpoint{url: "https://example.com/", pinned: netip.MustParseAddr("1.1.1.1")}

func TestNodeEgressTimeoutNamesTheStalledStage(t *testing.T) {
	stalledHeaders := func(t *testing.T) nodeEgressHTTP {
		server, roots, _ := newPinnedTLSFixture(t, func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
		probe := directProbe(server.Listener.Addr().String())
		probe.roots = roots.RootCAs
		return probe
	}
	cases := []struct {
		name, want string
		deadline   time.Duration
		setup      func(*testing.T) (nodeEgressHTTP, string)
	}{
		{"dial-stalled", "dial_timeout", 300 * time.Millisecond, func(*testing.T) (nodeEgressHTTP, string) {
			return nodeEgressHTTP{dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
				<-ctx.Done()
				return nil, errors.New("private-profile-marker dial aborted")
			}}, ""
		}},
		{"dialer-timed-out", "dial_timeout", 5 * time.Second, func(*testing.T) (nodeEgressHTTP, string) {
			return nodeEgressHTTP{dial: func(context.Context, string, string) (net.Conn, error) {
				return nil, &net.OpError{Op: "dial", Net: "tcp", Err: privateTimeoutError{}}
			}}, ""
		}},
		{"socks-connect-unanswered", "dial_timeout", 500 * time.Millisecond, func(t *testing.T) (nodeEgressHTTP, string) {
			return nodeEgressHTTP{}, holdingListener(t, stalledSOCKS(false))
		}},
		{"accept-then-silent", "tls_timeout", 500 * time.Millisecond, func(t *testing.T) (nodeEgressHTTP, string) {
			return directProbe(holdingListener(t, silentPeer)), ""
		}},
		{"socks-accepted-then-silent", "tls_timeout", 500 * time.Millisecond, func(t *testing.T) (nodeEgressHTTP, string) {
			return nodeEgressHTTP{}, holdingListener(t, stalledSOCKS(true))
		}},
		// The transport's own 3 s handshake and header timers, not a deadline.
		{"tls-handshake-timer", "tls_timeout", 10 * time.Second, func(t *testing.T) (nodeEgressHTTP, string) {
			return directProbe(holdingListener(t, silentPeer)), ""
		}},
		{"header-timer", "response_timeout", 10 * time.Second, func(t *testing.T) (nodeEgressHTTP, string) {
			return stalledHeaders(t), ""
		}},
		{"header-stall", "response_timeout", 500 * time.Millisecond, func(t *testing.T) (nodeEgressHTTP, string) {
			return stalledHeaders(t), ""
		}},
		{"body-stall", "response_timeout", 500 * time.Millisecond, func(t *testing.T) (nodeEgressHTTP, string) {
			server, roots, _ := newPinnedTLSFixture(t, func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, "ip=")
				w.(http.Flusher).Flush()
				<-r.Context().Done()
			})
			probe := directProbe(server.Listener.Addr().String())
			probe.roots = roots.RootCAs
			return probe, ""
		}},
		{"eof-after-accept", "tls_handshake", 5 * time.Second, func(t *testing.T) (nodeEgressHTTP, string) {
			return directProbe(holdingListener(t, func(conn net.Conn) { _ = conn.Close() })), ""
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			probe, proxy := tc.setup(t)
			ctx, cancel := context.WithTimeout(context.Background(), tc.deadline)
			defer cancel()
			ip, err := probe.get(ctx, stageEndpoint, proxy)
			if ip != "" || nodeEgressErrorCategory(err) != tc.want || strings.Contains(fmt.Sprint(err), "private-profile-marker") {
				t.Fatalf("ip=%q category=%s err=%v", ip, nodeEgressErrorCategory(err), err)
			}
		})
	}
	t.Run("canceled-is-not-a-stage", func(t *testing.T) {
		t.Parallel()
		probe := stalledHeaders(t)
		ctx, cancel := context.WithCancel(context.Background())
		timer := time.AfterFunc(200*time.Millisecond, cancel)
		defer timer.Stop()
		if _, err := probe.get(ctx, stageEndpoint, ""); !errors.Is(err, context.Canceled) || nodeEgressErrorCategory(err) != "canceled" {
			t.Fatalf("cancellation was explained as a node stage: %v", err)
		}
	})
}

// The attempt deadline used to override every stage get had named with the
// bare "timeout". Exercise the real HTTP stack under a short attempt limit.
func TestNodeEgressAttemptDeadlineKeepsTheStageFromGet(t *testing.T) {
	cases := []struct {
		name, want string
		setup      func(*testing.T) (nodeEgressHTTP, string)
	}{
		{"socks-connect-unanswered", "dial_timeout", func(t *testing.T) (nodeEgressHTTP, string) {
			return nodeEgressHTTP{}, holdingListener(t, stalledSOCKS(false))
		}},
		{"socks-accepted-then-silent", "tls_timeout", func(t *testing.T) (nodeEgressHTTP, string) {
			return nodeEgressHTTP{}, holdingListener(t, stalledSOCKS(true))
		}},
		{"accept-then-silent", "tls_timeout", func(t *testing.T) (nodeEgressHTTP, string) {
			return directProbe(holdingListener(t, silentPeer)), ""
		}},
		{"header-stall", "response_timeout", func(t *testing.T) (nodeEgressHTTP, string) {
			server, roots, _ := newPinnedTLSFixture(t, func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
			probe := directProbe(server.Listener.Addr().String())
			probe.roots = roots.RootCAs
			return probe, ""
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			probe, proxy := tc.setup(t)
			ip, err := measureNodeEgress(context.Background(), probe.get, stageEndpoint, proxy, 300*time.Millisecond)
			if ip != "" || nodeEgressErrorCategory(err) != tc.want {
				t.Fatalf("ip=%q category=%s err=%v", ip, nodeEgressErrorCategory(err), err)
			}
		})
	}
}

func TestNodeEgressAttemptDeadlineKeepsRefusalsAndCancellation(t *testing.T) {
	stalled := func(result string, err error) nodeEgressGetter {
		return func(ctx context.Context, _ nodeEgressEndpoint, _ string) (string, error) {
			<-ctx.Done()
			return result, err
		}
	}
	for _, stage := range []string{"dial_timeout", "tls_timeout", "response_timeout", "socks_connect", "http_transport"} {
		ip, err := measureNodeEgress(context.Background(), stalled("", nodeEgressFailure(stage)), stageEndpoint, "127.0.0.1:1080", 50*time.Millisecond)
		if ip != "" || nodeEgressErrorCategory(err) != stage {
			t.Fatalf("stage %s was replaced by the deadline: %v", stage, err)
		}
	}
	// Without a stage from get the result is exactly the former one.
	for _, late := range []struct {
		ip  string
		err error
	}{{"", context.DeadlineExceeded}, {"", errors.New("private-profile-marker")}, {"", nodeEgressFailure("timeout")}, {"8.8.8.8", nil}} {
		ip, err := measureNodeEgress(context.Background(), stalled(late.ip, late.err), stageEndpoint, "", 50*time.Millisecond)
		if ip != "" || !errors.Is(err, context.DeadlineExceeded) || nodeEgressErrorCategory(err) != "timeout" || strings.Contains(fmt.Sprint(err), "private-profile-marker") {
			t.Fatalf("late result %+v became %q %v", late, ip, err)
		}
	}
	parent, cancel := context.WithCancel(context.Background())
	timer := time.AfterFunc(20*time.Millisecond, cancel)
	defer timer.Stop()
	if _, err := measureNodeEgress(parent, stalled("", nodeEgressFailure("tls_timeout")), stageEndpoint, "", time.Minute); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation was explained as a node stage: %v", err)
	}
	// A refusal made before the deadline still wins over the stage.
	guarded := WithNodeResourceGuard(context.Background(), func(_ context.Context, host string, _ netip.Addr) error {
		if host == "refused.example" {
			return errors.New("refused")
		}
		return nil
	})
	refuseThenStall := func(ctx context.Context, _ nodeEgressEndpoint, _ string) (string, error) {
		_ = checkNodeResource(ctx, "refused.example", netip.Addr{})
		<-ctx.Done()
		return "", nodeEgressFailure("tls_timeout")
	}
	if _, err := measureNodeEgress(guarded, refuseThenStall, stageEndpoint, "", 50*time.Millisecond); !errors.Is(err, ErrNodeResourceDenied) {
		t.Fatalf("refusal was hidden by a timeout stage: %v", err)
	}
}

func TestNodeEgressTimeoutMessagesAreEngineAwareAndClosed(t *testing.T) {
	const prefix = "Точный выход через узел не подтвердился."
	categories := []string{"socks_connect", "tcp_connect", "tls_handshake", "certificate", "http_status", "timeout", "body_parse", "http_transport", "dial_timeout", "tls_timeout", "response_timeout"}
	for _, engine := range []string{"sing-box", "xray", ""} {
		seen := map[string]string{}
		for _, category := range categories {
			message := nodeEgressFailureMessage(category, engine)
			if !strings.HasPrefix(message, prefix+" ") || !validStoredCheckMessage(message) {
				t.Fatalf("%s/%s: unusable message %q", engine, category, message)
			}
			// The checker never observes the engine's own connect to the node.
			if strings.Contains(strings.ToLower(message), "tcp") {
				t.Fatalf("%s/%s: message claims a TCP stage: %q", engine, category, message)
			}
			if other, ok := seen[message]; ok {
				t.Fatalf("%s: %s and %s share one message", engine, other, category)
			}
			seen[message] = category
		}
	}
	if !strings.Contains(nodeEgressFailureMessage("dial_timeout", "xray"), "Xray") ||
		nodeEgressFailureMessage("dial_timeout", "sing-box") == nodeEgressFailureMessage("dial_timeout", "xray") ||
		nodeEgressFailureMessage("tls_timeout", "sing-box") == nodeEgressFailureMessage("tls_timeout", "xray") {
		t.Fatal("timeout wording ignores what the engine's CONNECT answer covers")
	}
	for _, category := range []string{"dial_timeout", "tls_timeout", "response_timeout"} {
		xray := fakeExactXrayChecker(t)
		xray.proxyEgress = func(context.Context, string) (string, error) { return "", nodeEgressFailure(category) }
		result, err := xray.Check(context.Background(), xrayCheckedRequest())
		if err != nil || result.ErrorCode != "node-egress-failed" || result.ProxyEgressError != category || result.Message != nodeEgressFailureMessage(category, "xray") {
			t.Fatalf("Xray check lost its engine wording: %+v %v", result, err)
		}
	}
}

// validStoredCheckMessage mirrors the NodeStore limits for a check message.
func validStoredCheckMessage(message string) bool {
	if !utf8.ValidString(message) || utf8.RuneCountInString(message) > 240 || strings.TrimSpace(message) != message {
		return false
	}
	for _, char := range message {
		if unicode.IsControl(char) {
			return false
		}
	}
	return true
}

func TestNodeServiceStageCategoriesFromLocalSOCKS(t *testing.T) {
	cases := []struct {
		name, code, category string
		deadline             time.Duration
		expect               catalog.ProbeExpectation
		handler              http.HandlerFunc
	}{
		{"header-stall", "request-failed", "service_timeout", 500 * time.Millisecond, catalog.ProbeExpectation{}, func(w http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
		}},
		{"connection-dropped", "request-failed", "service_transport", 5 * time.Second, catalog.ProbeExpectation{}, func(w http.ResponseWriter, r *http.Request) {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
		}},
		{"body-stall", "response-body-invalid", "service_timeout", 500 * time.Millisecond, catalog.ProbeExpectation{}, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, "<html>partial")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		}},
		{"body-interrupted", "response-body-invalid", "service_transport", 5 * time.Second, catalog.ProbeExpectation{}, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("Content-Length", "100")
			_, _ = io.WriteString(w, "<html>partial")
		}},
		{"forbidden", "http-403", "service_status_mismatch", 5 * time.Second, catalog.ProbeExpectation{}, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusForbidden)
		}},
		{"unexpected-status", "unexpected-http-status", "service_status_mismatch", 5 * time.Second, catalog.ProbeExpectation{StatusCodes: []int{204}}, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, "<html>service</html>")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(tc.handler)
			t.Cleanup(server.Close)
			proxy := newPinnedSOCKSFixture(t, server.Listener.Addr().String(), false)
			service := catalog.Service{ID: "discord", ProbeURL: "http://service.example/", Domains: []string{"service.example"}}
			service.Probes = []catalog.Probe{{URL: service.ProbeURL, Required: true, Expect: tc.expect}}
			ctx, cancel := context.WithTimeout(context.Background(), tc.deadline)
			defer cancel()
			probeCtx, failure := withNodeServiceFailure(ctx)
			proof, err := (&ExactNodeChecker{}).probeService(probeCtx, proxy.address, "sing-box:test", "8.8.8.8", service)
			if err != nil || !proof.Valid() || proof.ErrorCode != tc.code || proof.Verdict == evidence.VerdictPass || proof.Outcome == evidence.OutcomeServiceAccepted {
				t.Fatalf("service evidence changed: %+v err=%v", proof, err)
			}
			if got := nodeServiceFailureCategory(proof, failure); got != tc.category {
				t.Fatalf("category=%q want %q (proof=%+v)", got, tc.category, proof)
			}
		})
	}
}

func TestNodeServiceFailureKeepsOnlyClosedObservations(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{nil, ""},
		{context.Canceled, ""},
		{errors.Join(ErrNodeResourceDenied, context.DeadlineExceeded), ""},
		{fmt.Errorf("pinned service request failed: %w", context.DeadlineExceeded), "service_timeout"},
		{&net.OpError{Op: "read", Err: privateTimeoutError{}}, "service_timeout"},
		{fmt.Errorf("pinned service request failed: %w", io.ErrUnexpectedEOF), "service_transport"},
		{errors.New("private-profile-marker https://user:secret@private.example/"), "service_transport"},
	}
	for _, tc := range cases {
		ctx, failure := withNodeServiceFailure(context.Background())
		reportNodeServiceFailure(ctx, tc.err)
		if failure.category != tc.want {
			t.Fatalf("%v: category=%q want %q", tc.err, failure.category, tc.want)
		}
	}
	reportNodeServiceFailure(context.Background(), context.DeadlineExceeded) // no receiver: nothing to record
	if nodeServiceFailureMessage("База.", "private-profile-marker") != "База." || nodeServiceFailureMessage("База.", "") != "База." {
		t.Fatal("unknown service category reached the message")
	}
}

func TestNodeServiceStageMessageDistinguishesTimeoutFromMismatch(t *testing.T) {
	const serviceBase = "Узел передаёт трафик, но выбранный сервис через него не подтверждён."
	const ipBase = "Узел не подтвердил доступ к сервису по IP-адресу, необходимый для маршрута устройств."
	route := "sing-box:" + checkedNodeID
	failed := func(report error, status int, code string, verdict evidence.Verdict, outcome evidence.Outcome) func(context.Context) evidence.ProbeEvidence {
		return func(ctx context.Context) evidence.ProbeEvidence {
			if report != nil {
				reportNodeServiceFailure(ctx, report)
			}
			now := time.Now().UTC()
			return evidence.ProbeEvidence{
				SchemaVersion: evidence.ProbeSchemaVersion, ProbeID: "service-failure", StartedAt: now, FinishedAt: now.Add(time.Millisecond),
				Service: "telegram", Engine: "sing-box", RoutePathID: route, ExpectedRoutePathID: route, ObservedRoutePathID: route,
				Stage: "service", HTTPStatus: status, ErrorCode: code, Verdict: verdict, Outcome: outcome,
			}
		}
	}
	cases := []struct {
		name, stage, code, message string
		verdict                    evidence.Verdict
		probe                      func(context.Context) evidence.ProbeEvidence
	}{
		{"timeout", "service", "request-failed", serviceBase + " Сервис не ответил вовремя.", evidence.VerdictError,
			failed(context.DeadlineExceeded, 0, "request-failed", evidence.VerdictError, evidence.OutcomeUnknown)},
		{"transport", "service", "request-failed", serviceBase + " Соединение с сервисом не установилось или оборвалось.", evidence.VerdictError,
			failed(errors.New("private-profile-marker reset"), 0, "request-failed", evidence.VerdictError, evidence.OutcomeUnknown)},
		{"body-timeout", "service", "response-body-invalid", serviceBase + " Сервис не ответил вовремя.", evidence.VerdictError,
			failed(context.DeadlineExceeded, 0, "response-body-invalid", evidence.VerdictError, evidence.OutcomeUnknown)},
		{"status-mismatch", "service", "http-403", serviceBase + " Сервис ответил отказом или неожиданным ответом.", evidence.VerdictBlocked,
			failed(nil, 403, "http-403", evidence.VerdictBlocked, evidence.OutcomeServiceBlocked)},
		// A probe that reports nothing keeps the former text exactly.
		{"legacy-probe", "service", "request-failed", serviceBase, evidence.VerdictError,
			failed(nil, 0, "request-failed", evidence.VerdictError, evidence.OutcomeUnknown)},
		{"ip-timeout", "service_ip", "node-service-ip-path-failed", ipBase + " Сервис не ответил вовремя.", evidence.VerdictError,
			failed(context.DeadlineExceeded, 0, "request-failed", evidence.VerdictError, evidence.OutcomeUnknown)},
		{"ip-status-mismatch", "service_ip", "node-service-ip-path-failed", ipBase + " Сервис ответил отказом или неожиданным ответом.", evidence.VerdictError,
			failed(nil, 429, "http-429", evidence.VerdictPartial, evidence.OutcomeEdgeUnsuitable)},
		{"ip-transport", "service_ip", "node-service-ip-path-failed", ipBase + " Соединение с сервисом не установилось или оборвалось.", evidence.VerdictError,
			failed(io.ErrUnexpectedEOF, 0, "request-failed", evidence.VerdictError, evidence.OutcomeUnknown)},
		{"ip-legacy-probe", "service_ip", "node-service-ip-path-failed", ipBase, evidence.VerdictError,
			failed(nil, 0, "request-failed", evidence.VerdictError, evidence.OutcomeUnknown)},
	}
	messages := map[string]string{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			checker := fakeExactNodeChecker(t)
			if tc.stage == "service" {
				checker.serviceProbe = func(ctx context.Context, _, _, _ string, _ catalog.Service) (evidence.ProbeEvidence, error) {
					return tc.probe(ctx), nil
				}
			} else {
				checker.serviceIPProbe = func(ctx context.Context, _, _, _ string, _ catalog.Service, _ netip.Addr) (evidence.ProbeEvidence, error) {
					return tc.probe(ctx), nil
				}
			}
			result, err := checker.Check(context.Background(), checkedNodeRequest())
			if err != nil || result.Available || result.Stage != tc.stage || result.ErrorCode != tc.code || result.Verdict != tc.verdict || result.TestLevel != "service" {
				t.Fatalf("category changed the failure itself: %+v err=%v", result, err)
			}
			if tc.stage == "service_ip" && result.HTTPStatus != 204 {
				t.Fatalf("IP-stage failure lost the name probe's status: %d", result.HTTPStatus)
			}
			data, _ := json.Marshal(result)
			if result.Message != tc.message || !validStoredCheckMessage(result.Message) || strings.Contains(string(data), "private-profile-marker") {
				t.Fatalf("message=%q", result.Message)
			}
			messages[tc.name] = result.Message
		})
	}
	if messages["timeout"] == messages["status-mismatch"] || messages["ip-timeout"] == messages["ip-status-mismatch"] || messages["timeout"] == messages["transport"] {
		t.Fatal("service-stage messages do not tell a timeout from a refusal")
	}
	// A misrouted proof is not explained by the service at all.
	checker := fakeExactNodeChecker(t)
	checker.serviceProbe = func(ctx context.Context, _, _, _ string, _ catalog.Service) (evidence.ProbeEvidence, error) {
		proof := failed(context.DeadlineExceeded, 0, "request-failed", evidence.VerdictError, evidence.OutcomeUnknown)(ctx)
		proof.ObservedRoutePathID = "sing-box:other"
		return proof, nil
	}
	result, err := checker.Check(context.Background(), checkedNodeRequest())
	if err != nil || result.ErrorCode != "node-route-mismatch" || result.Message != serviceBase {
		t.Fatalf("misrouted proof gained a service explanation: %+v %v", result, err)
	}
}
