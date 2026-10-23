package dataplane

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/ArtixSx/razvilka/internal/evidence"
	xnetproxy "golang.org/x/net/proxy"
)

const NodeConnectivityURL = "https://www.gstatic.com/generate_204"
const NodeConnectivityTTL = 5 * time.Minute

type NodeConnectivityRequest struct {
	NodeID, NetworkProfile string
	Outbound               []byte
}

// NodeConnectivityResult has no service identity, evidence or route eligibility.
// It must never be written to NodeStore service history.
type NodeConnectivityResult struct {
	NodeID, NetworkProfile, Engine, ProbeID string
	CheckedAt, ExpiresAt                    time.Time
	Ready, CleanupVerified                  bool
	Verdict                                 evidence.Verdict
	Stage, ErrorCode, Message               string
	DirectControl                           string
	HTTPStatus                              int
	DurationMS                              int64
}

type NodeConnectivityChecker interface {
	CheckConnectivity(context.Context, NodeConnectivityRequest) (NodeConnectivityResult, error)
}

// Reuse the original gate, runtime owner, egress pair and all closing defers.
// Readiness is derived only AFTER Check has joined its ordinary cleanup.
func (c *ExactNodeChecker) CheckConnectivity(ctx context.Context, r NodeConnectivityRequest) (NodeConnectivityResult, error) {
	if c == nil {
		return NodeConnectivityResult{}, ErrExactNodeUnavailable
	}
	result, err := c.Check(ctx, NodeCheckRequest{NodeID: r.NodeID, Outbound: r.Outbound, NetworkProfile: r.NetworkProfile, connectivity: true})
	checked := c.currentTime()
	out := NodeConnectivityResult{NodeID: r.NodeID, NetworkProfile: r.NetworkProfile, Engine: c.EngineID(), ProbeID: result.ProbeID,
		CheckedAt: checked, ExpiresAt: checked.Add(NodeConnectivityTTL), Verdict: result.Verdict, Stage: result.Stage,
		ErrorCode: result.ErrorCode, Message: result.Message, HTTPStatus: result.HTTPStatus, DurationMS: result.LatencyMS, DirectControl: result.DirectControl}
	out.CleanupVerified = err == nil && ctx.Err() == nil && !c.poisoned.Load() && result.Stage != "cleanup" && result.ErrorCode != "node-cleanup-failed"
	out.Ready = out.CleanupVerified && result.NodeID == r.NodeID && result.ServiceID == "" && result.NetworkProfile == r.NetworkProfile &&
		result.RoutePathID == c.EngineID()+":"+r.NodeID && result.TestLevel == "connectivity" && result.Stage == "connectivity" &&
		result.Verdict == evidence.VerdictPass && result.HTTPStatus == http.StatusNoContent && result.ErrorCode == "" &&
		result.DirectControl == "measured" && !result.DirectLeak && !result.Available && result.EgressIP != ""
	if !out.Ready && out.Verdict == evidence.VerdictPass {
		out.Verdict = evidence.VerdictInconclusive
	}
	return out, err
}

func (c *ExactNodeChecker) finishConnectivity(ctx context.Context, address string, result *NodeCheckResult) {
	started := c.currentTime()
	result.TestLevel = "connectivity"
	status, err := c.connectivityProbe(ctx, address)
	result.HTTPStatus = status
	if err != nil {
		result.fail("connectivity", "node-connectivity-request-failed", "Общий HTTPS-запрос не завершён. Доступ к сервисам этим не проверен.")
	} else if status != http.StatusNoContent {
		result.fail("connectivity", "node-connectivity-response-mismatch", "Общий HTTPS-тест не получил ожидаемый ответ 204. Доступ к сервисам этим не проверен.")
	} else {
		result.Stage, result.Verdict, result.ErrorCode = "connectivity", evidence.VerdictPass, ""
		result.Message = "Общий HTTPS-тест пройден. Доступ к выбранному сервису проверьте отдельно."
	}
	state := "failed"
	if result.Verdict == evidence.VerdictPass {
		state = "passed"
	}
	result.addStage("connectivity", state, result.Message, started, c.currentTime())
}

func (c *ExactNodeChecker) probeConnectivity(parent context.Context, address string) (int, error) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	if err := checkNodeResourceURL(ctx, NodeConnectivityURL, netip.Addr{}); err != nil {
		return 0, err
	}
	addresses, err := resolveNodeServiceIPv4(ctx, NodeConnectivityURL, c.resolve)
	if err != nil || len(addresses) == 0 {
		return 0, errors.New("connectivity DNS unavailable")
	}
	pin := addresses[0]
	if err = checkNodeResourceURL(ctx, NodeConnectivityURL, pin); err != nil {
		return 0, err
	}
	proxy, err := xnetproxy.SOCKS5("tcp", address, nil, &net.Dialer{Timeout: 3 * time.Second})
	if err != nil {
		return 0, err
	}
	dial, ok := proxy.(xnetproxy.ContextDialer)
	if !ok {
		return 0, errors.New("connectivity SOCKS unavailable")
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, ForceAttemptHTTP2: false, TLSHandshakeTimeout: 3 * time.Second,
		ResponseHeaderTimeout: 4 * time.Second, MaxResponseHeaderBytes: 16384, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "www.gstatic.com"},
		DialContext: func(c context.Context, network, destination string) (net.Conn, error) {
			if network != "tcp" || destination != "www.gstatic.com:443" {
				return nil, errors.New("connectivity destination refused")
			}
			if err := checkNodeResourceURL(c, NodeConnectivityURL, pin); err != nil {
				return nil, err
			}
			return dial.DialContext(c, "tcp", net.JoinHostPort(pin.String(), "443"))
		}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, NodeConnectivityURL, nil)
	if err != nil {
		return 0, err
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 1025))
	defer clear(data)
	if err != nil || len(data) > 1024 || response.StatusCode == http.StatusNoContent && len(data) != 0 {
		return response.StatusCode, errors.New("connectivity response invalid")
	}
	if err = checkNodeResourceURL(ctx, NodeConnectivityURL, pin); err != nil {
		return response.StatusCode, err
	}
	return response.StatusCode, nil
}
