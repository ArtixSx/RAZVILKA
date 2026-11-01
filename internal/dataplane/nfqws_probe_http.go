package dataplane

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/probecheck"
	"github.com/ArtixSx/razvilka/internal/strategylab"
)

func (e *nfqwsProbeExecution) counter(ctx context.Context) (uint64, error) {
	if err := e.captureCurrent(ctx); err != nil {
		return 0, fmt.Errorf("probe counter opening capture: %w", err)
	}
	if e.resource == nil || e.binding == nil || len(e.resource.plan.chains) != 1 {
		return 0, ErrNFQWSScopedOwner
	}
	chain := e.resource.plan.chains[0].name
	out, err := e.binding.Runner.Run(ctx, e.binding.Tools.IPTables, "-t", "mangle", "-L", chain, "-n", "-v", "-x")
	if err != nil || len(out) > 16<<10 {
		return 0, fmt.Errorf("probe counter command: %w", errors.Join(ErrNFQWSScopedOwner, err))
	}
	protocol, protocolErr := e.counterProtocol(ctx)
	if protocolErr != nil {
		return 0, fmt.Errorf("probe counter original tool format: %w", protocolErr)
	}
	count, err := nfqwsProbeParseCounter(out, chain, protocol)
	if err != nil {
		return 0, fmt.Errorf("probe counter parse: %w", err)
	}
	if err := e.captureCurrent(ctx); err != nil {
		return 0, fmt.Errorf("probe counter closing capture: %w", err)
	}
	return count, nil
}

func (e *nfqwsProbeExecution) captureCurrent(ctx context.Context) error {
	return e.observeTools(ctx, e.captureCurrentObserved)
}
func (e *nfqwsProbeExecution) captureCurrentObserved(ctx context.Context) error {
	if err := e.current(ctx); err != nil {
		return err
	}
	if e.resource == nil || e.binding == nil {
		return ErrNFQWSScopedOwner
	}
	status, err := e.binding.Inspect(ctx, e.resource.plan, e.resource.root)
	if err != nil || !status.Complete || status.Removed || status.Unknown || status.Promoted || status.Pending != 0 || status.Cleaned != 0 || status.Added != len(e.resource.plan.mixed.Effects) {
		return fmt.Errorf("probe capture receipt complete=%t removed=%t unknown=%t promoted=%t pending=%d cleaned=%d added=%d: %w", status.Complete, status.Removed, status.Unknown, status.Promoted, status.Pending, status.Cleaned, status.Added, errors.Join(ErrNFQWSScopedOwner, err))
	}
	if err := e.binding.readback(ctx, e.resource.plan, nfqwsScopedComplete, -1); err != nil {
		return fmt.Errorf("probe capture full readback: %w", err)
	}
	return e.current(ctx)
}

// The exact owned one-rule chain must contain one NFQUEUE row. Rounded human
// counters, extra rules, multiple rows, headers for another chain and unknown
// output are refused. The complete -S inventory separately checks selectors.
func nfqwsProbeParseCounter(raw []byte, chain, protocol string) (uint64, error) {
	// Format comes only from the original protected tool owner, never the
	// response. Each invocation admits exactly that owner's known spelling.
	if protocol != "6" && protocol != "tcp" {
		return 0, ErrNFQWSScopedOwner
	}
	if len(raw) == 0 || len(raw) > 16<<10 {
		return 0, ErrNFQWSScopedOwner
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "Chain "+chain+" (") {
		return 0, ErrNFQWSScopedOwner
	}
	header := strings.Fields(lines[1])
	if len(header) < 9 || strings.Join(header[:9], " ") != "pkts bytes target prot opt in out source destination" {
		return 0, ErrNFQWSScopedOwner
	}
	row := strings.Fields(lines[2])
	if len(row) < 12 || row[2] != "NFQUEUE" || row[3] != protocol || strings.Join(row[len(row)-3:], " ") != "NFQUEUE num 200" {
		return 0, ErrNFQWSScopedOwner
	}
	pkts, err := strconv.ParseUint(row[0], 10, 64)
	if err != nil || strconv.FormatUint(pkts, 10) != row[0] {
		return 0, ErrNFQWSScopedOwner
	}
	if _, err := strconv.ParseUint(row[1], 10, 64); err != nil {
		return 0, ErrNFQWSScopedOwner
	}
	return pkts, nil
}

func (e *nfqwsProbeExecution) observeService(ctx context.Context, r *NFQWSExecutionResource, b *NFQWSScopedBinding) error {
	start := time.Now()
	e.evidence = strategylab.Evidence{CandidateID: e.record.CandidateID, ServiceID: e.record.ServiceID, Protocol: "tcp", IPFamily: "ipv4", Level: strategylab.LevelHTTP, Outcome: strategylab.OutcomeLocalError, CheckedAt: start.UTC().Format(time.RFC3339Nano)}
	stage := func(name, status, detail string) {
		e.evidence.Stages = append(e.evidence.Stages, strategylab.StageEvidence{Stage: name, Status: status, Detail: detail, Elapsed: time.Since(start).Milliseconds()})
	}
	if r != e.resource || b != e.binding {
		return ErrNFQWSScopedOwner
	}
	before, err := e.counter(ctx)
	if err != nil {
		stage("firewall", "fail", "owned exact counter unavailable")
		return err
	}
	// Actual wrong-source TCP handshake runs while the admitted source socket
	// remains reserved. It cannot reuse that source port, including on cancel.
	negativeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	negative, err := (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IP(e.spec.Probe.Source.Addr().AsSlice())}}).DialContext(negativeCtx, "tcp4", e.spec.Probe.Destination.String())
	cancel()
	if err != nil {
		stage("socket", "fail", "negative control TCP handshake unavailable")
		return err
	}
	wrong, ok := negative.LocalAddr().(*net.TCPAddr)
	closeErr := negative.Close()
	if !ok || wrong.Port == int(e.spec.Probe.Source.Port()) || closeErr != nil {
		stage("socket", "fail", "negative source tuple not independent")
		return ErrNFQWSScopedOwner
	}
	afterNegative, err := e.counter(ctx)
	if err != nil {
		stage("firewall", "fail", "negative control counter unavailable")
		return err
	}
	if afterNegative != before {
		stage("firewall", "fail", "wrong source reached owned NFQUEUE")
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	stage("negative-control", "pass", "actual wrong source bypassed exact capture")
	if err := e.current(ctx); err != nil {
		return err
	}
	close(e.connect)
	flow := <-e.flow
	// This synchronous consumer owns the only dial result from this point.
	e.connect = nil
	if flow.err != nil {
		stage("socket", "fail", "admitted source failed to connect")
		return flow.err
	}
	defer flow.conn.Close()
	observation, err := nfqwsProbeHTTPObservation(ctx, e.service.ProbeURL, flow.conn)
	if err != nil {
		stage("http", "fail", "bounded TLS/HTTP observation failed")
		return err
	}
	after, err := e.counter(ctx)
	if err != nil || after <= afterNegative {
		stage("firewall", "fail", "successful response lacks owned NFQUEUE packet proof")
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	e.evidence.RouteConfirmed = true
	e.evidence.HTTPStatus = observation.HTTPStatus
	e.evidence.BytesRead = int64(len(observation.Body))
	e.evidence.LatencyMS = time.Since(start).Milliseconds()
	assessment := probecheck.Evaluate(e.service, probecheck.ServiceProbe(e.service), observation)
	e.evidence.Success = assessment.Verdict == evidence.VerdictPass
	e.evidence.Outcome = strategylab.OutcomeServiceFail
	if e.evidence.Success {
		e.evidence.Outcome = strategylab.OutcomePass
		stage("http", "pass", "catalogue predicates and exact owned NFQUEUE confirmed")
	} else {
		stage("http", "fail", assessment.ErrorCode)
	}
	return e.current(ctx)
}

func nfqwsProbeHTTPObservation(ctx context.Context, rawURL string, conn net.Conn) (probecheck.Observation, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Port() != "" && u.Port() != "443" {
		return probecheck.Observation{}, ErrNFQWSScopedOwner
	}
	used := false
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, ForceAttemptHTTP2: false, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}, DialContext: func(c context.Context, network, address string) (net.Conn, error) {
		if used || address != net.JoinHostPort(u.Hostname(), "443") {
			return nil, ErrNFQWSScopedOwner
		}
		used = true
		return conn, nil
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return probecheck.Observation{}, err
	}
	response, err := client.Do(req)
	if err != nil {
		return probecheck.Observation{}, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, probecheck.MaxBodyBytes+1))
	if err != nil {
		return probecheck.Observation{}, err
	}
	truncated := len(body) > probecheck.MaxBodyBytes
	if truncated {
		body = body[:probecheck.MaxBodyBytes]
	}
	return probecheck.Observation{RequestedURL: u.String(), FinalURL: u.String(), HTTPStatus: response.StatusCode, ContentType: response.Header.Get("Content-Type"), Body: body, BodyTruncated: truncated}, nil
}
