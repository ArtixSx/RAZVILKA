package dataplane

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/cloudflareprovider"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/probecheck"
)

const cloudflareTraceURL = "https://1.1.1.1/cdn-cgi/trace"

type cloudflareScanProbeFacts struct {
	DirectEgressIP string
	EgressIP       string
	Trace          cloudflareprovider.TraceEvidence
	Service        evidence.ProbeEvidence
}

type cloudflareBoundClient func(source string) (*http.Client, func(), error)

// cloudflareScanHTTPProbe collects only bounded HTTP evidence. Interface,
// source-rule, handshake, MTU and cleanup ownership remain the runner's job.
// Test hooks are private to this package and cannot be configured through API.
type cloudflareScanHTTPProbe struct {
	directClient *http.Client
	boundClient  cloudflareBoundClient
	traceURL     string
	now          func() time.Time
}

func newCloudflareScanHTTPProbe() cloudflareScanHTTPProbe {
	transport := &http.Transport{Proxy: nil, TLSHandshakeTimeout: 8 * time.Second, ForceAttemptHTTP2: true}
	return cloudflareScanHTTPProbe{
		directClient: &http.Client{
			Transport: transport, Timeout: 12 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		boundClient: newSourceBoundWARPClient,
		traceURL:    cloudflareTraceURL,
	}
}

func (probe cloudflareScanHTTPProbe) observe(ctx context.Context, source, routePathID string, service catalog.Service) (cloudflareScanProbeFacts, error) {
	if probe.directClient == nil || probe.boundClient == nil || probe.traceURL == "" || !strings.HasPrefix(routePathID, "cloudflare-wg:") || !scanServiceID(service.ID) || service.ProbeURL == "" {
		return cloudflareScanProbeFacts{}, errors.New("Cloudflare scan HTTP probe is not configured")
	}
	directTrace, err := probe.trace(ctx, probe.directClient)
	if err != nil {
		return cloudflareScanProbeFacts{}, cloudflareHTTPFailure("direct-trace", err)
	}
	bound, closeBound, err := probe.boundClient(source)
	if err != nil || bound == nil || closeBound == nil {
		return cloudflareScanProbeFacts{}, errors.New("Cloudflare source-bound probe is unavailable")
	}
	defer closeBound()
	tunnelTrace, err := probe.trace(ctx, bound)
	if err != nil {
		return cloudflareScanProbeFacts{}, cloudflareHTTPFailure("tunnel-trace", err)
	}
	serviceEvidence, err := probe.service(ctx, bound, routePathID, tunnelTrace.IP, service)
	if err != nil {
		return cloudflareScanProbeFacts{}, err
	}
	return cloudflareScanProbeFacts{
		DirectEgressIP: directTrace.IP, EgressIP: tunnelTrace.IP,
		Trace: tunnelTrace, Service: serviceEvidence,
	}, nil
}

func (probe cloudflareScanHTTPProbe) trace(ctx context.Context, client *http.Client) (cloudflareprovider.TraceEvidence, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, probe.traceURL, nil)
	if err != nil {
		return cloudflareprovider.TraceEvidence{}, errors.New("build Cloudflare trace request")
	}
	request.Header.Set("User-Agent", "RAZVILKA-Cloudflare-Scanner/1")
	response, err := client.Do(request)
	if err != nil {
		return cloudflareprovider.TraceEvidence{}, errors.New("Cloudflare trace request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return cloudflareprovider.TraceEvidence{}, &cloudflareprovider.ScanFailure{ReasonCode: "trace-http-status", HTTPStatus: response.StatusCode}
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, cloudflareprovider.MaxTraceBytes+1))
	if err != nil || len(body) > cloudflareprovider.MaxTraceBytes {
		return cloudflareprovider.TraceEvidence{}, errors.New("Cloudflare trace body is invalid")
	}
	trace, err := cloudflareprovider.ParseCloudflareTrace(body)
	if err != nil {
		return cloudflareprovider.TraceEvidence{}, errors.New("Cloudflare trace evidence is invalid")
	}
	return trace, nil
}

func cloudflareHTTPFailure(stage string, err error) *cloudflareprovider.ScanFailure {
	var failure *cloudflareprovider.ScanFailure
	if errors.As(err, &failure) {
		copy := *failure
		copy.Stage = stage
		return &copy
	}
	code := "trace-request-failed"
	if strings.Contains(err.Error(), "body") {
		code = "trace-body-invalid"
	}
	if strings.Contains(err.Error(), "evidence") {
		code = "trace-content-invalid"
	}
	return &cloudflareprovider.ScanFailure{Stage: stage, ReasonCode: code}
}

func (probe cloudflareScanHTTPProbe) service(ctx context.Context, client *http.Client, routePathID, egressIP string, service catalog.Service) (evidence.ProbeEvidence, error) {
	parsed, err := url.Parse(service.ProbeURL)
	if err != nil || parsed.User != nil || parsed.Hostname() == "" || parsed.Scheme != "https" && parsed.Scheme != "http" || parsed.Port() != "" && parsed.Port() != "80" && parsed.Port() != "443" {
		return evidence.ProbeEvidence{}, errors.New("Cloudflare service probe URL is invalid")
	}
	started := probe.currentTime()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, service.ProbeURL, nil)
	if err != nil {
		return evidence.ProbeEvidence{}, errors.New("build Cloudflare service request")
	}
	request.Header.Set("User-Agent", "RAZVILKA-Cloudflare-Scanner/1")
	request.Header.Set("Range", "bytes=0-32767")
	redirects := []string{}
	response, requestErr := probecheck.RecordingClient(client, service, &redirects).Do(request)
	finished := probe.currentTime()
	result := evidence.ProbeEvidence{
		SchemaVersion: evidence.ProbeSchemaVersion, StartedAt: started, FinishedAt: finished,
		Service: service.ID, RoutePathID: routePathID, Engine: "cloudflare-provider", EgressIP: egressIP,
		Stage: "service", Outcome: evidence.OutcomeUnknown, Verdict: evidence.VerdictError,
		RequestedURL: probecheck.RedactedURL(service.ProbeURL), ExpectedRoutePathID: routePathID, ObservedRoutePathID: routePathID,
		Source: "source-bound-cloudflare-scan",
	}
	if requestErr != nil {
		result.ErrorCode = "request-failed"
		return result, nil
	}
	defer response.Body.Close()
	body, truncated, readErr := readServiceBodySample(ctx, response)
	if readErr != nil {
		result.ErrorCode = "response-body-invalid"
		return result, nil
	}
	defer clear(body)
	assessment := probecheck.Evaluate(service, probecheck.ServiceProbe(service), probecheck.Observation{
		RequestedURL: service.ProbeURL, FinalURL: probecheck.FinalURL(response, service.ProbeURL), RedirectChain: redirects,
		HTTPStatus: response.StatusCode, ContentType: response.Header.Get("Content-Type"), Body: body,
		BodyTruncated: truncated, ExpectedRoutePathID: routePathID, ObservedRoutePathID: routePathID,
	})
	result.HTTPStatus = response.StatusCode
	result.Outcome, result.Verdict = assessment.Outcome, assessment.Verdict
	result.ErrorCode, result.ContentFingerprint = assessment.ErrorCode, assessment.ContentFingerprint
	result.ContentType = response.Header.Get("Content-Type")
	result.FinalURL = probecheck.RedactedURL(probecheck.FinalURL(response, service.ProbeURL))
	for _, target := range redirects {
		result.RedirectChain = append(result.RedirectChain, probecheck.RedactedURL(target))
	}
	return result, nil
}

func (probe cloudflareScanHTTPProbe) currentTime() time.Time {
	if probe.now != nil {
		return probe.now().UTC()
	}
	return time.Now().UTC()
}

func scanServiceID(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, item := range []byte(value) {
		if !(item >= 'a' && item <= 'z' || item >= '0' && item <= '9' || item == '-') {
			return false
		}
	}
	return true
}
