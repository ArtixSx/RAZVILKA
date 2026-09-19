package dataplane

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/probecheck"
)

// A service page may ignore Range and return a large or chunked document.
// Sample at most MaxBodyBytes, using one lookahead byte to distinguish a
// complete response from truncation even when Content-Length is absent.
// The HTTP transport must honor ctx; cancellation and stream errors never
// become a usable sample. Semantic acceptance remains with probecheck.
func readServiceBodySample(ctx context.Context, response *http.Response) ([]byte, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, probecheck.MaxBodyBytes+1))
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		clear(body)
		return nil, false, err
	}
	truncated := len(body) > probecheck.MaxBodyBytes || response.ContentLength > int64(len(body))
	if len(body) > probecheck.MaxBodyBytes {
		clear(body[probecheck.MaxBodyBytes:])
		body = body[:probecheck.MaxBodyBytes]
	}
	return body, truncated, nil
}

func serviceProbeClient(client *http.Client, rawURL string) *http.Client {
	chain := []string{}
	return probecheck.RecordingClient(client, catalog.Service{ProbeURL: rawURL}, &chain)
}

// Candidate health must reject policy errors and block pages too. A TCP/SOCKS
// listener is checked separately and cannot substitute for this service test.
func strictServiceResponse(rawURL string, response *http.Response) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(response.Body, probecheck.MaxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("response stream interrupted: %w", err)
	}
	finalURL := rawURL
	chain := []string{}
	if response.Request != nil {
		finalURL = response.Request.URL.String()
		for request := response.Request; request != nil && request.Response != nil; request = request.Response.Request {
			chain = append([]string{request.URL.String()}, chain...)
		}
	}
	service := catalog.Service{ProbeURL: rawURL}
	assessment := probecheck.Evaluate(service, probecheck.ServiceProbe(service), probecheck.Observation{
		RequestedURL: rawURL, FinalURL: finalURL, RedirectChain: chain,
		HTTPStatus: response.StatusCode, ContentType: response.Header.Get("Content-Type"), Body: body,
		BodyTruncated: len(body) >= probecheck.MaxBodyBytes || response.ContentLength > int64(len(body)),
	})
	if assessment.Verdict != evidence.VerdictPass {
		return nil, fmt.Errorf("%s (%s): %s", assessment.Verdict, assessment.ErrorCode, assessment.Detail)
	}
	return body, nil
}
