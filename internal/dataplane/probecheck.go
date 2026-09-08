package dataplane

import (
	"fmt"
	"io"
	"net/http"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/probecheck"
)

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
