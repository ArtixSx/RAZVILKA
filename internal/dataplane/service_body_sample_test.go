package dataplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/probecheck"
)

// Exercise both production adapters over local HTTP streams. The node adapter
// still goes through a real SOCKS handshake; no external network is accessed.
func serviceBodyProbe(t *testing.T, adapter string, handler http.HandlerFunc) func(context.Context, catalog.ProbeExpectation) evidence.ProbeEvidence {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if adapter == "cloudflare" && r.Header.Get("Range") != "bytes=0-32767" {
			t.Error("Cloudflare probe lost its bounded Range request")
		}
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	backend := server.Listener.Addr().String()
	var run func(context.Context, catalog.Service) (evidence.ProbeEvidence, error)
	if adapter == "node" {
		proxy := newPinnedSOCKSFixture(t, backend, false)
		checker := &ExactNodeChecker{}
		run = func(ctx context.Context, service catalog.Service) (evidence.ProbeEvidence, error) {
			return checker.probeService(ctx, proxy.address, "sing-box:test", "8.8.8.8", service)
		}
	} else {
		transport := &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, backend)
		}}
		t.Cleanup(transport.CloseIdleConnections)
		client := &http.Client{Transport: transport}
		probe := cloudflareScanHTTPProbe{}
		run = func(ctx context.Context, service catalog.Service) (evidence.ProbeEvidence, error) {
			return probe.service(ctx, client, "cloudflare-wg:test", "8.8.8.8", service)
		}
	}
	return func(ctx context.Context, expect catalog.ProbeExpectation) evidence.ProbeEvidence {
		service := catalog.Service{ID: "discord", ProbeURL: "http://service.example/", Domains: []string{"service.example"}}
		service.Probes = []catalog.Probe{{URL: service.ProbeURL, Required: true, Expect: expect}}
		result, err := run(ctx, service)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
}

func TestServiceBodySamplingPreservesSemanticChecks(t *testing.T) {
	largeHTML := "<html><title>Service</title>" + strings.Repeat("x", probecheck.MaxBodyBytes)
	jsonPrefix := `{"ok":true}`
	jsonAtLimit := jsonPrefix + strings.Repeat(" ", probecheck.MaxBodyBytes-len(jsonPrefix))
	jsonExpect := catalog.ProbeExpectation{JSON: true, JSONFields: []string{"ok"}, ContentTypes: []string{"application/json"}}
	cases := []struct {
		name        string
		body        string
		contentType string
		status      int
		chunked     bool
		redirect    string
		expect      catalog.ProbeExpectation
		verdict     evidence.Verdict
		code        string
	}{
		{name: "large-html-ignoring-range", body: largeHTML, contentType: "text/html", status: 200, verdict: evidence.VerdictPass},
		{name: "chunked-html-ignoring-range", body: largeHTML, contentType: "text/html", status: 200, chunked: true, verdict: evidence.VerdictPass},
		// Even a syntactically valid JSON prefix must not prove a larger document.
		{name: "large-json", body: jsonAtLimit + " ", contentType: "application/json", status: 200, expect: jsonExpect, verdict: evidence.VerdictInconclusive, code: "json-sample-incomplete"},
		{name: "chunked-json", body: jsonAtLimit + " ", contentType: "application/json", status: 200, chunked: true, expect: jsonExpect, verdict: evidence.VerdictInconclusive, code: "json-sample-incomplete"},
		{name: "complete-json-at-limit", body: jsonAtLimit, contentType: "application/json", status: 200, expect: jsonExpect, verdict: evidence.VerdictPass},
		{name: "complete-chunked-json-at-limit", body: jsonAtLimit, contentType: "application/json", status: 200, chunked: true, expect: jsonExpect, verdict: evidence.VerdictPass},
		{name: "large-block-page", body: "<html>Доступ к запрашиваемому ресурсу ограничен</html>" + largeHTML, contentType: "text/html", status: 200, verdict: evidence.VerdictBlocked, code: "known-block-page"},
		{name: "large-forbidden", body: largeHTML, contentType: "text/html", status: 403, verdict: evidence.VerdictBlocked, code: "http-403"},
		{name: "large-external-redirect", body: largeHTML, contentType: "text/html", status: 302, redirect: "http://portal.invalid/login", verdict: evidence.VerdictBlocked, code: "redirect-host-rejected"},
		{name: "large-unexpected-status", body: largeHTML, contentType: "text/html", status: 200, expect: catalog.ProbeExpectation{StatusCodes: []int{204}}, verdict: evidence.VerdictInconclusive, code: "unexpected-http-status"},
		{name: "large-missing-predicate", body: largeHTML, contentType: "text/html", status: 200, expect: catalog.ProbeExpectation{BodyContains: []string{"required-service-marker"}}, verdict: evidence.VerdictError, code: "body-predicate-mismatch"},
		{name: "large-wrong-type", body: largeHTML, contentType: "text/plain", status: 200, expect: catalog.ProbeExpectation{ContentTypes: []string{"text/html"}}, verdict: evidence.VerdictError, code: "content-type-mismatch"},
	}
	for _, adapter := range []string{"node", "cloudflare"} {
		for _, tc := range cases {
			t.Run(adapter+"/"+tc.name, func(t *testing.T) {
				probe := serviceBodyProbe(t, adapter, func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", tc.contentType)
					if tc.redirect != "" {
						w.Header().Set("Location", tc.redirect)
					}
					if !tc.chunked {
						w.Header().Set("Content-Length", strconv.Itoa(len(tc.body)))
					}
					w.WriteHeader(tc.status)
					if tc.chunked {
						w.(http.Flusher).Flush()
					}
					_, _ = io.WriteString(w, tc.body)
				})
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				result := probe(ctx, tc.expect)
				wantVerdict, wantCode := tc.verdict, tc.code
				if adapter == "node" && tc.redirect != "" {
					// The SOCKS client stops this redirect, but its response chain
					// does not include a target that was never visited.
					wantVerdict, wantCode = evidence.VerdictInconclusive, "redirect-not-resolved"
				}
				if result.Verdict != wantVerdict || result.ErrorCode != wantCode || result.HTTPStatus != tc.status {
					t.Fatalf("unexpected assessment: %+v", result)
				}
				if tc.verdict != evidence.VerdictPass && result.Outcome == evidence.OutcomeServiceAccepted {
					t.Fatalf("negative response became accepted: %+v", result)
				}
				sample := tc.body
				if len(sample) > probecheck.MaxBodyBytes {
					sample = sample[:probecheck.MaxBodyBytes]
				}
				digest := sha256.Sum256([]byte(sample))
				if result.ContentFingerprint != "sha256:"+hex.EncodeToString(digest[:]) {
					t.Fatal("semantic evaluator did not receive exactly the bounded sample")
				}
			})
		}
	}
}

func TestServiceBodySamplingRejectsInterruptedHTTPStreams(t *testing.T) {
	for _, adapter := range []string{"node", "cloudflare"} {
		t.Run(adapter+"/unexpected-eof", func(t *testing.T) {
			probe := serviceBodyProbe(t, adapter, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				w.Header().Set("Content-Length", "100")
				_, _ = io.WriteString(w, "<html>partial")
				// Closing a shorter-than-declared HTTP body causes io.ErrUnexpectedEOF.
			})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			result := probe(ctx, catalog.ProbeExpectation{})
			if result.Verdict != evidence.VerdictError || result.ErrorCode != "response-body-invalid" || result.Outcome == evidence.OutcomeServiceAccepted {
				t.Fatalf("interrupted stream became usable: %+v", result)
			}
		})
		t.Run(adapter+"/canceled-read", func(t *testing.T) {
			probe := serviceBodyProbe(t, adapter, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				_, _ = io.WriteString(w, "<html>partial")
				w.(http.Flusher).Flush()
				<-r.Context().Done()
			})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			result := probe(ctx, catalog.ProbeExpectation{})
			if ctx.Err() == nil || result.Verdict != evidence.VerdictError || result.ErrorCode != "response-body-invalid" || result.Outcome == evidence.OutcomeServiceAccepted {
				t.Fatalf("canceled stream became usable: %+v, ctx=%v", result, ctx.Err())
			}
		})
	}
}

type bodySampleReader func([]byte) (int, error)

func (read bodySampleReader) Read(buffer []byte) (int, error) { return read(buffer) }

func TestServiceBodySampleKeepsBoundsAndCancellation(t *testing.T) {
	t.Run("bounded-read", func(t *testing.T) {
		read := 0
		response := &http.Response{ContentLength: -1, Body: io.NopCloser(bodySampleReader(func(buffer []byte) (int, error) {
			for i := range buffer {
				buffer[i] = 'x'
			}
			read += len(buffer)
			return len(buffer), nil
		}))}
		body, truncated, err := readServiceBodySample(context.Background(), response)
		if err != nil || !truncated || len(body) != probecheck.MaxBodyBytes || read != probecheck.MaxBodyBytes+1 {
			t.Fatalf("unbounded sample: len=%d read=%d truncated=%v err=%v", len(body), read, truncated, err)
		}
	})
	for _, cancelDuringRead := range []bool{false, true} {
		t.Run("cancel-during-read-"+strconv.FormatBool(cancelDuringRead), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			reads := 0
			if !cancelDuringRead {
				cancel()
			}
			response := &http.Response{Body: io.NopCloser(bodySampleReader(func(buffer []byte) (int, error) {
				reads++
				cancel()
				return copy(buffer, "usable-looking HTML"), io.EOF
			}))}
			body, _, err := readServiceBodySample(ctx, response)
			if !errors.Is(err, context.Canceled) || body != nil || !cancelDuringRead && reads != 0 {
				t.Fatalf("cancellation was ignored: len=%d reads=%d err=%v", len(body), reads, err)
			}
		})
	}
	t.Run("bytes-and-error", func(t *testing.T) {
		response := &http.Response{Body: io.NopCloser(bodySampleReader(func(buffer []byte) (int, error) {
			return copy(buffer, "usable-looking HTML"), io.ErrUnexpectedEOF
		}))}
		body, _, err := readServiceBodySample(context.Background(), response)
		if !errors.Is(err, io.ErrUnexpectedEOF) || body != nil {
			t.Fatalf("stream error was hidden by partial bytes: len=%d err=%v", len(body), err)
		}
	})
}
