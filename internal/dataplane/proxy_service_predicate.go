package dataplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/probecheck"
	"github.com/ArtixSx/razvilka/internal/publicfetch"
)

const (
	proxyServicePredicateMaxItems  = 64
	proxyServicePredicateMaxProbes = 32
	proxyServicePredicateMaxString = 16 << 10
	proxyServicePredicateMaxBytes  = 64 << 10
	proxyServicePredicateMaxJSON   = 256 << 10
)

var errProxyServicePredicate = errors.New("exact frozen catalog service predicate is required")

// Only a trusted local owner constructs this value from its selected catalog
// service. No request, receipt or boolean callback can manufacture the predicate.
// Its catalog data is private and detached from all caller-owned slices/pointers.
type proxyServicePredicate struct {
	service catalog.Service
	probe   catalog.Probe
	hash    string
}

func newProxyServicePredicate(service catalog.Service) (*proxyServicePredicate, error) {
	if !boundedProxyServicePredicate(service) || publicfetch.ValidateURL(service.ProbeURL) != nil ||
		catalog.Validate(catalog.Catalog{Services: []catalog.Service{service}}) != nil {
		return nil, errProxyServicePredicate
	}
	if len(service.Probes) > 0 {
		matches := 0
		for _, probe := range service.Probes {
			if probe.URL == service.ProbeURL {
				matches++
			}
		}
		if matches != 1 {
			return nil, errProxyServicePredicate
		}
	}
	frozen := copyProxyPredicateService(service)
	// An empty Probes list explicitly retains the catalog's existing safe web
	// default, including ServiceProbe's legacy YouTube no-content expectation.
	selected := probecheck.ServiceProbe(frozen)
	if selected.URL != frozen.ProbeURL || selected.ID == "" {
		return nil, errProxyServicePredicate
	}
	predicate := &proxyServicePredicate{service: frozen, probe: selected}
	hash, err := predicate.computeHash()
	if err != nil {
		return nil, errProxyServicePredicate
	}
	predicate.hash = hash
	return predicate, nil
}

func (p *proxyServicePredicate) digest() string {
	if p == nil {
		return ""
	}
	return p.hash
}

func (p *proxyServicePredicate) matches(serviceID, rawURL string) bool {
	if p == nil || p.hash == "" || serviceID != p.service.ID || rawURL != p.service.ProbeURL || rawURL != p.probe.URL {
		return false
	}
	hash, err := p.computeHash()
	return err == nil && hash == p.hash
}

func (p *proxyServicePredicate) computeHash() (string, error) {
	if !boundedProxyServicePredicate(p.service) {
		return "", errProxyServicePredicate
	}
	data, err := json.Marshal(struct {
		Version int             `json:"version"`
		Service catalog.Service `json:"service"`
		Probe   catalog.Probe   `json:"probe"`
	}{Version: 1, Service: p.service, Probe: p.probe})
	if err != nil || len(data) > proxyServicePredicateMaxJSON {
		return "", errProxyServicePredicate
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func boundedProxyServicePredicate(service catalog.Service) bool {
	bytes := 0
	add := func(values ...string) bool {
		for _, value := range values {
			if len(value) > proxyServicePredicateMaxString || !utf8.ValidString(value) {
				return false
			}
			bytes += len(value)
			if bytes > proxyServicePredicateMaxBytes {
				return false
			}
		}
		return true
	}
	list := func(values []string) bool {
		return len(values) <= proxyServicePredicateMaxItems && add(values...)
	}
	if !add(service.ID, service.Name, service.Category, service.Icon, service.Description, service.ProbeURL, service.Note) ||
		!list(service.Domains) || !list(service.CIDRs) || !list(service.Strategy) || !list(service.SourceRefs) ||
		len(service.Probes) > proxyServicePredicateMaxProbes {
		return false
	}
	if service.Provenance != nil {
		p := service.Provenance
		if !add(p.Provider, p.EntryID, p.URL, p.License, p.SHA256, p.FetchedAt) {
			return false
		}
	}
	for _, probe := range service.Probes {
		if !add(probe.ID, probe.Label, probe.URL, probe.Expect.RedirectPolicy) ||
			len(probe.Expect.StatusCodes) > proxyServicePredicateMaxItems ||
			!list(probe.Expect.RedirectHosts) || !list(probe.Expect.ContentTypes) ||
			!list(probe.Expect.JSONFields) || !list(probe.Expect.BodyContains) {
			return false
		}
	}
	return true
}

func copyProxyPredicateService(service catalog.Service) catalog.Service {
	service.Domains = append([]string(nil), service.Domains...)
	service.CIDRs = append([]string(nil), service.CIDRs...)
	service.Strategy = append([]string(nil), service.Strategy...)
	service.SourceRefs = append([]string(nil), service.SourceRefs...)
	probes := make([]catalog.Probe, len(service.Probes))
	for i, probe := range service.Probes {
		probe.Expect.StatusCodes = append([]int(nil), probe.Expect.StatusCodes...)
		probe.Expect.RedirectHosts = append([]string(nil), probe.Expect.RedirectHosts...)
		probe.Expect.ContentTypes = append([]string(nil), probe.Expect.ContentTypes...)
		probe.Expect.JSONFields = append([]string(nil), probe.Expect.JSONFields...)
		probe.Expect.BodyContains = append([]string(nil), probe.Expect.BodyContains...)
		probes[i] = probe
	}
	service.Probes = probes
	if service.Provenance != nil {
		provenance := *service.Provenance
		service.Provenance = &provenance
	}
	return service
}

// evaluateSample consumes the producer's already bounded, immutable response.
// It neither reads a stream nor issues another request. The exact service, URL
// and frozen predicate digest must still match before interpreting any bytes.
func (p *proxyServicePredicate) evaluateSample(ctx context.Context, serviceID, rawURL, hash string, status int, contentType, body string, truncated bool) error {
	if ctx == nil {
		return errProxyServicePredicate
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !p.matches(serviceID, rawURL) || hash != p.digest() || len(body) > probecheck.MaxBodyBytes ||
		len(contentType) > 1024 || !utf8.ValidString(contentType) || strings.ContainsAny(contentType, "\r\n\x00") {
		return errProxyServicePredicate
	}
	sample := []byte(body)
	defer clear(sample)
	assessment := probecheck.Evaluate(p.service, p.probe, probecheck.Observation{
		RequestedURL: rawURL, FinalURL: rawURL, HTTPStatus: status,
		ContentType: contentType, Body: sample, BodyTruncated: truncated,
	})
	if assessment.Verdict != evidence.VerdictPass {
		return &serviceResponseError{code: assessment.ErrorCode, detail: fmt.Sprintf("%s (%s): %s", assessment.Verdict, assessment.ErrorCode, assessment.Detail)}
	}
	return ctx.Err()
}

// Read one extra byte to distinguish a complete exactly-32KiB body from a
// truncated sample. The result hash remains a sample hash, never a full-body
// assertion. JSON/schema predicates require a complete response.
func (p *proxyServicePredicate) evaluateResponse(ctx context.Context, response *http.Response) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if response == nil || response.Body == nil {
		return nil, errors.New("service response is unavailable")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, probecheck.MaxBodyBytes+1))
	if err != nil {
		return body, fmt.Errorf("response stream interrupted: %w", err)
	}
	truncated := len(body) > probecheck.MaxBodyBytes || response.ContentLength > int64(len(body))
	if len(body) > probecheck.MaxBodyBytes {
		body[probecheck.MaxBodyBytes] = 0
		body = body[:probecheck.MaxBodyBytes]
	}
	if err := ctx.Err(); err != nil {
		return body, err
	}
	assessment := probecheck.Evaluate(p.service, p.probe, probecheck.Observation{
		RequestedURL: p.service.ProbeURL, FinalURL: probecheck.FinalURL(response, p.service.ProbeURL),
		HTTPStatus: response.StatusCode, ContentType: response.Header.Get("Content-Type"), Body: body, BodyTruncated: truncated,
	})
	if assessment.Verdict != evidence.VerdictPass {
		return body, &serviceResponseError{code: assessment.ErrorCode, detail: fmt.Sprintf("%s (%s): %s", assessment.Verdict, assessment.ErrorCode, assessment.Detail)}
	}
	return body, ctx.Err()
}
