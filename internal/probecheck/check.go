// Package probecheck evaluates bounded HTTP observations without confusing
// transport reachability with useful service access.
package probecheck

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/url"
	"strings"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/evidence"
)

const MaxBodyBytes = 32 * 1024

type Observation struct {
	RequestedURL           string
	FinalURL               string
	RedirectChain          []string
	HTTPStatus             int
	ContentType            string
	Body                   []byte
	BodyTruncated          bool
	ExpectedRoutePathID    string
	ObservedRoutePathID    string
	NegativeControlMatched bool
}

type Assessment struct {
	Status             string
	Verdict            evidence.Verdict
	Outcome            evidence.Outcome
	Detail             string
	ErrorCode          string
	ContentFingerprint string
}

func Evaluate(service catalog.Service, probe catalog.Probe, observation Observation) Assessment {
	assessment := Assessment{Status: "fail", Verdict: evidence.VerdictInconclusive, Outcome: evidence.OutcomeTransportReachable}
	if len(observation.Body) > 0 {
		digest := sha256.Sum256(observation.Body)
		assessment.ContentFingerprint = "sha256:" + hex.EncodeToString(digest[:])
	}
	if observation.NegativeControlMatched || routeMismatch(observation.ExpectedRoutePathID, observation.ObservedRoutePathID) {
		assessment.Status = "partial"
		assessment.Verdict = evidence.VerdictMisrouted
		assessment.ErrorCode = "route-identity-mismatch"
		assessment.Detail = "ответ получен не через запрошенный маршрут"
		return assessment
	}
	if badRedirect := rejectedRedirect(service, probe, observation); badRedirect != "" {
		assessment.Status = "partial"
		assessment.Verdict = evidence.VerdictBlocked
		assessment.Outcome = evidence.OutcomeServiceBlocked
		assessment.ErrorCode = "redirect-host-rejected"
		assessment.Detail = "перенаправление вывело проверку за пределы сервиса: " + RedactedURL(badRedirect)
		return assessment
	}
	switch observation.HTTPStatus {
	case 403, 451:
		assessment.Status = "partial"
		assessment.Verdict = evidence.VerdictBlocked
		assessment.Outcome = evidence.OutcomeServiceBlocked
		assessment.ErrorCode = fmt.Sprintf("http-%d", observation.HTTPStatus)
		assessment.Detail = fmt.Sprintf("сервис или сеть вернули блокирующий HTTP %d", observation.HTTPStatus)
		return assessment
	case 401, 407, 429:
		assessment.Status = "partial"
		assessment.Verdict = evidence.VerdictPartial
		assessment.Outcome = evidence.OutcomeEdgeUnsuitable
		assessment.ErrorCode = fmt.Sprintf("http-%d", observation.HTTPStatus)
		assessment.Detail = fmt.Sprintf("маршрут отвечает, но узел вернул ограничение HTTP %d", observation.HTTPStatus)
		return assessment
	}
	if observation.HTTPStatus >= 300 && observation.HTTPStatus < 400 {
		assessment.Status = "partial"
		assessment.Verdict = evidence.VerdictInconclusive
		assessment.ErrorCode = "redirect-not-resolved"
		assessment.Detail = fmt.Sprintf("HTTP %d сам по себе не подтверждает работу сервиса", observation.HTTPStatus)
		return assessment
	}
	if observation.HTTPStatus < 200 || observation.HTTPStatus >= 300 {
		if observation.HTTPStatus >= 400 && observation.HTTPStatus < 500 {
			assessment.Status = "partial"
			assessment.Verdict = evidence.VerdictPartial
			assessment.Detail = fmt.Sprintf("маршрут достиг узла, но получил HTTP %d", observation.HTTPStatus)
		} else {
			assessment.Verdict = evidence.VerdictError
			assessment.Detail = fmt.Sprintf("проверка получила HTTP %d", observation.HTTPStatus)
		}
		assessment.ErrorCode = fmt.Sprintf("http-%d", observation.HTTPStatus)
		return assessment
	}
	if !acceptedStatus(probe.Expect.StatusCodes, observation.HTTPStatus) {
		assessment.Verdict = evidence.VerdictInconclusive
		assessment.ErrorCode = "unexpected-http-status"
		assessment.Detail = fmt.Sprintf("получен HTTP %d, но предикат сервиса ожидает другой статус", observation.HTTPStatus)
		return assessment
	}
	if marker := blockPageMarker(observation.ContentType, observation.Body); marker != "" {
		assessment.Status = "partial"
		assessment.Verdict = evidence.VerdictBlocked
		assessment.Outcome = evidence.OutcomeServiceBlocked
		assessment.ErrorCode = "known-block-page"
		assessment.Detail = "обнаружена страница блокировки: " + marker
		return assessment
	}
	if !acceptedContentType(probe.Expect.ContentTypes, observation.ContentType) {
		assessment.Verdict = evidence.VerdictError
		assessment.Outcome = evidence.OutcomeContentMismatch
		assessment.ErrorCode = "content-type-mismatch"
		assessment.Detail = "тип содержимого не соответствует предикату сервиса"
		return assessment
	}
	if probe.Expect.JSON {
		if observation.BodyTruncated {
			assessment.Verdict = evidence.VerdictInconclusive
			assessment.ErrorCode = "json-sample-incomplete"
			assessment.Detail = "JSON превышает лимит проверки; схема не подтверждена"
			return assessment
		}
		var document interface{}
		if len(observation.Body) == 0 || json.Unmarshal(observation.Body, &document) != nil {
			assessment.Verdict = evidence.VerdictError
			assessment.Outcome = evidence.OutcomeContentMismatch
			assessment.ErrorCode = "invalid-json"
			assessment.Detail = "вместо ожидаемого JSON получено другое содержимое"
			return assessment
		}
		for _, field := range probe.Expect.JSONFields {
			if !jsonFieldExists(document, field) {
				assessment.Verdict = evidence.VerdictError
				assessment.Outcome = evidence.OutcomeContentMismatch
				assessment.ErrorCode = "json-schema-mismatch"
				assessment.Detail = "в JSON отсутствует обязательное поле " + field
				return assessment
			}
		}
	}
	lowerBody := strings.ToLower(string(observation.Body))
	for _, required := range probe.Expect.BodyContains {
		if !strings.Contains(lowerBody, strings.ToLower(required)) {
			assessment.Verdict = evidence.VerdictError
			assessment.Outcome = evidence.OutcomeContentMismatch
			assessment.ErrorCode = "body-predicate-mismatch"
			assessment.Detail = "ответ не содержит обязательный признак сервиса"
			return assessment
		}
	}
	assessment.Status = "pass"
	assessment.Verdict = evidence.VerdictPass
	assessment.Outcome = evidence.OutcomeServiceAccepted
	assessment.Detail = "контрольный адрес вернул ожидаемый ответ"
	return assessment
}

func routeMismatch(expected, observed string) bool {
	expected = strings.TrimSpace(expected)
	observed = strings.TrimSpace(observed)
	return expected != "" && observed != "" && expected != observed
}

func acceptedStatus(expected []int, actual int) bool {
	if len(expected) == 0 {
		return actual >= 200 && actual < 300
	}
	for _, status := range expected {
		if status == actual {
			return true
		}
	}
	return false
}

func acceptedContentType(expected []string, actual string) bool {
	if len(expected) == 0 {
		return true
	}
	mediaType, _, err := mime.ParseMediaType(actual)
	if err != nil {
		mediaType = strings.TrimSpace(strings.Split(actual, ";")[0])
	}
	for _, candidate := range expected {
		if strings.EqualFold(strings.TrimSpace(candidate), mediaType) {
			return true
		}
	}
	return false
}

func rejectedRedirect(service catalog.Service, probe catalog.Probe, observation Observation) string {
	chain := append([]string(nil), observation.RedirectChain...)
	if len(chain) == 0 && observation.FinalURL != "" && observation.FinalURL != observation.RequestedURL {
		chain = append(chain, observation.FinalURL)
	}
	if len(chain) == 0 {
		return ""
	}
	if probe.Expect.RedirectPolicy == "none" {
		return chain[0]
	}
	requested, _ := url.Parse(observation.RequestedURL)
	allowed := []string{}
	if probe.Expect.RedirectPolicy != "allowlist" {
		allowed = append(allowed, service.Domains...)
	}
	if requested != nil && requested.Hostname() != "" {
		allowed = append(allowed, requested.Hostname())
	}
	allowed = append(allowed, probe.Expect.RedirectHosts...)
	for _, raw := range chain {
		target, err := url.Parse(raw)
		if err != nil || target.Hostname() == "" || target.User != nil || (requested != nil && (target.Scheme != requested.Scheme || effectivePort(target) != effectivePort(requested))) || !hostAllowed(target.Hostname(), allowed) {
			return raw
		}
	}
	return ""
}

func hostAllowed(host string, allowed []string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	for _, candidate := range allowed {
		candidate = strings.TrimPrefix(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(candidate)), "."), "*.")
		if host == candidate || strings.HasSuffix(host, "."+candidate) {
			return true
		}
	}
	return false
}

func blockPageMarker(contentType string, body []byte) string {
	if len(body) == 0 {
		return ""
	}
	text := strings.ToLower(string(body))
	if contentType != "" && !strings.Contains(strings.ToLower(contentType), "text") && !strings.Contains(strings.ToLower(contentType), "html") && !strings.HasPrefix(strings.TrimSpace(text), "<") {
		return ""
	}
	markers := []string{
		"access to the requested resource has been restricted",
		"this website has been blocked by your internet service provider",
		"доступ к запрашиваемому ресурсу ограничен",
		"доступ к информационному ресурсу ограничен",
		"сайт заблокирован по решению",
		"внесен в единый реестр запрещенной информации",
		"blocked by roscomnadzor",
	}
	for _, marker := range markers {
		if strings.Contains(text, marker) {
			return marker
		}
	}
	return ""
}

func jsonFieldExists(document interface{}, path string) bool {
	current := document
	for _, part := range strings.Split(path, ".") {
		object, ok := current.(map[string]interface{})
		if !ok {
			return false
		}
		current, ok = object[part]
		if !ok {
			return false
		}
	}
	return true
}

// RedactedURL keeps diagnostic routing context without query credentials.
func RedactedURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

func effectivePort(parsed *url.URL) string {
	if parsed.Port() != "" {
		return parsed.Port()
	}
	if parsed.Scheme == "https" {
		return "443"
	}
	if parsed.Scheme == "http" {
		return "80"
	}
	return ""
}

func RedactedError(err error) string {
	var urlError *url.Error
	if errors.As(err, &urlError) {
		return urlError.Op + " " + RedactedURL(urlError.URL) + ": " + urlError.Err.Error()
	}
	return err.Error()
}
