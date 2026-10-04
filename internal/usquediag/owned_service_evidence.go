package usquediag

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

// Version 1 distinguishes reachability, diagnostic nonce challenges and
// approved semantic criteria. Older receipts cannot supply semantic grades.
const ownedServiceProofVersion = 1

var errOwnedNetworkService = errors.New("owned-network-service-invalid")

// Presence, including null and aliases, fences the typed identity from legacy
// fallback. Only one canonical envelope key can carry trusted typed evidence.
func ownedCanaryEnvelope(raw []byte) (present, canonical bool, err error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return false, false, errors.New("owned-receipt-envelope-invalid")
	}
	count := 0
	canonical = true
	for decoder.More() {
		token, tokenErr := decoder.Token()
		name, ok := token.(string)
		if tokenErr != nil || !ok {
			return present, false, errors.New("owned-receipt-envelope-invalid")
		}
		if strings.EqualFold(name, "owned_runtime") {
			present = true
			count++
			canonical = canonical && name == "owned_runtime" && count == 1
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return present, false, errors.New("owned-receipt-envelope-invalid")
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return present, false, errors.New("owned-receipt-envelope-invalid")
	}
	var trailing json.RawMessage
	if decoder.Decode(&trailing) != io.EOF {
		return present, false, errors.New("owned-receipt-envelope-invalid")
	}
	return present, canonical, nil
}

// ownedHTTPSResponse retains the owned operation deadline. It does not expose
// mutable headers, TLS objects or response buffers to a service validator.
func ownedHTTPSResponse(ctx context.Context, client *http.Client, raw, challenge string, limit int, requireOK, sample bool) (OwnedServiceResponse, error) {
	if ctx == nil || ctx.Err() != nil || client == nil || limit <= 0 || limit > ownedServiceBodyLimit {
		return OwnedServiceResponse{}, errOwnedNetworkHTTP
	}
	ctx, cancel := ownedOperationRequestContext(ctx, 20*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return OwnedServiceResponse{}, errOwnedNetworkHTTP
	}
	request.Close = true
	request.Header.Set("User-Agent", "RAZVILKA-Owned-USQUE-Probe/1")
	if challenge != "" {
		request.Header.Set(TransportChallengeHeader, challenge)
	}
	response, err := client.Do(request)
	if err != nil {
		return OwnedServiceResponse{}, errOwnedNetworkHTTP
	}
	defer response.Body.Close()
	contentType := response.Header.Get("Content-Type")
	if response.StatusCode < 200 || response.StatusCode > 299 || requireOK && response.StatusCode != http.StatusOK || !sample && response.ContentLength > int64(limit) || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 || len(contentType) > 256 || strings.ContainsAny(contentType, "\r\n\x00") {
		return OwnedServiceResponse{}, errOwnedNetworkHTTP
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, int64(limit)+1))
	defer clear(body)
	if err != nil || !sample && len(body) > limit || ctx.Err() != nil {
		return OwnedServiceResponse{}, errOwnedNetworkHTTP
	}
	truncated := len(body) > limit || response.ContentLength > int64(len(body))
	if !sample && truncated {
		return OwnedServiceResponse{}, errOwnedNetworkHTTP
	}
	if len(body) > limit {
		body = body[:limit]
	}
	return OwnedServiceResponse{URL: raw, HTTPStatus: response.StatusCode, ContentType: contentType, Body: string(body), BodyTruncated: truncated}, nil
}

func validateOwnedServiceResponse(ctx context.Context, service OwnedServiceProbe, challenge string, response OwnedServiceResponse) error {
	if ctx == nil || ctx.Err() != nil || response.URL != service.URL || response.HTTPStatus < 200 || response.HTTPStatus > 299 || len(response.Body) > ownedServiceBodyLimit {
		return errOwnedNetworkService
	}
	if service.Challenge {
		expected := TransportChallengeResponse(challenge)
		if response.BodyTruncated || response.HTTPStatus != http.StatusOK || expected == "" || response.Body != expected {
			return errOwnedNetworkService
		}
	} else if challenge != "" {
		return errOwnedNetworkService
	}
	if service.Validator != nil {
		if err := service.Validator(response); err != nil {
			return errOwnedNetworkService
		}
	}
	if ctx.Err() != nil {
		return errOwnedNetworkStopped
	}
	return nil
}

func recordOwnedServiceProof(proof *OwnedApplicationProof, service OwnedServiceProbe) {
	proof.ReachableRoutes = append(proof.ReachableRoutes, service.ID)
	if service.Validator != nil {
		proof.ConfirmedRoutes = append(proof.ConfirmedRoutes, service.ID)
	}
	if service.Challenge {
		proof.ChallengeRoutes = append(proof.ChallengeRoutes, service.ID)
	}
}

func safeOwnedServiceRoutes(reachable, confirmed, challenges []string) bool {
	if len(reachable) > 8 || len(confirmed) > 8 || len(challenges) > 8 {
		return false
	}
	seen := make(map[string]bool, len(reachable))
	for _, id := range reachable {
		if !ownedServiceID(id) || seen[id] {
			return false
		}
		seen[id] = true
	}
	for _, grade := range [][]string{confirmed, challenges} {
		subset := make(map[string]bool, len(grade))
		for _, id := range grade {
			if !seen[id] || subset[id] {
				return false
			}
			subset[id] = true
		}
	}
	return true
}

func ownedServiceProofMatches(services []OwnedServiceProbe, proof OwnedApplicationProof) bool {
	if len(proof.ReachableRoutes) != len(services) || !safeOwnedServiceRoutes(proof.ReachableRoutes, proof.ConfirmedRoutes, proof.ChallengeRoutes) {
		return false
	}
	reachable := make(map[string]bool, len(proof.ReachableRoutes))
	for _, id := range proof.ReachableRoutes {
		reachable[id] = true
	}
	confirmed := make(map[string]bool, len(proof.ConfirmedRoutes))
	for _, id := range proof.ConfirmedRoutes {
		confirmed[id] = true
	}
	challenges := make(map[string]bool, len(proof.ChallengeRoutes))
	for _, id := range proof.ChallengeRoutes {
		challenges[id] = true
	}
	for _, service := range services {
		if !reachable[service.ID] || confirmed[service.ID] != (service.Validator != nil) || challenges[service.ID] != service.Challenge {
			return false
		}
	}
	return true
}
