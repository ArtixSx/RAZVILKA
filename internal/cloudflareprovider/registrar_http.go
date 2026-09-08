package cloudflareprovider

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"
)

// This is an upstream-observed consumer API, not a documented Cloudflare
// stability contract. Request fields are pinned to USQUE v4.2.1 api/cloudflare.go
// and internal/consts.go. No existing enrollment is read or changed.
const ConsumerRegistrationVersion = "v0a4471"
const consumerRegistrationURL = "https://api.cloudflareclient.com/" + ConsumerRegistrationVersion + "/reg"
const maxConsumerResponse = 64 << 10

// RegistrationHTTPError exposes only bounded status facts. Bodies, endpoint
// errors, device IDs and tokens are deliberately absent from every format.
type RegistrationHTTPError struct {
	HTTPStatus  int    `json:"http_status,omitempty"`
	Uncertain   bool   `json:"remote_creation_uncertain"`
	RetryAfter  int    `json:"retry_after_seconds,omitempty"`
	SchemaCheck string `json:"schema_check,omitempty"`
}

func (e *RegistrationHTTPError) Error() string {
	return fmt.Sprintf("Cloudflare registration failed (HTTP %d; remote creation uncertain: %t; retry-after seconds: %d); no automatic retry", e.HTTPStatus, e.Uncertain, e.RetryAfter)
}

// ConsumerRegistrationAPI performs one bounded POST. It has no account-update,
// enrollment, redirect, proxy-environment or automatic retry capability.
type ConsumerRegistrationAPI struct {
	client *http.Client
	now    func() time.Time
	// CheckpointResponse is a trusted local private sink, used before decoding a
	// successful response. It must not log or expose its bytes publicly.
	CheckpointResponse func([]byte) error
}

func NewConsumerRegistrationAPI() *ConsumerRegistrationAPI {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	transport.TLSHandshakeTimeout = 8 * time.Second
	transport.ResponseHeaderTimeout = 12 * time.Second
	return &ConsumerRegistrationAPI{client: &http.Client{
		Transport: transport, Timeout: 20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, now: time.Now}
}

func (api *ConsumerRegistrationAPI) Register(ctx context.Context, input RegistrationRequest) (RegistrationResponse, error) {
	if api == nil || api.client == nil || !input.AcceptTerms || input.TermsRevision != registrationTerms {
		return RegistrationResponse{}, ErrRegistrationTerms
	}
	if _, err := wireGuardKey(input.PublicKey); err != nil || !boundedPublicText(input.Locale) || !boundedPublicText(input.Model) {
		return RegistrationResponse{}, ErrRegistration
	}
	if err := ctx.Err(); err != nil {
		return RegistrationResponse{}, err
	}
	serial := make([]byte, 8)
	if _, err := rand.Read(serial); err != nil {
		return RegistrationResponse{}, ErrRegistration
	}
	now := time.Now().UTC()
	if api.now != nil {
		now = api.now().UTC()
	}
	body, _ := json.Marshal(struct {
		Key        string `json:"key"`
		InstallID  string `json:"install_id"`
		FCMToken   string `json:"fcm_token"`
		TOS        string `json:"tos"`
		Model      string `json:"model"`
		Serial     string `json:"serial_number"`
		OSVersion  string `json:"os_version"`
		KeyType    string `json:"key_type"`
		TunnelType string `json:"tunnel_type"`
		Locale     string `json:"locale"`
	}{Key: input.PublicKey, TOS: now.Format(time.RFC3339Nano), Model: input.Model,
		Serial: hex.EncodeToString(serial), KeyType: "curve25519", TunnelType: "wireguard", Locale: input.Locale})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, consumerRegistrationURL, bytes.NewReader(body))
	if err != nil {
		return RegistrationResponse{}, ErrRegistration
	}
	request.GetBody = nil
	request.Header.Set("User-Agent", "WARP for Android")
	request.Header.Set("CF-Client-Version", "a-6.35-4471")
	request.Header.Set("Content-Type", "application/json; charset=UTF-8")
	response, err := api.client.Do(request)
	if err != nil {
		return RegistrationResponse{}, &RegistrationHTTPError{Uncertain: true}
	}
	defer response.Body.Close()
	failure := &RegistrationHTTPError{HTTPStatus: response.StatusCode, Uncertain: response.StatusCode >= 500 || response.StatusCode >= 200 && response.StatusCode < 300}
	if seconds, err := strconv.Atoi(response.Header.Get("Retry-After")); err == nil && seconds > 0 && seconds <= 86400 {
		failure.RetryAfter = seconds
	}
	if response.StatusCode != http.StatusOK {
		return RegistrationResponse{}, failure
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxConsumerResponse+1))
	defer eraseBytes(data)
	if err != nil || len(data) > maxConsumerResponse {
		failure.SchemaCheck = "bounded-body"
		return RegistrationResponse{}, failure
	}
	if api.CheckpointResponse != nil {
		if err := api.CheckpointResponse(data); err != nil {
			failure.SchemaCheck = "private-checkpoint"
			return RegistrationResponse{}, failure
		}
	}
	return decodeConsumerRegistration(data, input)
}

func decodeConsumerRegistration(data []byte, input RegistrationRequest) (RegistrationResponse, error) {
	failure := &RegistrationHTTPError{HTTPStatus: http.StatusOK, Uncertain: true}
	if len(data) == 0 || len(data) > maxConsumerResponse {
		failure.SchemaCheck = "bounded-body"
		return RegistrationResponse{}, failure
	}
	var document struct {
		ID         string `json:"id"`
		Token      string `json:"token"`
		Key        string `json:"key"`
		KeyType    string `json:"key_type"`
		TunnelType string `json:"tunnel_type"`
		Config     struct {
			Interface struct {
				Addresses struct {
					V4 string `json:"v4"`
					V6 string `json:"v6"`
				} `json:"addresses"`
			} `json:"interface"`
			Peers []struct {
				PublicKey string `json:"public_key"`
				Endpoint  struct {
					V4    string `json:"v4"`
					V6    string `json:"v6"`
					Ports []int  `json:"ports"`
				} `json:"endpoint"`
			} `json:"peers"`
		} `json:"config"`
	}
	if json.Unmarshal(data, &document) != nil {
		failure.SchemaCheck = "json"
		return RegistrationResponse{}, failure
	}
	if document.Key != input.PublicKey {
		failure.SchemaCheck = "key-echo"
		return RegistrationResponse{}, failure
	}
	if document.KeyType != "curve25519" {
		failure.SchemaCheck = "key-type"
		return RegistrationResponse{}, failure
	}
	if document.TunnelType != "wireguard" {
		failure.SchemaCheck = "tunnel-type"
		return RegistrationResponse{}, failure
	}
	if len(document.Config.Peers) != 1 {
		failure.SchemaCheck = "peer-count"
		return RegistrationResponse{}, failure
	}
	result := RegistrationResponse{DeviceID: document.ID, AccessToken: document.Token, PeerPublicKey: document.Config.Peers[0].PublicKey,
		APISchema: ConsumerRegistrationVersion, TermsRevision: input.TermsRevision}
	for _, raw := range []string{document.Config.Interface.Addresses.V4, document.Config.Interface.Addresses.V6} {
		if raw == "" {
			continue
		}
		address, err := netip.ParseAddr(raw)
		if err != nil || address.Zone() != "" {
			failure.SchemaCheck = "assigned-address"
			return RegistrationResponse{}, failure
		}
		result.Addresses = append(result.Addresses, netip.PrefixFrom(address, address.BitLen()).String())
	}
	for _, endpoint := range []string{document.Config.Peers[0].Endpoint.V4, document.Config.Peers[0].Endpoint.V6} {
		if endpoint != "" {
			endpoints, err := expandIssuedEndpoint(endpoint, document.Config.Peers[0].Endpoint.Ports)
			if err != nil {
				failure.SchemaCheck = "issued-endpoint-ports"
				return RegistrationResponse{}, failure
			}
			result.Endpoints = append(result.Endpoints, endpoints...)
		}
	}
	if validateRegistrationResponse(result, input.TermsRevision) != nil {
		failure.SchemaCheck = "peer-key-address-endpoint"
		return RegistrationResponse{}, failure
	}
	return result, nil
}

// Current registration may return IP:0 together with a separate ports array.
// Expand only ports issued in that same response; never invent a fallback.
func expandIssuedEndpoint(endpoint string, ports []int) ([]string, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, ErrRegistration
	}
	if port != "0" {
		return []string{endpoint}, nil
	}
	if len(ports) == 0 || len(ports) > 8 {
		return nil, ErrRegistration
	}
	out := make([]string, 0, len(ports))
	seen := map[int]bool{}
	for _, port := range ports {
		if port < 1 || port > 65535 || seen[port] {
			return nil, ErrRegistration
		}
		seen[port] = true
		out = append(out, net.JoinHostPort(host, strconv.Itoa(port)))
	}
	return out, nil
}

// RecoverConsumerCandidate reconciles a locally checkpointed POST response
// with its original private key. It performs no network operation and still
// grants only registered-unverified provenance, never connectivity authority.
func RecoverConsumerCandidate(privateBytes, response []byte, now time.Time) (RegistrationCandidate, error) {
	if len(privateBytes) != 32 || now.IsZero() {
		return RegistrationCandidate{}, ErrRegistration
	}
	privateKey, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		return RegistrationCandidate{}, ErrRegistration
	}
	public := privateKey.PublicKey().Bytes()
	parsed, err := decodeConsumerRegistration(response, RegistrationRequest{PublicKey: base64.StdEncoding.EncodeToString(public), TermsRevision: registrationTerms})
	if err != nil {
		return RegistrationCandidate{}, err
	}
	return makeRegistrationCandidate(append([]byte(nil), privateBytes...), public, parsed, now.UTC()), nil
}

// safeRegistrationError preserves the concrete adapter's status without
// exposing arbitrary errors returned by mock or third-party API adapters.
func safeRegistrationError(err error) error {
	var failure *RegistrationHTTPError
	if errors.As(err, &failure) {
		return errors.Join(ErrRegistration, failure)
	}
	return ErrRegistration
}
