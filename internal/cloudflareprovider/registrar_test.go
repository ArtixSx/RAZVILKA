package cloudflareprovider

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

type mockRegistrationAPI struct {
	request RegistrationRequest
	result  RegistrationResponse
	err     error
	calls   int
}

func (mock *mockRegistrationAPI) Register(_ context.Context, request RegistrationRequest) (RegistrationResponse, error) {
	mock.calls++
	mock.request = request
	return mock.result, mock.err
}

func validRegistrationResponse() RegistrationResponse {
	return RegistrationResponse{
		DeviceID: "private-device-marker", AccessToken: "private-token-marker",
		PeerPublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)),
		Addresses:     []string{"172.16.0.2/32", "2606:4700:110::2/128"},
		Endpoints:     []string{"162.159.192.1:2408", "[2606:4700:d0::1]:2408"},
		APISchema:     "mock-v1", TermsRevision: "cloudflare-client-current",
	}
}

func TestRegistrarGeneratesKeyLocallyAndExposesOnlyPublicMaterial(t *testing.T) {
	mock := &mockRegistrationAPI{result: validRegistrationResponse()}
	registrar := Registrar{API: mock, Random: bytes.NewReader(bytes.Repeat([]byte{7}, 64)), Now: func() time.Time { return time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC) }}
	candidate, err := registrar.NewCandidate(context.Background(), true)
	if err != nil || mock.calls != 1 {
		t.Fatal(err, mock.calls)
	}
	if !mock.request.AcceptTerms || mock.request.PublicKey == "" || mock.request.TermsRevision == "" {
		t.Fatalf("incomplete public request: %+v", mock.request)
	}
	privateMarker := base64.StdEncoding.EncodeToString(candidate.privateKey)
	requestJSON, _ := json.Marshal(mock.request)
	if bytes.Contains(requestJSON, candidate.privateKey) || strings.Contains(string(requestJSON), privateMarker) {
		t.Fatal("private key crossed registrar API boundary")
	}
	view := candidate.Public()
	if view.Verification != "registered-unverified" || view.Ownership != "locally-generated-candidate" || len(view.PublicKeyFingerprint) != 64 || len(view.AssignedAddresses) != 2 {
		t.Fatalf("unexpected public candidate: %+v", view)
	}
	encoded, _ := json.Marshal(candidate)
	responseJSON, _ := json.Marshal(candidate.response)
	for _, output := range []string{string(encoded), fmt.Sprintf("%s %+v %#v", candidate, candidate, candidate), string(responseJSON), fmt.Sprintf("%s %+v %#v %q", candidate.response, candidate.response, candidate.response, candidate.response)} {
		for _, secret := range []string{privateMarker, "private-device-marker", "private-token-marker"} {
			if strings.Contains(output, secret) {
				t.Fatalf("registration secret leaked through public representation: %s", secret)
			}
		}
	}
}

func TestRegistrarRequiresTermsAPIAndValidResponse(t *testing.T) {
	valid := &mockRegistrationAPI{result: validRegistrationResponse()}
	if _, err := (Registrar{API: valid}).NewCandidate(context.Background(), false); !errors.Is(err, ErrRegistrationTerms) || valid.calls != 0 {
		t.Fatal("terms gate did not prevent registration", err, valid.calls)
	}
	if _, err := (Registrar{}).NewCandidate(context.Background(), true); !errors.Is(err, ErrRegistrationAPIAbsent) {
		t.Fatal("missing API was accepted", err)
	}
	for name, mutate := range map[string]func(*RegistrationResponse){
		"missing-token":     func(response *RegistrationResponse) { response.AccessToken = "" },
		"bad-peer-key":      func(response *RegistrationResponse) { response.PeerPublicKey = "bad" },
		"private-endpoint":  func(response *RegistrationResponse) { response.Endpoints = []string{"192.168.1.1:2408"} },
		"duplicate-address": func(response *RegistrationResponse) { response.Addresses = []string{"172.16.0.2/32", "172.16.0.2/32"} },
		"wrong-terms":       func(response *RegistrationResponse) { response.TermsRevision = "future" },
	} {
		t.Run(name, func(t *testing.T) {
			response := validRegistrationResponse()
			mutate(&response)
			mock := &mockRegistrationAPI{result: response}
			if _, err := (Registrar{API: mock, Random: bytes.NewReader(bytes.Repeat([]byte{3}, 64))}).NewCandidate(context.Background(), true); !errors.Is(err, ErrRegistration) {
				t.Fatal("invalid response accepted", err)
			}
		})
	}
}

func TestRegistrarHonorsCancellationBeforeNetwork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	mock := &mockRegistrationAPI{result: validRegistrationResponse()}
	if _, err := (Registrar{API: mock}).NewCandidate(ctx, true); !errors.Is(err, context.Canceled) || mock.calls != 0 {
		t.Fatal("canceled registration reached API", err, mock.calls)
	}
}
