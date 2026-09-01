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

func TestLocalCandidatePersistsAtomicallyButCannotBeForgedByPublicImport(t *testing.T) {
	mock := &mockRegistrationAPI{result: validRegistrationResponse()}
	candidate, err := (Registrar{API: mock, Random: bytes.NewReader(bytes.Repeat([]byte{5}, 64))}).NewCandidate(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := candidate.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseImport(SourceLocalRegistration, snapshot.raw); !errors.Is(err, ErrImport) {
		t.Fatal("public import forged a locally generated registration", err)
	}
	store, _ := privateStore(t)
	first, err := store.ImportCandidate(context.Background(), candidate)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.ImportCandidate(context.Background(), candidate)
	if err != nil || second.ID != first.ID {
		t.Fatal("candidate persistence is not idempotent", err)
	}
	list, err := store.List(context.Background())
	if err != nil || len(list) != 1 {
		t.Fatal(err, len(list))
	}
	view := list[0]
	if view.SourceKind != SourceLocalRegistration || view.Ownership != "locally-generated-candidate" || view.Verification != "registered-unverified" || !view.HasPrivateKey || !view.HasDeviceID || !view.HasAccessToken {
		t.Fatalf("stored candidate was misclassified: %+v", view)
	}
	encoded, _ := json.Marshal(list)
	for _, secret := range []string{base64.StdEncoding.EncodeToString(candidate.privateKey), "private-device-marker", "private-token-marker"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatal("stored candidate leaked through List", secret)
		}
	}
}

func TestLocalCandidateEncryptedBackupRoundTripStaysInactive(t *testing.T) {
	mock := &mockRegistrationAPI{result: validRegistrationResponse()}
	candidate, err := (Registrar{API: mock, Random: bytes.NewReader(bytes.Repeat([]byte{11}, 64))}).NewCandidate(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	source, _ := privateStore(t)
	if _, err := source.ImportCandidate(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	envelope, err := source.Backup(context.Background(), "registrar-test-password", "0.18.1-dev")
	if err != nil {
		t.Fatal(err)
	}
	destination, _ := privateStore(t)
	review, err := destination.PreviewBackup(context.Background(), envelope, "registrar-test-password")
	if err != nil || review.Added != 1 {
		t.Fatal("local candidate backup preview failed", review, err)
	}
	restored, err := destination.RestoreReviewedBackup(context.Background(), envelope, "registrar-test-password", review.Digest)
	if err != nil || len(restored) != 1 || restored[0].SourceKind != SourceLocalRegistration || restored[0].Verification != "registered-unverified" {
		t.Fatalf("local candidate backup restore=%+v err=%v", restored, err)
	}
}
