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
)

func storedCandidate(t *testing.T, random byte) (*Store, Account, RegistrationCandidate) {
	t.Helper()
	candidate, err := (Registrar{
		API:    &mockRegistrationAPI{result: validRegistrationResponse()},
		Random: bytes.NewReader(bytes.Repeat([]byte{random}, 64)),
	}).NewCandidate(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	store, _ := privateStore(t)
	account, err := store.ImportCandidate(context.Background(), candidate)
	if err != nil {
		t.Fatal(err)
	}
	return store, account, candidate
}

func TestWireGuardCandidateIsInertBoundedAndRedacted(t *testing.T) {
	store, account, registration := storedCandidate(t, 19)
	privateMarker := base64.StdEncoding.EncodeToString(registration.privateKey)
	var retained WireGuardCandidate
	err := store.WithWireGuardCandidate(context.Background(), account.ID, CandidateOptions{}, func(_ context.Context, candidate WireGuardCandidate) error {
		retained = candidate
		view := candidate.Public()
		if view.AccountID != account.ID || view.Endpoint != "162.159.192.1:2408" || view.MTU != 1280 || view.PersistentKeepalive != 25 || view.Verification != "built-unverified" {
			t.Fatalf("unexpected candidate: %+v", view)
		}
		encoded, _ := json.Marshal(candidate)
		output := string(encoded) + fmt.Sprintf(" %s %+v %#v", candidate, candidate, candidate)
		if strings.Contains(output, privateMarker) || strings.Contains(output, "private-token-marker") || strings.Contains(output, "private-device-marker") {
			t.Fatal("candidate leaked secrets through public representation")
		}
		var config bytes.Buffer
		if err := candidate.WriteConfig(&config); err != nil {
			t.Fatal(err)
		}
		text := config.String()
		for _, required := range []string{privateMarker, "Address = 172.16.0.2/32, 2606:4700:110::2/128", "Endpoint = 162.159.192.1:2408", "AllowedIPs = 0.0.0.0/0, ::/0"} {
			if !strings.Contains(text, required) {
				t.Fatalf("candidate config lacks %q", required)
			}
		}
		for _, forbidden := range []string{"DNS =", "PostUp", "PreUp", "private-token-marker", "private-device-marker"} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("candidate config contains forbidden field %q", forbidden)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := retained.WriteConfig(&bytes.Buffer{}); !errors.Is(err, ErrCandidateExpired) {
		t.Fatal("expired candidate remained exportable", err)
	}
}

func TestWireGuardCandidateOptionsAreBounded(t *testing.T) {
	store, account, _ := storedCandidate(t, 23)
	called := false
	consume := func(context.Context, WireGuardCandidate) error { called = true; return nil }
	for _, options := range []CandidateOptions{
		{EndpointIndex: -1}, {EndpointIndex: 2}, {MTU: 575}, {MTU: 1501},
		{PersistentKeepalive: -1}, {PersistentKeepalive: 121},
	} {
		called = false
		if err := store.WithWireGuardCandidate(context.Background(), account.ID, options, consume); !errors.Is(err, ErrCandidateInvalid) || called {
			t.Fatalf("invalid options reached candidate consumer: %+v err=%v", options, err)
		}
	}
	if err := store.WithWireGuardCandidate(context.Background(), account.ID, CandidateOptions{EndpointIndex: 1, MTU: 1360, PersistentKeepalive: 15}, func(_ context.Context, candidate WireGuardCandidate) error {
		if candidate.Public().Endpoint != "[2606:4700:d0::1]:2408" || candidate.Public().MTU != 1360 || candidate.Public().PersistentKeepalive != 15 {
			t.Fatal("valid explicit options were not preserved")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestWireGuardCandidatePropagatesConsumerFailure(t *testing.T) {
	store, account, _ := storedCandidate(t, 29)
	want := errors.New("isolated runner stopped")
	if err := store.WithWireGuardCandidate(context.Background(), account.ID, CandidateOptions{}, func(context.Context, WireGuardCandidate) error { return want }); !errors.Is(err, want) {
		t.Fatal("candidate consumer failure was hidden", err)
	}
}
