package cloudflareprovider

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func reviewedWGFixture(endpoint string) []byte {
	private := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	public := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	return []byte("[Interface]\nPrivateKey = " + private + "\nAddress = 172.16.0.2/32, 2606:4700:110::2/128\nDNS = 1.1.1.1\nMTU = 1280\n[Peer]\nPublicKey = " + public + "\nEndpoint = " + endpoint + "\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n")
}

func TestReviewedWireGuardCandidateIsExplicitEphemeralAndRedacted(t *testing.T) {
	profile := reviewedWGFixture("162.159.192.1:2408")
	called := false
	var retained WireGuardCandidate
	err := WithReviewedWireGuardCandidate(context.Background(), profile, true, CandidateOptions{}, func(_ context.Context, candidate WireGuardCandidate) error {
		called = true
		retained = candidate
		view := candidate.Public()
		if view.Endpoint != "162.159.192.1:2408" || view.MTU != 1280 || view.PersistentKeepalive != 25 || !view.valid || !strings.HasPrefix(view.RoutePathID, "cloudflare-wg:") {
			t.Fatalf("wrong reviewed candidate: %+v", view)
		}
		if view.EndpointCatalog.AddressClass != EndpointOfficialConsumer || len(candidate.privateKey) != 32 || len(candidate.peerPublicKey) != 32 {
			t.Fatal("reviewed candidate lost private material or endpoint classification")
		}
		return nil
	})
	if err != nil || !called {
		t.Fatal(err)
	}
	if !bytes.Equal(retained.privateKey, make([]byte, 32)) || !bytes.Equal(retained.peerPublicKey, make([]byte, 32)) {
		t.Fatal("reviewed candidate keys survived their callback lease")
	}
}

func TestReviewedWireGuardCandidateRejectsImplicitOrUnsafeInput(t *testing.T) {
	consume := func(context.Context, WireGuardCandidate) error {
		t.Fatal("unsafe candidate reached consumer")
		return nil
	}
	for _, test := range []struct {
		name     string
		profile  []byte
		reviewed bool
	}{
		{"not-reviewed", reviewedWGFixture("162.159.192.1:2408"), false},
		{"hostname", reviewedWGFixture("engage.cloudflareclient.com:2408"), true},
		{"private-endpoint", reviewedWGFixture("192.168.1.1:2408"), true},
		{"not-full-tunnel", bytes.Replace(reviewedWGFixture("162.159.192.1:2408"), []byte("0.0.0.0/0, ::/0"), []byte("1.1.1.1/32"), 1), true},
		{"preshared", bytes.Replace(reviewedWGFixture("162.159.192.1:2408"), []byte("AllowedIPs"), []byte("PresharedKey = "+base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32))+"\nAllowedIPs"), 1), true},
		{"nul", append(reviewedWGFixture("162.159.192.1:2408"), 0), true},
		{"oversize", bytes.Repeat([]byte{'x'}, MaxImportBytes+1), true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := WithReviewedWireGuardCandidate(context.Background(), test.profile, test.reviewed, CandidateOptions{}, consume); !errors.Is(err, ErrReviewedCandidate) {
				t.Fatalf("unsafe reviewed profile accepted: %v", err)
			}
		})
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := WithReviewedWireGuardCandidate(canceled, reviewedWGFixture("162.159.192.1:2408"), true, CandidateOptions{}, consume); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled reviewed candidate was not rejected", err)
	}
}

func TestReviewedEndpointSafety(t *testing.T) {
	for _, raw := range []string{"162.159.192.1", "2606:4700:100::1"} {
		if !safeReviewedEndpoint(netip.MustParseAddr(raw)) {
			t.Fatal("public endpoint rejected", raw)
		}
	}
}
