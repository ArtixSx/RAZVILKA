package dnscontrol

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// Explicitly opt-in, read-only hardware gate. No registration, service restart,
// file persistence or resolver changes are performed by this test.
func TestUSQUECandidateDNSLiveQuad9(t *testing.T) {
	if os.Getenv("RAZVILKA_TEST_USQUE_DNS_LIVE") != "1" {
		t.Skip("requires explicit read-only live DNS test opt-in")
	}
	m, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(m.Snapshot())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, err := m.ResolveCandidate(ctx, "quad9-unfiltered", "api.cloudflareclient.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range result.Results {
		t.Logf("%s: %s; public answers=%d; v4=%t; v6=%t; error=%s", item.Transport, item.Status, item.Addresses, item.IPv4, item.IPv6, item.Error)
	}
	after, _ := json.Marshal(m.Snapshot())
	if string(before) != string(after) {
		t.Fatal("candidate changed DNS state")
	}
	if !result.Ready {
		t.Fatal("no Quad9 endpoint returned verified public registration DNS answers")
	}
}
