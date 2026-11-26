package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/security"
)

func TestInstallProgressAuthAndReadDuringExclusiveInstall(t *testing.T) {
	sec, err := security.NewGate(componentRecoveryToken)
	if err != nil {
		t.Fatal(err)
	}
	a := &App{Security: sec}
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	held, release, err := a.Operations.ExclusiveContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	const id = "aabbccddeeff00112233445566778899"
	a.installProgress.begin(held, id)
	for _, tc := range []struct {
		token, id      string
		status, events int
	}{
		{"", id, 401, 0}, {componentRecoveryToken, id, 200, 1}, {componentRecoveryToken, strings.Repeat("f", 32), 200, 0}, {componentRecoveryToken, "not-an-id", 200, 0},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+installProgressPath, nil)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		req.Header.Set(installProgressHeader, tc.id)
		if tc.token != "" {
			req.Header.Set("Authorization", "Bearer "+tc.token)
		}
		resp, err := server.Client().Do(req)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		if resp.StatusCode != tc.status {
			t.Errorf("status: %d, want %d", resp.StatusCode, tc.status)
		}
		if tc.status == 200 {
			var body struct {
				Events []installEvent `json:"events"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if body.Events == nil || len(body.Events) != tc.events || resp.Header.Get("Cache-Control") != "no-store" {
				t.Errorf("unexpected response %+v", body)
			}
			for _, item := range body.Events {
				if item.At.IsZero() || item.Message != components.InstallPreflight.Message() {
					t.Errorf("unexpected first event %+v", item)
				}
			}
		}
		resp.Body.Close()
		cancel()
	}
}

func TestInstallProgressBoundedPerRequest(t *testing.T) {
	var p installProgress
	ctx := context.Background()
	for _, bad := range []string{"", strings.Repeat("A", 32), strings.Repeat("g", 32), "short", strings.Repeat("a", 33)} {
		if p.begin(ctx, bad) != ctx {
			t.Fatal("invalid ID registered")
		}
	}
	const id = "00000000000000000000000000000000"
	if p.begin(ctx, id) == ctx || p.begin(ctx, id) != ctx {
		t.Fatal("duplicate request replaced report")
	}
	first := p.reports[0]
	for i := 0; i < maxInstallEvents*2; i++ {
		p.record(first, components.InstallStage(i%2))
	}
	p.record(first, components.InstallStage(255))
	events := p.snapshot(id)
	if len(events) != maxInstallEvents {
		t.Fatalf("event cap %d", len(events))
	}
	events[0].Message = "modified"
	if p.snapshot(id)[0].Message == "modified" {
		t.Fatal("reader owns live data")
	}
	for i := 1; i <= maxInstallReports; i++ {
		p.begin(ctx, fmt.Sprintf("%032x", i))
	}
	if len(p.reports) != maxInstallReports || len(p.snapshot(id)) != 0 {
		t.Fatal("report cap")
	}
}
