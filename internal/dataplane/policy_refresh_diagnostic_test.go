package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type diagnosticRefreshAdapter struct {
	*fakeAdapter
	cause error
}

func (a *diagnosticRefreshAdapter) RefreshPolicy(context.Context, Plan) (bool, error) {
	return false, a.cause
}

func TestPolicyRefreshDiagnosticKnownAndSecretErrors(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cause error
		code  string
	}{
		{"dns", fmt.Errorf("secret-profile token=private: %w", ErrDNSRefreshIncomplete), "dns-incomplete"},
		{"deadline", errors.Join(errors.New("secret-host.example"), context.DeadlineExceeded), "deadline"},
		{"unknown", errors.New("secret-host.example token=private C:/private/profile"), "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := New(t.TempDir())
			if err := m.Register(&diagnosticRefreshAdapter{&fakeAdapter{id: "nfqws2"}, tc.cause}); err != nil {
				t.Fatal(err)
			}
			plan, err := BuildAt(Input{Revision: 1, Routes: []Route{{ServiceID: "youtube", Resolved: "nfqws2"}}, Engines: []Engine{{ID: "nfqws2", Installed: true, Configured: true, Activatable: true}}, Host: HostState{IPCommand: true, IPTables: true, IP6Tables: true, NFQueueTarget: true, NFQWS2Config: true, NFQWS2Init: true, OffloadState: "disabled"}}, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			plan.State = "committed"
			if err = m.Record(plan); err != nil {
				t.Fatal(err)
			}
			_, err = m.RefreshCommitted(context.Background())
			if !errors.Is(err, tc.cause) {
				t.Fatalf("original cause lost: %v", err)
			}
			raw, err := os.ReadFile(filepath.Join(m.StateRoot, "latest-policy-refresh.json"))
			if err != nil {
				t.Fatal(err)
			}
			var report PolicyRefresh
			if err = json.Unmarshal(raw, &report); err != nil {
				t.Fatal(err)
			}
			if report.FailureStage != "adapter-refresh" || report.FailureAdapter != "nfqws2" || report.FailureCause != tc.code {
				t.Fatalf("unexpected diagnostic: %+v", report)
			}
			for _, secret := range []string{"secret-", "token=", "C:/private"} {
				if strings.Contains(string(raw), secret) {
					t.Fatal("diagnostic leaked error material")
				}
			}
		})
	}
}
func TestPolicyRefreshDiagnosticCodesAreClosed(t *testing.T) {
	if policyRefreshAdapterCode("secret-token") != "unknown" {
		t.Fatal("arbitrary adapter exposed")
	}
	for _, tc := range []struct {
		err  error
		code string
	}{
		{context.Canceled, "canceled"}, {ErrNetworkChanged, "network-changed"}, {ErrReviewChanged, "review-changed"},
		{ErrPolicyAdditionUnknown, "policy-settlement-unknown"}, {ErrProxyPolicyUnknown, "proxy-policy-unknown"},
		{ErrRuntimeInactivity, "runtime-inactivity-unconfirmed"}, {ErrProxyRuntimeInactive, "proxy-inactivity-unconfirmed"},
		{ErrPolicyDefaultReferenced, "policy-default-referenced"}, {ErrNodeEndpointChanged, "endpoint-changed"},
		{ErrWGEndpointChanged, "endpoint-changed"}, {ErrExecutionJournal, "journal-unavailable"},
	} {
		if got := policyRefreshFailureCause(fmt.Errorf("private: %w", tc.err)); got != tc.code {
			t.Fatalf("got %s want %s", got, tc.code)
		}
	}
}

func TestPolicyRefreshNetworkDiagnosticUsesActualFailureBoundary(t *testing.T) {
	for _, tc := range []struct {
		name  string
		at    int
		stage string
	}{
		{"initial", 1, "network-before"}, {"closing", 3, "network-after"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := New(t.TempDir())
			if err := m.Register(&diagnosticRefreshAdapter{&fakeAdapter{id: "sing-box"}, errors.New("private-adapter-failure")}); err != nil {
				t.Fatal(err)
			}
			plan := networkExecutionPlan()
			plan.State = "committed"
			if err := m.Record(plan); err != nil {
				t.Fatal(err)
			}
			calls := 0
			m.FreshProfile = func(context.Context) (string, error) {
				calls++
				if calls >= tc.at {
					return "wan-ffffffffffff", nil
				}
				return executionNetwork, nil
			}
			_, err := m.RefreshCommitted(context.Background())
			if !errors.Is(err, ErrNetworkChanged) {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(filepath.Join(m.StateRoot, "latest-policy-refresh.json"))
			if err != nil {
				t.Fatal(err)
			}
			var report PolicyRefresh
			if err = json.Unmarshal(raw, &report); err != nil {
				t.Fatal(err)
			}
			if report.FailureStage != tc.stage || report.FailureCause != "network-changed" || report.FailureAdapter != "" {
				t.Fatalf("unexpected boundary: %+v", report)
			}
		})
	}
}
