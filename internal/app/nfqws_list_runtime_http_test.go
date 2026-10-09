package app

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestManagedNFQRuntimeCallBudgetKeepsOriginalParentAndCleanupBounds(t *testing.T) {
	type callerValueKey struct{}
	caller := context.WithValue(context.Background(), callerValueKey{}, "original caller")
	for _, action := range []string{"start", "plan", "apply", "check", "stop"} {
		t.Run(action, func(t *testing.T) {
			budget := 15 * time.Second
			if action == "start" || action == "plan" || action == "apply" {
				budget = defaultDataplaneApplyTimeout
			}
			before := time.Now()
			ctx, cancel := managedNFQRuntimeCallContext(caller, action)
			defer cancel()
			after := time.Now()
			deadline, bounded := ctx.Deadline()
			if !bounded || deadline.Before(before.Add(budget)) || deadline.After(after.Add(budget)) || ctx.Value(callerValueKey{}) != "original caller" {
				t.Fatal("caller deadline/value replaced or short cleanup budget widened", deadline)
			}
			parent, parentCancel := context.WithTimeout(caller, 2*time.Second)
			defer parentCancel()
			parentDeadline, _ := parent.Deadline()
			child, childCancel := managedNFQRuntimeCallContext(parent, action)
			defer childCancel()
			childDeadline, _ := child.Deadline()
			parentCancel()
			if childDeadline != parentDeadline || child.Err() != context.Canceled {
				t.Fatal("earlier original parent deadline/cancellation was renewed", childDeadline, child.Err())
			}
		})
	}
}

// The real HTTP security/admission and original Stores are exercised here.
// A positive native activation requires the real installed source and stock
// tools; it is deliberately not replaced with a synthetic successful runtime.
func TestManagedNFQRuntimeHTTPMissingStartupOwnerDoesNotCreateOrApply(t *testing.T) {
	a := managedNFQInitialControlFixture(t)
	if _, err := a.StrategyLab.AddCandidate("tcp-tls", "original", "--filter-tcp=443", "expert"); err != nil {
		t.Fatal(err)
	}
	before := a.Store.Get()
	source, err := os.ReadFile(a.StrategyLab.Path)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	for _, body := range []map[string]any{
		{"action": "start", "service_id": "telegram", "protocol": "tcp", "ip_family": "ipv4"},
		{"action": "check"}, {"action": "stop"},
	} {
		status, data := componentHTTP(t, server, "POST", managedNFQListRuntimePath, body, componentRecoveryToken, server.URL)
		if status != http.StatusServiceUnavailable || !bytes.Contains(data, []byte("MANAGED_NFQWS_RUNTIME_UNAVAILABLE")) || bytes.Contains(data, []byte("native-active")) || bytes.Contains(data, []byte("live_applied")) {
			t.Fatal("missing original owner created activation claim", status, string(data))
		}
	}
	after, err := os.ReadFile(a.StrategyLab.Path)
	if err != nil || !bytes.Equal(source, after) || !reflect.DeepEqual(before, a.Store.Get()) || a.managedNFQList != nil || a.Operations.Snapshot().Active != 0 {
		t.Fatal("HTTP created owner, changed source/config or retained admission", err)
	}
}

func TestManagedNFQRuntimeHTTPRequiresSecurityAndExactFiniteIntent(t *testing.T) {
	a := managedNFQInitialControlFixture(t)
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	for _, request := range []struct {
		method, token, origin string
		body                  any
		want                  int
	}{
		{"POST", "", server.URL, map[string]any{"action": "stop"}, 401},
		{"POST", componentRecoveryToken, "https://foreign.example", map[string]any{"action": "stop"}, 403},
		{"GET", componentRecoveryToken, server.URL, nil, 405},
		{"POST", componentRecoveryToken, server.URL, map[string]any{"action": "resume"}, 400},
		{"POST", componentRecoveryToken, server.URL, map[string]any{"action": "start", "service_id": "service", "protocol": "udp", "ip_family": "ipv4"}, 400},
		{"POST", componentRecoveryToken, server.URL, map[string]any{"action": "start", "service_id": "service", "protocol": "tcp", "ip_family": "ipv7"}, 400},
		{"POST", componentRecoveryToken, server.URL, map[string]any{"action": "stop", "service_id": "other"}, 400},
		{"POST", componentRecoveryToken, server.URL, map[string]any{"action": "start", "trusted_assets": true}, 400},
		{"POST", componentRecoveryToken, server.URL, map[string]any{"action": "start", "runner": "request supplied", "ready": true}, 400},
	} {
		status, data := componentHTTP(t, server, request.method, managedNFQListRuntimePath, request.body, request.token, request.origin)
		if status != request.want {
			t.Fatal("security/intent admitted", status, string(data))
		}
	}
	response := httptest.NewRecorder()
	a.managedNFQListRuntimeHTTP(response, httptest.NewRequest("POST", managedNFQListRuntimePath, bytes.NewBufferString(`{"action":"stop"}{"action":"start"}`)))
	if response.Code != http.StatusBadRequest || a.Operations.Snapshot().Active != 0 {
		t.Fatal("multiple intents admitted", response.Code)
	}
}

func TestManagedNFQRuntimeHTTPCannotAdoptDecodedOrCopiedOwnerBehindFence(t *testing.T) {
	a := managedNFQInitialControlFixture(t)
	// A zero/decoded runtime or copied owner is never the original factory
	// object. The cleanup endpoint bypasses middleware admission, not the
	// runtime's private ownership checks; fencing cannot turn it into a grant.
	original := &ManagedNFQWSListRuntime{}
	original.self = original
	a.managedNFQList = &ManagedNFQWSListRuntime{self: original}
	a.Operations.FenceJournal()
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	status, data := componentHTTP(t, server, "POST", managedNFQListRuntimePath, map[string]any{"action": "stop"}, componentRecoveryToken, server.URL)
	if status != http.StatusConflict || !bytes.Contains(data, []byte("MANAGED_NFQWS_RUNTIME_REFUSED")) || a.Operations.Snapshot().Active != 0 || !a.Operations.Snapshot().Fenced {
		t.Fatal("copied owner adopted or new operation entered", status, string(data))
	}
	if a.managedNFQList.Stop(context.Background()) == nil {
		t.Fatal("copied owner directly accepted Stop")
	}
}
