//go:build linux && razvilka_native_fixture

package dataplane

import (
	"bytes"
	"context"
	"errors"
	"log"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestNFQWSBoundaryMeasurementClosedOutput(t *testing.T) {
	t.Setenv("RAZVILKA_MANAGED_PROBE_FIXTURE_WORK", "fixture-only-secret-path")
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	m := beginNFQWSBoundaryMeasurement(ctx, "counter", "negative-before")
	m.begin("capture-opening")
	m.begin("command")
	m.cause("private-config-secret")
	m.end(errors.New("private-error-secret"), true)
	var out bytes.Buffer
	m.writeTo(&out, 17, "refused", "deadline")
	s := out.String()
	for _, want := range []string{"kind=counter role=negative-before", "cause=invalid", "records=2 overflow=false", "stage=capture-opening:returned-nil:", "stage=command:refused:"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q: %s", want, s)
		}
	}
	if strings.Contains(s, "secret") || m.openingRemaining >= 0 || m.rows[1].remaining >= 0 {
		t.Fatalf("private data or expired budget lost: %s", s)
	}
	bad := beginNFQWSBoundaryMeasurement(ctx, "private-kind", "private-role")
	bad.begin("private-stage")
	bad.end(nil, true)
	if bad.kind != "invalid" || bad.role != "invalid" || bad.rows[0].stage != "invalid" {
		t.Fatal("unknown label escaped")
	}
}

func TestNFQWSBoundaryMeasurementBoundAndIdentity(t *testing.T) {
	t.Setenv("RAZVILKA_MANAGED_PROBE_FIXTURE_WORK", "enabled")
	a := beginNFQWSBoundaryMeasurement(context.Background(), "counter", "positive-after")
	b := beginNFQWSBoundaryMeasurement(context.Background(), "counter", "negative-after")
	if a.id == 0 || a.id == b.id || a.finite || a.openingRemaining != 0 {
		t.Fatal("identity/finite declaration")
	}
	for i := 0; i < 9; i++ {
		a.begin("parse")
	}
	a.end(nil, true)
	if a.count != 5 || !a.overflow {
		t.Fatal("unbounded rows")
	}
	var out bytes.Buffer
	a.writeTo(&out, 0, "returned-nil", "returned-nil")
	if strings.Count(out.String(), " stage=") != 5 || out.Len() > 2048 {
		t.Fatal("output bounds")
	}
}

func TestNFQWSBoundaryMeasurementAbortAndCancellation(t *testing.T) {
	t.Setenv("RAZVILKA_MANAGED_PROBE_FIXTURE_WORK", "enabled")
	for _, mode := range []string{"panic", "goexit", "deadline", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			var out bytes.Buffer
			previous := log.Writer()
			log.SetOutput(&out)
			defer log.SetOutput(previous)
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer func() { _ = recover() }()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				m := beginNFQWSBoundaryMeasurement(ctx, "policy-apply", "unspecified")
				returned := false
				var result error
				defer func() { m.finish(ctx, result, returned) }()
				m.begin("effects")
				switch mode {
				case "panic":
					panic("private-panic")
				case "goexit":
					runtime.Goexit()
				case "deadline":
					result = context.DeadlineExceeded
				case "canceled":
					cancel()
					result = context.Canceled
				}
				returned = true
			}()
			<-done
			want := mode
			if mode == "panic" || mode == "goexit" {
				want = "aborted"
			}
			if !strings.Contains(out.String(), "outcome="+want) || strings.Contains(out.String(), "private-panic") {
				t.Fatalf("wrong completion %s", out.String())
			}
		})
	}
}

func TestNFQWSBoundaryMeasurementOriginalEntryRefusals(t *testing.T) {
	t.Setenv("RAZVILKA_MANAGED_PROBE_FIXTURE_WORK", "enabled")
	var out bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&out)
	defer log.SetOutput(previous)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := nfqws2ActiveRead(ctx, nil, true)
	if err != ErrNFQWSManagedProcessUnknown {
		t.Fatalf("changed owner error: %v", err)
	}
	if !strings.Contains(out.String(), "kind=owner-read") || !strings.Contains(out.String(), "stage=admission:refused:") {
		t.Fatal(out.String())
	}
	out.Reset()
	var b *NFQWSScopedBinding
	err = b.Apply(ctx, nil, "")
	if err != ErrNFQWSScopedOwner {
		t.Fatalf("changed apply error: %v", err)
	}
	if !strings.Contains(out.String(), "stage=prepare:refused:") || strings.Contains(out.String(), "stage=effects:") {
		t.Fatal(out.String())
	}
}

func TestNFQWSBoundaryMeasurementDisabled(t *testing.T) {
	t.Setenv("RAZVILKA_MANAGED_PROBE_FIXTURE_WORK", "")
	m := beginNFQWSBoundaryMeasurement(nil, "counter", "unspecified")
	m.begin("command")
	m.cause("protected-path")
	m.finish(nil, nil, true)
	if m.enabled || m.count != 0 || m.id != 0 || !m.started.IsZero() {
		t.Fatal("disabled measurement active")
	}
}
