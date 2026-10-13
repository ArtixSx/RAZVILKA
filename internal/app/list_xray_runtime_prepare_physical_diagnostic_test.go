package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/physicalscope"
)

func xrayPreparePhysicalRefusal(t *testing.T) error {
	t.Helper()
	// The genuine closed dependency guard rejects before a provider, reader,
	// fence or physical observation can run. It grants no native capability.
	review, err := physicalscope.NewReviewedStockNC1812(nil, nil).Observe(context.Background())
	if review != nil || err == nil {
		t.Fatal("original physical dependency guard did not refuse")
	}
	return err
}

func TestManagedXrayPreparePhysicalLogKeepsJoinedTypedCausePrivate(t *testing.T) {
	out := captureXrayDiagnosticLog(t)
	physical := xrayPreparePhysicalRefusal(t)
	private := xrayDiagnosticPrivateError{}
	joined := errors.Join(private, errors.Join(ErrListScopeChanged, physical), context.Canceled)
	logManagedXrayPrepareFailure("scope-acquire", time.Millisecond, joined)
	want := "Managed Xray prepare refused substage=scope-acquire elapsed_ms=1\n" +
		"Managed Xray prepare physical substage=scope-acquire physical_stages=observe.dependencies>context.canceled\n"
	if out.String() != want {
		t.Fatal("closed physical labels lost or private cause formatted", out.String())
	}
	if !errors.Is(joined, private) || !errors.Is(joined, physical) || !errors.Is(joined, ErrListScopeChanged) || !errors.Is(joined, context.Canceled) {
		t.Fatal("logging changed the retained original cause")
	}
	out.Reset()
	logManagedXrayPrepareFailure("private/path/node-id", time.Hour, physical)
	if out.String() != "Managed Xray prepare refused substage=unclassified elapsed_ms=120000\n"+
		"Managed Xray prepare physical substage=unclassified physical_stages=observe.dependencies\n" {
		t.Fatal("physical metadata accepted a foreign phase or unbounded duration", out.String())
	}
}

func TestManagedXrayPreparePhysicalLogRefusesUntypedAndContextOnlyStages(t *testing.T) {
	out := captureXrayDiagnosticLog(t)
	for _, err := range []error{
		xrayDiagnosticPrivateError{},
		errors.New("physical LAN: observe.capture > private/path/node-id"),
		errors.Join(physicalscope.ErrUnknown, xrayDiagnosticPrivateError{}),
		errors.Join(context.Canceled, context.DeadlineExceeded),
	} {
		out.Reset()
		logManagedXrayPrepareFailure("scope-acquire", time.Millisecond, err)
		if out.String() != "Managed Xray prepare refused substage=scope-acquire elapsed_ms=1\n" {
			t.Fatal("untyped or context-only error manufactured physical metadata", out.String())
		}
	}
	out.Reset()
	logManagedXrayPrepareFailure("scope-acquire", time.Millisecond, nil)
	if out.Len() != 0 {
		t.Fatal("successful prepare manufactured a refusal")
	}
}

func TestManagedXrayPreparePhysicalLogBoundsJoinedAndCyclicFields(t *testing.T) {
	out := captureXrayDiagnosticLog(t)
	physical := xrayPreparePhysicalRefusal(t)
	wide := make([]error, 200)
	for i := range wide {
		wide[i] = physical
	}
	logManagedXrayPrepareFailure("scope-acquire", time.Millisecond, errors.Join(wide...))
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	prefix := "Managed Xray prepare physical substage=scope-acquire physical_stages="
	if len(lines) != 2 || !strings.HasPrefix(lines[1], prefix) {
		t.Fatal("joined physical metadata lost its single finite field", out.String())
	}
	labels := strings.Split(strings.TrimPrefix(lines[1], prefix), ">")
	if len(labels) < 1 || len(labels) > 64 || len(lines[1]) > len(prefix)+64*len("observe.dependencies>") {
		t.Fatal("joined physical metadata exceeded extractor bound")
	}
	for _, label := range labels {
		if label != "observe.dependencies" {
			t.Fatal("joined field contains an unrecognized label")
		}
	}
	out.Reset()
	cycle := &xrayDiagnosticCycle{}
	logManagedXrayPrepareFailure("scope-acquire", time.Millisecond, cycle)
	if cycle.visits > 64 || out.String() != "Managed Xray prepare refused substage=scope-acquire elapsed_ms=1\n" {
		t.Fatal("opaque cyclic error escaped finite extraction")
	}
}
