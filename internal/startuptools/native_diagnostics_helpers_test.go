package startuptools

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

type cycleDiagnostic struct{}

func (*cycleDiagnostic) Error() string   { return "/private/secret CLI output" }
func (e *cycleDiagnostic) Unwrap() error { return e }

func TestNativeDiagnosticWalkRetainsJoinedStagesWithoutRawErrors(t *testing.T) {
	err := errors.Join(dataplane.ErrBackendInventoryUnknown, at("READ", errors.Join(netidentity.ErrUnknown, at("HASH_CONTEXT", context.DeadlineExceeded))), errors.New("/private/secret CLI output"))
	got := nativeStages(err)
	for _, want := range []string{"INVENTORY_UNKNOWN", "READ", "NET_IDENTITY_UNKNOWN", "HASH_CONTEXT", "DEADLINE"} {
		if !strings.Contains(got, want) {
			t.Fatal("joined error lost diagnostic category", got, want)
		}
	}
	if strings.Contains(got, "secret") || len(got) > 16*81 {
		t.Fatal("raw or unbounded error diagnostic", got)
	}
	if got := nativeStages(&cycleDiagnostic{}); got != "TRUNCATED" {
		t.Fatal("cyclic diagnostic was not bounded", got)
	}
	if got := nativeInventoryStage("network backend inventory refused at TOOLS_B"); got != "INVENTORY_TOOLS_B" {
		t.Fatal(got)
	}
	if got := nativeInventoryStage("network backend inventory refused at /private/secret"); got != "INVENTORY_UNCLASSIFIED" {
		t.Fatal("dynamic stage leaked", got)
	}
}

func TestNativeDiagnosticContextSamplePrecedesCleanupCancellation(t *testing.T) {
	c, cancel := context.WithCancel(context.Background())
	if nativeContextState(c) != "LIVE" {
		t.Fatal("fresh capture not live")
	}
	cancel()
	if nativeContextState(c) != "CANCELED" {
		t.Fatal("cancelled context misclassified")
	}
	c, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if nativeContextState(c) != "DEADLINE" {
		t.Fatal("deadline misclassified")
	}
}
