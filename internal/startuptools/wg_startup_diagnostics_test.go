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

type wgStartupDiagnosticCycle struct{}

func (*wgStartupDiagnosticCycle) Error() string   { panic("diagnostic must not read foreign text") }
func (e *wgStartupDiagnosticCycle) Unwrap() error { return e }

func TestWGStartupDiagnosticClosedTypedStagesAndOriginalCategories(t *testing.T) {
	marker := "/private/profile-and-cli-marker"
	for _, label := range []string{"WG_STARTUP_CONTEXT", "WG_STARTUP_OWNER", "WG_STARTUP_OPEN_CURRENT", "WG_STARTUP_DESCRIPTORS", "WG_STARTUP_CLOSE_CURRENT", "WG_STARTUP_OBSERVATION", "WG_INACTIVITY_UNISSUED", "WG_INACTIVITY_DEADLINE", "WG_INACTIVITY_LOCK", "WG_INACTIVITY_ABSENCE", "WG_INACTIVITY_CURRENT", "WG_INACTIVITY_SOURCE"} {
		for _, known := range []error{at(label, errors.New(marker)), wgInactivityStartupAt(label, errors.New(marker))} {
			if got := WGStartupStage(errors.Join(errors.New(marker), known)); got != label || strings.Contains(known.Error(), marker) {
				t.Fatal("typed closed startup label was lost", label, got)
			}
		}
		for _, text := range []string{label, "trusted startup tools: " + label, "trusted startup tools: " + label + marker} {
			if got := WGStartupStage(errors.New(text)); got != "unclassified" {
				t.Fatal("foreign marker/text replaced the real original startup reader", label, got)
			}
		}
	}
	sourceErr := wgInactivityStartupAt("WG_INACTIVITY_SOURCE", errors.Join(dataplane.ErrWGOperationOwner, context.DeadlineExceeded))
	if !errors.Is(sourceErr, dataplane.ErrWGOperationOwner) || !errors.Is(sourceErr, context.DeadlineExceeded) || errors.Is(sourceErr, ErrUnknown) {
		t.Fatal("source diagnostic changed original refusal categories", sourceErr)
	}
	if WGStartupStage(nil) != "none" || WGStartupStage(&wgStartupDiagnosticCycle{}) != "unclassified" || WGStartupStage(wgInactivityStartupAt(marker, errors.New(marker))) != "unclassified" {
		t.Fatal("foreign cycle or dynamic marker became a closed startup stage")
	}
	for _, typedNil := range []error{(*failure)(nil), (*wgInactivityStartupFailure)(nil)} {
		if WGStartupStage(typedNil) != "unclassified" {
			t.Fatal("nil private error became a closed stage")
		}
	}
	children := make([]error, 33)
	for i := range children {
		children[i] = errors.New(marker)
	}
	children[32] = at("WG_STARTUP_OWNER", nil)
	if got := WGStartupStage(errors.Join(children...)); got != "unclassified" {
		t.Fatal("foreign width escaped the bounded stage walk", got)
	}
}

func TestWGStartupDiagnosticPublicNegativeFactoriesCannotIssueTools(t *testing.T) {
	var lease *Lease
	tools, err := lease.ManagedListWGCommandTools(nil, netidentity.Identity{})
	if tools != nil || WGStartupStage(err) != "WG_STARTUP_CONTEXT" || !errors.Is(err, ErrUnknown) {
		t.Fatal("negative production tools entry lost its typed stage", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	source, err := lease.ReviewWGInactivity(ctx, nil, nil, "wireguard")
	if source != nil || WGStartupStage(err) != "WG_INACTIVITY_UNISSUED" || !errors.Is(err, ErrUnknown) {
		t.Fatal("negative production source entry lost its typed stage", err)
	}
}
