package dataplane

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// Negative factory/pure-context paths only: no provider, original source,
// native facts, command admission or file reader can be issued by these inputs.
func TestWGInactivityDiagnosticPreservesOriginalFactoryAndPureContextCause(t *testing.T) {
	for _, mode := range []string{"nil", "unbounded", "canceled", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			var ctx context.Context
			var cause error
			switch mode {
			case "unbounded":
				ctx = context.Background()
			case "canceled":
				finite, stop := context.WithTimeout(context.Background(), time.Second)
				defer stop()
				c, cancel := context.WithCancel(finite)
				cancel()
				ctx, cause = c, context.Canceled
			case "deadline":
				c, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				defer cancel()
				ctx, cause = c, context.DeadlineExceeded
			}
			source, err := ReviewWGInactivityRead(ctx, context.Background(), nil, nil, WGCommandTools{})
			if source != nil || !errors.Is(err, ErrWGOperationOwner) || WGInactivityReadStage(err) != "review-context" || cause != nil && !errors.Is(err, cause) {
				t.Fatal("factory lost original owner or actual context cause", mode, err)
			}
			// Private negative-only structural model; context rejection precedes
			// every missing owner and never grants an observation.
			r := &WGInactivityRead{}
			r.self = r
			err = r.pureCurrent(ctx)
			if !errors.Is(err, ErrWGOperationOwner) || WGInactivityReadStage(err) != "context" || cause != nil && !errors.Is(err, cause) {
				t.Fatal("pure read lost actual context cause", mode, err)
			}
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	lifetime, stop := context.WithCancel(context.Background())
	stop()
	if source, err := ReviewWGInactivityRead(ctx, lifetime, nil, nil, WGCommandTools{}); source != nil || WGInactivityReadStage(err) != "review-lifetime" || !errors.Is(err, context.Canceled) || !errors.Is(err, ErrWGOperationOwner) {
		t.Fatal("original lifetime rejection lost its cause", err)
	}
	if source, err := ReviewWGInactivityRead(ctx, context.Background(), nil, nil, WGCommandTools{}); source != nil || WGInactivityReadStage(err) != "review-input" || !errors.Is(err, ErrWGOperationOwner) {
		t.Fatal("invalid input reached original source construction", err)
	}
}

type wgReadDiagnosticCycle struct{}

func (*wgReadDiagnosticCycle) Error() string   { panic("diagnostic must not read foreign text") }
func (e *wgReadDiagnosticCycle) Unwrap() error { return e }

func TestWGInactivityDiagnosticOnlyExposesTypedClosedLabels(t *testing.T) {
	labels := []string{"review-context", "review-lifetime", "review-input", "review-control", "review-adapter", "review-runner", "review-paths", "review-root", "review-source", "owner", "context", "lifetime", "adapter-shape", "bound-tools", "identity", "registry", "root", "control-opening", "tools", "control-closing"}
	marker := "/private/profile-and-cli-marker"
	for _, label := range labels {
		known := wgInactivityReadAt(label, errors.Join(ErrWGOperationOwner, errors.New(marker)))
		if got := WGInactivityReadStage(errors.Join(errors.New(marker), known)); got != label || !errors.Is(known, ErrWGOperationOwner) || strings.Contains(known.Error(), marker) {
			t.Fatal("typed original diagnostic label or sentinel was lost", label, got)
		}
		for _, text := range []string{label, "WG inactivity read refused at " + label, "WG inactivity read refused at " + label + marker} {
			if got := WGInactivityReadStage(errors.New(text)); got != "unclassified" {
				t.Fatal("foreign text became an actual typed boundary", label, got)
			}
		}
	}
	if got := WGInactivityReadStage(&wgReadDiagnosticCycle{}); got != "unclassified" {
		t.Fatal("foreign cycle was not bounded", got)
	}
	children := make([]error, 33)
	for i := range children {
		children[i] = errors.New(marker)
	}
	children[32] = wgInactivityReadAt("root", ErrWGOperationOwner)
	if got := WGInactivityReadStage(errors.Join(children...)); got != "unclassified" {
		t.Fatal("unbounded foreign width exposed a stage beyond the walk limit", got)
	}
	if WGInactivityReadStage(nil) != "none" || WGInactivityReadStage(wgInactivityReadAt(marker, ErrWGOperationOwner)) != "unclassified" {
		t.Fatal("missing or dynamic marker became a closed diagnostic")
	}
	if WGInactivityReadStage((*wgInactivityReadFailure)(nil)) != "unclassified" {
		t.Fatal("nil private error became a closed stage")
	}
}
