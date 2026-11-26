package physicalscope

import (
	"context"
	"errors"
	"reflect"
	"strings"
)

// Boundaries expose only this package's closed branch labels. Foreign error
// text remains available through Unwrap, never through the diagnostic string.
// The separate type retains errors.As access to the original decoder failure.
type boundaryFailure struct {
	stage string
	cause error
}

func boundary(stage string, err error) error {
	return &boundaryFailure{stage: stage, cause: errors.Join(ErrUnknown, err)}
}
func (e *boundaryFailure) Unwrap() error { return e.cause }
func (e *boundaryFailure) Error() string {
	return "physical LAN: " + strings.Join(DiagnosticStages(e), " > ")
}

// DiagnosticStages extracts only this package's private, closed branch labels
// and exact context sentinels from an outer error chain. It never formats a
// foreign cause or accepts caller text as a stage. This is diagnostic data,
// not freshness, physical evidence or permission to retry a revoked Review.
// Joined branches are flattened in traversal order, not a single call stack.
// The 16-stage depth bound applies to closed physical labels; opaque outer
// wrappers and the package's sentinel joins consume only the 64-node budget.
func DiagnosticStages(err error) []string {
	stages := []string{}
	remaining := 64
	var visit func(error, int)
	visit = func(err error, depth int) {
		if err == nil || remaining == 0 || depth == 16 {
			return
		}
		remaining--
		switch e := err.(type) {
		case *boundaryFailure:
			stages = append(stages, e.stage)
			depth++
		case *failure:
			stages = append(stages, e.stage)
			depth++
		default:
			if err == context.Canceled {
				stages = append(stages, "context.canceled")
				depth++
			} else if err == context.DeadlineExceeded {
				stages = append(stages, "context.deadline")
				depth++
			}
		}
		switch e := err.(type) {
		case interface{ Unwrap() []error }:
			for _, cause := range e.Unwrap() {
				visit(cause, depth)
			}
		case interface{ Unwrap() error }:
			visit(e.Unwrap(), depth)
		}
	}
	visit(err, 0)
	return stages
}

// Called only after the original exact snapshot comparison has refused.
// Classification does not decide admission and emits no changed values.
func snapshotDifference(a, b Snapshot) string {
	if !reflect.DeepEqual(a.Identity, b.Identity) {
		return "snapshot.identity"
	}
	if !reflect.DeepEqual(a.Selection, b.Selection) {
		return "snapshot.selection"
	}
	if len(a.Segments) != len(b.Segments) {
		return "snapshot.segment-count"
	}
	for i, s := range a.Segments {
		t := b.Segments[i]
		if !reflect.DeepEqual(s.Prefixes, t.Prefixes) {
			return "snapshot.prefixes"
		}
		if !reflect.DeepEqual(s.LinkAddresses, t.LinkAddresses) {
			return "snapshot.link-addresses"
		}
		if !reflect.DeepEqual(s.Members, t.Members) {
			return "snapshot.members"
		}
		if !reflect.DeepEqual(s.RouterNeighbors, t.RouterNeighbors) {
			return "snapshot.router-neighbors"
		}
		if !reflect.DeepEqual(s, t) {
			return "snapshot.segment-binding"
		}
	}
	if len(a.Devices) != len(b.Devices) {
		return "snapshot.device-count"
	}
	for i, d := range a.Devices {
		t := b.Devices[i]
		if !reflect.DeepEqual(d.Addresses, t.Addresses) {
			return "snapshot.device-addresses"
		}
		if !reflect.DeepEqual(d.LinkLocalAddresses, t.LinkLocalAddresses) {
			return "snapshot.device-link-local"
		}
		if !reflect.DeepEqual(d, t) {
			return "snapshot.device-binding"
		}
	}
	return "snapshot.other"
}
