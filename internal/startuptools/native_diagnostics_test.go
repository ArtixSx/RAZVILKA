package startuptools

import (
	"context"
	"os/exec"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Diagnostic-only fixed labels. This parser is never an authority predicate.
// The private dataplane type has no exported stage API, so match only its exact
// typed Error text against the compiled list, without printing that text.
func nativeInventoryStage(text string) string {
	for _, stage := range []string{"SCOPE", "TOOLS_A", "OPEN_A", "GETGEN_A", "GETTABLE", "TOOLS_B", "CLASSIC", "OPEN_B", "GETGEN_B", "CLOSE"} {
		if text == "network backend inventory refused at "+stage {
			return "INVENTORY_" + stage
		}
	}
	return "INVENTORY_UNCLASSIFIED"
}

func nativeStages(err error) string {
	var labels []string
	stack := []error{err}
	add := func(label string) {
		if label != "" && !slices.Contains(labels, label) {
			labels = append(labels, label)
		}
	}
	visited := 0
	for len(stack) != 0 && visited < 64 && len(labels) < 16 {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		visited++
		if current == nil {
			continue
		}
		if f, ok := current.(*failure); ok {
			if len(f.stage) <= 80 && strings.Trim(f.stage, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_") == "" {
				add(f.stage)
			}
		} else if reflect.TypeOf(current).String() == "*dataplane.backendInventoryFailure" {
			add(nativeInventoryStage(current.Error()))
		} else if exited, ok := current.(*exec.ExitError); ok {
			code := exited.ExitCode()
			if code >= 0 && code <= 255 {
				add("EXIT_RC_" + strconv.Itoa(code))
			} else {
				add("EXIT_SIGNAL_OR_UNKNOWN")
			}
		}
		switch current {
		case context.DeadlineExceeded:
			add("DEADLINE")
		case context.Canceled:
			add("CANCELED")
		case ErrUnknown:
			add("TOOLS_UNKNOWN")
		case dataplane.ErrBackendInventoryUnknown:
			add("INVENTORY_UNKNOWN")
		case netidentity.ErrUnknown:
			add("NET_IDENTITY_UNKNOWN")
		}
		if joined, ok := current.(interface{ Unwrap() []error }); ok {
			children := joined.Unwrap()
			count := min(len(children), 64-len(stack))
			for i := count - 1; i >= 0; i-- {
				stack = append(stack, children[i])
			}
			if count < len(children) {
				add("TRUNCATED")
			}
		} else if wrapped, ok := current.(interface{ Unwrap() error }); ok {
			stack = append(stack, wrapped.Unwrap())
		}
	}
	if len(stack) != 0 && len(labels) < 16 {
		add("TRUNCATED")
	}
	if len(labels) == 0 {
		return "UNCLASSIFIED"
	}
	return strings.Join(labels, "/")
}

func nativeContextState(ctx context.Context) string {
	if ctx == nil {
		return "MISSING"
	}
	switch ctx.Err() {
	case nil:
		return "LIVE"
	case context.DeadlineExceeded:
		return "DEADLINE"
	case context.Canceled:
		return "CANCELED"
	default:
		return "OTHER"
	}
}
