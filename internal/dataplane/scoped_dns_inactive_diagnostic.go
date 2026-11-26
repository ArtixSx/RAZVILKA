package dataplane

import "errors"

type scopedDNSInactiveFailure struct {
	stage string
	cause error
}

func (e *scopedDNSInactiveFailure) Error() string { return "scoped DNS inactivity observation failed" }
func (e *scopedDNSInactiveFailure) Unwrap() error { return e.cause }
func scopedDNSInactiveAt(stage string, cause error) error {
	return &scopedDNSInactiveFailure{stage, errors.Join(ErrScopedDNSRuntimeInactive, cause)}
}

type scopedDNSInactiveProcFailure struct {
	stage string
	cause error
}

func (e *scopedDNSInactiveProcFailure) Error() string { return "scoped DNS process observation failed" }
func (e *scopedDNSInactiveProcFailure) Unwrap() error { return e.cause }

// ScopedDNSRuntimeInactiveStage reads only labels attached to the original
// failed observation. The closed quiesce formatter separately admits labels;
// no error text, path, PID or new observation enters that formatter.
func ScopedDNSRuntimeInactiveStage(err error) string {
	stage, proc, remaining := "", "", 64
	var visit func(error)
	visit = func(err error) {
		if err == nil || remaining == 0 {
			return
		}
		remaining--
		switch failure := err.(type) {
		case *scopedDNSInactiveFailure:
			if failure == nil {
				return
			}
			stage = failure.stage
		case *scopedDNSInactiveProcFailure:
			if failure == nil {
				return
			}
			proc = failure.stage
		}
		switch e := err.(type) {
		case interface{ Unwrap() []error }:
			for _, cause := range e.Unwrap() {
				visit(cause)
			}
		case interface{ Unwrap() error }:
			visit(e.Unwrap())
		}
	}
	visit(err)
	if (stage == "proc-opening" || stage == "proc-closing") && proc != "" {
		return stage + "-" + proc
	}
	return stage
}
