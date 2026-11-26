package updatecheck

import "errors"

// Observation labels are diagnostic data from the original reader only.
// They cannot mint a controller role or reproduce an original join.
type ordinaryInstallerRoleFailure struct {
	stage string
	cause error
}

func (e *ordinaryInstallerRoleFailure) Error() string {
	return "ordinary installer controller observation failed"
}
func (e *ordinaryInstallerRoleFailure) Unwrap() error { return e.cause }
func ordinaryInstallerRoleAt(stage string, cause error) error {
	return &ordinaryInstallerRoleFailure{stage, errors.Join(ErrOrdinaryInstallerControllerRole, cause)}
}

func OrdinaryInstallerControllerFailureStage(err error) string {
	stage, remaining := "", 64
	var visit func(error)
	visit = func(err error) {
		if err == nil || remaining == 0 {
			return
		}
		remaining--
		if failure, ok := err.(*ordinaryInstallerRoleFailure); ok {
			if failure == nil {
				return
			}
			stage = failure.stage
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
	if !ordinaryInstallerRoleStageValid(stage) {
		return ""
	}
	return stage
}

func ordinaryInstallerRoleStageValid(stage string) bool {
	switch stage {
	case "source", "control-opening", "review-opening", "helper-identity-opening", "old-panel-opening", "panel-absent-opening",
		"command-root", "command-opening", "receipt-opening", "join-opening", "helper-opening", "supervisor-opening", "child-opening", "caller-opening", "peer-opening",
		"header-closing", "old-panel-closing", "panel-absent-closing", "control-closing", "facts-closing", "receipt-closing", "context-closing":
		return true
	}
	return false
}
