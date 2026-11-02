package dataplane

import "errors"

// Documentary fixed stages only. The wrapper preserves the original exception
// and carries no admission or retry classification.
type mihomoSameBootStageFailure struct {
	stage string
	cause error
}

func (e *mihomoSameBootStageFailure) Error() string {
	return "Mihomo same-boot retirement refused at " + e.stage
}
func (e *mihomoSameBootStageFailure) Unwrap() error { return e.cause }
func mihomoSameBootStageError(stage string, err error) error {
	if err == nil {
		return nil
	}
	return &mihomoSameBootStageFailure{stage: stage, cause: err}
}

// MihomoSameBootRetirementStage returns a closed, source-authored diagnostic
// label. It never formats underlying paths, configuration, arguments or errors.
func MihomoSameBootRetirementStage(err error) string {
	var stage *mihomoSameBootStageFailure
	if errors.As(err, &stage) {
		return stage.stage
	}
	return "unclassified"
}
