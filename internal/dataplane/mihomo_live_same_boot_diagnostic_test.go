package dataplane

import (
	"errors"
	"testing"
)

func TestMihomoSameBootDiagnosticPreservesOriginalException(t *testing.T) {
	original := errors.New("original diagnostic exception")
	if mihomoSameBootStageError("prepare-inputs", nil) != nil {
		t.Fatal("successful result changed")
	}
	wrapped := mihomoSameBootStageError("prepare-inputs", original)
	if !errors.Is(wrapped, original) || MihomoSameBootRetirementStage(errors.Join(ErrMihomoLiveRetirement, wrapped)) != "prepare-inputs" {
		t.Fatal("original cause or fixed stage lost")
	}
	if MihomoSameBootRetirementStage(original) != "unclassified" {
		t.Fatal("unknown exception formatted")
	}
}
