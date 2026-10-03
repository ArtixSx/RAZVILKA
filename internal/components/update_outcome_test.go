package components

import (
	"errors"
	"fmt"
	"testing"
)

func TestResearchUpdateOutcomeSurvivesWrapping(t *testing.T) {
	cause := errors.New("synthetic failure")
	for _, kind := range []error{ErrNoMutation, ErrRollbackUnconfirmed, ErrRollbackVerified} {
		err := fmt.Errorf("outer: %w", &UpdateFailure{Outcome: kind, Version: "1", Cause: cause})
		if !errors.Is(err, kind) || !errors.Is(err, cause) {
			t.Fatal(err)
		}
	}
	if NoMutation(nil) != nil {
		t.Fatal("nil became error")
	}
}
