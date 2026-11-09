package dataplane

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type mihomoStopDiagnosticCycle struct{}

func (e *mihomoStopDiagnosticCycle) Error() string { return "private data must not be formatted" }
func (e *mihomoStopDiagnosticCycle) Unwrap() error { return e }

func TestMihomoLiveStopDiagnosticPreservesCausesWithoutFormattingThem(t *testing.T) {
	secret := errors.New("private profile or command must not be printed")
	err := errors.Join(mihomoLiveStopAt("close-row", secret), mihomoLiveStopAt("engine-native", context.Canceled))
	if !errors.Is(err, secret) || !errors.Is(err, context.Canceled) {
		t.Fatal("original causes lost")
	}
	if strings.Contains(err.Error(), secret.Error()) {
		t.Fatal("diagnostic formatted private cause")
	}
	if got := MihomoLiveStopFailurePhases(err); !reflect.DeepEqual(got, []string{"close-row", "engine-native"}) {
		t.Fatal(got)
	}
	if mihomoLiveStopAt("close-row", nil) != nil {
		t.Fatal("success became an error")
	}
	if got := MihomoLiveStopFailurePhases(&mihomoStopDiagnosticCycle{}); len(got) != 0 {
		t.Fatal("cyclic foreign error acquired a stage", got)
	}
	unknown := mihomoLiveStopAt("private profile should not become a phase", secret)
	if got := MihomoLiveStopFailurePhases(unknown); !reflect.DeepEqual(got, []string{"unknown-step"}) || strings.Contains(unknown.Error(), "private profile") {
		t.Fatal("unrecognized phase escaped closed diagnostic labels", got)
	}
}
