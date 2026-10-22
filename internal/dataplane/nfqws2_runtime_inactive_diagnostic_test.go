package dataplane

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestNFQWSInactiveErrorKeepsNestedFixedStagesWithoutForeignText(t *testing.T) {
	private := errors.New("private-path-address-command")
	for _, inner := range []string{"files", "processes", "inventory.source", "kernel", "files.closure"} {
		t.Run(inner, func(t *testing.T) {
			err := nfqws2InactiveAt("observation", fmt.Errorf("private-wrapper: %w", nfqws2InactiveAt(inner, private)))
			if got, want := err.Error(), "NFQWS runtime inactivity: observation/"+inner; got != want {
				t.Fatalf("nested diagnostic: got %q want %q", got, want)
			}
			if !errors.Is(err, private) || !errors.Is(err, ErrNFQWSManagedKernelOwner) || NFQWSRuntimeInactiveStage(err) != inner {
				t.Fatal("diagnostic changed the original refusal or deepest typed stage")
			}
		})
	}
}

func TestNFQWSInactiveErrorNeverFormatsForeignOrUnknownStages(t *testing.T) {
	private := "private-path-address-command"
	err := nfqws2InactiveAt("observation", errors.Join(
		errors.New(private), nfqws2InactiveAt(private, errors.New(private)),
		nfqws2InactiveAt("files", nfqws2InactiveAt("files", nil))))
	if got := err.Error(); got != "NFQWS runtime inactivity: observation/unknown/files" || strings.Contains(got, private) {
		t.Fatal("untrusted text or repeated labels entered the public diagnostic", got)
	}
}

func TestNFQWSInactiveErrorProjectsOnlyTypedClosedBackendStage(t *testing.T) {
	private := errors.New("private-path-address-command")
	for _, stage := range []string{"SCOPE", "TOOLS_A", "OPEN_A", "GETGEN_A", "GETTABLE", "TOOLS_B", "CLASSIC", "OPEN_B", "GETGEN_B", "CLOSE", "private-path-address-command"} {
		t.Run(stage, func(t *testing.T) {
			err := nfqws2InactiveAt("observation", nfqws2InactiveAt("kernel", nfqws2InactiveAt("inventory.source", fmt.Errorf("private wrapper: %w", backendInventoryAt(stage, private)))))
			label := stage
			if label == private.Error() {
				label = "unknown"
			}
			want := "NFQWS runtime inactivity: observation/kernel/inventory.source/backend." + label
			if got := err.Error(); got != want || strings.Contains(got, private.Error()) {
				t.Fatal("backend diagnostic exposed foreign data or omitted fixed stage", got, want)
			}
			if !errors.Is(err, private) || !errors.Is(err, ErrBackendInventoryUnknown) || NFQWSRuntimeInactiveStage(err) != "inventory.source" {
				t.Fatal("diagnostic changed refusal/cause semantics")
			}
		})
	}
	foreign := nfqws2InactiveAt("inventory.source", errors.New("network backend inventory refused at GETGEN_A: private-path-address-command"))
	if got := foreign.Error(); got != "NFQWS runtime inactivity: inventory.source" {
		t.Fatal("foreign message forged a backend diagnostic", got)
	}
}
