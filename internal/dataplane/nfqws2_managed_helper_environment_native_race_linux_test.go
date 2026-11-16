//go:build linux && razvilka_native_fixture && race

package dataplane

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNFQWSManagedHelperEnvironmentNativeRaceOptIn(t *testing.T) {
	original := []string{"PATH=/original", "LANG=C", "TZ=UTC"}
	t.Setenv("RAZVILKA_NATIVE_RACE_HELPER_EXIT", "")
	t.Setenv("GORACE", "atexit_sleep_ms=60000 exitcode=0 halt_on_error=1")
	got, err := nfqws2ManagedHelperEnvironment(original)
	if err != nil || len(got) != len(original) || &got[0] != &original[0] {
		t.Fatal("default native race helper environment changed")
	}
	t.Setenv("RAZVILKA_NATIVE_RACE_HELPER_EXIT", "0")
	got, err = nfqws2ManagedHelperEnvironment(original)
	if err != nil || !slices.Equal(got, append(slices.Clone(original), "GORACE=atexit_sleep_ms=0")) || &got[0] == &original[0] {
		t.Fatal("fixed experiment option or original storage changed")
	}
	got[0] = "changed"
	if original[0] != "PATH=/original" {
		t.Fatal("candidate mutated original environment")
	}
	for _, value := range []string{"1", "false", " 0", "0 ", "exitcode=0"} {
		t.Setenv("RAZVILKA_NATIVE_RACE_HELPER_EXIT", value)
		if got, err := nfqws2ManagedHelperEnvironment(original); got != nil || !errors.Is(err, ErrNFQWSManagedProcessUnknown) {
			t.Fatal("invalid experiment option accepted")
		}
	}
	t.Setenv("RAZVILKA_NATIVE_RACE_HELPER_EXIT", "0")
	if got, err := nfqws2ManagedHelperEnvironment(append(slices.Clone(original), "GORACE=exitcode=0")); got != nil || !errors.Is(err, ErrNFQWSManagedProcessUnknown) {
		t.Fatal("competing helper race options accepted")
	}
}

// The deliberate race exists only in an isolated opt-in child. It proves the
// fixed experiment option retains actual reporting and the default nonzero66,
// rather than merely asserting that a string omitted exitcode=0.
func TestNFQWSManagedHelperRaceExitCodePreserved(t *testing.T) {
	if os.Getenv("RAZVILKA_RACE_EXIT_CODE_CHILD") == "1" {
		var shared int
		var joined sync.WaitGroup
		ready := make(chan struct{})
		for range 2 {
			joined.Add(1)
			go func() {
				defer joined.Done()
				<-ready
				shared++
			}()
		}
		close(ready)
		joined.Wait()
		os.Exit(0) // Race runtime must replace success with its default66.
	}
	t.Setenv("RAZVILKA_NATIVE_RACE_HELPER_EXIT", "0")
	var original []string
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "GORACE=") && !strings.HasPrefix(entry, "RAZVILKA_RACE_EXIT_CODE_CHILD=") {
			original = append(original, entry)
		}
	}
	original = append(original, "RAZVILKA_RACE_EXIT_CODE_CHILD=1")
	environment, err := nfqws2ManagedHelperEnvironment(original)
	if err != nil {
		t.Fatal("fixed race experiment refused")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNFQWSManagedHelperRaceExitCodePreserved$", "-test.count=1")
	child.Env = environment
	output, err := child.CombinedOutput()
	defer clear(output)
	var exit *exec.ExitError
	if ctx.Err() != nil || !errors.As(err, &exit) || exit.ExitCode() != 66 || !strings.Contains(string(output), "WARNING: DATA RACE") {
		t.Fatal("fixed experiment lost actual race report/default nonzero exit")
	}
}
