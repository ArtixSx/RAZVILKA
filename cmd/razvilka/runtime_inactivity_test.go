package main

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func TestSelfUpdateRuntimeSourceRequiresOriginalFiniteContextBeforeOpeningManager(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, expireCancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer expireCancel()
	for _, ctx := range []context.Context{nil, context.Background(), cancelled, expired} {
		manager, closeSource, err := selfUpdateRuntimeManagerBound(ctx)
		if manager != nil || closeSource != nil || !errors.Is(err, dataplane.ErrRuntimeInactivity) || selfUpdateRuntimeManagerFailureStage(err) != "manager-context" {
			t.Fatal("unbounded helper acquired a runtime source", err)
		}
	}
}

func TestSelfUpdateRuntimePlatformSelectionRefusesOtherObservedTuples(t *testing.T) {
	ubuntu := selfUpdateRuntimePlatformFacts{system: "Linux", arch: "amd64", release: "7.0.0-38-generic", machine: "x86_64", distribution: "ubuntu", version: "26.04"}
	stock := selfUpdateRuntimePlatformFacts{system: "Linux", arch: "arm64", release: "4.9-ndm-5", machine: "aarch64"}
	for _, tc := range []struct {
		facts selfUpdateRuntimePlatformFacts
		want  selfUpdateRuntimePlatform
	}{{ubuntu, selfUpdateRuntimeUbuntu70}, {stock, selfUpdateRuntimeStockNC1812}} {
		if got, err := selectSelfUpdateRuntimePlatform(tc.facts); err != nil || got != tc.want {
			t.Fatal("reviewed selection refused", got, err)
		}
	}
	// Detached selection results are enums only. These tests do not mint a
	// provider, lease, collector or any runtime-inactivity evidence.
	for _, mutate := range []func(*selfUpdateRuntimePlatformFacts){
		func(f *selfUpdateRuntimePlatformFacts) { f.system = "Windows" },
		func(f *selfUpdateRuntimePlatformFacts) { f.arch = "arm64" },
		func(f *selfUpdateRuntimePlatformFacts) { f.machine = "aarch64" },
		func(f *selfUpdateRuntimePlatformFacts) { f.release = "7.0.0-34-generic" },
		func(f *selfUpdateRuntimePlatformFacts) { f.release = "7.0.0-39-generic" },
		func(f *selfUpdateRuntimePlatformFacts) { f.distribution = "debian" },
		func(f *selfUpdateRuntimePlatformFacts) { f.version = "26.10" },
	} {
		facts := ubuntu
		mutate(&facts)
		if got, err := selectSelfUpdateRuntimePlatform(facts); got != 0 || !errors.Is(err, dataplane.ErrRuntimeInactivity) {
			t.Fatal("unsupported tuple selected a family")
		}
	}
	for _, mutate := range []func(*selfUpdateRuntimePlatformFacts){
		func(f *selfUpdateRuntimePlatformFacts) { f.arch = "mips" },
		func(f *selfUpdateRuntimePlatformFacts) { f.arch = "amd64" },
		func(f *selfUpdateRuntimePlatformFacts) { f.machine = "armv7l" },
		func(f *selfUpdateRuntimePlatformFacts) { f.release = "4.9-other" },
	} {
		facts := stock
		mutate(&facts)
		if got, err := selectSelfUpdateRuntimePlatform(facts); got != 0 || err == nil {
			t.Fatal("unsupported stock tuple selected a family")
		}
	}
}

func TestSelfUpdateRuntimeSourceFailureKeepsCausesPrivateAndCleanupVisible(t *testing.T) {
	cause := errors.New("private-path-token-output")
	for _, stage := range []string{"manager-context", "manager-platform", "manager-registry", "network-provider", "tools-acquire", "tools-inventory", "backend-inventory", "inactivity-owner-bind"} {
		err := selfUpdateRuntimeSourceFailed(stage, cause)
		if !errors.Is(err, cause) || !errors.Is(err, dataplane.ErrRuntimeInactivity) || selfUpdateRuntimeManagerFailureStage(err) != stage || strings.Contains(err.Error(), cause.Error()) {
			t.Fatal("causal refusal lost or disclosed private data")
		}
		joined := fmt.Errorf("trusted wrapper: %w", selfUpdateRuntimeSourceFailed(stage, errors.Join(cause, errSelfUpdateRuntimeSourceClose)))
		if selfUpdateRuntimeManagerFailureStage(joined) != stage+"-source-close" || !errors.Is(joined, cause) {
			t.Fatal("joined source cleanup was hidden")
		}
	}
	if selfUpdateRuntimeManagerFailureStage(cause) != "manager-construction" || selfUpdateRuntimeManagerFailureStage(selfUpdateRuntimeSourceFailed(cause.Error(), cause)) != "manager-construction" {
		t.Fatal("arbitrary error text became a diagnostic stage")
	}
}

func TestSelfUpdateRuntimeQuiesceJoinsOnRefusalAndUsesOneFinalStage(t *testing.T) {
	for _, tc := range []struct {
		primary, want string
		closeErr      error
	}{{"", "", nil}, {"installer-role-binding", "installer-role-binding", nil},
		{"", "runtime-source-close", errors.New("private-close-output")},
		{"installer-role-binding", "installer-role-binding-source-close", errors.New("private-close-output")},
		{"runtime-source-close", "runtime-source-close", errors.New("private-close-output")}} {
		calls := 0
		got := finishSelfUpdateRuntimeQuiesce(tc.primary, func() error { calls++; return tc.closeErr })
		if calls != 1 || got != tc.want {
			t.Fatal("source not joined or failure classification changed", calls, got)
		}
	}
	if finishSelfUpdateRuntimeQuiesce("", nil) != "runtime-source-close" {
		t.Fatal("missing source closer became success")
	}
}

func TestSelfUpdateRuntimeSourceUnsupportedHostCannotOpenManager(t *testing.T) {
	if runtime.GOOS == "linux" && (runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64") {
		t.Skip("actual reviewed assembly is covered by the explicit native test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	manager, closeSource, err := selfUpdateRuntimeManagerBound(ctx)
	if manager != nil || closeSource != nil || !errors.Is(err, dataplane.ErrRuntimeInactivity) || selfUpdateRuntimeManagerFailureStage(err) != "manager-platform" {
		t.Fatal("unsupported host acquired a runtime source")
	}
}
