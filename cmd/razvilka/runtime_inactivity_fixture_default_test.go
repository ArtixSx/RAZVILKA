//go:build !linux || !amd64 || !razvilka_native_fixture

package main

import (
	"context"
	"testing"
)

func TestOrdinaryRuntimeSourceIgnoresEveryNativeFixtureEnvironment(t *testing.T) {
	t.Setenv("RAZVILKA_RUNTIME_NATIVE_REVIEW", "/nonexistent/private/review")
	t.Setenv("RAZVILKA_RUNTIME_NATIVE_OUTER_NET_FD", "3")
	fixture, err := runtimeInactivityFixture(context.Background(), selfUpdateRuntimePlatformFacts{})
	if err != nil || fixture != nil {
		t.Fatal("ordinary binary admitted fixture classification", fixture, err)
	}
}
