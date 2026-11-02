//go:build linux

package restorejournal

import (
	"context"
	"errors"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

func TestArtifactExpectedReadComparisonWorkerGoexitJoinsOtherReader(t *testing.T) {
	target, image, _, _ := artifactComparisonFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var managedJoined atomic.Bool
	fault := func(role, step string) error {
		if role == "managed" && step == "hashed" {
			managedJoined.Store(true)
		}
		if role == "pool" && step == "opened" {
			runtime.Goexit()
		}
		return nil
	}
	invoked := false
	err := target.withExpectedReadComparison(ctx, image, func(context.Context, Image, *ArtifactSourceComparison) error { invoked = true; return nil }, fault)
	if invoked || !managedJoined.Load() || !errors.Is(err, ErrUnavailable) {
		t.Fatal("worker Goexit lost join or invoked comparison callback", invoked, managedJoined.Load(), err)
	}
}
