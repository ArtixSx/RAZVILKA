//go:build linux

package dataplane

import (
	"errors"
	"testing"
)

func TestMihomoActiveCheckingFirstPublicationPanicRetainsOriginalCursor(t *testing.T) {
	c, ctx := mihomoCheckingWriterModel(t)
	s := c.owner.scope
	cut := errors.New("model first publication panic")
	c.fault = func(step string) error {
		if step == "before-latest" {
			panic(cut)
		}
		return nil
	}
	var caught any
	func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		defer func() { caught = recover() }()
		_ = c.initialPublicationLocked()
	}()
	if caught != cut {
		t.Fatal("original panic changed", caught)
	}
	if !s.pending || c.open || !c.failed || c.publishing || c.owner.healthCheck != c {
		t.Fatal("first panic lost original cursor or left writer usable")
	}
	if err := c.owner.records.current(ctx, false); err != nil {
		t.Fatal("original partial ACK owners lost", err)
	}
	if err := s.checkRetainedMihomoOperation(ctx, true); err == nil {
		t.Fatal("panic retained forward operation authority")
	}
	if version, _, err := InspectRetainedExecutionReadVersion(ctx, s.managerRoot); err != nil || version != 9 {
		t.Fatal("first acknowledged header lost required reader9", version, err)
	}
}
