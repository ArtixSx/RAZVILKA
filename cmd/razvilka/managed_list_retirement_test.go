package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestManagedListRetirementRetainsProcessUntilSameCleanupJoins(t *testing.T) {
	first := make(chan context.Context, 1)
	retry := make(chan context.Context, 1)
	joined := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-joined:
		default:
			close(joined)
		}
	})
	done := make(chan struct{})
	go func() {
		attempts := 0
		retainManagedListRetirement(func(ctx context.Context) error {
			attempts++
			if attempts == 1 {
				first <- ctx
				return errors.New("original child retirement is pending")
			}
			retry <- ctx
			<-joined
			return nil
		})
		close(done)
	}()

	var original context.Context
	select {
	case original = <-first:
	case <-time.After(5 * time.Second):
		t.Fatal("first cleanup attempt did not start")
	}
	select {
	case <-done:
		t.Fatal("pending cleanup let the process return")
	case current := <-retry:
		if original.Err() == nil || current.Err() != nil || current == original {
			t.Fatal("retry did not use a fresh live cleanup context")
		}
		if _, finite := current.Deadline(); !finite {
			t.Fatal("retry cleanup has no deadline")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("retained cleanup did not retry")
	}
	select {
	case <-done:
		t.Fatal("process returned before the retained cleanup joined")
	default:
	}
	close(joined)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("confirmed cleanup did not release process retention")
	}
}
