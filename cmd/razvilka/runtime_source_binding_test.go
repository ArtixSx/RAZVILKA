package main

import (
	"context"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func TestRuntimeSourceBindingNeverReturnsUnboundManagerOnRefusal(t *testing.T) {
	for _, refusal := range []string{"unbounded", "canceled-acquisition", "canceled-lifetime", "invalid-layout"} {
		t.Run(refusal, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			life, stop := context.WithCancel(context.Background())
			defer stop()
			if refusal == "unbounded" {
				ctx = context.Background()
			}
			if refusal == "canceled-acquisition" {
				cancel()
			}
			if refusal == "canceled-lifetime" {
				stop()
			}
			// A partial registry and relative DNS path can never become an actual
			// owner. Unsupported platforms must refuse too, not return this DTO.
			m, closeSource, err := runtimeManagerSourcesBoundLifetime(ctx, life, func() (*dataplane.Manager, error) { return dataplane.New(t.TempDir()), nil }, "relative-dns.json")
			if err == nil || m != nil || closeSource != nil {
				t.Fatal("refused assembly returned an unbound manager", refusal, err)
			}
		})
	}
}
