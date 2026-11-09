//go:build linux && razvilka_native_fixture

package dataplane

import (
	"context"
	"log"
)

// Stack-local fixture counters. They cannot grant authority or replace any
// actual source/process/kernel check, and are emitted only after source close.
type nfqwsPreAddMeasurement struct{ presence, guards int }

func (m *nfqwsPreAddMeasurement) sequence(ctx context.Context, s *policyEffectSession, runtime PolicyEffectRuntime, index int) error {
	observed := runtime
	observed.ExactPresence = func(c context.Context, i int) (int, error) {
		m.presence++
		return runtime.ExactPresence(c, i)
	}
	observed.Guard = func(c context.Context, i int) error {
		m.guards++
		return runtime.Guard(c, i)
	}
	return s.observeBeforeAddUnshared(ctx, observed, index)
}

func (m *nfqwsPreAddMeasurement) closed(index int, err error) {
	log.Printf("actual_nfq_pre_add_closed index=%d presence=%d guards=%d closing_ok=%t", index, m.presence, m.guards, err == nil)
}
