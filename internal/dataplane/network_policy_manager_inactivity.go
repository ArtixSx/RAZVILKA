package dataplane

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
)

var ErrRuntimeInactivity = errors.New("fresh owned runtime inactivity proof is unavailable")

// RuntimeInactivityObserver independently inspects every owned process,
// interface, socket and policy attachment. Neither successful Deactivate nor a
// missing lease/process listing is sufficient. Implementations must refuse
// unknown ownership/incarnation and must perform no effects or journal writes.
// They must not reenter a blocking Manager operation.
type RuntimeInactivityObserver interface {
	VerifyRuntimeInactive(context.Context) error
}

// VerifyRuntimeInactive observes the complete registered runtime under the
// existing Manager operation gate. Every adapter must supply a concrete owner
// observer, including unused adapters. Missing observers, registry changes or
// recovery fences prevent a grant; no prior deactivation report is consulted.
func (m *Manager) VerifyRuntimeInactive(ctx context.Context) error {
	if m == nil || m.StateRoot == "" {
		return ErrRuntimeInactivity
	}
	if err := m.beginOperation(ctx); err != nil {
		return err
	}
	defer m.endOperation()
	if err := m.CheckExecutionRecovery(ctx); err != nil {
		return errors.Join(ErrRuntimeInactivity, err)
	}
	m.registryMu.RLock()
	adapters := make(map[string]Adapter, len(m.Adapters))
	ids := make([]string, 0, len(m.Adapters))
	for id, adapter := range m.Adapters {
		adapters[id] = adapter
		ids = append(ids, id)
	}
	generation := m.registryGeneration
	m.registryMu.RUnlock()
	if len(ids) == 0 {
		return ErrRuntimeInactivity
	}
	sort.Strings(ids)
	var result error
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			result = errors.Join(result, err)
			break
		}
		observer, ok := adapters[id].(RuntimeInactivityObserver)
		if !ok || observer == nil || isNilRuntimeObserver(observer) {
			result = errors.Join(result, fmt.Errorf("%w: %s has no owner observer", ErrRuntimeInactivity, id))
			continue
		}
		if err := observer.VerifyRuntimeInactive(ctx); err != nil {
			result = errors.Join(result, fmt.Errorf("%w: %s: %w", ErrRuntimeInactivity, id, err))
		}
	}
	m.registryMu.RLock()
	unchanged := generation == m.registryGeneration && reflect.DeepEqual(adapters, m.Adapters)
	m.registryMu.RUnlock()
	if !unchanged {
		result = errors.Join(result, ErrRuntimeInactivity, ErrReviewChanged)
	}
	if err := m.CheckExecutionRecovery(ctx); err != nil {
		result = errors.Join(result, ErrRuntimeInactivity, err)
	}
	return result
}

func isNilRuntimeObserver(observer RuntimeInactivityObserver) bool {
	v := reflect.ValueOf(observer)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}
