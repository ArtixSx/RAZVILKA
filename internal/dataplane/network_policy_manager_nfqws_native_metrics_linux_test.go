//go:build linux

package dataplane

import (
	"context"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// Fixture measurements only. They do not supply a context, deadline, proof,
// cache, retry or admission; nested check durations must not be summed as wall
// time because they include the same CLI calls measured separately.
type nfqwsExecutionNativeMetrics struct {
	mu         sync.Mutex
	t          *testing.T
	phase      string
	phaseStart time.Time
	started    time.Time
	phaseOrder []string
	phaseTime  map[string]time.Duration
	samples    map[string]*nfqwsExecutionNativeSample
}

type nfqwsExecutionNativeSample struct {
	calls, failures       int
	total, longest, start time.Duration
}

func newNFQWSExecutionNativeMetrics(t *testing.T) *nfqwsExecutionNativeMetrics {
	return &nfqwsExecutionNativeMetrics{t: t, started: time.Now(), phaseTime: map[string]time.Duration{}, samples: map[string]*nfqwsExecutionNativeSample{}}
}

func (m *nfqwsExecutionNativeMetrics) setPhase(ctx context.Context, phase string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.phase == phase {
		return
	}
	now := time.Now()
	if m.phase != "" {
		m.phaseTime[m.phase] += now.Sub(m.phaseStart)
	}
	m.phase, m.phaseStart = phase, now
	m.phaseOrder = append(m.phaseOrder, phase)
	deadline, bounded := ctx.Deadline()
	remaining := time.Duration(0)
	if bounded {
		remaining = time.Until(deadline)
	}
	m.t.Logf("paired phase: name=%s elapsed=%s context-bounded=%t remaining=%s context-error=%v", phase, now.Sub(m.started), bounded, remaining, ctx.Err())
}

func (m *nfqwsExecutionNativeMetrics) phaseName() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.phase
}

func (m *nfqwsExecutionNativeMetrics) begin(kind string) func(time.Duration, error) {
	if m == nil {
		return func(time.Duration, error) {}
	}
	started := time.Now()
	m.mu.Lock()
	key := m.phase + " | " + kind
	m.mu.Unlock()
	return func(admission time.Duration, err error) {
		elapsed := time.Since(started)
		m.mu.Lock()
		defer m.mu.Unlock()
		s := m.samples[key]
		if s == nil {
			s = &nfqwsExecutionNativeSample{}
			m.samples[key] = s
		}
		s.calls++
		s.total += elapsed
		s.start += admission
		if elapsed > s.longest {
			s.longest = elapsed
		}
		if err != nil {
			s.failures++
		}
	}
}

func (m *nfqwsExecutionNativeMetrics) report() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.phaseTime[m.phase] += time.Since(m.phaseStart)
	for _, phase := range m.phaseOrder {
		m.t.Logf("paired phase total: name=%s wall=%s", phase, m.phaseTime[phase])
	}
	keys := make([]string, 0, len(m.samples))
	for key := range m.samples {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		s := m.samples[key]
		m.t.Logf("paired measured calls: %s calls=%d failures=%d inclusive-total=%s max=%s start-admission=%s", key, s.calls, s.failures, s.total, s.longest, s.start)
	}
}

func nfqwsExecutionNativeCommandKind(name string, args []string) string {
	tool := filepath.Base(name)
	if strings.Contains(tool, "iptables") || strings.Contains(tool, "ip6tables") {
		if len(args) == 3 && args[0] == "-t" && args[2] == "-S" {
			return "CLI " + tool + " read " + args[1]
		}
		if len(args) == 1 && args[0] == "--version" {
			return "CLI " + tool + " version"
		}
		return "CLI " + tool + " effect"
	}
	return "CLI " + tool // Fixture ip/nft categories; no command data logged.
}
