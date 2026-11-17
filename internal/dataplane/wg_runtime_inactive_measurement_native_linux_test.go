//go:build linux && razvilka_native_fixture

package dataplane

import (
	"bytes"
	"context"
	"errors"
	"log"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestWGRuntimeInactiveMeasurementOriginalTwoPassOrder(t *testing.T) {
	a := NewWireGuardAdapter(nil, t.TempDir())
	a.IP = "ip"
	r := &wgInactiveRunner{cut: "none"}
	a.Runner = r
	m := wgRuntimeInactiveMeasurement{enabled: true, started: time.Now()}
	processCalls := 0
	err := a.verifyRuntimeInactiveMeasured(context.Background(), func(context.Context, []string) error {
		processCalls++
		return nil
	}, &m)
	if err != nil || processCalls != 2 || m.count != 34 || m.active || m.overflow {
		t.Fatal("original complete two-pass observation changed", err, processCalls, m.count)
	}
	for pass := 1; pass <= 2; pass++ {
		rows := m.rows[(pass-1)*17 : pass*17]
		want := []wgRuntimeInactiveTiming{{stage: "ownership"}, {stage: "links"}, {stage: "rules", family: 4}, {stage: "rules", family: 6}}
		for slot := 0; slot < 3; slot++ {
			for _, family := range []int{4, 6} {
				want = append(want, wgRuntimeInactiveTiming{stage: "table-reference", slot: slot, family: family}, wgRuntimeInactiveTiming{stage: "table-empty", slot: slot, family: family})
			}
		}
		want = append(want, wgRuntimeInactiveTiming{stage: "processes"})
		for i, row := range rows {
			if row.pass != pass || row.stage != want[i].stage || row.slot != want[i].slot || row.family != want[i].family || row.outcome != "completed" || row.nanos < 0 {
				t.Fatal("stage order/identity changed", pass, i, row)
			}
		}
	}
	if len(r.calls)%2 != 0 || len(r.calls) == 0 {
		t.Fatal("original command inventory missing")
	}
	for i, call := range r.calls[:len(r.calls)/2] {
		if call != r.calls[i+len(r.calls)/2] {
			t.Fatal("second observation changed command order")
		}
	}
}

func TestWGRuntimeInactiveMeasurementRefusalAndPrivacy(t *testing.T) {
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded, errors.New("secret-path-config-command")} {
		a := NewWireGuardAdapter(nil, t.TempDir())
		a.IP, a.Runner = "ip", &wgInactiveRunner{cut: "none"}
		m := wgRuntimeInactiveMeasurement{enabled: true, started: time.Now()}
		calls := 0
		err := a.verifyRuntimeInactiveMeasured(context.Background(), func(context.Context, []string) error { calls++; return cause }, &m)
		if err != cause || calls != 1 || m.count != 17 || m.rows[16].stage != "processes" || m.rows[16].outcome != wgRuntimeInactiveOutcome(cause, true) {
			t.Fatal("refusal/order/error identity changed", err, calls, m.count)
		}
		m.begin(100, "secret-path-config-command", 999, 999)
		m.end(cause, true)
		var output bytes.Buffer
		m.writeTo(&output, 1, wgRuntimeInactiveOutcome(cause, true))
		if strings.Contains(output.String(), "secret") || !strings.Contains(output.String(), "pass=0 stage=invalid slot=0 family=0") {
			t.Fatal("measurement exposed unbounded inputs", output.String())
		}
	}
}

func TestWGRuntimeInactiveMeasurementBoundAndIncomplete(t *testing.T) {
	m := wgRuntimeInactiveMeasurement{enabled: true, started: time.Now()}
	for i := 0; i < 50; i++ {
		m.begin(1, "ownership", 0, 0)
	}
	m.end(nil, false)
	if m.count != len(m.rows) || !m.overflow || wgRuntimeInactiveOutcome(nil, false) != "aborted" {
		t.Fatal("unbounded or false successful completion")
	}
	for _, abrupt := range []string{"panic", "goexit"} {
		t.Run(abrupt, func(t *testing.T) {
			t.Setenv("RAZVILKA_MANAGED_PROBE_FIXTURE_WORK", "enabled-test-only")
			var output bytes.Buffer
			old := log.Writer()
			log.SetOutput(&output)
			t.Cleanup(func() { log.SetOutput(old) })
			a := NewWireGuardAdapter(nil, t.TempDir())
			a.IP, a.Runner = "ip", &wgInactiveRunner{cut: "none"}
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer func() { _ = recover() }()
				_ = a.verifyRuntimeInactive(context.Background(), func(context.Context, []string) error {
					if abrupt == "panic" {
						panic("secret-panic")
					}
					runtime.Goexit()
					return nil
				})
			}()
			<-done
			if !strings.Contains(output.String(), "outcome=aborted records=17") || !strings.Contains(output.String(), "stage=processes slot=0 family=0") || strings.Contains(output.String(), "secret") {
				t.Fatal("aborted body reported completion or leaked payload", output.String())
			}
		})
	}
}
