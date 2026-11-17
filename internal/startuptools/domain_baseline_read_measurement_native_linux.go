//go:build linux && (amd64 || arm64) && razvilka_native_fixture

package startuptools

import (
	"os"
	"sync"
	"time"
)

const domainBaselineReadTimingEnabled = true

const (
	domainBaselineMeasuredCall = int(domainBaselineReadPhaseCount) + iota
	domainBaselineMeasuredReturn
	domainBaselineMeasuredReadFailed
	domainBaselineMeasuredUnstarted
	domainBaselineMeasuredStart
	domainBaselineMeasuredStartFailed
	domainBaselineMeasuredStarted
	domainBaselineMeasuredWait
	domainBaselineMeasuredWaitError
	domainBaselineMeasuredNoProcessState
	domainBaselineMeasuredNonzeroExit
	domainBaselineMeasuredSignalExit
	domainBaselineMeasuredChildUser
	domainBaselineMeasuredChildSys
	domainBaselineMeasuredStdoutOverflow
	domainBaselineMeasuredStderrOverflow
	domainBaselineMeasuredStderrNonempty
	domainBaselineMeasuredCount
)

var domainBaselineMetricNames = [domainBaselineMeasuredCount]string{
	domainBaselineReadQueue:              "queue",
	domainBaselineReadProvider:           "provider-inclusive",
	domainBaselineReadProviderBody:       "provider-body",
	domainBaselineReadOpening:            "opening-check",
	domainBaselineReadClosing:            "closing-check",
	domainBaselineMeasuredCall:           "call",
	domainBaselineMeasuredReturn:         "returned",
	domainBaselineMeasuredReadFailed:     "read-failed",
	domainBaselineMeasuredUnstarted:      "unstarted",
	domainBaselineMeasuredStart:          "start",
	domainBaselineMeasuredStartFailed:    "start-failed",
	domainBaselineMeasuredStarted:        "started",
	domainBaselineMeasuredWait:           "started-to-wait",
	domainBaselineMeasuredWaitError:      "wait-error",
	domainBaselineMeasuredNoProcessState: "wait-without-process-state",
	domainBaselineMeasuredNonzeroExit:    "nonzero-exit",
	domainBaselineMeasuredSignalExit:     "signal-exit",
	domainBaselineMeasuredChildUser:      "child-user-cpu",
	domainBaselineMeasuredChildSys:       "child-system-cpu",
	domainBaselineMeasuredStdoutOverflow: "stdout-overflow",
	domainBaselineMeasuredStderrOverflow: "stderr-overflow",
	domainBaselineMeasuredStderrNonempty: "stderr-nonempty",
}

// Order matches the exact accepted forms in domainBaselineObservedRead.
var domainBaselineVerbNames = [...]string{"rules", "routes-all", "links", "forwarded-lookup", "direct-output"}
var domainBaselineSourceNames = [...]string{"standalone", "scoped"}

type domainBaselineReadTotals [domainBaselineMeasuredCount]DomainNativeToolTiming
type domainBaselineReadSeries [len(domainBaselineSourceNames)][len(domainBaselineVerbNames)]domainBaselineReadTotals

var domainBaselineReadMetrics struct {
	sync.Mutex
	active bool
	epoch  uint64
	values domainBaselineReadSeries
}

// Each command owns its marks. Only beginning and publishing a completed row
// touch the collector. In particular Start and Wait do not take its lock.
type domainBaselineReadMeasurement struct {
	epoch        uint64
	source, verb int
	began        time.Time
	started      time.Time
	values       domainBaselineReadTotals
}

// StartDomainBaselineReadMeasurement starts one CI-only measurement epoch.
// Stop after joining the original scope. The returned function is idempotent
// and cannot stop or write to a subsequent epoch.
func StartDomainBaselineReadMeasurement() func() {
	domainBaselineReadMetrics.Lock()
	defer domainBaselineReadMetrics.Unlock()
	if domainBaselineReadMetrics.active {
		panic("overlapping baseline IP measurements")
	}
	domainBaselineReadMetrics.epoch++
	epoch := domainBaselineReadMetrics.epoch
	domainBaselineReadMetrics.active = true
	domainBaselineReadMetrics.values = domainBaselineReadSeries{}
	return func() {
		domainBaselineReadMetrics.Lock()
		defer domainBaselineReadMetrics.Unlock()
		if domainBaselineReadMetrics.epoch == epoch {
			domainBaselineReadMetrics.active = false
		}
	}
}

// DomainBaselineReadTimingSnapshot contains only fixed labels and aggregates.
// Incomplete calls are attempts without a returned result at this snapshot.
// Other phase marks are published for returned calls only. Provider time
// includes its body. Start runs to Start's return, and started reports the
// successful subset of that interval. Started-to-wait ends at the original
// Cmd.Wait return before joining the cancellation callback.
func DomainBaselineReadTimingSnapshot() map[string]DomainNativeToolTiming {
	domainBaselineReadMetrics.Lock()
	values := domainBaselineReadMetrics.values
	domainBaselineReadMetrics.Unlock()
	out := make(map[string]DomainNativeToolTiming)
	for source, sourceName := range domainBaselineSourceNames {
		for verb, verbName := range domainBaselineVerbNames {
			row := &values[source][verb]
			key := sourceName + "/" + verbName + "/"
			for metric, label := range domainBaselineMetricNames {
				if row[metric].Calls != 0 {
					out[key+label] = row[metric]
				}
			}
			if pending := row[domainBaselineMeasuredCall].Calls - row[domainBaselineMeasuredReturn].Calls; pending > 0 {
				out[key+"incomplete"] = DomainNativeToolTiming{Calls: pending}
			}
		}
	}
	return out
}

// Only called after the original closed argument grammar has accepted args.
// Neither the arguments nor any descriptor/context identity is retained.
func beginDomainBaselineReadMeasurement(args []string, scoped bool) *domainBaselineReadMeasurement {
	verb := 0
	switch len(args) {
	case 4:
		if args[2] == "link" {
			verb = 2
		}
	case 6:
		verb = 1
	case 9:
		verb = 3
	case 7:
		verb = 4
	default:
		return nil
	}
	source := 0
	if scoped {
		source = 1
	}
	domainBaselineReadMetrics.Lock()
	defer domainBaselineReadMetrics.Unlock()
	if !domainBaselineReadMetrics.active {
		return nil
	}
	domainBaselineReadMetrics.values[source][verb][domainBaselineMeasuredCall].Calls++
	return &domainBaselineReadMeasurement{epoch: domainBaselineReadMetrics.epoch, source: source, verb: verb, began: time.Now()}
}

func (m *domainBaselineReadMeasurement) now() time.Time {
	if m == nil {
		return time.Time{}
	}
	return time.Now()
}

func (m *domainBaselineReadMeasurement) phase(stage domainBaselineReadStage, start time.Time) {
	if m != nil {
		m.values[stage] = DomainNativeToolTiming{Calls: 1, Elapsed: time.Since(start)}
	}
}

func (m *domainBaselineReadMeasurement) startResult(start time.Time, failed bool) {
	if m == nil {
		return
	}
	end := time.Now()
	timing := DomainNativeToolTiming{Calls: 1, Elapsed: end.Sub(start)}
	m.values[domainBaselineMeasuredStart] = timing
	if failed {
		m.values[domainBaselineMeasuredStartFailed] = timing
		return
	}
	m.started = end
	m.values[domainBaselineMeasuredStarted] = timing
}

func (m *domainBaselineReadMeasurement) waitResult(state *os.ProcessState, failed bool) {
	if m == nil {
		return
	}
	m.values[domainBaselineMeasuredWait] = DomainNativeToolTiming{Calls: 1, Elapsed: time.Since(m.started)}
	if failed {
		m.values[domainBaselineMeasuredWaitError].Calls = 1
	}
	if state == nil {
		m.values[domainBaselineMeasuredNoProcessState].Calls = 1
		return
	}
	m.values[domainBaselineMeasuredChildUser] = DomainNativeToolTiming{Calls: 1, Elapsed: state.UserTime()}
	m.values[domainBaselineMeasuredChildSys] = DomainNativeToolTiming{Calls: 1, Elapsed: state.SystemTime()}
	if !state.Exited() {
		m.values[domainBaselineMeasuredSignalExit].Calls = 1
	} else if state.ExitCode() != 0 {
		m.values[domainBaselineMeasuredNonzeroExit].Calls = 1
	}
}

func (m *domainBaselineReadMeasurement) output(stdoutOverflow, stderrOverflow, stderrNonempty bool) {
	if m == nil {
		return
	}
	if stdoutOverflow {
		m.values[domainBaselineMeasuredStdoutOverflow].Calls = 1
	}
	if stderrOverflow {
		m.values[domainBaselineMeasuredStderrOverflow].Calls = 1
	}
	if stderrNonempty {
		m.values[domainBaselineMeasuredStderrNonempty].Calls = 1
	}
}

func (m *domainBaselineReadMeasurement) finish(success bool) {
	if m == nil {
		return
	}
	m.values[domainBaselineMeasuredReturn] = DomainNativeToolTiming{Calls: 1, Elapsed: time.Since(m.began)}
	if !success {
		m.values[domainBaselineMeasuredReadFailed].Calls = 1
	}
	if m.values[domainBaselineMeasuredStart].Calls == 0 {
		m.values[domainBaselineMeasuredUnstarted].Calls = 1
	}
	domainBaselineReadMetrics.Lock()
	defer domainBaselineReadMetrics.Unlock()
	if !domainBaselineReadMetrics.active || domainBaselineReadMetrics.epoch != m.epoch {
		return
	}
	row := &domainBaselineReadMetrics.values[m.source][m.verb]
	for i, metric := range m.values {
		row[i].Calls += metric.Calls
		row[i].Elapsed += metric.Elapsed
	}
}
