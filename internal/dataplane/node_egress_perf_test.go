package dataplane

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"runtime"
	"sort"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// Opt-in local transport experiment. This measures the paired-egress change
// already present at a36f5343, not a new optimization or router performance.
// RAZVILKA_EGRESS_PERF=1 go test ./internal/dataplane -run '^TestNodeEgressLocalPerformance$' -count=1 -v
// Optional RAZVILKA_EGRESS_PERF_CSV writes sanitized raw durations to that path.
func TestNodeEgressLocalPerformance(t *testing.T) {
	if os.Getenv("RAZVILKA_EGRESS_PERF") != "1" {
		t.Skip("opt-in local HTTPS/SOCKS experiment")
	}
	rows := [][]string{{"scenario", "mode", "phase", "sample", "elapsed_ms", "cleanup_ms", "direct_category", "proxy_category", "heap_bytes", "goroutines"}}
	var memory runtime.MemStats
	t.Logf("environment GOOS=%s GOARCH=%s go=%s CPUs=%d; loopback HTTPS/SOCKS; response_delay=40ms attempt_limit=80ms; CPU usage not sampled; heap is Go runtime allocation, not process RSS", runtime.GOOS, runtime.GOARCH, runtime.Version(), runtime.NumCPU())
	for _, scenario := range []string{"live", "http503", "stalled"} {
		t.Run(scenario, func(t *testing.T) {
			var activeHandlers, activeConnections atomic.Int64
			server, roots, names := newPinnedTLSFixture(t, func(w http.ResponseWriter, r *http.Request) {
				activeHandlers.Add(1)
				defer activeHandlers.Add(-1)
				if scenario == "stalled" {
					<-r.Context().Done()
					return
				}
				timer := time.NewTimer(40 * time.Millisecond)
				defer timer.Stop()
				select {
				case <-r.Context().Done():
					return
				case <-timer.C:
				}
				if scenario == "http503" {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				_, _ = io.WriteString(w, "8.8.8.8")
			})
			server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				switch state {
				case http.StateNew:
					activeConnections.Add(1)
				case http.StateClosed, http.StateHijacked:
					activeConnections.Add(-1)
				}
			}
			socks := newPinnedSOCKSFixture(t, server.Listener.Addr().String(), false)
			stopDrain := make(chan struct{})
			defer close(stopDrain)
			go func() {
				for {
					select {
					case <-names:
					case <-socks.requests:
					case <-stopDrain:
						return
					}
				}
			}()
			p := nodeEgressHTTP{roots: roots.RootCAs, dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
			}}
			endpoint := nodeEgressEndpoint{url: "https://example.com/", pinned: netip.MustParseAddr("1.1.1.1")}
			get := func(ctx context.Context, e nodeEgressEndpoint, address string) (string, error) {
				attempt, cancel := context.WithTimeout(ctx, 80*time.Millisecond)
				defer cancel()
				return p.get(attempt, e, address)
			}
			run := func(ctx context.Context, mode string) nodeEgressPair {
				if mode == "paired" {
					return measureNodeEgressPair(ctx, get, endpoint, socks.address)
				}
				direct, de := measureNodeEgress(ctx, get, endpoint, "", 5*time.Second)
				proxy, pe := measureNodeEgress(ctx, get, endpoint, socks.address, 5*time.Second)
				return nodeEgressPair{directIP: direct, proxyIP: proxy, directErr: de, proxyErr: pe}
			}
			waitClean := func() time.Duration {
				start := time.Now()
				deadline := start.Add(time.Second)
				for activeHandlers.Load() != 0 || activeConnections.Load() != 0 {
					if time.Now().After(deadline) {
						t.Fatal("local HTTPS handlers/connections did not quiesce")
					}
					time.Sleep(time.Millisecond)
				}
				return time.Since(start)
			}
			for _, mode := range []string{"sequential_reference", "paired"} {
				var samples []float64
				for i := 0; i < 13; i++ {
					start := time.Now()
					pair := run(context.Background(), mode)
					elapsed := time.Since(start)
					cleanup := waitClean()
					if scenario == "live" && (pair.directErr != nil || pair.proxyErr != nil) {
						t.Fatalf("live fixture failed: %s %s", nodeEgressErrorCategory(pair.directErr), nodeEgressErrorCategory(pair.proxyErr))
					}
					if scenario != "live" && (pair.directErr == nil || pair.proxyErr == nil) {
						t.Fatal("unavailable fixture accepted")
					}
					phase := "repeated"
					if i == 0 {
						phase = "first_sample"
					} else {
						samples = append(samples, float64(elapsed)/float64(time.Millisecond))
					}
					runtime.ReadMemStats(&memory)
					rows = append(rows, []string{scenario, mode, phase, strconv.Itoa(i), fmt.Sprintf("%.3f", float64(elapsed)/float64(time.Millisecond)), fmt.Sprintf("%.3f", float64(cleanup)/float64(time.Millisecond)), nodeEgressErrorCategory(pair.directErr), nodeEgressErrorCategory(pair.proxyErr), strconv.FormatUint(memory.HeapAlloc, 10), strconv.Itoa(runtime.NumGoroutine())})
				}
				sort.Float64s(samples)
				t.Logf("%s N=%d repeated p50=%.3fms p95=%.3fms", mode, len(samples), samples[(len(samples)-1)/2], samples[len(samples)-1])
			}
			if scenario == "stalled" {
				for i := 0; i < 12; i++ {
					ctx, cancel := context.WithCancel(context.Background())
					var canceledAt time.Time
					finished := make(chan struct{})
					go func() { time.Sleep(15 * time.Millisecond); canceledAt = time.Now(); cancel(); close(finished) }()
					pair := run(ctx, "paired")
					<-finished
					elapsed := time.Since(canceledAt)
					cleanup := waitClean()
					if nodeEgressErrorCategory(pair.directErr) != "canceled" || nodeEgressErrorCategory(pair.proxyErr) != "canceled" {
						t.Fatal("cancellation did not join both requests")
					}
					rows = append(rows, []string{scenario, "paired", "cancel_to_join", strconv.Itoa(i), fmt.Sprintf("%.3f", float64(elapsed)/float64(time.Millisecond)), fmt.Sprintf("%.3f", float64(cleanup)/float64(time.Millisecond)), "canceled", "canceled", "", ""})
				}
			}
		})
	}
	if path := os.Getenv("RAZVILKA_EGRESS_PERF_CSV"); path != "" {
		file, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		writer := csv.NewWriter(file)
		err = writer.WriteAll(rows)
		closeErr := file.Close()
		if err != nil || closeErr != nil {
			t.Fatal(err, closeErr)
		}
	}
}
