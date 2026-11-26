package dataplane

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/nativecheckfixture"
)

// This reference changes ONLY the per-Check reuse observation. The native
// validation, original controller, scope, paired egress and cleanup stay real.
// It models the historical duplicate request, not a historical release binary.
type noLiteralObservationContext struct{ context.Context }

func (c noLiteralObservationContext) Value(key any) any {
	if _, ok := key.(literalServiceObservationKey); ok {
		return nil
	}
	return c.Context.Value(key)
}

func TestNativeVLESSCheckPerformance(t *testing.T) {
	if os.Getenv("RAZVILKA_NODE_NATIVE_PERF") != "1" {
		t.Skip("requires check-node-native-performance.sh")
	}
	algorithm := os.Getenv("RAZVILKA_NODE_PERF_ALGORITHM")
	if algorithm == "" {
		for _, name := range []string{"historical-request-reference", "current-reuse"} {
			command := exec.Command(os.Args[0], "-test.run=^TestNativeVLESSCheckPerformance$", "-test.v", "-test.timeout=15m")
			command.Env = append(os.Environ(), "RAZVILKA_NODE_PERF_ALGORITHM="+name)
			output, err := command.CombinedOutput()
			t.Logf("%s\n%s", name, output)
			if err != nil {
				t.Fatalf("native measurement subprocess: %v", err)
			}
		}
		return
	}
	fixture := nativecheckfixture.Start(t)
	checker := NewExactXrayNodeCheckerSlots(filepath.Join(fixture.Root, "client"), 1)
	checker.Binary, checker.Port = fixture.Binary, 29185
	checker.FreshProfile = func(context.Context) (string, error) { return nativecheckfixture.Profile, nil }
	if algorithm == "historical-request-reference" {
		original := checker.serviceProbe
		checker.serviceProbe = func(ctx context.Context, address, route, egress string, service catalog.Service) (evidence.ProbeEvidence, error) {
			return original(noLiteralObservationContext{ctx}, address, route, egress, service)
		}
	} else if algorithm != "current-reuse" {
		t.Fatal("unknown algorithm")
	}
	request := NodeCheckRequest{NodeID: checkedNodeID, Outbound: fixture.Outbound, NetworkProfile: nativecheckfixture.Profile, Service: catalog.Service{ID: "telegram", ProbeURL: fixture.ProbeURL, Strategy: []string{"xray"}}}
	rows := [][]string{{"algorithm", "scenario", "sample", "phase", "started_utc", "wall_monotonic_ms", "check_latency_ms", "finished_utc", "available", "error_code", "cleanup", "service_requests", "stages_json"}}
	rows[0] = append(rows[0], nativecheckfixture.ResourceCSVHeaders...)
	for _, scenario := range []string{"live", "dead-service", "cancel", "dead-node"} {
		if scenario == "dead-node" {
			fixture.StopServer(t)
		}
		var samples []float64
		for sample := 0; sample < 13; sample++ {
			fixture.SetService(scenario, 40*time.Millisecond)
			ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
			ctx = WithNodeResourceGuard(ctx, func(ctx context.Context, _ string, ip netip.Addr) error {
				if err := ctx.Err(); err != nil {
					return err
				}
				if !ip.IsValid() {
					return nil
				} // Host-only bookend; every actual dial is pinned below.
				if ip.String() != nativecheckfixture.HTTPSIP && ip.String() != nativecheckfixture.ServerIP {
					return ErrNodeResourceDenied
				}
				return nil
			})
			cancelDone := make(chan struct{})
			if scenario == "cancel" {
				go func() {
					defer close(cancelDone)
					select {
					case <-fixture.Entered:
						cancel()
					case <-ctx.Done():
					}
				}()
			} else {
				close(cancelDone)
			}
			calls := fixture.ServiceCalls.Load()
			resources, err := nativecheckfixture.StartResourceSample()
			if err != nil {
				t.Fatal("native resource observation", err)
			}
			defer resources.Stop() // Also joins on a failed assertion or panic.
			started := time.Now()
			result, err := checker.Check(ctx, request)
			elapsed := time.Since(started)
			cancel()
			<-cancelDone
			usage, resourceErr := resources.Stop()
			if resourceErr != nil {
				t.Fatal("native resource closing observation", resourceErr)
			}
			if err != nil && scenario != "cancel" {
				t.Fatalf("%s check error: %v", scenario, err)
			}
			if scenario == "live" && (!result.Available || result.CleanupStatus != NodeCleanupVerified || result.EgressIP != nativecheckfixture.ExitIP) {
				t.Fatalf("native live proof failed: %+v", result)
			}
			if scenario != "live" && result.Available {
				t.Fatalf("%s incorrectly passed", scenario)
			}
			if scenario != "dead-node" && result.CleanupStatus != NodeCleanupVerified {
				t.Fatalf("%s original cleanup not verified: %+v", scenario, result)
			}
			for slot := range checker.Capacity() {
				if checker.Processes.Running(checker.session(slot).Spec) {
					t.Fatal("native original client leaked")
				}
			}
			phase := "repeated"
			if sample == 0 {
				phase = "first-scenario-check"
				if scenario == "live" {
					phase = "cold-fixture-first-check"
				}
			} else {
				samples = append(samples, float64(elapsed)/float64(time.Millisecond))
			}
			stages, _ := json.Marshal(result.Stages)
			if scenario == "live" {
				wanted := int64(1)
				if algorithm == "historical-request-reference" {
					wanted = 2
				}
				if got := fixture.ServiceCalls.Load() - calls; got != wanted {
					t.Fatalf("actual service request count=%d want%d", got, wanted)
				}
			}
			row := []string{algorithm, scenario, strconv.Itoa(sample), phase, started.UTC().Format(time.RFC3339Nano), fmt.Sprintf("%.3f", float64(elapsed)/float64(time.Millisecond)), strconv.FormatInt(result.LatencyMS, 10), result.FinishedAt.Format(time.RFC3339Nano), strconv.FormatBool(result.Available), result.ErrorCode, string(result.CleanupStatus), strconv.FormatInt(fixture.ServiceCalls.Load()-calls, 10), string(stages)}
			rows = append(rows, append(row, usage.CSV()...))
		}
		sort.Float64s(samples)
		t.Logf("native full Check algorithm=%s scenario=%s repeated N=%d p50=%.3fms p95=%.3fms; stages overlap; fixture service delay40ms", algorithm, scenario, len(samples), samples[5], samples[11])
	}
	output := os.Getenv("RAZVILKA_NODE_PERF_OUTPUT")
	if output == "" {
		t.Fatal("output directory required")
	}
	file, err := os.Create(filepath.Join(output, "check-"+algorithm+".csv"))
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
