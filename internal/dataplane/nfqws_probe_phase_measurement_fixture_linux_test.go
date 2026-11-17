//go:build linux && (amd64 || arm64) && razvilka_native_fixture

package dataplane

import (
	"math"
	"testing"
	"time"
)

func TestNativeActivePhaseMeasurementGeneration(t *testing.T) {
	a, b := new([nfqwsProbePhaseCount]nfqwsProbeNativePhaseCounts), new([nfqwsProbePhaseCount]nfqwsProbeNativePhaseCounts)
	values := func(n uint64, wall time.Duration) [nfqwsProbePhaseCount]NativeFixtureNFQWSProbePhase {
		var v [nfqwsProbePhaseCount]NativeFixtureNFQWSProbePhase
		v[0] = NativeFixtureNFQWSProbePhase{n, n, wall}
		return v
	}
	before := nfqwsActivePhaseSnapshot{a: values(2, 10)}
	after := nfqwsActivePhaseSnapshot{a: values(3, 15), b: values(4, 20)}
	got, err := nfqwsActivePhaseDelta(before, after)
	if err != nil || got["current"] != (NativeFixtureNFQWSProbePhase{5, 5, 25}) {
		t.Fatalf("delta %v %v", got, err)
	}
	for _, tc := range []struct {
		name  string
		after nfqwsActivePhaseSnapshot
	}{
		{"missing", nfqwsActivePhaseSnapshot{b: values(20, 100)}},
		{"reset-offset-by-new-generation", nfqwsActivePhaseSnapshot{a: values(1, 5), b: values(20, 100)}},
		{"wall-regression", nfqwsActivePhaseSnapshot{a: values(3, 9)}},
		{"count-overflow", nfqwsActivePhaseSnapshot{a: values(math.MaxUint64, 20), b: values(4, 20)}},
		{"wall-overflow", nfqwsActivePhaseSnapshot{a: values(3, time.Duration(math.MaxInt64)), b: values(4, 20)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if out, err := nfqwsActivePhaseDelta(before, tc.after); err == nil || out != nil {
				t.Fatalf("accepted invalid measurement %v %v", out, err)
			}
		})
	}
	incomplete := values(3, 15)
	incomplete[0].Completed = 2
	if _, err := nfqwsActivePhaseDelta(before, nfqwsActivePhaseSnapshot{a: incomplete}); err == nil {
		t.Fatal("accepted in-flight phase")
	}
}

func TestNativeActivePhaseMeasurementPopulation(t *testing.T) {
	key := new(int)
	counts := new([nfqwsProbePhaseCount]nfqwsProbeNativePhaseCounts)
	nfqwsActiveNativePhases.Store(key, counts)
	defer nfqwsActiveNativePhases.Delete(key)
	finish, err := NativeFixtureBeginNFQWSActivePhaseMeasurement()
	if err != nil {
		t.Fatal(err)
	}
	defer finish()
	if other, err := NativeFixtureBeginNFQWSActivePhaseMeasurement(); err == nil {
		other()
		t.Fatal("overlap accepted")
	}
	counts[0].started.Add(1)
	counts[0].nanos.Add(17)
	counts[0].completed.Add(1)
	got, err := finish()
	if err != nil || got["current"] != (NativeFixtureNFQWSProbePhase{1, 1, 17}) {
		t.Fatalf("delta %v %v", got, err)
	}
	if out, err := finish(); err == nil || out != nil {
		t.Fatal("replay accepted")
	}
	counts[0].started.Add(1)
	if out, err := NativeFixtureBeginNFQWSActivePhaseMeasurement(); err == nil {
		out()
		t.Fatal("unfinished opening accepted")
	}
	counts[0].completed.Add(1)
	finish2, err := NativeFixtureBeginNFQWSActivePhaseMeasurement()
	if err != nil {
		t.Fatal("lock retained after error", err)
	}
	counts[0].started.Add(1)
	if out, err := finish2(); err == nil || out != nil {
		t.Fatal("unfinished closing accepted")
	}
	counts[0].completed.Add(1)
	finish3, err := NativeFixtureBeginNFQWSActivePhaseMeasurement()
	if err != nil {
		t.Fatal("lock retained after closing error", err)
	}
	if _, err := finish3(); err != nil {
		t.Fatal(err)
	}
}
