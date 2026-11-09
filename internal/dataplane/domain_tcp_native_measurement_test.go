//go:build linux && razvilka_native_fixture

package dataplane

import "testing"

func TestDomainNativeMeasurementSnapshotsRemainCumulative(t *testing.T) {
	stop := StartDomainTCPNativeMeasurement()
	defer stop()
	first := domainTCPMeasure("snapshot-fixture")
	second := domainTCPMeasure("snapshot-fixture")
	first(3)
	snapshot := DomainTCPNativeMeasurementSnapshot()
	if got := snapshot["snapshot-fixture"]; got.Calls != 1 || got.Bytes != 3 {
		t.Fatal("snapshot included unfinished observation or lost completed work", got)
	}
	snapshot["snapshot-fixture"] = DomainTCPNativeMetric{Calls: 999, Bytes: 999}
	delete(snapshot, "snapshot-fixture")
	second(7)
	for _, result := range []map[string]DomainTCPNativeMetric{DomainTCPNativeMeasurementSnapshot(), stop()} {
		if got := result["snapshot-fixture"]; got.Calls != 2 || got.Bytes != 10 {
			t.Fatal("snapshot mutated/reset counters or stopped measurement", got)
		}
	}
}

func TestDomainNativeHashBucketsPreserveAggregate(t *testing.T) {
	stop := StartDomainTCPNativeMeasurement()
	defer stop()
	domainTCPMeasure("whole-executable-hash")(13)
	result := stop()
	aggregate := result["whole-executable-hash"]
	bucket := result["hash-stack/direct/other"]
	if aggregate.Calls != 1 || aggregate.Bytes != 13 || bucket.Calls != aggregate.Calls || bucket.Bytes != aggregate.Bytes || bucket.Elapsed != aggregate.Elapsed {
		t.Fatal("hash attribution changed the aggregate or exposed an arbitrary caller", result)
	}
	if result["native-hash-attribution"].Calls != 1 {
		t.Fatal("diagnostic overhead was not separately recorded")
	}
}
