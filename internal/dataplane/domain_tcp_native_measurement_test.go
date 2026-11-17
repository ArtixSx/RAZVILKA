//go:build linux && razvilka_native_fixture

package dataplane

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

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

func TestDomainNativeAcceptedStagesAreClosedAndIncomplete(t *testing.T) {
	stop := StartDomainTCPNativeMeasurement()
	defer stop()
	finish := domainTCPMeasureAcceptedStage(context.Background(), "initial-current")
	prefix := "accepted-stage/initial-current/"
	before := DomainTCPNativeMeasurementSnapshot()
	if before[prefix+"started"].Calls != 1 || before[prefix+"completed"].Calls != 0 {
		t.Fatal("in-flight stage falsely completed", before)
	}
	finish(errors.New("private-details-must-not-be-recorded"))
	finish(nil)
	domainTCPMeasureAcceptedStage(context.Background(), "baseline")(nil)
	domainTCPMeasureAcceptedStage(context.Background(), "unrecognized-private-label")(nil)
	domainTCPMeasureAcceptedStage(context.Background(), "socks-dial")(nil)
	accepted := &domainAcceptedTCP{}
	accepted.self = accepted
	accepted.open.Store(true)
	ctx := context.WithValue(context.Background(), domainAcceptedTCPKey{}, accepted)
	domainTCPMeasureAcceptedStage(ctx, "socks-dial")(nil)
	accepted.open.Store(false)
	domainTCPMeasureAcceptedStage(ctx, "socks-dial")(nil)
	after := DomainTCPNativeMeasurementSnapshot()
	if after[prefix+"completed"].Calls != 1 || after[prefix+"completed"].Elapsed <= 0 || after[prefix+"returned-error"].Calls != 1 || after[prefix+"returned-nil"].Calls != 0 {
		t.Fatal("outcome/once contract", after)
	}
	if after["accepted-stage/socks-dial/started"].Calls != 1 || after["accepted-stage/socks-dial/completed"].Calls != 1 {
		t.Fatal("unaccepted dial counted", after)
	}
	for name := range after {
		if strings.Contains(name, "private") || !strings.HasPrefix(name, "accepted-stage/") {
			t.Fatal("unbounded diagnostic", name)
		}
	}
	stages := []string{"admit", "baseline", "socks-dial", "socks-handshake", "post-socks-check", "post-dial-check", "relay-enter", "baseline-issue", "baseline-prepare", "baseline-connect", "direct-current-pre", "direct-current-post", "direct-local-route", "direct-connect-wait"}
	accepted.open.Store(true)
	for _, name := range stages {
		prefix := "accepted-stage/" + name + "/"
		before := DomainTCPNativeMeasurementSnapshot()
		finish := domainTCPMeasureAcceptedStage(ctx, name)
		finish(nil)
		finish(errors.New("must-not-change-first-outcome"))
		after := DomainTCPNativeMeasurementSnapshot()
		if after[prefix+"started"].Calls != before[prefix+"started"].Calls+1 || after[prefix+"completed"].Calls != before[prefix+"completed"].Calls+1 || after[prefix+"returned-nil"].Calls != before[prefix+"returned-nil"].Calls+1 || after[prefix+"returned-error"].Calls != before[prefix+"returned-error"].Calls {
			t.Fatal("closed stage outcome", name, after)
		}
	}
	accepted.open.Store(false)
	before = DomainTCPNativeMeasurementSnapshot()
	for _, name := range stages {
		domainTCPMeasureAcceptedStage(ctx, name)(nil)
		domainTCPMeasureAcceptedStage(context.Background(), name)(nil)
	}
	if after := DomainTCPNativeMeasurementSnapshot(); !reflect.DeepEqual(before, after) {
		t.Fatal("closed/unmarked stage recorded", after)
	}
}

func TestDomainNativeAcceptedStagesCannotFinishInLaterMeasurement(t *testing.T) {
	stop := StartDomainTCPNativeMeasurement()
	accepted := &domainAcceptedTCP{}
	accepted.self = accepted
	accepted.open.Store(true)
	ctx := context.WithValue(context.Background(), domainAcceptedTCPKey{}, accepted)
	finish := domainTCPMeasureAcceptedStage(ctx, "admit")
	old := stop()
	if old["accepted-stage/admit/started"].Calls != 1 || old["accepted-stage/admit/completed"].Calls != 0 {
		t.Fatal(old)
	}
	stopNext := StartDomainTCPNativeMeasurement()
	defer stopNext()
	finish(nil)
	if got := DomainTCPNativeMeasurementSnapshot(); len(got) != 0 {
		t.Fatal("stale stage contaminated later sample", got)
	}
	if old["accepted-stage/admit/completed"].Calls != 0 {
		t.Fatal("stopped snapshot mutated")
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
