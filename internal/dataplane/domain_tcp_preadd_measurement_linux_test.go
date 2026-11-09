//go:build linux && razvilka_native_fixture

package dataplane

import (
	"context"
	"testing"
)

func TestDomainPreAddOriginalByteReadMeasurement(t *testing.T) {
	process, ctx := domainFileObservationModel(t)
	measure := func(shared bool) (DomainTCPNativeMetric, int) {
		stop := StartDomainTCPNativeMeasurement()
		defer stop()
		calls := 0
		readFour := func(scoped context.Context, baseline *syntheticBaselineExecutionResource) error {
			for range 4 {
				if err := withDomainTCPPreAddFiles(scoped, process, baseline, nil, false, func(files *xrayDomainTCPFileObservation) error {
					calls++
					return process.filesCurrentForObservation(scoped, files)
				}); err != nil {
					return err
				}
			}
			return nil
		}
		var err error
		if shared {
			err = domainPreAddFileLoan(t, ctx, process, func(scoped context.Context, baseline *syntheticBaselineExecutionResource, _ *domainTCPPreAddLoan) error {
				return readFour(scoped, baseline)
			})
		} else {
			err = readFour(ctx, &syntheticBaselineExecutionResource{})
		}
		if err != nil {
			t.Fatal(err)
		}
		return stop()["whole-executable-hash"], calls
	}
	before, beforeCalls := measure(false)
	after, afterCalls := measure(true)
	if before.Calls != 8 || after.Calls != 2 || before.Bytes != 4*after.Bytes || after.Bytes != 2*process.executable.info.Size() || beforeCalls != 4 || afterCalls != 4 {
		t.Fatalf("original pre-Add primitive bytes before=%+v after=%+v calls=%d/%d", before, after, beforeCalls, afterCalls)
	}
	next, calls := measure(true)
	if next.Calls != 2 || next.Bytes != after.Bytes || calls != 4 {
		t.Fatal("independent next pre-Add reused old bytes", next, calls)
	}
	t.Logf("pre-Add immutable-byte primitive before=%+v after=%+v; all4callbacks retained; full native readiness measured separately", before, after)
}
