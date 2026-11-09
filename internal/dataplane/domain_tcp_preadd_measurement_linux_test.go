//go:build linux && razvilka_native_fixture

package dataplane

import (
	"context"
	"testing"
)

// Exact categories, not merely a smaller SHA counter: each successful original
// bracket either performs two ordinary hashes or one authenticated capture and
// one complete byte comparison. Independent reads still require their own SHA.
func requireDomainExecutableReadMeasurement(t *testing.T, metrics map[string]DomainTCPNativeMetric, independent, pairs int64, size int64) DomainTCPNativeMetric {
	t.Helper()
	hash := metrics["whole-executable-hash"]
	capture := metrics["executable-image-capture"]
	compare := metrics["executable-image-compare"]
	if capture.Calls != 0 && capture.Calls != pairs || compare.Calls != capture.Calls || hash.Calls != independent+2*(pairs-capture.Calls) {
		t.Fatalf("full-byte categories changed: independent=%d pairs=%d hash=%+v capture=%+v compare=%+v", independent, pairs, hash, capture, compare)
	}
	var total DomainTCPNativeMetric
	for _, metric := range []DomainTCPNativeMetric{hash, capture, compare} {
		if metric.Bytes != metric.Calls*size {
			t.Fatalf("full-byte category omitted actual bytes: %+v size=%d", metric, size)
		}
		total.Calls += metric.Calls
		total.Bytes += metric.Bytes
		total.Elapsed += metric.Elapsed
	}
	return total
}

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
		pairs := int64(4)
		if shared {
			pairs = 1
		}
		return requireDomainExecutableReadMeasurement(t, stop(), 0, pairs, process.executable.info.Size()), calls
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
