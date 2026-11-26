//go:build linux && razvilka_native_fixture

package dataplane

import (
	"context"
	"os"
	"testing"
)

// Count only this new mapping-entry file primitive. The production mapping's
// current=true bookends and two real kernel passes require the native fixture.
func TestDomainPriorReadMappingContextKeepsIndependentPriorBytes(t *testing.T) {
	for range 2 { // A second operation must open a fresh complete image again.
		p, ctx, cancel := domainPriorFileResourceModel(t)
		defer cancel()
		old, _ := domainFileObservationModel(t)
		old.scope = &executionResourceScope{manager: p.scope.manager}
		e := p.executable
		file, err := os.Open(e.path)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil {
			t.Fatal(err)
		}
		old.executable = &xrayDomainTCPExecutable{file: file, info: info, path: e.path, sha256: e.sha256}
		stop := StartDomainTCPNativeMeasurement()
		defer stop()
		err = p.observeOriginalPriorFilesFrom(ctx, false, nil, func(observed context.Context, files *xrayDomainTCPFileObservation) error {
			if observed == ctx || !domainTCPHasPriorRead(observed) || files.current(observed, p) != nil {
				t.Fatal("standalone mapping lost its own bounded prior context")
			}
			for range 2 {
				root, err := p.scope.domainSuccessor.originalSuccessorRead(observed)
				if err != nil {
					return err
				}
				priorCtx, read, err := root.forPriorContext(observed, old)
				if err != nil {
					return err
				}
				if err := read.priorFilesCurrent(priorCtx, old); err != nil {
					return err
				}
			}
			return nil
		})
		metrics := stop()
		if err != nil {
			t.Fatal(err)
		}
		if metric := metrics["whole-executable-hash"]; metric.Calls != 0 {
			t.Fatal("mapping prior comparison repeated whole SHA", metric)
		}
		for name, count := range map[string]int64{"executable-image-capture": 1, "successor-prior-executable-byte-read": 2, "executable-image-compare": 1} {
			if metric := metrics[name]; metric.Calls != count || metric.Bytes != info.Size()*count {
				t.Fatalf("mapping omitted independent original bytes: %s %+v size=%d", name, metric, info.Size())
			}
		}
	}
}
