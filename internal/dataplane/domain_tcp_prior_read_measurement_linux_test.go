//go:build linux && razvilka_native_fixture

package dataplane

import (
	"context"
	"os"
	"testing"
)

// Exact byte/category evidence for this read primitive only. Native readiness
// still needs the real process, listener, journal and kernel acceptance test.
func TestDomainPriorReadFreshImageKeepsBothOriginalFileReads(t *testing.T) {
	for range 2 {
		stop := StartDomainTCPNativeMeasurement()
		defer stop()
		var size int64
		err := domainPriorReadModel(t, func(l *domainTCPPriorReadLoan, root *domainTCPSuccessorRead, _ context.CancelFunc) error {
			old, _ := domainFileObservationModel(t)
			old.scope = &executionResourceScope{manager: l.cursor.pool.manager}
			e := l.process.executable
			file, err := os.Open(e.path)
			if err != nil {
				return err
			}
			defer file.Close()
			info, err := file.Stat()
			if err != nil {
				return err
			}
			size = info.Size()
			old.executable = &xrayDomainTCPExecutable{file: file, info: info, path: e.path, sha256: e.sha256}
			ctx, read, err := root.forPriorContext(l.ctx, old)
			if err != nil {
				return err
			}
			return read.priorFilesCurrent(ctx, old)
		})
		metrics := stop()
		if err != nil {
			t.Fatal(err)
		}
		if hash := metrics["whole-executable-hash"]; hash.Calls != 0 {
			t.Fatal("prior reread repeated SHA instead of comparing authenticated bytes", hash)
		}
		for _, name := range []string{"executable-image-capture", "successor-prior-executable-byte-read", "executable-image-compare"} {
			if metric := metrics[name]; metric.Calls != 1 || metric.Bytes != size {
				t.Fatalf("independent comparison omitted full original bytes: %s %+v size=%d", name, metric, size)
			}
		}
		if metrics["successor-prior-read-scope"].Calls != 1 {
			t.Fatal("comparison did not close its own independent image")
		}
	}
}

func TestDomainPriorFileObservationSharesOnlyFreshExecutableBytes(t *testing.T) {
	for range 2 {
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
		err = p.observeOriginalPriorFiles(ctx, false, func(observed context.Context, _ *xrayDomainTCPFileObservation) error {
			for range 2 { // Same independent opening and closing prior comparisons.
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
			t.Fatal("nested prior comparison repeated a whole SHA", metric)
		}
		for name, calls := range map[string]int64{"executable-image-capture": 1, "successor-prior-executable-byte-read": 2, "executable-image-compare": 1} {
			if metric := metrics[name]; metric.Calls != calls || metric.Bytes != info.Size()*calls {
				t.Fatalf("closed comparison lost independent full bytes: %s %+v", name, metric)
			}
		}
	}
}
