//go:build linux && razvilka_native_fixture

package dataplane

import (
	"errors"
	"os"
	"testing"
)

// Actual held-file reads only, not a successful source/process/standby model.
// Standalone standby Current retains two complete process comparisons, and
// currentBaseline retains four. Their four/eight executable-byte bookends
// can share one synchronous opening/closing;
// every nested metadata/config comparison still executes. Native workflow
// measurements separately establish whether that saves end-to-end time.
func TestDomainStandbyReadFileBracketMeasurement(t *testing.T) {
	r, ctx := domainFileObservationModel(t)
	measure := func(reads int, shared bool) DomainTCPNativeMetric {
		t.Helper()
		stop := StartDomainTCPNativeMeasurement()
		defer stop()
		read := func(files *xrayDomainTCPFileObservation) error {
			for range reads {
				if err := r.filesCurrentForObservation(ctx, files); err != nil {
					return err
				}
			}
			return nil
		}
		var err error
		if shared {
			err = r.withFileObservation(ctx, read)
		} else {
			err = read(nil)
		}
		if err != nil {
			t.Fatal(err)
		}
		return stop()["whole-executable-hash"]
	}
	for _, reads := range []int{4, 8} {
		before, after := measure(reads, false), measure(reads, true)
		if before.Calls != int64(reads) || after.Calls != 2 || before.Bytes != int64(reads/2)*after.Bytes || after.Bytes != 2*r.executable.info.Size() {
			t.Fatalf("actual byte reads before=%+v after=%+v", before, after)
		}
		if next := measure(reads, true); next.Calls != 2 || next.Bytes != after.Bytes {
			t.Fatalf("successive independent bracket reused prior proof: %+v", next)
		}
		t.Logf("primitive-only original byte reads before=%+v after=%+v; no native readiness or speed claim", before, after)
	}
	stop := StartDomainTCPNativeMeasurement()
	defer stop()
	if err := r.filesCurrent(ctx); err != nil {
		t.Fatal(err)
	}
	if next := stop()["whole-executable-hash"]; next.Calls != 1 || next.Bytes != r.executable.info.Size() {
		t.Fatalf("independent read reused revoked byte proof: %+v", next)
	}
}

func TestDomainStandbyReadFileBracketMutationCannotEscape(t *testing.T) {
	r, ctx := domainFileObservationModel(t)
	witness := errors.New("original inventory read failed")
	err := r.withFileObservation(ctx, func(files *xrayDomainTCPFileObservation) error {
		if err := r.filesCurrentForObservation(ctx, files); err != nil {
			return err
		}
		file, err := os.OpenFile(r.executable.path, os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		_, writeErr := file.WriteAt([]byte("X"), 0)
		if err := errors.Join(writeErr, file.Close()); err != nil {
			return err
		}
		if err := os.Chtimes(r.executable.path, r.executable.info.ModTime(), r.executable.info.ModTime()); err != nil {
			return err
		}
		// Equal metadata cannot replace the closing whole-byte proof.
		return errors.Join(witness, r.filesCurrentForObservation(ctx, files))
	})
	if !errors.Is(err, ErrXrayDomainTCPOriginal) || !errors.Is(err, witness) {
		t.Fatal("changed original bytes or callback error escaped closing bracket", err)
	}
	if err := r.filesCurrent(ctx); !errors.Is(err, ErrXrayDomainTCPOriginal) {
		t.Fatal("independent read adopted changed bytes", err)
	}
}
