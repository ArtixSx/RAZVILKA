//go:build linux && amd64 && razvilka_native_fixture

package startuptools

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

func TestStaticVersionFactNativeNFQLANRPDB(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	l := staticFactNativeLease(t, ctx)
	tools, issued, err := l.PolicyRuntimeTools()
	if err != nil {
		t.Fatal(err)
	}
	r, ok := issued.(*policyRunner)
	if !ok {
		t.Fatal("original policy issuer missing")
	}
	var baseline [2][]byte
	for i, family := range []string{"-4", "-6"} {
		baseline[i], err = r.Run(ctx, tools.IP, family, "-N", "rule", "show")
		if err != nil {
			t.Fatal(err)
		}
	}
	var escaped context.Context
	stop := StartDomainNativeToolMeasurement()
	defer stop()
	versions := NativeFixtureVersionChildCount(l)
	err = l.WithReadOnlyToolObservation(ctx, l.identity, l.digest, func(observed context.Context) error {
		metadata := NativeFixtureVersionMetadataCount(l)
		err := r.WithOriginalNFQWSLANRPDB(observed, func(scoped context.Context) error {
			escaped = scoped
			for i, family := range []string{"-4", "-6"} {
				data, err := r.Run(scoped, tools.IP, family, "-N", "rule", "show")
				if err != nil {
					return err
				}
				if !bytes.Equal(data, baseline[i]) {
					return errors.New("actual RPDB output changed")
				}
			}
			return nil
		})
		if err == nil && NativeFixtureVersionMetadataCount(l)-metadata != 4 {
			return errors.New("actual RPDB opening/closing metadata changed")
		}
		return err
	})
	if err != nil {
		t.Fatal("original complete RPDB observation", nativeStages(err), err)
	}
	if counts := stop(); len(counts) != 1 || counts["original-read"] != 2 {
		t.Fatal("actual pair child count", counts)
	}
	if got := NativeFixtureVersionChildCount(l); got != versions {
		t.Fatal("RPDB path changed version child count", got, versions)
	}
	if data, err := r.Run(escaped, tools.IP, "-4", "-N", "rule", "show"); err == nil || data != nil {
		t.Fatal("escaped original RPDB observation accepted")
	}
	t.Log("actual original NFQ RPDB pair children=2 metadata=4 output_parity=true closing_full_source=true expired_scope_refused=true")
}

func BenchmarkNFQLANRPDBPair(b *testing.B) {
	for _, mode := range []string{"before", "after"} {
		b.Run(mode, func(b *testing.B) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			l := versionNamesActualLease(b, ctx)
			tools, issued, err := l.PolicyRuntimeTools()
			if err != nil {
				b.Fatal(err)
			}
			r, ok := issued.(*policyRunner)
			if !ok {
				b.Fatal("original policy issuer missing")
			}
			var want [2][]byte
			for i, family := range []string{"-4", "-6"} {
				want[i], err = r.Run(ctx, tools.IP, family, "-N", "rule", "show")
				if err != nil {
					b.Fatal(err)
				}
			}
			pair := func(c context.Context) error {
				for i, family := range []string{"-4", "-6"} {
					got, err := r.Run(c, tools.IP, family, "-N", "rule", "show")
					if err != nil {
						return err
					}
					if !bytes.Equal(got, want[i]) {
						return errors.New("actual RPDB changed")
					}
				}
				return nil
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				err := l.WithReadOnlyToolObservation(ctx, l.identity, l.digest, func(c context.Context) error {
					if mode == "after" {
						return r.WithOriginalNFQWSLANRPDB(c, pair)
					}
					return pair(c)
				})
				if err != nil {
					b.Fatal(nativeStages(err), err)
				}
			}
			b.StopTimer()
			b.ReportMetric(2, "actual_IP_children/op")
		})
	}
}
