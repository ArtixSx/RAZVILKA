package dataplane

import (
	"context"
	"errors"
	"os"
	"testing"
)

// Real held file bytes exercise the readonly primitive. This model cannot
// mint a native process, kernel observation or successful service mapping.
func TestDomainMappingPriorFilesPreserveParentAndClosing(t *testing.T) {
	for _, mode := range []string{"clean", "body-error", "mutate-restored-time", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			p, ctx, cancel := domainPriorFileResourceModel(t)
			defer cancel()
			var retained *xrayDomainTCPFileObservation
			bodyError := errors.New("mapping body refused")
			err := p.withFileObservation(ctx, func(parent *xrayDomainTCPFileObservation) error {
				retained = parent
				// A parent never opens a new successor loan or adopts its source.
				p.scope.domainSuccessor = nil
				return p.observeOriginalPriorFilesFrom(ctx, false, parent, func(observed context.Context, files *xrayDomainTCPFileObservation) error {
					if observed != ctx || files != parent || domainTCPHasPriorRead(observed) || files.current(ctx, p) != nil {
						t.Fatal("mapping replaced its exact original parent/context")
					}
					switch mode {
					case "body-error":
						return bodyError
					case "cancel":
						cancel()
					case "mutate-restored-time":
						e := p.executable
						data, err := os.ReadFile(e.path)
						if err != nil {
							return err
						}
						data[len(data)-1] ^= 1
						if err := os.WriteFile(e.path, data, 0700); err != nil {
							return err
						}
						return os.Chtimes(e.path, e.info.ModTime(), e.info.ModTime())
					}
					return nil
				})
			})
			if (err == nil) != (mode == "clean") || mode == "body-error" && !errors.Is(err, bodyError) {
				t.Fatal("original parent body/closing result changed", mode, err)
			}
			if retained == nil || retained.current(ctx, p) == nil || retained.open.Load() {
				t.Fatal("parent file observation escaped its original closing")
			}
		})
	}
}

func TestDomainMappingPriorFilesRejectForeignOrExpiredParent(t *testing.T) {
	p, ctx, cancel := domainPriorFileResourceModel(t)
	defer cancel()
	var expired *xrayDomainTCPFileObservation
	if err := p.withFileObservation(ctx, func(files *xrayDomainTCPFileObservation) error { expired = files; return nil }); err != nil {
		t.Fatal(err)
	}
	other, _, otherCancel := domainPriorFileResourceModel(t)
	defer otherCancel()
	called := false
	use := func(context.Context, *xrayDomainTCPFileObservation) error { called = true; return nil }
	for _, current := range []bool{false, true} {
		for _, parent := range []*xrayDomainTCPFileObservation{expired, {}} {
			if err := p.observeOriginalPriorFilesFrom(ctx, current, parent, use); err == nil || called {
				t.Fatal("expired/foreign parent silently opened another observation")
			}
		}
	}
	if err := p.withFileObservation(ctx, func(parent *xrayDomainTCPFileObservation) error {
		foreign := context.WithValue(ctx, struct{}{}, true)
		for _, current := range []bool{false, true} {
			if err := p.observeOriginalPriorFilesFrom(foreign, current, parent, use); err == nil || called {
				t.Fatal("derived context consumed the exact parent")
			}
			if err := other.observeOriginalPriorFilesFrom(ctx, current, parent, use); err == nil || called {
				t.Fatal("another process consumed the exact parent")
			}
		}
		if p.observeOriginalPriorFilesFrom(nil, false, parent, use) == nil || p.observeOriginalPriorFilesFrom(ctx, false, parent, nil) == nil || called {
			t.Fatal("missing context/callback admitted")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestDomainMappingPriorFilesKeepOriginalProcessBookends(t *testing.T) {
	p, ctx, cancel := domainPriorFileResourceModel(t)
	defer cancel()
	called := false
	use := func(context.Context, *xrayDomainTCPFileObservation) error { called = true; return nil }
	// current=true is the production mapping entry. Valid file bytes alone
	// cannot bypass either original live-process bookend to reach its body.
	if err := p.observeOriginalPriorFilesFrom(ctx, true, nil, use); err == nil || called {
		t.Fatal("standalone file loan invented a current native process")
	}
	if err := p.withFileObservation(ctx, func(parent *xrayDomainTCPFileObservation) error {
		if err := p.observeOriginalPriorFilesFrom(ctx, true, parent, use); err == nil || called {
			t.Fatal("accepted-prefix parent invented a current native process")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
