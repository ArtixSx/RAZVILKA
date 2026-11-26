package dataplane

import (
	"context"
	"errors"
	"testing"
)

// File possession alone must never replace original source/process authority.
// These models intentionally have no actual source, child or kernel birth.
func TestXrayListenerImageRefusalReleasesPrivateStorage(t *testing.T) {
	for _, mode := range []string{"missing-material", "invalid-material", "foreign-resource", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			r, parent := domainFileObservationModel(t)
			ctx, cancel := context.WithCancel(parent)
			defer cancel()
			image := r.borrowFileObservationImage(ctx)
			if image == nil {
				t.Fatal("private image unavailable")
			}
			t.Cleanup(image.release)
			if mode != "missing-material" {
				r.material = &XrayDomainTCPOperationMaterial{}
				r.material.self = r.material
			}
			target := r
			if mode == "foreign-resource" {
				target = &XrayDomainTCPExecutionResource{material: r.material, executable: r.executable}
				target.self = target
			}
			if mode == "cancel" {
				cancel()
			}
			err := target.listenerCurrentWithImage(ctx, image)
			if !errors.Is(err, ErrXrayDomainTCPOriginal) || mode == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal("file image replaced original authority or cancellation", err)
			}
			if !image.lease.closed.Load() || image.phase.Load() != 4 {
				t.Fatal("failed listener comparison retained private image")
			}
			xrayImageScopeReleased(t, r.executable.info.Size())
		})
	}
}
