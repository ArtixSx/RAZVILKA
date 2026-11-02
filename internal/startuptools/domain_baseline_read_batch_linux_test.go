//go:build linux && (amd64 || arm64)

package startuptools

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Original private source comparison models only: every case must refuse
// before a command or positive kernel observation can be issued.
func TestDomainBaselineScopedReadRejectsForeignRevokedAndEffectInput(t *testing.T) {
	for _, kind := range []string{"missing", "copied", "foreign", "revoked", "canceled", "effect"} {
		t.Run(kind, func(t *testing.T) {
			l := syntheticDNSLeaseModel(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			deadline, _ := ctx.Deadline()
			o := &toolReadObservation{lease: l, review: l.review, identity: l.identity, digest: l.digest, active: true, deadline: deadline}
			o.self = o
			observed := context.WithValue(ctx, toolReadObservationKey{}, o)
			o.ctx = observed
			args := []string{"-4", "-j", "rule", "show"}
			switch kind {
			case "missing":
				observed = context.WithValue(ctx, toolReadObservationKey{}, "foreign value")
			case "copied":
				copy := &toolReadObservation{self: o, lease: l, review: l.review, identity: l.identity, digest: l.digest, active: true, deadline: deadline, ctx: observed}
				observed = context.WithValue(ctx, toolReadObservationKey{}, copy)
			case "foreign":
				o.lease = unitLease(t)
			case "revoked":
				o.active = false
			case "canceled":
				cancel()
			case "effect":
				args = []string{"-4", "rule", "add", "priority", "31000"}
			}
			data, err := l.domainBaselineRead(observed, args)
			if !errors.Is(err, ErrUnknown) || data != nil {
				t.Fatal("invalid original readonly scope issued a result", kind, err)
			}
		})
	}
}
