//go:build linux && (amd64 || arm64)

package startuptools

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestClassicReadBatchBoundaryRejectsForeignRevokedAndCopiedObservation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	l := &Lease{lifetime: ctx, review: &heldReview{}}
	o := &toolReadObservation{lease: l, review: l.review, active: true, deadline: time.Now().Add(time.Second)}
	o.self = o
	scoped := context.WithValue(ctx, toolReadObservationKey{}, o)
	o.ctx = scoped
	for _, kind := range []string{"foreign", "revoked", "copied", "malformed", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			source, held := l, scoped
			o.active = true
			switch kind {
			case "foreign":
				source = &Lease{lifetime: ctx, review: l.review}
			case "revoked":
				o.active = false
			case "copied":
				copy := &toolReadObservation{self: o, lease: l, review: l.review, active: true, deadline: o.deadline, ctx: scoped}
				held = context.WithValue(ctx, toolReadObservationKey{}, copy)
			case "malformed":
				held = context.WithValue(ctx, toolReadObservationKey{}, "foreign")
			case "canceled":
				cancel()
			}
			if err := source.classicBatchBytesCurrent(held); err == nil {
				t.Fatal("unissued observation crossed batch boundary", kind)
			}
		})
	}
}

func TestClassicReadBatchRejectsCopiedExpiredAndForeignInvocation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l := &Lease{review: &heldReview{}, lifetime: ctx}
	b := &classicTableReadBatch{lease: l, ctx: ctx, active: true, commands: []classicTableReadCommand{{family: 0, table: "mangle"}}}
	b.self = b
	for _, tc := range []struct {
		name         string
		b            *classicTableReadBatch
		ctx          context.Context
		l            *Lease
		index, limit int
	}{
		{"copy", &classicTableReadBatch{self: b, lease: l, ctx: ctx, active: true, commands: b.commands}, ctx, l, 0, 1024},
		{"foreign-context", b, context.Background(), l, 0, 1024},
		{"foreign-lease", b, ctx, &Lease{review: l.review, lifetime: ctx}, 0, 1024},
		{"out-of-order", b, ctx, l, 1, 1024},
		{"nil-context", b, nil, l, 0, 1024},
		{"zero-budget", b, ctx, l, 0, 0},
		{"oversize-budget", b, ctx, l, 0, maxOutputBytes + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.b.read(tc.ctx, tc.l, tc.index, tc.limit)
			var refused *failure
			if !errors.Is(err, ErrUnknown) || !errors.As(err, &refused) || refused.stage != "CLASSIC_BATCH_SCOPE" {
				t.Fatal("invalid invocation reached command leaf", err)
			}
		})
	}
	b.active = false
	if _, err := b.read(ctx, l, 0, 1024); err == nil {
		t.Fatal("expired batch remained usable")
	}
	for _, command := range []classicTableReadCommand{{family: 2, table: "mangle"}, {family: 0, table: "mangle -F"}, {family: 0, table: "-S"}} {
		bad := &classicTableReadBatch{lease: l, ctx: ctx, active: true, commands: []classicTableReadCommand{command}}
		bad.self = bad
		_, err := bad.read(ctx, l, 0, 1024)
		var refused *failure
		if !errors.As(err, &refused) || refused.stage != "CLASSIC_BATCH_SCOPE" {
			t.Fatal("nonliteral read reached command image", err)
		}
	}
}
