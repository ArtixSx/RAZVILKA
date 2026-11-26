package dataplane

import (
	"context"
	"errors"
	"testing"
)

// Error/state classification model only. No original five-lease/native source
// is supplied, so this fixture cannot issue a command or complete recovery.
func TestMihomoSameBootRetryNeverClassifiesLaterNativeFailure(t *testing.T) {
	for _, kind := range []string{"sidecar-wait", "policy", "forwarding", "effect-unknown", "archive", "terminal", "no-signal", "close-error", "generic-unknown"} {
		t.Run(kind, func(t *testing.T) {
			cause := errors.New("original native failure")
			c := &mihomoSameBootRetirementCursor{owner: &mihomoSameBootCleanup{sidecar: &mihomoSameBootSidecar{validated: true, attempted: true}}}
			c.self, c.owner.self, c.owner.sidecar.self = c, c.owner, c.owner.sidecar
			switch kind {
			case "policy":
				c.sidecarDone = true
			case "forwarding":
				c.sidecarDone, c.policyDone = true, true
			case "effect-unknown":
				c.owner.effectUnknown = true
			case "archive":
				c.forwardingDone = true
			case "terminal":
				c.owner.sidecar.terminal = true
			case "no-signal":
				c.owner.sidecar.attempted = false
			case "close-error":
				c.owner.sidecar.closeErr = cause
			}
			if kind == "generic-unknown" {
				c.unknown = cause
			} else {
				c.unknown = c.sidecarFailureAfterAttempt(cause)
			}
			pending, ok := c.unknown.(*mihomoSameBootSidecarWaitFailure)
			if kind == "sidecar-wait" {
				if !ok || !pending.matches(c) || !errors.Is(pending, cause) {
					t.Fatal("original first-phase exception not retained")
				}
				c.sidecarDone = true
				if pending.matches(c) {
					t.Fatal("old wait token survived later native phase")
				}
				return
			}
			if ok && pending.matches(c) {
				t.Fatal("later/generic/close failure gained sidecar retry", kind)
			}
			h := &MihomoSameBootRetirement{ctx: context.Background(), cursor: c, open: true, attempted: true, retrySidecar: true, lastErr: errors.Join(c.unknown, ErrMihomoSameBootRetainedRetry)}
			h.self = h
			if _, err := h.Retry(h.ctx); err == nil || !errors.Is(err, cause) {
				t.Fatal("forged retry hid original failure", err)
			}
			if c.unknown == nil || !errors.Is(c.unknown, cause) {
				t.Fatal("retry cleared unrelated unknown")
			}
		})
	}
}

func TestMihomoSameBootRetryCannotEraseObservedSourceLoss(t *testing.T) {
	ctx := context.Background()
	cause := errors.New("original source closing observation failed")
	c := &mihomoSameBootRetirementCursor{closed: true, closeErr: cause}
	c.self = c
	h := &MihomoSameBootRetirement{ctx: ctx, cursor: c, open: true, attempted: true, retryArchive: "retirement.json", lastErr: ErrMihomoSameBootRetainedRetry}
	h.self = h
	if _, err := h.Retry(ctx); !errors.Is(err, cause) {
		t.Fatal("source failure lost", err)
	}
	if h.retryArchive != "" || h.retrySidecar || h.retryTerminal != 0 {
		t.Fatal("observed source loss left original retry token usable")
	}
	// A modeled later apparently-current observation cannot resurrect this
	// SAME opportunity. No native source/lease is fabricated by this model.
	c.closed, c.closeErr = false, nil
	if _, err := h.Retry(ctx); !errors.Is(err, cause) {
		t.Fatal("later attempt erased original source failure", err)
	}
}
