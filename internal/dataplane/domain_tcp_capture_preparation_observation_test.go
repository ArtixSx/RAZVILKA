package dataplane

import (
	"context"
	"errors"
	"testing"
)

func TestDomainCaptureClosingObservationCannotMintOriginalResource(t *testing.T) {
	o := &DomainTCPOriginalScope{}
	o.self = o
	c := &DomainPolicyTCPCapture{owner: o}
	c.self = c
	called := false
	err := c.observePreparationClosing(context.Background(), nil, func(context.Context, *xrayDomainTCPFileObservation) error {
		called = true
		return nil
	})
	if called || !errors.Is(err, ErrDomainPolicyTCPConsumer) {
		t.Fatal("comparison-only owner entered original source observation", called, err)
	}
}

func TestDomainCaptureClosingObservationKeepsLegacyFullPath(t *testing.T) {
	c := &DomainPolicyTCPCapture{owner: &syntheticTCPModelOwner{}}
	c.self = c
	witness := errors.New("legacy original observation failure")
	called := 0
	err := c.observePreparationClosing(context.Background(), nil, func(ctx context.Context, files *xrayDomainTCPFileObservation) error {
		called++
		if files != nil {
			t.Fatal("legacy comparison obtained a file view")
		}
		return witness
	})
	if called != 1 || !errors.Is(err, witness) {
		t.Fatal("legacy full-check callback or its error changed", called, err)
	}
}
