package dataplane

import (
	"context"
	"errors"
	"testing"
)

func TestDomainCapturePairedAddRejectsForeignOrRevokedRead(t *testing.T) {
	for _, change := range []string{"no-loan", "copy", "foreign-context", "foreign-capture", "foreign-baseline", "foreign-files", "closed"} {
		t.Run(change, func(t *testing.T) {
			capture := &domainTCPCaptureExecutionResource{}
			capture.self = capture
			baseline := &syntheticBaselineExecutionResource{}
			read := &domainTCPPreAddRead{capture: capture, baseline: baseline}
			read.self = read
			files := &xrayDomainTCPFileObservation{}
			loan := &domainTCPPreAddLoan{read: read, files: files}
			loan.self = loan
			ctx := context.WithValue(context.Background(), domainTCPPreAddKey{}, loan)
			loan.ctx = ctx
			loan.open.Store(true)
			switch change {
			case "no-loan":
				ctx = context.Background()
			case "copy":
				loan.self = &domainTCPPreAddLoan{}
			case "foreign-context":
				ctx = context.WithValue(ctx, struct{}{}, true)
			case "foreign-capture":
				read.capture = &domainTCPCaptureExecutionResource{}
			case "foreign-baseline":
				baseline = &syntheticBaselineExecutionResource{}
			case "foreign-files":
				files = &xrayDomainTCPFileObservation{}
			case "closed":
				loan.open.Store(false)
			}
			if err := capture.observeOriginalPreAddPair(ctx, baseline, 0, files); !errors.Is(err, ErrDomainPolicyTCPConsumer) {
				t.Fatalf("paired read accepted a changed original owner: %v", err)
			}
		})
	}
}
