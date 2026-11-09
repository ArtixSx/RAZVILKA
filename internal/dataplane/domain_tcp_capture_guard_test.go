package dataplane

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDomainCaptureGuardRejectsInvalidEntryBeforeBaseline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, resource := range []*domainTCPCaptureExecutionResource{nil, {}, {process: &XrayDomainTCPExecutionResource{}}} {
		if resource != nil {
			resource.self = resource
		}
		// A nil baseline would panic if an invalid opening evaluated the later
		// comparison, as eager errors.Join argument evaluation otherwise does.
		if err := resource.guardOriginalBaseline(ctx, nil); !errors.Is(err, ErrDomainPolicyTCPConsumer) {
			t.Fatal("invalid original capture reached baseline or succeeded", err)
		}
	}
}
