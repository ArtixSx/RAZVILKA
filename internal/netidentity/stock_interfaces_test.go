package netidentity

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestStockInterfacesRejectsUnissuedAndProcProvider(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, p := range []*Provider{nil, {}, NewProcProvider()} {
		if raw, err := p.ReadReviewedStockInterfaces(ctx); !errors.Is(err, ErrUnknown) || raw != nil {
			t.Fatal("unreviewed provider read stock metadata")
		}
		if raw, err := p.ReadReviewedStockIPPolicies(ctx); !errors.Is(err, ErrUnknown) || raw != nil {
			t.Fatal("unreviewed provider read stock policy metadata")
		}
	}
}
