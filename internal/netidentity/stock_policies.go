package netidentity

import (
	"bytes"
	"context"
)

// StockEmptyIPPolicyTable recognizes the complete output of a successful
// NC-1812 NDMC read. It says nothing about additional kernel routing rules.
func StockEmptyIPPolicyTable(raw []byte) bool {
	return len(raw) == 0 || bytes.Equal(raw, []byte("\x1b[K\x1b[K"))
}

func (p *Provider) RequireReviewedStockEmptyIPPolicies(ctx context.Context) error {
	raw, err := p.ReadReviewedStockIPPolicies(ctx)
	if err != nil {
		return err
	}
	if !StockEmptyIPPolicyTable(raw) {
		return ErrUnknown
	}
	return nil
}
