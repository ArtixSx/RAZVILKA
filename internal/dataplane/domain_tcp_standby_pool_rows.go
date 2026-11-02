package dataplane

import "context"

// Pure counterfactual only. All prior SAME owners and their whole actual
// receipts/kernel readbacks bracket this actual collector image. No effect or
// packet may accept the resulting rows as permission to skip an original gate.
func (c *domainTCPGlobalSuccessor) counterfactualRows(ctx context.Context, backend *BackendInventory, rows []backendInventoryRow) ([]backendInventoryRow, error) {
	if backend == nil || c.forwardCurrent() != nil {
		return nil, ErrPolicyAdditionUnknown
	}
	if err := c.records.current(ctx, true); err != nil {
		return nil, err
	}
	entries, err := c.pool.originals()
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		o := e.detached.original
		if o == nil || o.backend == nil || !sameNetworkPolicyDependency(o.source, backend.reader.Runner) || o.backend.reader.Provider != backend.reader.Provider || o.backend.review != backend.review || o.backend.reader.IPTables != backend.reader.IPTables || o.backend.reader.IP6Tables != backend.reader.IP6Tables {
			return nil, ErrPolicyAdditionUnknown
		}
	}
	if err := c.comparePrior(ctx, true); err != nil {
		return nil, err
	}
	filtered := rows
	for _, e := range entries {
		filtered, err = domainTCPRetainedBaselineRows(filtered, e.detached.owner.baseline.effects)
		if err != nil {
			return nil, err
		}
	}
	if err := c.comparePrior(ctx, true); err != nil {
		return nil, err
	}
	if err := c.records.current(ctx, true); err != nil {
		return nil, err
	}
	return filtered, nil
}

// Shape comparison is separate from original ownership above, so negative
// fixtures can exercise duplicate/foreign/family/reference refusal without
// acquiring a process, standby, publication or cleanup grant.
func domainTCPRetainedBaselineRows(rows []backendInventoryRow, plan PolicyEffectPlan) ([]backendInventoryRow, error) {
	if _, err := syntheticBaselineTupleFromPlan(plan); err != nil {
		return nil, err
	}
	for i := range plan.Effects {
		count, err := syntheticBaselineExactPresence(rows, plan, i)
		if err != nil || count != 1 {
			return nil, ErrSyntheticBaselineTransition
		}
	}
	chain := plan.Effects[0].Add[3]
	result := make([]backendInventoryRow, 0, len(rows))
	for _, row := range rows {
		t := row.Tokens
		owned := len(t) > 1 && t[1] == chain
		for n := 2; n+1 < len(t); n++ {
			if (t[n] == "-j" || t[n] == "-g" || t[n] == "--jump" || t[n] == "--goto") && t[n+1] == chain {
				owned = true
			}
		}
		if !owned {
			result = append(result, row)
		}
	}
	return result, nil
}
