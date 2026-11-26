package dataplane

import (
	"context"
	"strconv"
	"strings"
)

// The original scope boundary already captures every actually registered
// classic table and nft twice. Direct mode adds no table, mark or RPDB effect;
// it must not require an unregistered raw table or change firmware matches.
// All project routing ownership conflicts remain a refusal.
func (r *LANPolicyRuntime) preflightDirect(ctx context.Context, p *LANPolicyRuntimePlan) error {
	if err := r.inspectDirectRPDB(ctx); err != nil {
		return err
	}
	return lanPolicyPreflightAt("scope-close", r.check(ctx, p))
}

// A retained cleanup caller brackets this read with its original cleanup
// guard. It must not borrow an expired forward ScopeCheck to prove absence.
func (r *LANPolicyRuntime) inspectDirectRPDB(ctx context.Context) error {
	for _, family := range []int{4, 6} {
		output, err := r.read(ctx, "ip", "-"+strconv.Itoa(family), "-N", "rule", "show")
		if err != nil {
			return lanPolicyPreflightAt("rpdb-read", err)
		}
		for _, line := range strings.Split(output, "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			priority, ok := policyLinePriority(line)
			if !ok || !lanPolicyRuleSyntax(line) {
				return lanPolicyPreflightAt("rpdb-syntax", ErrLANPolicyRuntime)
			}
			if priority == LANPolicySkipPriority || priority == LANPolicyAnchorPriority {
				return lanPolicyPreflightAt("rpdb-reserved-priority", ErrLANPolicyRuntime)
			}
			fields := strings.Fields(line)
			for i, field := range fields {
				if field == "goto" && i+1 < len(fields) && fields[i+1] == "73" {
					return lanPolicyPreflightAt("rpdb-goto-anchor", ErrLANPolicyRuntime)
				}
				if (field == "lookup" || field == "table") && i+1 < len(fields) {
					for _, owner := range PolicyOwnershipSpecs() {
						if fields[i+1] == strconv.Itoa(owner.Table) {
							return lanPolicyPreflightAt("rpdb-owned-table", ErrLANPolicyRuntime)
						}
					}
				}
			}
		}
	}
	return ctx.Err()
}
