package startuptools

import (
	"context"
	"slices"
)

// The compiled stock IP lacks -N. Its SAME held review already captures the
// absence of iproute2 naming inputs. Adapt only these numeric rule reads; the
// owner's one-use issuer still compares the exact original logical command.
func wgStockNumericRuleArguments(args []string) ([]string, bool) {
	if len(args) == 3 && slices.Equal(args, []string{"-N", "rule", "show"}) {
		return []string{"rule", "show"}, true
	}
	if len(args) == 4 && args[2] == "rule" && args[3] == "show" {
		family := args[0]
		if family == "-N" {
			family = args[1]
		}
		if (family == "-4" || family == "-6") && (args[0] == "-N" || args[1] == "-N") {
			return []string{family, "rule", "show"}, true
		}
	}
	return nil, false
}

type wgStockRuleAdmission struct {
	self             *wgStockRuleAdmission
	ctx              context.Context
	owner            CommandAdmission
	name, review     string
	original, actual []string
}

// This is a fixed WG stock read adapter, never a new admission issuer. Only
// the original sealed WG RPC carrier may reach the concrete Start callback.
func (a *wgStockRuleAdmission) WithStart(ctx context.Context, name string, args []string, review string, begin func() error) error {
	if a == nil || a.self != a || a.ctx == nil || a.owner == nil || ctx == nil || begin == nil || a.name != name || a.review != review || !slices.Equal(args, a.actual) {
		return at("WG_STOCK_READ_ADMISSION", nil)
	}
	carrier, ok := ctx.Value(admissionKey{}).(commandAdmission)
	if !ok || carrier.owner != a {
		return at("WG_STOCK_READ_ADMISSION", nil)
	}
	return a.owner.WithStart(a.ctx, name, slices.Clone(a.original), review, begin)
}

func wgStockReadContext(ctx context.Context, name, review string, original, actual []string) (context.Context, error) {
	if ctx == nil {
		return nil, at("WG_STOCK_READ_ADMISSION", nil)
	}
	expected, valid := wgStockNumericRuleArguments(original)
	if !valid || !slices.Equal(expected, actual) {
		return nil, at("WG_STOCK_READ_ADMISSION", nil)
	}
	owner, ok := ctx.Value(admissionKey{}).(commandAdmission)
	if !ok || owner.owner == nil {
		return nil, at("WG_STOCK_READ_ADMISSION", nil)
	}
	a := &wgStockRuleAdmission{ctx: ctx, owner: owner.owner, name: name, review: review, original: slices.Clone(original), actual: slices.Clone(actual)}
	a.self = a
	return WithCommandAdmission(ctx, a), nil
}
