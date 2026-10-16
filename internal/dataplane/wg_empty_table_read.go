package dataplane

import (
	"context"
	"errors"
	"strconv"
)

// This is negative inspection of a complete, numerically selected owned
// table. Stock Entware iproute2 4.4 has neither -N nor -j. Only its exact option
// diagnostic permits one plain retry through the SAME adapter/command owner.
// Empty successful text is absence, never a decoded route, receipt or cleanup
// grant. Any nonempty text refuses; positive service proof stays JSON-only.
func (a *WARPWireGuardAdapter) verifyWGEmptyNumericTable(ctx context.Context, table, family int) error {
	if a == nil || ctx == nil || ctx.Err() != nil || family != 4 && family != 6 {
		return errWGInactiveUnknown
	}
	spec, err := a.endpointSpec()
	if err != nil || table != spec.Table && table != spec.EndpointTable && table != 219 {
		return errors.Join(err, errWGInactiveUnknown)
	}
	data, err := a.readWGCompleteNumericTable(ctx, table, family)
	if err == nil {
		rows, parseErr := parseWGEndpointRoutes(data)
		if parseErr != nil || len(rows) != 0 {
			return errors.Join(parseErr, errWGInactiveUnknown)
		}
		return ctx.Err()
	}
	if !wgEndpointUnknownOption(data, "-N") && !wgEndpointUnknownOption(data, "-j") {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	args := []string{}
	if family == 6 {
		args = append(args, "-6")
	}
	args = append(args, "route", "show", "table", strconv.Itoa(table))
	data, err = a.run(ctx, a.ip(), args...)
	if err != nil || len(data) != 0 {
		return errors.Join(err, errWGInactiveUnknown)
	}
	return ctx.Err()
}
