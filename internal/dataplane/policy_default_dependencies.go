package dataplane

import (
	"context"
	"errors"
	"strconv"
	"strings"
)

var ErrPolicyDefaultReferenced = errors.New("policy table default still has a selector dependency or unrecognized RPDB state")

type numericPolicyReadRunner struct{ base NFQWS2Runner }

func (r numericPolicyReadRunner) Run(ctx context.Context, command string, args ...string) ([]byte, error) {
	return r.base.Run(ctx, command, append([]string{"-N"}, args...)...)
}

// AssertPolicyDefaultUnreferenced is a read-only negative dependency check,
// never deletion authority. Call it immediately before a durable default
// cleanup intent and again after that intent, before the delete syscall.
// Every remaining selector of this family must be understood. Unknown syntax
// retains the parent default; a matching table number does not grant a right
// to remove someone else's selector. Use the caller's bounded cleanup context.
func AssertPolicyDefaultUnreferenced(ctx context.Context, runner NFQWS2Runner, ip string, state PolicyState, family int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if runner == nil || ip == "" || (family != 4 && family != 6) || state.Table < 1 || state.Table > 252 {
		return ErrPolicyDefaultReferenced
	}
	numeric := numericPolicyReadRunner{base: runner}
	lines, err := readPolicyRules(ctx, numeric, ip, family)
	if err != nil {
		return errors.Join(ErrPolicyDefaultReferenced, err)
	}
	for _, raw := range lines {
		if err := ctx.Err(); err != nil {
			return err
		}
		line := strings.Join(strings.Fields(raw), " ")
		if line == "" {
			continue
		}
		switch line {
		case "0: from all lookup 255", "32766: from all lookup 254", "32767: from all lookup 253":
			continue
		}
		// Even a tool that silently ignores -N cannot turn a reserved-looking
		// alias (e.g. rt_tables "203 main") into proof of a different table.
		fields := strings.Fields(line)
		for i, field := range fields {
			if field == "lookup" || field == "table" {
				if i+1 >= len(fields) {
					return ErrPolicyDefaultReferenced
				}
				value, err := strconv.ParseUint(fields[i+1], 10, 32)
				if err != nil || strconv.FormatUint(value, 10) != fields[i+1] {
					return ErrPolicyDefaultReferenced
				}
			}
		}
		parsed, ok := parseKernelPolicyRule(family, line)
		if !ok && state.WireGuardEndpoint != nil {
			endpoint := *state.WireGuardEndpoint
			if endpoint.matchesRule(family, line) {
				// The immutable receipt's transport selector is independent of
				// this default only while its exact host pin is actually present.
				// Reuse NET's full rule/route readback; this observer has no file,
				// process, installation or effect callbacks and mutates nothing.
				observer := &WARPWireGuardAdapter{Runner: numeric, IP: ip}
				pinned, present, err := observer.inspectWGEndpoint(ctx, &endpoint)
				if err != nil || !pinned || !present {
					return errors.Join(ErrPolicyDefaultReferenced, err)
				}
				continue
			}
		}
		if !ok || parsed.table == state.Table {
			return ErrPolicyDefaultReferenced
		}
	}
	return ctx.Err()
}
