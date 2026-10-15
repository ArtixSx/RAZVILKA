package dataplane

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

var ErrPolicyDefaultReferenced = errors.New("policy table default still has a selector dependency or unrecognized RPDB state")

type numericPolicyReadRunner struct{ base NFQWS2Runner }

func (r numericPolicyReadRunner) Run(ctx context.Context, command string, args ...string) ([]byte, error) {
	return runIPNumeric(ctx, r.base, command, append([]string{"-N"}, args...)...)
}

// AssertPolicyDefaultUnreferenced is a read-only negative dependency check,
// never deletion authority. Call it immediately before a durable default
// cleanup intent and again after that intent, before the delete syscall.
// Every remaining selector of this family must be understood. Unknown syntax
// retains the parent default; a matching table number does not grant a right
// to remove someone else's selector. Use the caller's bounded cleanup context.
func AssertPolicyDefaultUnreferenced(ctx context.Context, runner NFQWS2Runner, ip string, state PolicyState, family int) error {
	return assertPolicyDefaultUnreferenced(ctx, runner, ip, state, family, nil)
}

// AssertPolicyDefaultUnreferencedWithLAN understands only the negative RPDB
// effects of this exact frozen generation. It grants no gate or deletion
// authority. An observed gate must be complete and unique; an absent gate is
// compatible with a preflight before activation or after complete retirement.
func AssertPolicyDefaultUnreferencedWithLAN(ctx context.Context, runner NFQWS2Runner, ip string, state PolicyState, family int, frozen *LANPolicyRuntimePlan) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	lan := CloneLANPolicyRuntime(frozen)
	if ValidateLANPolicyRuntime(lan) != nil || !validNetworkPolicyGeneration(state.NetworkPolicyGeneration) || lan.Generation != state.NetworkPolicyGeneration {
		return ErrPolicyDefaultReferenced
	}
	return assertPolicyDefaultUnreferenced(ctx, runner, ip, state, family, lan)
}

func assertPolicyDefaultUnreferenced(ctx context.Context, runner NFQWS2Runner, ip string, state PolicyState, family int, lan *LANPolicyRuntimePlan) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if runner == nil || ip == "" || (family != 4 && family != 6) || state.Table < 1 || state.Table > 252 {
		return ErrPolicyDefaultReferenced
	}
	lanLines := map[string]bool{}
	if lan != nil {
		for _, rule := range lanPolicyRules(lan) {
			if rule.family == family {
				lanLines[lanPolicyRuleKey(rule.line())] = false
			}
		}
	}
	seenLAN := 0
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
		if seen, expected := lanLines[lanPolicyRuleKey(line)]; expected {
			if seen {
				return ErrPolicyDefaultReferenced
			}
			lanLines[lanPolicyRuleKey(line)] = true
			seenLAN++
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
		if !ok {
			if table, known := knownWGTransportRuleTable(family, line); known && table != state.Table {
				continue // An understood other-table lookup is not deletion authority.
			}
		}
		if !ok || parsed.table == state.Table {
			return ErrPolicyDefaultReferenced
		}
	}
	if seenLAN != 0 && seenLAN != len(lanLines) {
		return ErrPolicyDefaultReferenced
	}
	return ctx.Err()
}

// Reuse NET's exact rule parser and published coordinates to understand a
// transport lookup. This explains no ownership, process, WAN path or host pin.
func knownWGTransportRuleTable(family int, line string) (int, bool) {
	fields := strings.Fields(line)
	if len(fields) != 9 {
		return 0, false
	}
	var destination netip.Prefix
	for i := 1; i+1 < len(fields); i += 2 {
		if fields[i] != "to" {
			continue
		}
		var err error
		destination, err = netip.ParsePrefix(fields[i+1])
		if err != nil {
			address, err := netip.ParseAddr(fields[i+1])
			if err != nil {
				return 0, false
			}
			destination = netip.PrefixFrom(address, address.BitLen())
		}
	}
	address := destination.Addr()
	if !address.IsValid() || address.Is4In6() || address.Zone() != "" || !address.IsGlobalUnicast() || address.IsPrivate() || destination.Bits() != address.BitLen() {
		return 0, false
	}
	for _, spec := range PolicyOwnershipSpecs() {
		if spec.EndpointPriority == 0 || spec.EndpointMark == 0 {
			continue
		}
		for _, table := range []int{spec.Table, spec.EndpointTable} {
			if table == 0 {
				continue
			}
			endpoint := WGEndpointState{Endpoint: net.JoinHostPort(address.String(), "1"), Priority: spec.EndpointPriority, Mark: spec.EndpointMark, Table: table}
			if endpoint.matchesRule(family, line) {
				return table, true
			}
		}
	}
	return 0, false
}
