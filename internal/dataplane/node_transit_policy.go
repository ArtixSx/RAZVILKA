package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"strings"
)

func CompileNodeTransit(spec NodeTransitSpec) (PolicyEffectPlan, error) {
	digest, err := nodeTransitSpecDigest(spec)
	if err != nil {
		return PolicyEffectPlan{}, err
	}
	args := func(action string) []string {
		return []string{"-4", "rule", action, "priority", strconv.Itoa(spec.Priority),
			"from", netip.PrefixFrom(spec.Source, 32).String(), "to", netip.PrefixFrom(spec.Destination, 32).String(),
			"oif", spec.Interface, "lookup", strconv.Itoa(spec.Table)}
	}
	return PolicyEffectPlan{Generation: digest, Effects: []PolicyEffect{{Tool: PolicyEffectIP, Add: args("add"), Delete: args("del")}}}, nil
}

// Only this typed grammar extends the shared parser with oif. From/to and
// numeric selector validation still use CORE's sole kernel policy parser.
func nodeTransitRuleMatches(spec NodeTransitSpec, family int, line string) bool {
	if family != 4 || len(line) > 2048 || strings.ContainsAny(line, "\x00\r\n") {
		return false
	}
	fields := strings.Fields(line)
	if len(fields) != 9 || fields[5] != "oif" || fields[6] != spec.Interface || fields[7] != "lookup" && fields[7] != "table" {
		return false
	}
	table, err := strconv.Atoi(fields[8])
	if err != nil || strconv.Itoa(table) != fields[8] || table != spec.Table {
		return false
	}
	plain := append(append([]string(nil), fields[:5]...), fields[7:]...)
	rule, ok := parseKernelPolicyRule(family, strings.Join(plain, " "))
	return ok && rule.priority == spec.Priority && rule.table == spec.Table && rule.source == netip.PrefixFrom(spec.Source, 32).String() &&
		rule.destination == netip.PrefixFrom(spec.Destination, 32).String() && rule.ingress == "" && !rule.managed
}

func (l *nodeTransitLease) presence(ctx context.Context) (int, error) {
	if err := l.guard(ctx); err != nil {
		return 0, err
	}
	count := 0
	for _, family := range []int{4, 6} {
		lines, err := readPolicyRules(ctx, numericPolicyReadRunner{base: l.runtime.runner}, l.runtime.ip, family)
		if err != nil {
			return 0, errors.Join(ErrNodeTransitUnavailable, err, ctx.Err())
		}
		for _, line := range lines {
			if err := ctx.Err(); err != nil {
				return 0, err
			}
			if strings.TrimSpace(line) == "" {
				continue
			}
			priority, ok := policyLinePriority(line)
			if !ok || priority > 1<<31-1 || len(line) > 2048 {
				return 0, ErrNodeTransitUnavailable
			}
			if priority != l.spec.Priority {
				continue
			}
			if !nodeTransitRuleMatches(l.spec, family, line) {
				return 0, ErrNodeTransitUnavailable
			}
			count++
			if count > 1 {
				return 0, ErrNodeTransitUnavailable
			}
		}
	}
	if err := l.guard(ctx); err != nil {
		return 0, err
	}
	return count, nil
}

func (l *nodeTransitLease) VerifyRoute(ctx context.Context) error {
	if l == nil || ctx == nil {
		return ErrNodeTransitUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, nodeTransitBudget)
	defer cancel()
	status, err := l.Inspect(ctx)
	if err != nil || !status.Complete || status.Unknown || status.Removed {
		return nodeTransitPhase("route-receipt", errors.Join(ErrNodeTransitUnavailable, err))
	}
	count, err := l.presence(ctx)
	if err != nil || count != 1 {
		return nodeTransitPhase("route-presence", errors.Join(ErrNodeTransitUnavailable, err))
	}
	output, err := l.readRoute(ctx)
	if err != nil {
		return err
	}
	if len(output) > 4096 || !nodeTransitRouteMatches(l.spec, string(output)) {
		return nodeTransitPhase("route-lookup-shape", ErrNodeTransitUnavailable)
	}
	return nodeTransitPhase("route-closing-guard", l.guard(ctx))
}

// Entware iproute2 4.4 has route get/from/oif but not -N. Negotiate only
// that exact unsupported option, never a failed route or malformed success.
// The query remains the same frozen tuple; the normal strict route parser
// still requires its exact source, interface and numeric table afterwards.
func (l *nodeTransitLease) readRoute(ctx context.Context) ([]byte, error) {
	args := []string{"-N", "-4", "route", "get", l.spec.Destination.String(), "from", l.spec.Source.String(), "oif", l.spec.Interface}
	output, err := l.runtime.runner.Run(ctx, l.runtime.ip, args...)
	if ctx.Err() != nil {
		return nil, nodeTransitPhase("route-lookup-context", errors.Join(ErrNodeTransitUnavailable, ctx.Err()))
	}
	var exited interface{ ExitCode() int }
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) &&
		errors.As(err, &exited) && exited.ExitCode() == 255 && wgEndpointUnknownOption(output, "-N") {
		if !reservedTableNamesUnaliased() {
			return nil, nodeTransitPhase("route-lookup-table-alias", ErrNodeTransitUnavailable)
		}
		if err := l.guard(ctx); err != nil {
			return nil, nodeTransitPhase("route-lookup-fallback-guard", err)
		}
		output, err = l.runtime.runner.Run(ctx, l.runtime.ip, args[1:]...)
		if err != nil || ctx.Err() != nil {
			return nil, nodeTransitPhase("route-lookup-plain", errors.Join(ErrNodeTransitUnavailable, err, ctx.Err()))
		}
		if !reservedTableNamesUnaliased() {
			return nil, nodeTransitPhase("route-lookup-closing-table-alias", ErrNodeTransitUnavailable)
		}
		return numericReservedTables(output), nil
	}
	if err != nil {
		return nil, nodeTransitPhase("route-lookup-numeric", errors.Join(ErrNodeTransitUnavailable, err))
	}
	return output, nil
}

func nodeTransitRouteMatches(spec NodeTransitSpec, output string) bool {
	if len(output) > 4096 || strings.ContainsAny(output, "\x00\r") {
		return false
	}
	fields := strings.Fields(output)
	if len(fields) < 7 || len(fields) > 32 || fields[0] != spec.Destination.String() {
		return false
	}
	want := map[string]string{"from": spec.Source.String(), "dev": spec.Interface, "table": strconv.Itoa(spec.Table), "src": spec.Source.String()}
	seen := map[string]bool{}
	for i := 1; i < len(fields); i++ {
		key := fields[i]
		if seen[key] {
			return false
		}
		seen[key] = true
		if key == "cache" {
			continue
		}
		if i+1 >= len(fields) {
			return false
		}
		i++
		if value, ok := want[key]; ok {
			if fields[i] != value {
				return false
			}
		} else if key == "uid" {
			value, err := strconv.ParseUint(fields[i], 10, 32)
			if err != nil || strconv.FormatUint(value, 10) != fields[i] {
				return false
			}
		} else {
			return false
		}
	}
	return seen["from"] && seen["dev"] && seen["table"]
}
