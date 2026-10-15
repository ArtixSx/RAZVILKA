package dataplane

import (
	"context"
	"regexp"
	"slices"
)

// iproute2 before 4.17, such as Entware ip-full 4.4 on Keenetic routers
// ("Option "-N" is unknown"), has no -N. Every rule/route readback that asks
// for numeric output then failed, so no proxy, WG or LAN policy could be
// replaced, stopped or rolled back on such a router. Without -N iproute2 names
// only the reserved tables (and rt_tables entries); those reserved names are
// translated to the numbers -N prints. Any other name stays as printed and the
// strict parsers keep refusing it.

type ipReadRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

var reservedTableName = regexp.MustCompile(`\b(lookup|table) (local|main|default)\b`)

var reservedTableNumber = map[string]string{"local": "255", "main": "254", "default": "253"}

// runIPNumeric runs an ip readback that contains -N and, when it fails, reads
// the plain form once and translates the reserved table names. A failure of
// the plain form returns the original result.
func runIPNumeric(ctx context.Context, runner ipReadRunner, command string, args ...string) ([]byte, error) {
	out, err := runner.Run(ctx, command, args...)
	if err == nil || ctx.Err() != nil {
		return out, err
	}
	plain, ok := plainNumericReadback(args)
	if !ok {
		return out, err
	}
	fallback, fallbackErr := runner.Run(ctx, command, plain...)
	if fallbackErr != nil {
		return out, err
	}
	return numericReservedTables(fallback), nil
}

// plainNumericReadback drops the single -N of an `ip [-4|-6] -N rule|route
// show ...` readback. Any other command (for example iptables -N, which
// creates a chain) is not a readback and is never rewritten.
func plainNumericReadback(args []string) ([]string, bool) {
	index := slices.Index(args, "-N")
	if index < 0 || slices.Index(args[index+1:], "-N") >= 0 || index+2 >= len(args) {
		return nil, false
	}
	for _, option := range args[:index] {
		if option != "-4" && option != "-6" {
			return nil, false
		}
	}
	if object, action := args[index+1], args[index+2]; object != "rule" && object != "route" || action != "show" && action != "list" {
		return nil, false
	}
	return append(slices.Clone(args[:index]), args[index+1:]...), true
}

func numericReservedTables(output []byte) []byte {
	return reservedTableName.ReplaceAllFunc(output, func(match []byte) []byte {
		parts := reservedTableName.FindSubmatch(match)
		return []byte(string(parts[1]) + " " + reservedTableNumber[string(parts[2])])
	})
}
