package dataplane

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
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
	if !ok || !reservedTableNamesUnaliased() {
		return out, err
	}
	fallback, fallbackErr := runner.Run(ctx, command, plain...)
	if fallbackErr != nil {
		return out, err
	}
	return numericReservedTables(fallback), nil
}

// plainNumericReadback drops the single -N of an `ip -N [-4|-6] rule|route
// show ...` readback (the family option may also precede -N). Any other
// option, such as -j, which ip 4.4 lacks as well, and any other command (for
// example iptables -N, which creates a chain) is never rewritten.
func plainNumericReadback(args []string) ([]string, bool) {
	var plain []string
	numeric, index := 0, 0
	for ; index < len(args) && strings.HasPrefix(args[index], "-"); index++ {
		switch args[index] {
		case "-N":
			numeric++
		case "-4", "-6":
			plain = append(plain, args[index])
		default:
			return nil, false
		}
	}
	if numeric != 1 || index+1 >= len(args) || slices.Contains(args[index:], "-N") {
		return nil, false
	}
	if object, action := args[index], args[index+1]; object != "rule" && object != "route" || action != "show" && action != "list" {
		return nil, false
	}
	return append(plain, args[index:]...), true
}

// rtTablesSources are the rt_tables files and directories of the stock and
// Entware iproute2 builds.
var rtTablesSources = []string{"/etc/iproute2", "/opt/etc/iproute2", "/usr/share/iproute2", "/usr/lib/iproute2"}

// reservedTableNamesUnaliased reports that no rt_tables entry gives another
// table a reserved name. With an entry such as "203 main" a plain readback
// would print table 203 as main, so the names prove nothing and the fallback
// is refused. Numeric names must identify themselves too: "205 204" would
// otherwise print a foreign table as the exact number a strict parser expects.
// An unreadable source also refuses it.
func reservedTableNamesUnaliased() bool {
	var files []string
	for _, root := range rtTablesSources {
		files = append(files, filepath.Join(root, "rt_tables"))
		entries, err := os.ReadDir(filepath.Join(root, "rt_tables.d"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return false
		}
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".conf") {
				files = append(files, filepath.Join(root, "rt_tables.d", entry.Name()))
			}
		}
	}
	for _, path := range files {
		data, err := os.ReadFile(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil || len(data) > 1<<20 {
			return false
		}
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 || strings.HasPrefix(fields[0], "#") {
				continue
			}
			if displayed, err := strconv.ParseUint(fields[1], 10, 32); err == nil && strconv.FormatUint(displayed, 10) == fields[1] {
				number, err := strconv.ParseUint(fields[0], 0, 32)
				if err != nil || number != displayed {
					return false
				}
			}
			want, reserved := reservedTableNumber[fields[1]]
			if !reserved {
				continue
			}
			if number, err := strconv.ParseUint(fields[0], 0, 32); err != nil || strconv.FormatUint(number, 10) != want {
				return false
			}
		}
	}
	return true
}

func numericReservedTables(output []byte) []byte {
	return reservedTableName.ReplaceAllFunc(output, func(match []byte) []byte {
		parts := reservedTableName.FindSubmatch(match)
		return []byte(string(parts[1]) + " " + reservedTableNumber[string(parts[2])])
	})
}
