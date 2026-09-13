package dataplane

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// Independent stateful RPDB fixture. Add/delete operate on complete selectors,
// and readback returns actual state instead of assuming every route exists.
type policyKernelFake struct {
	entries     []policyKernelEntry
	foreignIPv4 []string
}

type policyKernelEntry struct {
	family, priority    int
	source, dest, table string
}

func (f *policyKernelFake) run(args []string) ([]byte, bool, error) {
	family := 4
	if len(args) > 0 && args[0] == "-6" {
		family, args = 6, args[1:]
	}
	if len(args) < 2 || args[0] != "rule" {
		return nil, false, nil
	}
	if args[1] == "show" {
		lines := []string{"0: from all lookup local", "32766: from all lookup main", "32767: from all lookup default"}
		if family == 4 {
			lines = append(lines, f.foreignIPv4...)
		}
		for _, rule := range f.entries {
			if rule.family == family {
				lines = append(lines, fmt.Sprintf("%d: from %s to %s lookup %s", rule.priority, rule.source, rule.dest, rule.table))
			}
		}
		return []byte(strings.Join(lines, "\n") + "\n"), true, nil
	}
	entry := policyKernelEntry{family: family, source: "all", dest: "all"}
	for i := 2; i+1 < len(args); i += 2 {
		switch args[i] {
		case "priority":
			entry.priority, _ = strconv.Atoi(args[i+1])
		case "from":
			entry.source = args[i+1]
		case "to":
			entry.dest = args[i+1]
		case "lookup":
			entry.table = args[i+1]
		default:
			return nil, true, errors.New("unknown fake RPDB attribute")
		}
	}
	if entry.dest == "" || entry.table == "" {
		return nil, true, errors.New("missing fake RPDB selector")
	}
	switch args[1] {
	case "add":
		f.entries = append(f.entries, entry)
		return nil, true, nil
	case "del":
		for i, old := range f.entries {
			if old == entry {
				f.entries = slices.Delete(f.entries, i, i+1)
				return nil, true, nil
			}
		}
		return nil, true, errors.New("No such policy rule")
	default:
		return nil, true, errors.New("unknown fake RPDB operation")
	}
}
