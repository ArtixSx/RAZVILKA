package dataplane

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

type recordedPolicyFakeRunner struct {
	kernel    policyKernelFake
	calls     []string
	beforeAdd func(int)
	failRead  int
	failAdd   int
	failRule  int
	ruleAdds  int
}

func (r *recordedPolicyFakeRunner) Run(_ context.Context, command string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, command+" "+strings.Join(args, " "))
	family := 4
	plain := args
	if len(plain) > 0 && plain[0] == "-6" {
		family = 6
		plain = plain[1:]
	}
	joined := strings.Join(plain, " ")
	if strings.HasPrefix(joined, "route show table ") && r.failRead == family {
		return nil, errors.New("table read failed")
	}
	if strings.HasPrefix(joined, "route add default ") {
		if r.beforeAdd != nil {
			r.beforeAdd(family)
		}
		if r.failAdd == family {
			return nil, errors.New("default add failed")
		}
	}
	if strings.HasPrefix(joined, "rule add ") {
		r.ruleAdds++
		if r.failRule == r.ruleAdds {
			return nil, errors.New("selector add failed")
		}
	}
	out, handled, err := r.kernel.run(args)
	if !handled {
		return nil, errors.New("unsupported policy test command")
	}
	return out, err
}

// Independent stateful RPDB fixture. Add/delete operate on complete selectors,
// and readback returns actual state instead of assuming every route exists.
type policyKernelFake struct {
	entries     []policyKernelEntry
	foreignIPv4 []string
	defaults    map[string]string
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
	if len(args) > 2 && args[0] == "route" {
		if args[1] == "show" && len(args) == 4 && args[2] == "table" && args[3] != "main" {
			return []byte(f.defaults[fmt.Sprintf("%d/%s", family, args[3])]), true, nil
		}
		if (args[1] == "add" || args[1] == "del") && args[2] == "default" {
			dev, table, metric := "", "", "0"
			for i := 3; i+1 < len(args); i += 2 {
				switch args[i] {
				case "dev":
					dev = args[i+1]
				case "table":
					table = args[i+1]
				case "metric":
					metric = args[i+1]
				}
			}
			key := fmt.Sprintf("%d/%s", family, table)
			if f.defaults == nil {
				f.defaults = map[string]string{}
			}
			if args[1] == "add" {
				if f.defaults[key] != "" {
					return nil, true, errors.New("File exists")
				}
				f.defaults[key] = fmt.Sprintf("default dev %s proto boot metric %s\n", dev, metric)
			} else {
				delete(f.defaults, key)
			}
			return nil, true, nil
		}
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
