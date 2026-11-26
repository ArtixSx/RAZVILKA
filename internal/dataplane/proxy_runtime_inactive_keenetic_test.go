package dataplane

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// Representative captured router RPDB grammar, with fixture addresses. The
// existing ip-full 4.4 reader normalizes only reserved table names; the same
// CORE grammar must be used by both independent inactivity inventories.
const inactiveKeeneticRules4 = "0:\tfrom all lookup local \n100:\tfrom all fwmark 0xffffaaa lookup 4096 \n101:\tfrom all fwmark 0xffffaaa blackhole\n1154:\tfrom 100.64.1.2 lookup 16386 \n1172:\tfrom 172.16.50.2 lookup 16395 \n32766:\tfrom all lookup main \n32767:\tfrom all lookup default \n"
const inactiveKeeneticRules6 = "0:\tfrom all lookup local \n1172:\tfrom all oif nwg0 lookup 16395 \n1176:\tfrom fd00:1::2 lookup 16395 \n32766:\tfrom all lookup main \n"

func TestProxyRuntimeInactiveUsesSameKeeneticGrammarInBothReads(t *testing.T) {
	for _, mode := range []string{"foreign-firmware", "late-own-table", "late-owned-slot", "late-unknown-token", "late-alias", "reserved-table-alias"} {
		t.Run(mode, func(t *testing.T) {
			f := newInactiveFixture(t, "xray")
			if mode == "reserved-table-alias" {
				aliasReservedTableName(t, f.a.Table)
			}
			reads := map[int]int{}
			numericAttempts, routes := 0, 0
			f.a.Runner = runnerFunc(func(ctx context.Context, name string, args ...string) ([]byte, error) {
				if name != "ip" {
					return f.runner.Run(ctx, name, args...)
				}
				if slices.Contains(args, "-N") {
					numericAttempts++
					return []byte("Option \"-N\" is unknown, try \"ip -help\".\n"), errors.New("exit status 255")
				}
				family, plain := 4, args
				if len(plain) > 0 && plain[0] == "-6" {
					family, plain = 6, plain[1:]
				}
				if reflect.DeepEqual(plain, []string{"rule", "show"}) {
					reads[family]++
					out := map[int]string{4: inactiveKeeneticRules4, 6: inactiveKeeneticRules6}[family]
					// First read is the dependency check. Only its later slot
					// inventory sees these newly appeared unsafe rows.
					if family == 4 && reads[family] == 2 {
						switch mode {
						case "late-own-table":
							out += fmt.Sprintf("1400: from all lookup %d\n", f.a.Table)
						case "late-owned-slot":
							out += fmt.Sprintf("%d: from all fwmark 0x1 lookup 4096\n", f.a.Priority)
						case "late-unknown-token":
							out += "1400: from all lookup 4096 proto unknown\n"
						case "late-alias":
							out += "1400: from all lookup foreign-alias\n"
						}
					}
					return []byte(out), ctx.Err()
				}
				if reflect.DeepEqual(plain, []string{"route", "show", "table", fmt.Sprint(f.a.Table)}) {
					routes++
					return nil, ctx.Err()
				}
				t.Fatal("unexpected or mutating read", strings.Join(args, " "))
				return nil, ErrProxyRuntimeInactive
			})
			err := f.a.verifyRuntimeInactive(context.Background(), f.proof)
			if mode == "foreign-firmware" {
				if err != nil || reads[4] != 4 || reads[6] != 4 || routes != 4 || numericAttempts != 12 {
					t.Fatal("closed foreign RPDB did not pass both complete observations", reads, routes, numericAttempts, err)
				}
			} else if err == nil {
				t.Fatal("late unsafe or aliased state was accepted", mode)
			}
			if f.processes.calls != 0 {
				t.Fatal("read-only inactivity proof touched process lifecycle")
			}
		})
	}
}
