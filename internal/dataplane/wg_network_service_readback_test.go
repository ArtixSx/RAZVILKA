package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestWGNetworkServiceReadbackRequestsCompleteDetails(t *testing.T) {
	for _, family := range []int{4, 6} {
		t.Run(fmt.Sprint(family), func(t *testing.T) {
			a := NewWireGuardAdapter(nil, t.TempDir())
			a.IP = "ip"
			state := PolicyState{Interface: a.interfaceName(), Table: a.table(), NetworkPolicyGeneration: strings.Repeat("a", 64)}
			want := []string{"-N", "-details"}
			metric, scope := 0, 253
			if family == 6 {
				want = append(want, "-6")
				metric, scope = 1024, 0
			}
			want = append(want, "-j", "route", "show", "table", "206")
			a.Runner = networkCleanupRunner(func(_ context.Context, name string, args ...string) ([]byte, error) {
				if name != "ip" || !slices.Equal(args, want) {
					t.Errorf("readback did not request the full detailed numeric table: %s %v", name, args)
					// Quiet iproute2 output elides boot. Never infer it from absence.
					return []byte(fmt.Sprintf(`[{"dst":"default","dev":"rz-wg","scope":"%d","metric":%d,"flags":[]}]`, scope, metric)), nil
				}
				return []byte(fmt.Sprintf(`[{"type":"1","dst":"default","dev":"rz-wg","protocol":"3","scope":"%d","metric":%d,"flags":[]}]`, scope, metric)), nil
			})
			count, err := a.wgNetworkServiceTablePresence(context.Background(), state, family)
			if err != nil || count != 1 {
				t.Fatal("complete same-family compiler default refused", count, err)
			}
		})
	}
}

func TestWGNetworkDetailedServiceReadbackRejectsForeignAndIncompleteTuples(t *testing.T) {
	for _, family := range []int{4, 6} {
		for _, cut := range []string{"missing-protocol", "missing-scope", "missing-type", "scope", "protocol", "type", "table", "gateway", "source", "specific", "details-unsupported"} {
			t.Run(fmt.Sprintf("%d/%s", family, cut), func(t *testing.T) {
				a := NewWireGuardAdapter(nil, t.TempDir())
				a.IP = "ip"
				state := PolicyState{Interface: a.interfaceName(), Table: a.table(), NetworkPolicyGeneration: strings.Repeat("a", 64)}
				metric, scope, foreignScope := 0, 253, 0
				if family == 6 {
					metric, scope, foreignScope = 1024, 0, 253
				}
				row := map[string]any{"type": "1", "dst": "default", "dev": "rz-wg", "protocol": "3", "scope": scope, "metric": metric, "flags": []string{}}
				switch cut {
				case "missing-protocol":
					delete(row, "protocol")
				case "missing-scope":
					delete(row, "scope")
				case "missing-type":
					delete(row, "type")
				case "scope":
					row["scope"] = foreignScope
				case "protocol":
					row["protocol"] = 4
				case "type":
					row["type"] = "6"
				case "table":
					row["table"] = 205
				case "gateway":
					row["gateway"] = "192.0.2.1"
				case "source":
					row["from"] = "fd01:77::2/128"
				}
				rows := []map[string]any{row}
				if cut == "specific" {
					rows = append(rows, map[string]any{"dst": "198.51.100.10/32", "dev": "foreign", "protocol": 4})
				}
				wire, _ := json.Marshal(rows)
				a.Runner = networkCleanupRunner(func(_ context.Context, _ string, args ...string) ([]byte, error) {
					if cut == "details-unsupported" {
						return []byte("unsupported option"), errors.New("exit status 1")
					}
					return wire, nil
				})
				if count, err := a.wgNetworkServiceTablePresence(context.Background(), state, family); err == nil || count != 0 {
					t.Fatal("foreign/incomplete detailed tuple became owned", count, err)
				}
			})
		}
	}
}
