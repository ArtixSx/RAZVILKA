package dataplane

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

type wgEndpointKernelFake struct {
	routes      map[string]wgEndpointRoute
	routeTables map[string]int
	rules       map[string]string
	mark        string
	publicKey   string
	wanDevice   string
}

func (f *wgEndpointKernelFake) ruleOutput(args []string) []byte {
	family := "4"
	if len(args) > 0 && args[0] == "-6" {
		family = "6"
	}
	var out string
	for key, line := range f.rules {
		if strings.HasPrefix(key, family+"|") {
			out += line + "\n"
		}
	}
	return []byte(out)
}

func (f *wgEndpointKernelFake) run(name string, args []string) ([]byte, bool, error) {
	if name == "wg" && len(args) == 3 && args[0] == "setconf" {
		profile, _ := os.ReadFile(args[2])
		f.publicKey, _ = wgRuntimePublicKey(profile)
	}
	if name == "wg" && len(args) == 3 && args[0] == "show" && args[2] == "public-key" {
		return []byte(f.publicKey), true, nil
	}
	if name == "wg" && len(args) == 4 && args[0] == "set" && args[2] == "fwmark" {
		f.mark = args[3]
		return nil, true, nil
	}
	if name == "wg" && len(args) == 3 && args[0] == "show" && args[2] == "fwmark" {
		return []byte(f.mark), true, nil
	}
	if name != "ip" {
		return nil, false, nil
	}
	family := "4"
	if len(args) > 0 && args[0] == "-6" {
		family = "6"
		args = args[1:]
	}
	if len(args) >= 4 && args[0] == "-j" && args[1] == "route" && args[2] == "get" {
		dev := f.wanDevice
		if dev == "" {
			dev = "eth0"
		}
		source, gateway := "192.0.2.2", "192.0.2.1"
		if family == "6" {
			source, gateway = "2001:db8::2", "2001:db8::1"
		}
		data, _ := json.Marshal([]wgEndpointRoute{{Destination: args[3], Device: dev, Source: source, Gateway: gateway}})
		return data, true, nil
	}
	if len(args) >= 5 && args[0] == "-j" && args[1] == "route" && args[2] == "show" && args[3] == "table" {
		table, err := strconv.Atoi(args[4])
		if err != nil {
			return nil, true, err
		}
		routes := []wgEndpointRoute{}
		for key, r := range f.routes {
			origin := f.routeTables[key]
			if !strings.HasPrefix(key, family+"|") || origin != 0 && origin != table || origin == 0 && len(r.Table) != 0 && !wgEndpointTableMatches(r.Table, table) {
				continue
			}
			if len(args) >= 7 && args[5] == "exact" && key != family+"|"+args[6] {
				continue
			}
			routes = append(routes, r)
		}
		data, _ := json.Marshal(routes)
		return data, true, nil
	}
	joined := " " + strings.Join(args, " ") + " "
	if len(args) > 2 && args[0] == "rule" && strings.Contains(joined, " fwmark ") && !strings.Contains(joined, " from ") && !strings.Contains(joined, " iif ") {
		v := map[string]string{}
		for i := 2; i+1 < len(args); i += 2 {
			v[args[i]] = args[i+1]
		}
		if f.rules == nil {
			f.rules = map[string]string{}
		}
		key := family + "|" + v["priority"]
		line := fmt.Sprintf("%s: from all to %s fwmark %s lookup %s", v["priority"], v["to"], v["fwmark"], v["lookup"])
		if args[1] == "add" {
			if f.rules[key] != "" {
				return nil, true, fmt.Errorf("rule exists")
			}
			f.rules[key] = line
		} else {
			if f.rules[key] != line {
				return nil, true, fmt.Errorf("rule missing or mismatch")
			}
			delete(f.rules, key)
		}
		return nil, true, nil
	}
	if len(args) > 2 && args[0] == "route" && (args[1] == "add" || args[1] == "del") {
		if _, err := netip.ParsePrefix(args[2]); err != nil {
			return nil, false, nil
		}
		if f.routes == nil {
			f.routes = map[string]wgEndpointRoute{}
		}
		key := family + "|" + args[2]
		if args[1] == "del" {
			delete(f.routes, key)
			delete(f.routeTables, key)
			return nil, true, nil
		}
		if _, ok := f.routes[key]; ok {
			return nil, true, fmt.Errorf("route exists")
		}
		r := wgEndpointRoute{Destination: args[2]}
		for i := 3; i < len(args); i++ {
			switch args[i] {
			case "via":
				i++
				r.Gateway = args[i]
			case "dev":
				i++
				r.Device = args[i]
			case "src":
				i++
				r.Source = args[i]
			case "onlink":
				r.Flags = []string{"onlink"}
			case "table":
				i++
				r.Table = json.RawMessage(args[i])
			case "metric":
				i++
				r.Metric, _ = strconv.Atoi(args[i])
			case "proto":
				i++
				r.Protocol = args[i]
			}
		}
		f.routes[key] = r
		if f.routeTables == nil {
			f.routeTables = map[string]int{}
		}
		var tableID int
		_ = json.Unmarshal(r.Table, &tableID)
		f.routeTables[key] = tableID
		return nil, true, nil
	}
	return nil, false, nil
}
