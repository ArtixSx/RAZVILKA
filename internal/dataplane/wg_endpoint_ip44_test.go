package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

type wgEndpointIP44Runner struct {
	base                      *warpFakeRunner
	calls                     []string
	get, show                 string
	overrideGet, overrideShow bool
}

func (r *wgEndpointIP44Runner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, strings.Join(args, " "))
	if name != "ip" {
		return r.base.Run(ctx, name, args...)
	}
	for _, option := range []string{"-N", "-j"} {
		if slices.Contains(args, option) {
			return []byte(fmt.Sprintf("Option %q is unknown, try \"ip -help\".\n", option)), errors.New("exit status 255")
		}
	}
	plain := args
	family := ""
	if len(plain) > 0 && (plain[0] == "-4" || plain[0] == "-6") {
		family, plain = plain[0], plain[1:]
	}
	if len(plain) < 2 || plain[0] != "route" || plain[1] != "get" && plain[1] != "show" {
		return r.base.Run(ctx, name, args...)
	}
	if plain[1] == "get" && r.overrideGet {
		return []byte(r.get), nil
	}
	if plain[1] == "show" && r.overrideShow {
		return []byte(r.show), nil
	}
	jsonArgs := append([]string{"-j"}, plain...)
	if family == "-6" {
		jsonArgs = append([]string{family}, jsonArgs...)
	}
	data, err := r.base.Run(ctx, name, jsonArgs...)
	if err != nil {
		return data, err
	}
	var rows []wgEndpointRoute
	if err := json.Unmarshal(data, &rows); err != nil {
		return nil, err
	}
	var lines []string
	for _, row := range rows {
		line := row.Destination
		if row.Gateway != "" {
			line += " via " + row.Gateway
		}
		line += " dev " + row.Device
		if row.Protocol != "" {
			line += " proto " + row.Protocol
		}
		if row.Scope != "" {
			line += " scope " + row.Scope
		}
		if row.Source != "" {
			line += " src " + row.Source
		}
		if row.Metric != 0 {
			line += " metric " + strconv.Itoa(row.Metric)
		}
		if len(row.Table) != 0 {
			line += " table " + string(row.Table)
		}
		if len(row.Flags) != 0 {
			line += " " + strings.Join(row.Flags, " ")
		}
		lines = append(lines, line)
	}
	return []byte(strings.Join(lines, "\n")), nil
}

func TestWGEndpointIP44CapturedWANPaths(t *testing.T) {
	for _, tc := range []struct{ name, endpoint, text, device, gateway, source string }{
		{"IPv4", "1.1.1.1:51820", "1.1.1.1 via 192.0.2.1 dev eth3  src 192.0.2.2 \n    cache \n", "eth3", "192.0.2.1", "192.0.2.2"},
		{"IPv6-owner-VPN", "[2606:4700:4700::1111]:51820", "2606:4700:4700::1111 from :: dev nwg0  src fd00:1::2  metric 1000  pref medium\n", "nwg0", "", "fd00:1::2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, base, endpoint, _ := wgEndpointFixture(t)
			endpoint.Endpoint = tc.endpoint
			r := &wgEndpointIP44Runner{base: base, get: tc.text, overrideGet: true}
			a.Runner = r
			if err := a.readWGEndpointWAN(context.Background(), endpoint); err != nil {
				t.Fatal(err)
			}
			if endpoint.Device != tc.device || endpoint.Gateway != tc.gateway || endpoint.Source != tc.source {
				t.Fatal("firmware baseline was replaced", endpoint)
			}
			if len(r.calls) != 2 || !strings.Contains(r.calls[0], "-j route get") || strings.Contains(r.calls[1], "-j") {
				t.Fatal("unexpected format negotiation", r.calls)
			}
		})
	}
}

func TestWGEndpointIP44ExactPinLifecycle(t *testing.T) {
	for _, engine := range []string{"wireguard", "amneziawg"} {
		for _, numeric := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/numeric=%t", engine, numeric), func(t *testing.T) {
				a, base, e, _ := wgEndpointFixture(t)
				if engine == "amneziawg" {
					a.EngineID, a.Interface, a.Table, a.PriorityBase = engine, "rz-awg", 205, 26000
					e.Table, e.Mark, e.Priority = 205, 0x02000000, 51
				}
				r := &wgEndpointIP44Runner{base: base}
				a.Runner = r
				ctx := context.Background()
				if err := a.installWGEndpoint(ctx, e); err != nil {
					t.Fatal(err)
				}
				if numeric {
					observer := *a
					observer.Runner = numericPolicyReadRunner{base: r}
					route, rule, err := observer.inspectWGEndpoint(ctx, e)
					if err != nil || !route || !rule {
						t.Fatal("numeric reader failed endpoint negotiation", err)
					}
				}
				if err := a.installWGEndpoint(ctx, e); err == nil {
					t.Fatal("occupied pin adopted")
				}
				if err := a.removeWGEndpoint(ctx, e); err != nil {
					t.Fatal(err)
				}
				if len(base.endpoint.routes) != 0 || len(base.endpoint.rules) != 0 {
					t.Fatal("pin left behind")
				}
				for _, call := range r.calls {
					if strings.Contains(call, "flush") || strings.Contains(call, "lookup 254") {
						t.Fatal("baseline modified", call)
					}
				}
			})
		}
	}
}

func TestWGEndpointIP44ConflictsAndAmbiguityPreventMutation(t *testing.T) {
	for _, line := range []string{
		"93.184.216.34 via 192.0.2.99 dev eth0 proto static src 192.0.2.2 metric 1 onlink",
		"93.184.216.34 via 192.0.2.1 dev foreign proto static src 192.0.2.2 metric 1 onlink",
		"93.184.216.34 via 192.0.2.1 dev eth0 proto boot src 192.0.2.2 metric 1 onlink",
		"93.184.216.34 via 192.0.2.1 dev eth0 proto static src 192.0.2.2 metric 2 onlink",
		"93.184.216.34 via 192.0.2.1 dev eth0 proto static src 192.0.2.2 metric 1 onlink table 254",
		"93.184.216.34 proto static metric 1 nexthop via 192.0.2.1 dev eth0 weight 1 nexthop via 192.0.2.3 dev eth1 weight 1",
		"93.184.216.34 dev eth0 proto static src 192.0.2.2 metric 1\n93.184.216.34 dev eth1 proto static src 192.0.2.2 metric 1",
	} {
		t.Run(line, func(t *testing.T) {
			a, base, e, _ := wgEndpointFixture(t)
			r := &wgEndpointIP44Runner{base: base, show: line, overrideShow: true}
			a.Runner = r
			if err := a.installWGEndpoint(context.Background(), e); err == nil {
				t.Fatal("foreign pin accepted")
			}
			if err := a.removeWGEndpoint(context.Background(), e); err == nil {
				t.Fatal("foreign pin became cleanup authority")
			}
			for _, call := range r.calls {
				if strings.Contains(call, "route add") || strings.Contains(call, "route del") || strings.Contains(call, "rule del") {
					t.Fatal("conflict mutated", call)
				}
			}
		})
	}
}

func TestWGEndpointIP44TextGrammarIsClosed(t *testing.T) {
	base := "1.1.1.1 via 192.0.2.1 dev eth3 src 192.0.2.2"
	for _, text := range []string{"", "default via 192.0.2.1 dev eth3 src 192.0.2.2", base + " dev eth4", base + " from 192.0.2.9", base + " mtu 1400", base + " proto foreign", base + " scope foreign", base + " table vpn", base + " metric 01", base + " linkdown", base + " onlink onlink", base + "\ncache", base + "\n    cache expires 2sec", base + "\n    cache\n    cache", base + "\x00"} {
		if _, err := parseWGEndpointTextRoutes([]byte(text), 4, true); err == nil {
			t.Fatal("unsupported text accepted", text)
		}
	}
	if _, err := parseWGEndpointTextRoutes([]byte(base), 6, true); err == nil {
		t.Fatal("wrong family accepted")
	}
}

func TestWGEndpointIP44OnlyUnsupportedOptionsTriggerFallback(t *testing.T) {
	for _, tc := range []struct {
		output  string
		failure bool
	}{
		{`[{"dst":"1.1.1.1","unknown":true}]`, false},
		{"Option \"-j\" is unknown, try \"ip -help\".\nextra", true},
		{"RTNETLINK answers: Operation not permitted", true},
		{"Error: ipv4: FIB table does not exist.", true},
	} {
		a, _, e, _ := wgEndpointFixture(t)
		e.Endpoint = "1.1.1.1:51820"
		calls := 0
		a.Runner = networkCleanupRunner(func(context.Context, string, ...string) ([]byte, error) {
			calls++
			var err error
			if tc.failure {
				err = errors.New("failed")
			}
			return []byte(tc.output), err
		})
		if err := a.readWGEndpointWAN(context.Background(), e); err == nil || calls != 1 {
			t.Fatal("unexpected retry/grant", err, calls)
		}
	}
}

func TestWGEndpointIP44AliasesCannotForgeStaticPin(t *testing.T) {
	previous := rtTablesSources
	t.Cleanup(func() { rtTablesSources = previous })
	root := t.TempDir()
	rtTablesSources = []string{root}
	for file, text := range map[string]string{"rt_protos": "99 static\n", "rt_scopes": "12 link\n", "rt_tables": "203 main\n"} {
		if err := os.WriteFile(filepath.Join(root, file), []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		if wgEndpointTextNamesUnaliased() {
			t.Fatal("foreign numeric enum adopted", file)
		}
		if err := os.Remove(filepath.Join(root, file)); err != nil {
			t.Fatal(err)
		}
	}
	if !wgEndpointTextNamesUnaliased() {
		t.Fatal("unaliased standard names refused")
	}
}

func TestWGEndpointIP44EmptyTableAndConfirmedFIBAbsence(t *testing.T) {
	a, base, _, _ := wgEndpointFixture(t)
	runner := &wgEndpointIP44Runner{base: base}
	a.Runner = runner
	rows, err := a.readWGEndpointRoutes(context.Background(), "-N", "-j", "route", "show", "table", "213")
	if err != nil || len(rows) != 0 || len(runner.calls) != 3 {
		t.Fatal("empty numeric transport table refused", rows, err, runner.calls)
	}
	for _, second := range []string{"", "Error: ipv4: FIB table does not exist.\nDump terminated", "unrecognized failure"} {
		calls := 0
		a.Runner = networkCleanupRunner(func(context.Context, string, ...string) ([]byte, error) {
			calls++
			if calls == 1 {
				return []byte("Error: ipv4: FIB table does not exist."), errors.New("exit status 2")
			}
			if second == "" {
				return nil, nil
			}
			return []byte(second), errors.New("exit status 2")
		})
		rows, err := a.readWGEndpointRoutes(context.Background(), "-j", "route", "show", "table", "213")
		if second == "unrecognized failure" {
			if err == nil {
				t.Fatal("unknown confirmation became absence")
			}
		} else if err != nil || len(rows) != 0 || calls != 2 {
			t.Fatal("exact absence was not independently confirmed", rows, err, calls)
		}
	}
}

func TestWGEndpointMissingTableJSONRequiresIndependentTextConfirmation(t *testing.T) {
	for _, tc := range []struct {
		name, first, second     string
		family6, plain, allowed bool
		calls                   int
	}{
		{"ipv4", "[]\nError: ipv4: FIB table does not exist.\nDump terminated\n", "Error: ipv4: FIB table does not exist.\nDump terminated", false, false, true, 2},
		{"ipv4-suffix", "Error: ipv4: FIB table does not exist.\nDump terminated\n[]\n", "Error: ipv4: FIB table does not exist.\nDump terminated", false, false, true, 2},
		{"ipv6-suffix", "Error: ipv6: FIB table does not exist.\nDump terminated\n[]\n", "", true, false, true, 2},
		{"ipv6", "[]\nError: ipv6: FIB table does not exist.\nDump terminated", "", true, false, true, 2},
		{"whitespace", " \t[]\r\nError: ipv4: FIB table does not exist.\r\n", "", false, false, true, 2},
		{"permission", "[]\nRTNETLINK answers: Operation not permitted", "", false, false, false, 1},
		{"wrong-family", "[]\nError: ipv6: FIB table does not exist.", "", false, false, false, 1},
		{"nonempty-json", "[{}]\nError: ipv4: FIB table does not exist.", "", false, false, false, 1},
		{"extra-json", "[]\n[]\nError: ipv4: FIB table does not exist.", "", false, false, false, 1},
		{"both-edges", "[]\nError: ipv4: FIB table does not exist.\n[]", "", false, false, false, 1},
		{"nonempty-suffix", "Error: ipv4: FIB table does not exist.\n[{}]", "", false, false, false, 1},
		{"extra-diagnostic", "[]\nError: ipv4: FIB table does not exist.\npermission denied", "", false, false, false, 1},
		{"nul", "[]\x00\nError: ipv4: FIB table does not exist.", "", false, false, false, 1},
		{"plain-json-prefix", "[]\nError: ipv4: FIB table does not exist.", "", false, true, false, 1},
		{"confirmation-fails", "[]\nError: ipv4: FIB table does not exist.", "permission denied", false, false, false, 2},
		{"confirmation-json-refused", "[]\nError: ipv4: FIB table does not exist.", "[]\nError: ipv4: FIB table does not exist.", false, false, false, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _, _, _ := wgEndpointFixture(t)
			calls := 0
			a.Runner = networkCleanupRunner(func(_ context.Context, _ string, args ...string) ([]byte, error) {
				calls++
				if calls == 1 {
					return []byte(tc.first), errors.New("exit status 2")
				}
				if strings.Contains(strings.Join(args, " "), "-j") {
					t.Fatal("confirmation retained JSON instead of fresh text observation")
				}
				if tc.second == "" {
					return nil, nil
				}
				return []byte(tc.second), errors.New("exit status 2")
			})
			args := []string{"-N"}
			if tc.family6 {
				args = append(args, "-6")
			}
			if !tc.plain {
				args = append(args, "-j")
			}
			args = append(args, "route", "show", "table", "213")
			rows, err := a.readWGEndpointRoutes(context.Background(), args...)
			if (err == nil) != tc.allowed || tc.allowed && len(rows) != 0 || calls != tc.calls {
				t.Fatalf("allowed=%t rows=%d err=%v calls=%d want=%d", tc.allowed, len(rows), err, calls, tc.calls)
			}
		})
	}
}

func TestWGEndpointIP44WANRefusalRetainsOriginalPin(t *testing.T) {
	for _, text := range []string{
		"1.1.1.2 via 192.0.2.1 dev eth3 src 192.0.2.2\n    cache",
		"1.1.1.1 via 192.0.2.1 dev eth3 src 192.0.2.2 table 100",
		"1.1.1.1 src 192.0.2.2 nexthop via 192.0.2.1 dev eth3 weight 1 nexthop via 192.0.2.3 dev eth4 weight 1",
	} {
		a, base, endpoint, _ := wgEndpointFixture(t)
		endpoint.Endpoint = "1.1.1.1:51820"
		before := *endpoint
		a.Runner = &wgEndpointIP44Runner{base: base, overrideGet: true, get: text}
		if err := a.readWGEndpointWAN(context.Background(), endpoint); err == nil {
			t.Fatal("ambiguous/foreign WAN accepted", text)
		}
		if *endpoint != before {
			t.Fatal("refusal changed the retained pin")
		}
	}
}

// The child Start/Wait and original read owner are real; unsupported-option
// output and the WAN tuple are explicit models, never native traffic proof.
type wgEndpointIP44SourceModel struct {
	*wgCommandProcessModel
	calls      int
	afterFirst func()
}

func (m *wgEndpointIP44SourceModel) RunWG(ctx context.Context, admission WGCommandAdmission, name string, args ...string) ([]byte, error) {
	m.calls++
	out, err := m.wgCommandProcessModel.RunWG(ctx, admission, name, args...)
	if err != nil {
		return out, err
	}
	if m.calls == 1 && m.afterFirst != nil {
		m.afterFirst()
	}
	if slices.Contains(args, "-j") {
		return []byte("Option \"-j\" is unknown, try \"ip -help\".\n"), errors.New("exit status 255")
	}
	return out, nil
}

func TestWGEndpointIP44OriginalSourceOwnerSurvivesFormatNegotiation(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(fmt.Sprint(changed), func(t *testing.T) {
			f := newWGSourceReadFixture(t)
			if err := f.read.Close(); err != nil {
				t.Fatal(err)
			}
			model := &wgEndpointIP44SourceModel{wgCommandProcessModel: f.model}
			f.a.wgCommandTools.Runner = model
			var err error
			f.read, err = ReviewWGSourceRead(f.ctx, f.manager, f.control, "wireguard")
			if err != nil {
				t.Fatal(err)
			}
			profile, err := f.read.CaptureProfile(f.ctx, "server")
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv("RAZVILKA_WG_COMMAND_TEST_OUTPUT", "1.1.1.1 via 192.0.2.1 dev eth3 src 192.0.2.2\n    cache\n")
			if changed {
				model.afterFirst = func() { f.a.RuntimeConfigPath += ".changed" }
			}
			wan, err := f.read.ObserveNumericEndpoint(f.ctx, profile)
			if changed {
				if err == nil || model.calls != 1 {
					t.Fatal("changed owner retried/published", err, model.calls)
				}
			} else if err != nil || model.calls != 2 || wan.Device != "eth3" || wan.Source != "192.0.2.2" {
				t.Fatal("original source failed narrow retry", wan, err, model.calls)
			}
		})
	}
}

func TestWGEndpointIP44InactivityABIAllowsOnlyEndpointTextTables(t *testing.T) {
	f, reader, _ := wgInactivityFixture(t, false)
	tools := reader.tools
	tools.IP = filepath.Join(f.manager.StateRoot, "fixed-ip")
	spec, err := reader.adapter.endpointSpec()
	if err != nil {
		t.Fatal(err)
	}
	for _, suffix := range [][]string{nil, {"exact", "1.1.1.1/32"}} {
		args := append([]string{"route", "show", "table", strconv.Itoa(spec.EndpointTable)}, suffix...)
		actual, ok := wgInactivityReadArguments(reader.adapter, tools, tools.IP, args)
		if !ok || !slices.Equal(actual, args) {
			t.Fatal("endpoint format retry had -N reinserted", actual, ok)
		}
	}
	for _, args := range [][]string{{"route", "show", "table", "254"}, {"route", "show", "table", "vpn"}, {"route", "show", "table", strconv.Itoa(spec.EndpointTable), "exact", "1.1.1.0/24"}, {"route", "del", "1.1.1.1/32"}} {
		if _, ok := wgInactivityReadArguments(reader.adapter, tools, tools.IP, args); ok {
			t.Fatal("broad/effect fallback admitted", args)
		}
	}
}
