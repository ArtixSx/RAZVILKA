package dataplane

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

type wgNumericRouteRunner struct {
	*warpFakeRunner
	response string
}

func (r *wgNumericRouteRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if name == "ip" && strings.Contains(strings.Join(args, " "), "-j route show table") {
		return []byte(r.response), nil
	}
	return r.warpFakeRunner.Run(ctx, name, args...)
}

func TestWGEndpointNumericStaticProtocolAndScopeKeepExactPinAuthority(t *testing.T) {
	for _, family := range []int{4, 6} {
		for _, protocol := range []string{"4", `"4"`, `"static"`} {
			for _, scope := range []string{"0", `"0"`, `"global"`, "253", `"253"`, `"link"`} {
				t.Run(fmt.Sprintf("%d/%s/%s", family, protocol, scope), func(t *testing.T) {
					a, base, e, _ := wgEndpointFixture(t)
					if family == 6 {
						e.Endpoint = "[2606:4700::1111]:51820"
						e.Source = "2001:db8::2"
						e.Gateway = "2001:db8::1"
					}
					flags := `["onlink"]`
					if scope == "253" || scope == `"253"` || scope == `"link"` {
						e.Gateway = ""
						flags = `[]`
					}
					response := fmt.Sprintf(`[{"dst":%q,"dev":%q,"gateway":%q,"prefsrc":%q,"table":206,"protocol":%s,"scope":%s,"metric":1,"flags":%s}]`, e.prefix(), e.Device, e.Gateway, e.Source, protocol, scope, flags)
					a.Runner = &wgNumericRouteRunner{warpFakeRunner: base, response: response}
					present, _, err := a.inspectWGEndpoint(context.Background(), e)
					if err != nil || !present {
						t.Fatal("numeric static pin rejected", err)
					}
				})
			}
		}
	}
}

func TestWGEndpointNumericReadbackRejectsForeignProtocolAndScope(t *testing.T) {
	for _, field := range []string{"protocol", "scope"} {
		for _, raw := range []string{"3", "253", "254", `"foreign"`, `"04"`, "4.0", "4e0", "-4", "256", "null", "true", "[]", "{}"} {
			t.Run(field+"/"+raw, func(t *testing.T) {
				a, base, e, _ := wgEndpointFixture(t)
				protocol, scope := "4", "0"
				if field == "protocol" {
					protocol = raw
				} else {
					scope = raw
				}
				response := fmt.Sprintf(`[{"dst":%q,"dev":%q,"gateway":%q,"prefsrc":%q,"table":206,"protocol":%s,"scope":%s,"metric":1,"flags":["onlink"]}]`, e.prefix(), e.Device, e.Gateway, e.Source, protocol, scope)
				a.Runner = &wgNumericRouteRunner{warpFakeRunner: base, response: response}
				if _, _, err := a.inspectWGEndpoint(context.Background(), e); err == nil {
					t.Fatal("foreign/malformed route accepted")
				}
			})
		}
	}
	for _, raw := range []string{"253", `"253"`, `"link"`} {
		var route wgEndpointRoute
		if err := json.Unmarshal([]byte(`{"scope":`+raw+`,"protocol":4}`), &route); err != nil || route.Scope != "link" || route.Protocol != "static" {
			t.Fatal(route, err)
		}
	}
}

func TestWGEndpointNumericFixturePreservesIPv6PinReadback(t *testing.T) {
	a, runner, e, _ := wgEndpointFixture(t)
	e.Endpoint = "[2606:4700::1111]:51820"
	e.Source = "2001:db8::2"
	e.Gateway = "2001:db8::1"
	if err := a.installWGEndpoint(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	observer := *a
	observer.Runner = numericPolicyReadRunner{base: runner}
	route, rule, err := observer.inspectWGEndpoint(context.Background(), e)
	if err != nil || !route || !rule {
		t.Fatal("numeric IPv6 fixture lost endpoint", err)
	}
}

func TestWGEndpointNumericRouteTypeAllowsOnlyCanonicalUnicast(t *testing.T) {
	for _, raw := range []string{"1", `"1"`, `"unicast"`, "2", `"01"`, `"local"`, `""`, "1.0", "1e0", "-1", "256", "null", "true", "[]", "{}"} {
		wire := []byte(`[{"type":` + raw + `,"dst":"93.184.216.34/32","dev":"wan-c","protocol":4,"scope":253,"metric":1,"flags":[]}]`)
		rows, err := parseWGEndpointRoutes(wire)
		allowed := raw == "1" || raw == `"1"` || raw == `"unicast"`
		if allowed {
			if err != nil || len(rows) != 1 || rows[0].Type != "unicast" {
				t.Fatal("canonical numeric unicast was refused", raw, err)
			}
		} else if err == nil {
			t.Fatal("foreign/malformed numeric route type became unicast", raw)
		}
	}
}
