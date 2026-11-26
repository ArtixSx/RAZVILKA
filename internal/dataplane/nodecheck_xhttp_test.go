package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/evidence"
)

const xhttpNodeMaterial = `{"type":"vless","server":"node.example","server_port":443,"uuid":"123e4567-e89b-12d3-a456-426614174000","tls":{"enabled":true,"server_name":"front.example","alpn":["h2"]},"transport":{"type":"xhttp","host":"cdn.example","path":"/tunnel?token=private","mode":"packet-up","extra":{"headers":{"Authorization":"private-header"},"xmux":{"maxConcurrency":2},"xPaddingBytes":"100-200"}}}`

func xhttpCheckedRequest() NodeCheckRequest {
	r := xrayCheckedRequest()
	r.Outbound = []byte(xhttpNodeMaterial)
	return r
}

func TestXHTTPPinnedConfigPreservesHostSNIPathAndExtra(t *testing.T) {
	endpoint := exactNodeEndpoint{Host: "node.example", Port: 443, Pinned: netip.MustParseAddr("203.0.113.9"), Protocol: "vless", Transport: "xhttp"}
	config, err := compilePinnedXrayNodeConfig([]byte(xhttpNodeMaterial), endpoint, 29185)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(config)
	var doc struct {
		Inbounds  []map[string]any `json:"inbounds"`
		Outbounds []map[string]any `json:"outbounds"`
	}
	if json.Unmarshal(config, &doc) != nil || len(doc.Outbounds) != 1 || len(doc.Inbounds) != 1 || doc.Inbounds[0]["listen"] != "127.0.0.1" {
		t.Fatal("invalid exact client configuration")
	}
	out := doc.Outbounds[0]
	server := out["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)
	stream := out["streamSettings"].(map[string]any)
	xhttp := stream["xhttpSettings"].(map[string]any)
	if server["address"] != endpoint.Pinned.String() || stream["network"] != "xhttp" || stream["tlsSettings"].(map[string]any)["serverName"] != "front.example" || xhttp["host"] != "cdn.example" || xhttp["path"] != "/tunnel?token=private" || xhttp["mode"] != "packet-up" || !strings.Contains(string(config), "private-header") {
		t.Fatal("pin replaced required XHTTP or TLS identity")
	}
	// Empty SNI/Host uses the original endpoint before the compiler pins it.
	raw := strings.Replace(xhttpNodeMaterial, `"server_name":"front.example",`, "", 1)
	raw = strings.Replace(raw, `"host":"cdn.example",`, "", 1)
	config, err = compilePinnedXrayNodeConfig([]byte(raw), endpoint, 29185)
	if err != nil || !strings.Contains(string(config), `"serverName": "node.example"`) {
		t.Fatal("default HTTP authority became pinned IP")
	}
	for _, mismatch := range []exactNodeEndpoint{
		{Host: "other.example", Port: 443, Pinned: endpoint.Pinned},
		{Host: endpoint.Host, Port: 444, Pinned: endpoint.Pinned},
		{Host: endpoint.Host, Port: endpoint.Port, Pinned: netip.MustParseAddr("127.0.0.1")},
	} {
		if _, err := compilePinnedXrayNodeConfig([]byte(xhttpNodeMaterial), mismatch, 29185); err == nil {
			t.Fatal("endpoint mismatch admitted")
		}
	}
}

func TestXHTTPUnsupportedBeforeDNSSharedQuotaAndReputation(t *testing.T) {
	for _, mode := range []string{"sing-box", "xray-mode", "xray-h3", "xray-download", "xray-flow", "xray-key", "xray-fingerprint"} {
		t.Run(mode, func(t *testing.T) {
			c := fakeExactXrayChecker(t)
			r := xhttpCheckedRequest()
			switch mode {
			case "sing-box":
				c.engine = "sing-box"
			case "xray-mode":
				r.Outbound = []byte(strings.Replace(xhttpNodeMaterial, "packet-up", "unknown", 1))
			case "xray-h3":
				r.Outbound = []byte(strings.Replace(xhttpNodeMaterial, `"h2"`, `"h3"`, 1))
			case "xray-download":
				r.Outbound = []byte(strings.Replace(xhttpNodeMaterial, `"extra":{`, `"extra":{"downloadSettings":{},`, 1))
			case "xray-flow":
				r.Outbound = []byte(strings.Replace(xhttpNodeMaterial, `"type":"vless"`, `"type":"vless","flow":"xtls-rprx-vision"`, 1))
			case "xray-key":
				r.Outbound = []byte(strings.Replace(xhttpNodeMaterial, `"enabled":true,`, `"enabled":true,"reality":{"enabled":true,"public_key":"BAD"},`, 1))
			case "xray-fingerprint":
				r.Outbound = []byte(strings.Replace(xhttpNodeMaterial, `"enabled":true,`, `"enabled":true,"utls":{"enabled":true,"fingerprint":"unknown"},`, 1))
			}
			c.resolve = func(context.Context, string) ([]netip.Addr, error) {
				t.Fatal("capability rejection reached DNS")
				return nil, nil
			}
			d, err := NewExactNodeDispatcher(1, c)
			if err != nil {
				t.Fatal(err)
			}
			view, _ := d.ForEngine(c.EngineID())
			// Even a full shared quota must return unsupported, with no proof.
			d.gate <- struct{}{}
			result, err := view.Check(context.Background(), r)
			if !errors.Is(err, ErrExactNodeUnsupported) || result.ProbeID != "" || result.NodeID != "" || len(c.gate) != 1 || c.poisoned.Load() {
				t.Fatal("unsupported input consumed a slot or created failure evidence")
			}
			if screen, decided, err := view.ScreenTransport(context.Background(), r); !errors.Is(err, ErrExactNodeUnsupported) || decided || screen.ProbeID != "" {
				t.Fatal("unsupported input became a transport result")
			}
			<-d.gate
		})
	}
}

func TestXHTTPRuntimeCapabilityIsPinnedAndNeutralBeforeQuota(t *testing.T) {
	for _, tc := range []struct {
		output    string
		supported bool
	}{
		{"Xray 26.3.27 (Xray, Penetrates Everything.)\nA unified platform", true},
		{"Xray 26.3.270 future", false}, {"Xray 26.3.26 old", false}, {"Xray 26.4.1 future", false},
		{"sing-box version 1.14.2", false}, {"warning\nXray 26.3.27 spoof", false}, {"", false},
		{"Xray 26.3.27 " + strings.Repeat("x", 4096), false},
	} {
		if exactXHTTPVersionOutput([]byte(tc.output)) != tc.supported {
			t.Fatal("runtime version was not checked exactly")
		}
	}
	for _, runtimeErr := range []error{nil, errors.New("version unavailable")} {
		c := fakeExactXrayChecker(t)
		c.xhttpRuntime = func(context.Context, string) (bool, error) { return false, runtimeErr }
		c.resolve = func(context.Context, string) ([]netip.Addr, error) {
			t.Fatal("unknown runtime reached DNS")
			return nil, nil
		}
		d, err := NewExactNodeDispatcher(1, c)
		if err != nil {
			t.Fatal(err)
		}
		view, _ := d.ForEngine("xray")
		d.gate <- struct{}{}
		want := ErrExactNodeUnsupported
		if runtimeErr != nil {
			want = ErrExactNodeRuntime
		}
		result, err := view.Check(context.Background(), xhttpCheckedRequest())
		if !errors.Is(err, want) || result.ProbeID != "" || len(c.gate) != 1 || c.poisoned.Load() {
			t.Fatal("unsupported runtime created reputation evidence or consumed slot")
		}
		<-d.gate
	}
}

// Stateful checker library fixtures verify engine/path fences, not native
// XHTTP traffic. The opt-in Linux server/client test supplies that evidence.
func TestXHTTPCheckerUsesXrayProofAndRejectsCrossEngineProbe(t *testing.T) {
	c := fakeExactXrayChecker(t)
	r := xhttpCheckedRequest()
	result, err := c.Check(context.Background(), r)
	if err != nil || !result.Available || result.RoutePathID != "xray:"+r.NodeID || result.Evidence.Engine != "xray" {
		t.Fatal("XHTTP did not keep the Xray proof path")
	}
	for _, engine := range []string{"sing-box", ""} {
		for _, stage := range []string{"name", "ip"} {
			c = fakeExactXrayChecker(t)
			probe := c.serviceProbe
			wrong := func(ctx context.Context, address, route, egress string, service catalog.Service) (evidence.ProbeEvidence, error) {
				proof, err := probe(ctx, address, route, egress, service)
				proof.Engine = engine
				return proof, err
			}
			if stage == "name" {
				c.serviceProbe = wrong
			} else {
				c.serviceIPProbe = func(ctx context.Context, address, route, egress string, service catalog.Service, _ netip.Addr) (evidence.ProbeEvidence, error) {
					return wrong(ctx, address, route, egress, service)
				}
			}
			result, _ = c.Check(context.Background(), r)
			if result.Available || result.Verdict == evidence.VerdictPass {
				t.Fatal("missing/cross-engine service proof authorized XHTTP")
			}
		}
	}
}
