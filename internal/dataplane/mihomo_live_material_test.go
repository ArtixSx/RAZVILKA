package dataplane

import (
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/catalog"
)

func TestMihomoLiveIntentIsOneExplicitNodeAndIPv4ServiceOnly(t *testing.T) {
	service := catalog.Service{ID: "listed", Name: "Listed fixture", Category: "fixture", Strategy: []string{"mihomo"}, ProbeURL: "https://1.1.1.1/", CIDRs: []string{"1.1.1.0/24"}}
	selected := "mihomo:node-" + strings.Repeat("1", 64)
	base := Plan{Routes: []Route{{ServiceID: service.ID, LogicalServiceID: service.ID, Selected: selected, Resolved: selected, CIDRs: []string{"1.1.1.0/24"}, ProbeURL: service.ProbeURL, ProbeService: &service}}}
	if _, err := mihomoLiveIntentNode(base); err != nil {
		t.Fatal("closed explicit content intent", err)
	}
	for _, tc := range []struct {
		name   string
		change func(*Plan)
	}{
		{"domain", func(p *Plan) { p.Routes[0].Domains = []string{"service.example"} }},
		{"empty-cidrs", func(p *Plan) { p.Routes[0].CIDRs = nil }},
		{"ipv6", func(p *Plan) { p.Routes[0].CIDRs = []string{"2606:4700::/32"} }},
		{"default-route", func(p *Plan) { p.Routes[0].CIDRs = []string{"0.0.0.0/0"} }},
		{"host-bits", func(p *Plan) { p.Routes[0].CIDRs = []string{"1.1.1.1/24"} }},
		{"duplicate", func(p *Plan) { p.Routes[0].CIDRs = []string{"1.1.1.0/24", "1.1.1.0/24"} }},
		{"auto-fallback", func(p *Plan) { p.Routes[0].Selected = "auto" }},
		{"bare-engine", func(p *Plan) { p.Routes[0].Selected = "mihomo"; p.Routes[0].Resolved = "mihomo" }},
		{"group", func(p *Plan) {
			p.Routes[0].Selected = "mihomo:group-0123456789abcdef"
			p.Routes[0].Resolved = p.Routes[0].Selected
		}},
		{"another-engine", func(p *Plan) { p.Routes[0].Resolved = "xray:node-0123456789abcdef" }},
		{"second-route", func(p *Plan) { p.Routes = append(p.Routes, p.Routes[0]) }},
		{"missing-predicate", func(p *Plan) { p.Routes[0].ProbeService = nil }},
		{"changed-probe", func(p *Plan) { p.Routes[0].ProbeURL = "https://2.2.2.2/" }},
		{"dns-intent", func(p *Plan) { p.SuspendDNS = true }},
		{"unregistered-home-mode", func(p *Plan) { p.LAN = &LANPolicyRuntimePlan{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := cloneExecutionResourcePlan(base)
			tc.change(&p)
			if _, err := mihomoLiveIntentNode(p); err == nil {
				t.Fatal("broadened content intent accepted")
			}
		})
	}
}
