package app

import (
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
)

func TestMihomoNodeRouteSyntaxNeverAcceptsLegacyHealthOrGroups(t *testing.T) {
	valid := "mihomo:node-" + strings.Repeat("a", 64)
	if id, ok := mihomoNodeRouteID(valid); !ok || id != strings.TrimPrefix(valid, "mihomo:") {
		t.Fatal("canonical selected node refused")
	}
	for _, route := range []string{"mihomo", "auto", "sing-box:" + strings.TrimPrefix(valid, "mihomo:"), "mihomo:group-" + strings.Repeat("a", 64), valid + "x", strings.ToUpper(valid), "mihomo:node-" + strings.Repeat("g", 64)} {
		if _, ok := mihomoNodeRouteID(route); ok {
			t.Fatalf("noncanonical route accepted: %s", route)
		}
	}
}

func TestMihomoNodeManualScopeRefusesImplicitAndMixedPlans(t *testing.T) {
	service := catalog.Service{ID: "listed", Name: "Listed fixture", Category: "fixture", Strategy: []string{"mihomo"}, ProbeURL: "https://1.1.1.1/", CIDRs: []string{"1.1.1.0/24"}}
	cfg := config.Default()
	cfg.SafeMode = false
	cfg.Services = map[string]config.ServiceState{"listed": {Enabled: true, Route: "mihomo:node-" + strings.Repeat("a", 64)}}
	if err := mihomoNodeServiceScope(cfg, service, []string{"192.168.1.42/32"}); err != nil {
		t.Fatal("explicit public service/private client content scope", err)
	}
	for _, tc := range []struct {
		name string
		edit func(*config.Config, *catalog.Service) []string
	}{
		{"implicit-all", func(*config.Config, *catalog.Service) []string { return nil }},
		{"public-source", func(*config.Config, *catalog.Service) []string { return []string{"1.1.1.1/32"} }},
		{"mixed", func(c *config.Config, _ *catalog.Service) []string {
			c.Services["other"] = config.ServiceState{Enabled: true}
			return []string{"192.168.1.42/32"}
		}},
		{"home", func(c *config.Config, _ *catalog.Service) []string {
			c.NetworkPolicy = &config.NetworkPolicy{}
			return []string{"192.168.1.42/32"}
		}},
		{"domain", func(_ *config.Config, s *catalog.Service) []string {
			s.Domains = []string{"service.example"}
			return []string{"192.168.1.42/32"}
		}},
		{"public-first-private-containing", func(_ *config.Config, s *catalog.Service) []string {
			s.CIDRs = []string{"8.0.0.0/6"}
			return []string{"192.168.1.42/32"}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copy := cfg
			copy.Services = map[string]config.ServiceState{"listed": cfg.Services["listed"]}
			candidate := service
			sources := tc.edit(&copy, &candidate)
			if err := mihomoNodeServiceScope(copy, candidate, sources); err == nil {
				t.Fatal("unsupported scope accepted")
			}
		})
	}
}
