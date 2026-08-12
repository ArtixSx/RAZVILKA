package main

import (
	"strings"
	"testing"
)

func TestEmbeddedWebLayoutDoesNotOffsetPanelHeaders(t *testing.T) {
	t.Parallel()

	data, err := embedded.ReadFile("web/style.css")
	if err != nil {
		t.Fatalf("read embedded stylesheet: %v", err)
	}
	css := string(data)

	for _, forbidden := range []string{
		".sticky-title{position:sticky",
		".full-panel{min-height:calc(100vh",
		".engine-workspace{display:grid;grid-template-columns:270px minmax(0,1fr);min-height:650px",
	} {
		if strings.Contains(css, forbidden) {
			t.Fatalf("layout regression: stylesheet contains %q", forbidden)
		}
	}

	for _, required := range []string{
		".full-panel{min-height:0}",
		".sticky-title{position:relative;top:auto",
		".engine-workspace{display:grid;grid-template-columns:270px minmax(0,1fr);min-height:0}",
	} {
		if !strings.Contains(css, required) {
			t.Fatalf("layout guard missing %q", required)
		}
	}
}

func TestEmbeddedWebAssetsUseCurrentCacheKey(t *testing.T) {
	t.Parallel()

	data, err := embedded.ReadFile("web/index.html")
	if err != nil {
		t.Fatalf("read embedded index: %v", err)
	}
	html := string(data)
	for _, asset := range []string{
		"/style.css?v=0.0.9-ui-layout",
		"/app.js?v=0.0.9-ui-layout",
	} {
		if !strings.Contains(html, asset) {
			t.Fatalf("cache-busted asset missing %q", asset)
		}
	}
}
