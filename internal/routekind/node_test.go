package routekind

import (
	"strings"
	"testing"
)

func TestExactNodeRouteEngineAndTarget(t *testing.T) {
	for _, engine := range []string{"sing-box", "xray"} {
		for _, target := range []string{"node-" + strings.Repeat("a", 64), "group-" + strings.Repeat("f", 32)} {
			e, id, ok := ParseNodeRoute(engine + ":" + target)
			if !ok || e != engine || id != target {
				t.Fatal("exact identity lost", e, id, ok)
			}
		}
	}
	for _, route := range []string{"xray", "Xray:node-" + strings.Repeat("a", 64), "xray:node-" + strings.Repeat("A", 64), "xray:node-a", "xray:node-" + strings.Repeat("a", 64) + " ", "sing-box:group-" + strings.Repeat("a", 31), "xray:home", "auto:node-" + strings.Repeat("a", 64)} {
		if _, _, ok := ParseNodeRoute(route); ok {
			t.Fatal("noncanonical route accepted", route)
		}
	}
}
