package routekind

import "strings"

// ParseNodeRoute accepts only an exact registry node/group and its concrete
// engine. Syntax does not grant runtime capability or service permission.
func ParseNodeRoute(route string) (engine, target string, ok bool) {
	engine, target, found := strings.Cut(route, ":")
	if !found || engine != "sing-box" && engine != "xray" {
		return "", "", false
	}
	prefix, size := "node-", 64
	if strings.HasPrefix(target, "group-") {
		prefix, size = "group-", 32
	}
	if !strings.HasPrefix(target, prefix) || len(target) != len(prefix)+size || strings.Trim(target[len(prefix):], "0123456789abcdef") != "" {
		return "", "", false
	}
	return engine, target, true
}

// HasNodeRoutePrefix also recognizes malformed registry IDs so their missing
// proof cannot quietly become authority for a generic engine profile.
func HasNodeRoutePrefix(route string) bool {
	for _, prefix := range []string{"sing-box:node-", "sing-box:group-", "xray:node-", "xray:group-"} {
		if strings.HasPrefix(route, prefix) {
			return true
		}
	}
	return false
}
