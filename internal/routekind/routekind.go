// Package routekind is the shared vocabulary of managed autonomous executors.
// Membership is syntax, not permission or proof. Callers must still check the
// installed runtime, the current policy, exact evidence and transaction guards.
package routekind

const PreferredCount = 7

// PreferredIDs returns an independent list; callers cannot mutate the registry.
func PreferredIDs() []string {
	return []string{"nfqws2", "usque", "warp-wg", "amneziawg", "wireguard", "sing-box", "xray"}
}

// IsExecutor accepts only canonical, concrete executor IDs. In particular auto,
// direct, arbitrary profile suffixes and case/whitespace variants are not IDs.
func IsExecutor(id string) bool {
	switch id {
	case "nfqws2", "usque", "warp-wg", "amneziawg", "wireguard", "sing-box", "xray":
		return true
	default:
		return false
	}
}
