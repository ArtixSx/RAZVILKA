package providerprofile

import "maps"

// SingBoxRealityUTLSContract identifies the effective default used by both
// exact-node checks and route materialization. Older evidence cannot attest it.
const SingBoxRealityUTLSContract = "sing-box-reality-utls-chrome-v1"

// SingBoxRuntimeOutbound supplies the same omitted REALITY fingerprint default
// as the Xray compiler. Explicit uTLS values (including disabled or invalid
// values) are preserved for runtime validation. Canonical material is untouched.
func SingBoxRuntimeOutbound(out map[string]any) (map[string]any, string) {
	if out["type"] != "vless" {
		return out, ""
	}
	tls, ok := out["tls"].(map[string]any)
	if !ok || tls["enabled"] != true {
		return out, ""
	}
	reality, ok := tls["reality"].(map[string]any)
	if !ok || reality["enabled"] != true {
		return out, ""
	}
	if _, explicit := tls["utls"]; explicit {
		return out, ""
	}
	runtime := maps.Clone(out)
	runtimeTLS := maps.Clone(tls)
	runtimeTLS["utls"] = map[string]any{"enabled": true, "fingerprint": "chrome"}
	runtime["tls"] = runtimeTLS
	return runtime, SingBoxRealityUTLSContract
}
