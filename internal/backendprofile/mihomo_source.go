package backendprofile

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/ArtixSx/razvilka/internal/providerprofile"
	"gopkg.in/yaml.v3"
)

// Called only after the bounded general parser has accepted the complete input.
// Source-level DNS/routing/listeners are intentionally ignored, but every node
// option must survive conversion. This also covers duplicates that the general
// importer deduplicates after stripping options it does not understand.
func validateMihomoSource(raw, format string) error {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(format, "base64-") {
		decoded := false
		for _, encoding := range []*base64.Encoding{base64.RawStdEncoding, base64.StdEncoding, base64.RawURLEncoding, base64.URLEncoding} {
			if data, err := encoding.DecodeString(raw); err == nil {
				raw, decoded = strings.TrimSpace(string(data)), true
				break
			}
		}
		if !decoded {
			return ErrUnsupported
		}
		format = strings.TrimPrefix(format, "base64-")
	}
	if format == "uri" || format == "text-subscription" {
		// URI parsing already rejects unknown parameters and ambiguous aliases.
		return nil
	}
	if format == "clash-mihomo-yaml" {
		var document map[string]any
		if yaml.Unmarshal([]byte(raw), &document) != nil {
			return ErrUnsupported
		}
		entries, ok := document["proxies"].([]any)
		if !ok {
			return ErrUnsupported
		}
		for _, entry := range entries {
			source, ok := entry.(map[string]any)
			if !ok || !clashNodePreserved(source) {
				return ErrUnsupported
			}
		}
		return nil
	}
	var document any
	if json.Unmarshal([]byte(raw), &document) != nil {
		return ErrUnsupported
	}
	entries, ok := document.([]any)
	if !ok {
		root, ok := document.(map[string]any)
		if !ok {
			return ErrUnsupported
		}
		entries, ok = root["outbounds"].([]any)
		if !ok {
			entries, ok = root["uris"].([]any)
		}
		if !ok {
			return ErrUnsupported
		}
	}
	for _, entry := range entries {
		if _, ok := entry.(string); ok {
			continue // Already validated as a strict URI by the general parser.
		}
		source, ok := entry.(map[string]any)
		if !ok {
			return ErrUnsupported
		}
		switch str(source, "type") {
		case "direct", "block", "selector", "urltest":
			continue // Source routing is explicitly outside this export.
		}
		if _, err := mihomoNode(source); err != nil {
			return ErrUnsupported
		}
	}
	return nil
}

func clashNodePreserved(source map[string]any) bool {
	data, err := yaml.Marshal(map[string]any{"proxies": []any{source}})
	if err != nil {
		return false
	}
	parsed, err := providerprofile.ParseProfile(string(data))
	if err != nil {
		return false
	}
	var document struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if json.Unmarshal(parsed.Config, &document) != nil || len(document.Outbounds) == 0 {
		return false
	}
	node, err := mihomoNode(document.Outbounds[0])
	if err != nil {
		return false
	}
	for key, value := range source {
		switch key {
		case "name", "type":
			continue // A fixed output name and canonical protocol are intentional.
		case "sni", "servername":
			if node["type"] == "vless" {
				key = "servername"
			} else {
				key = "sni"
			}
		case "network":
			if value == "tcp" && node[key] == nil {
				continue // TCP is the native default, represented without an option.
			}
		case "skip-cert-verify", "tls":
			if value == false && node[key] == nil {
				continue
			}
		}
		actual, exists := node[key]
		if !exists {
			return false
		}
		want, e1 := json.Marshal(value)
		got, e2 := json.Marshal(actual)
		if e1 != nil || e2 != nil || !bytes.Equal(want, got) {
			return false
		}
	}
	return true
}

func stringSequence(value any) bool {
	items, ok := value.([]any)
	if !ok {
		return false
	}
	for _, item := range items {
		if _, ok := item.(string); !ok {
			return false
		}
	}
	return true
}

func stringMapping(value any) bool {
	items, ok := value.(map[string]any)
	if !ok {
		return false
	}
	for _, item := range items {
		if _, ok := item.(string); !ok {
			return false
		}
	}
	return true
}
