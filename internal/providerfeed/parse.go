package providerfeed

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/ArtixSx/razvilka/internal/providerprofile"
)

type batch struct {
	raw                                     string
	accepted, rejected, duplicates, omitted int
	total                                   int
	nextCursor, snapshotEntries             int
	materials                               []json.RawMessage
	countries                               []string
	issues                                  []providerprofile.EntryIssue
}

func (batch) String() string   { return "[private feed batch]" }
func (batch) GoString() string { return "[private feed batch]" }

func parse(ctx context.Context, data []byte, format string, limit int) (batch, error) {
	return parseWindow(ctx, data, format, limit, 0)
}

// Cursor counts source entries, including rejected/control entries. It is tied
// to the exact response digest, never to a publisher's display names or order.
func parseWindow(ctx context.Context, data []byte, format string, limit, cursor int) (batch, error) {
	if cursor < 0 || cursor > MaxEntries || limit < 1 || limit > MaxCandidates {
		return batch{}, ErrRequest
	}
	if len(data) > MaxBytes || !utf8.Valid(data) || strings.ContainsRune(string(data), '\x00') {
		return batch{}, ErrSize
	}
	if format == "profile" {
		if parsed, handled, err := parseJSONFeedWindow(ctx, data, limit, cursor); handled {
			return parsed, err
		}
		parsed, err := providerprofile.ParseProfile(string(data))
		if err != nil {
			return batch{}, ErrFormat
		}
		var profile struct {
			Outbounds []json.RawMessage `json:"outbounds"`
		}
		if json.Unmarshal(parsed.Config, &profile) != nil {
			return batch{}, ErrFormat
		}
		selected := make([]json.RawMessage, 0, min(limit, parsed.Preview.NodeCount))
		if cursor > parsed.Preview.NodeCount {
			return batch{}, ErrRequest
		}
		b := batch{snapshotEntries: parsed.Preview.NodeCount, nextCursor: cursor}
		previewIndex := 0
		for _, raw := range profile.Outbounds {
			var outbound struct {
				Type string `json:"type"`
			}
			if json.Unmarshal(raw, &outbound) != nil {
				return batch{}, ErrFormat
			}
			switch outbound.Type {
			case "vless", "hysteria2", "tuic", "shadowsocks":
				if previewIndex >= cursor && len(selected) < limit {
					selected = append(selected, raw)
					material, err := canonicalOutbound(raw)
					if err != nil {
						return batch{}, ErrFormat
					}
					b.materials = append(b.materials, material)
					b.countries = append(b.countries, inferCountry(parsed.Preview.Nodes[previewIndex].Name))
					b.nextCursor = previewIndex + 1
				}
				previewIndex++
			}
		}
		if len(selected) == 0 && cursor != parsed.Preview.NodeCount {
			return batch{}, ErrFormat
		}
		raw, err := json.Marshal(selected)
		if err != nil {
			return batch{}, ErrFormat
		}
		b.raw, b.accepted, b.total, b.omitted, b.rejected, b.duplicates, b.issues = string(raw), len(selected), parsed.Preview.NodeCount+len(parsed.Preview.Rejected)+len(parsed.Preview.Skipped), parsed.Preview.NodeCount-len(selected), len(parsed.Preview.Rejected), len(parsed.Preview.Skipped), parsed.Preview.Rejected
		return b, nil
	}
	var entries []string
	var err error
	if format == "keys-json" {
		entries, err = keysJSON(data)
	} else {
		entries, err = uriLines(data)
	}
	if err != nil {
		return batch{}, err
	}
	if cursor > len(entries) {
		return batch{}, ErrRequest
	}
	b := batch{total: len(entries), snapshotEntries: len(entries), nextCursor: cursor}
	seen := map[[32]byte]bool{}
	accepted := []string{}
	for index := cursor; index < len(entries); index++ {
		entry := entries[index]
		if err := ctx.Err(); err != nil {
			return b, err
		}
		if len(accepted) >= limit {
			b.omitted = len(entries) - index
			break
		}
		b.nextCursor = index + 1
		parsed, err := providerprofile.ParseURI(entry)
		if err != nil {
			b.rejected++
			if len(b.issues) < MaxCandidates {
				b.issues = append(b.issues, providerprofile.EntryIssue{Index: index + 1, Code: providerprofile.ErrorCode(err), Reason: "Запись не прошла строгую проверку импорта."})
			}
			continue
		}
		var document struct {
			Outbounds []map[string]any `json:"outbounds"`
		}
		if json.Unmarshal(parsed.Config, &document) != nil || len(document.Outbounds) == 0 {
			return b, ErrFormat
		}
		delete(document.Outbounds[0], "tag")
		canonical, _ := json.Marshal(document.Outbounds[0])
		digest := sha256.Sum256(canonical)
		if seen[digest] {
			b.duplicates++
			continue
		}
		seen[digest] = true
		accepted = append(accepted, entry)
		b.materials = append(b.materials, canonical)
		b.countries = append(b.countries, inferCountry(parsed.Preview.Name))
	}
	if len(accepted) == 0 && cursor != len(entries) {
		return b, ErrFormat
	}
	b.raw = strings.Join(accepted, "\n")
	if len(b.raw) > providerprofile.MaxProfileBytes {
		return b, ErrSize
	}
	b.accepted = len(accepted)
	return b, nil
}

// Large sing-box catalogs are normalized one outbound at a time before the
// retained candidate limit is applied. Unselected raw configuration never
// enters nodestore or a local engine configuration.
func parseJSONFeed(ctx context.Context, data []byte, limit int) (batch, bool, error) {
	return parseJSONFeedWindow(ctx, data, limit, 0)
}
func parseJSONFeedWindow(ctx context.Context, data []byte, limit, cursor int) (batch, bool, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '[' && trimmed[0] != '{' {
		return batch{}, false, nil
	}
	if !validJSONShape(data) {
		return batch{}, true, ErrFormat
	}
	var entries []json.RawMessage
	if trimmed[0] == '[' {
		if json.Unmarshal(data, &entries) != nil {
			return batch{}, true, ErrFormat
		}
	} else {
		var doc map[string]json.RawMessage
		if json.Unmarshal(data, &doc) != nil {
			return batch{}, true, ErrFormat
		}
		raw, ok := doc["outbounds"]
		if !ok {
			return batch{}, false, nil
		}
		if json.Unmarshal(raw, &entries) != nil {
			return batch{}, true, ErrFormat
		}
	}
	if len(entries) == 0 || len(entries) > MaxEntries {
		return batch{}, true, ErrSize
	}
	if cursor > len(entries) {
		return batch{}, true, ErrRequest
	}
	b := batch{total: len(entries), snapshotEntries: len(entries), nextCursor: cursor}
	seen := map[[32]byte]bool{}
	selected := []json.RawMessage{}
	for index := cursor; index < len(entries); index++ {
		entry := entries[index]
		if err := ctx.Err(); err != nil {
			return b, true, err
		}
		if len(selected) >= limit {
			b.omitted += len(entries) - index
			break
		}
		b.nextCursor = index + 1
		var kind struct {
			Type string `json:"type"`
		}
		_ = json.Unmarshal(entry, &kind)
		if kind.Type == "direct" || kind.Type == "block" || kind.Type == "selector" || kind.Type == "urltest" {
			b.omitted++
			continue
		}
		parsed, err := providerprofile.ParseProfile("[" + string(entry) + "]")
		if err != nil || parsed.Preview.NodeCount != 1 {
			b.rejected++
			if len(b.issues) < MaxCandidates {
				b.issues = append(b.issues, providerprofile.EntryIssue{Index: index + 1, Code: "FEED_ENTRY", Reason: "Запись не прошла строгую проверку импорта."})
			}
			continue
		}
		var rebuilt struct {
			Outbounds []json.RawMessage `json:"outbounds"`
		}
		if json.Unmarshal(parsed.Config, &rebuilt) != nil || len(rebuilt.Outbounds) == 0 {
			return b, true, ErrFormat
		}
		material, err := canonicalOutbound(rebuilt.Outbounds[0])
		if err != nil {
			return b, true, ErrFormat
		}
		digest := sha256.Sum256(material)
		if seen[digest] {
			b.duplicates++
			continue
		}
		seen[digest] = true
		selected = append(selected, material)
		b.materials = append(b.materials, material)
		b.countries = append(b.countries, inferCountry(parsed.Preview.Nodes[0].Name))
	}
	if len(selected) == 0 && cursor != len(entries) {
		return b, true, ErrFormat
	}
	raw, err := json.Marshal(selected)
	if err != nil || len(raw) > providerprofile.MaxProfileBytes {
		return b, true, ErrSize
	}
	b.raw, b.accepted = string(raw), len(selected)
	return b, true, nil
}

func uriLines(data []byte) ([]string, error) {
	raw := strings.TrimSpace(string(data))
	if !strings.Contains(raw, "://") {
		var decoded []byte
		for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			candidate, err := encoding.DecodeString(raw)
			if err == nil {
				decoded = candidate
				break
			}
		}
		if len(decoded) == 0 || len(decoded) > MaxBytes || !utf8.Valid(decoded) {
			return nil, ErrFormat
		}
		raw = string(decoded)
	}
	raw = strings.ReplaceAll(strings.ReplaceAll(raw, "\r\n", "\n"), "\r", "\n")
	entries := []string{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		if len(entries) >= MaxEntries {
			return nil, ErrSize
		}
		entries = append(entries, line)
	}
	if len(entries) == 0 {
		return nil, ErrFormat
	}
	return entries, nil
}

func keysJSON(data []byte) ([]string, error) {
	if !validJSONShape(data) {
		return nil, ErrFormat
	}
	var root map[string]json.RawMessage
	if json.Unmarshal(data, &root) != nil || len(root) == 0 || len(root) > 64 {
		return nil, ErrFormat
	}
	entries := []string{}
	group := func(raw json.RawMessage) error {
		var value map[string]json.RawMessage
		if json.Unmarshal(raw, &value) != nil || !exactSelectionFields(value, "top10", "top5") {
			return ErrFormat
		}
		selected, ok := value["top10"]
		if !ok {
			selected = value["top5"]
		}
		var keys []map[string]json.RawMessage
		if json.Unmarshal(selected, &keys) != nil || keys == nil || len(keys) > 64 {
			return ErrFormat
		}
		for _, row := range keys {
			if !exactSelectionFields(row, "key") {
				return ErrFormat
			}
			var key string
			if rawKey, ok := row["key"]; !ok || bytes.Equal(bytes.TrimSpace(rawKey), []byte("null")) || json.Unmarshal(rawKey, &key) != nil {
				return ErrFormat
			}
			if len(entries) >= MaxEntries {
				return ErrSize
			}
			entries = append(entries, key)
		}
		return nil
	}
	keys := make([]string, 0, len(root))
	for key := range root {
		keys = append(keys, key)
	}
	sort.Strings(keys) // Never depend on randomized map iteration for candidate order.
	for _, key := range keys {
		if key == "updated_at" {
			continue
		} // Publisher clocks and TCP health grant no local authority.
		if key == "other_countries" {
			var countries map[string]json.RawMessage
			if json.Unmarshal(root[key], &countries) != nil || len(countries) > 128 {
				return nil, ErrFormat
			}
			names := make([]string, 0, len(countries))
			for name := range countries {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				if err := group(countries[name]); err != nil {
					return nil, err
				}
			}
		} else if err := group(root[key]); err != nil {
			return nil, err
		}
	}
	if len(entries) == 0 {
		return nil, ErrFormat
	}
	return entries, nil
}

// Ignore unrelated publisher metadata, but never let encoding/json's folded
// struct-field matching turn KEY/TOP10 into credential-selection aliases.
// Country labels remain case-sensitive data rather than schema field names.
func exactSelectionFields(fields map[string]json.RawMessage, names ...string) bool {
	for field := range fields {
		for _, name := range names {
			if field != name && strings.EqualFold(field, name) {
				return false
			}
		}
	}
	return true
}

// Reject duplicate keys and unexpectedly deep source objects instead of silently
// accepting last-wins metadata/key values. This also bounds recursive decoding.
func validJSONShape(data []byte) bool {
	d := json.NewDecoder(strings.NewReader(string(data)))
	var value func(int) bool
	value = func(depth int) bool {
		if depth > 8 {
			return false
		}
		token, err := d.Token()
		if err != nil {
			return false
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return true
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return false
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return false
				}
				seen[name] = true
				if !value(depth + 1) {
					return false
				}
			}
			end, err := d.Token()
			return err == nil && end == json.Delim('}')
		case '[':
			for d.More() {
				if !value(depth + 1) {
					return false
				}
			}
			end, err := d.Token()
			return err == nil && end == json.Delim(']')
		default:
			return false
		}
	}
	if !value(0) {
		return false
	}
	_, err := d.Token()
	return err == io.EOF
}
