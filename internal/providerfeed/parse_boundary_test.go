package providerfeed

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestKeysJSONRejectsCaseAliasedSelection(t *testing.T) {
	uri, _ := json.Marshal(goodURI)
	row := `{"key":` + string(uri) + `}`
	for _, tc := range []struct{ name, group string }{
		{"alias-key", `{"top10":[{"KEY":` + string(uri) + `}]}`},
		{"overwritten-key", `{"top10":[{"key":"unsupported://reject-me","KEY":` + string(uri) + `}]}`},
		{"alias-selection", `{"TOP10":[` + row + `]}`},
		{"overwritten-selection", `{"top10":[{"key":"unsupported://reject-me"}],"TOP10":[` + row + `]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := keysJSON([]byte(`{"europe":` + tc.group + `}`)); !errors.Is(err, ErrFormat) {
				t.Fatal("case alias silently selected an imported credential")
			}
		})
	}
	entries, err := keysJSON([]byte(`{"updated_at":"untrusted-clock","Europe":{"top10":[{"key":` + string(uri) + `,"latency":1,"status":"PASS"}],"country":"EU"}}`))
	if err != nil || len(entries) != 1 || entries[0] != goodURI {
		t.Fatal("unrelated publisher metadata or country spelling became authoritative")
	}
}

func TestAmbiguousKeysJSONDoesNotReplaceLastKnownGood(t *testing.T) {
	m, store, path := testManager(t)
	uri, _ := json.Marshal(goodURI)
	req := Request{URL: "https://feed.example.org/private", Format: "keys-json"}
	setResponse(m, 200, `{"europe":{"top10":[{"key":`+string(uri)+`}]}}`, nil)
	if _, err := m.Sync(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	before := snapshotBytes(t, path)
	other, _ := json.Marshal(strings.Replace(goodURI, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", 1))
	setResponse(m, 200, `{"europe":{"top10":[{"key":"unsupported://reject-me","KEY":`+string(other)+`}]}}`, nil)
	if _, err := m.Sync(context.Background(), req); !errors.Is(err, ErrFormat) {
		t.Fatal("malformed feed did not fail before node import")
	}
	snapshot, err := store.Snapshot(context.Background(), testTime)
	if err != nil || len(snapshot.Nodes) != 1 || snapshotBytes(t, path) != before || !m.List()[0].LastKnownGood {
		t.Fatal("ambiguous feed changed retained candidates or evidence")
	}
}
