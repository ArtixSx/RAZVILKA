package providerprofile

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/publicfetch"
)

// Explicit read-only parser smoke test. Never dials proxy endpoints, stages
// configs, stores credentials or logs source content. Not a health authority.
func TestPublicVLESSSamplesParseOnly(t *testing.T) {
	if os.Getenv("RAZVILKA_TEST_PUBLIC_PROFILES") != "1" {
		t.Skip("requires explicit public sample opt-in")
	}
	for _, source := range []struct {
		name, url string
		json      bool
	}{
		{"vless-checker", "https://tiagorrg.github.io/vless-checker/keys.json", true},
		{"goida", "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/26.txt", false},
	} {
		t.Run(source.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, source.url, nil)
			resp, err := publicfetch.NewClient(20 * time.Second).Do(req)
			if err != nil {
				t.Fatal("sample fetch failed (detail suppressed)")
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("sample HTTP status: %d", resp.StatusCode)
			}
			data, err := io.ReadAll(io.LimitReader(resp.Body, (2<<20)+1))
			if err != nil || len(data) > 2<<20 {
				t.Fatal("sample read/size limit failure")
			}
			var candidates []string
			seen := map[string]bool{}
			add := func(s string) {
				s = strings.TrimSpace(s)
				if len(candidates) < 16 && strings.HasPrefix(s, "vless://") && !seen[s] {
					candidates = append(candidates, s)
					seen[s] = true
				}
			}
			if source.json {
				var document any
				if json.Unmarshal(data, &document) != nil {
					t.Fatal("sample JSON invalid")
				}
				var walk func(any, int)
				walk = func(v any, depth int) {
					if depth > 32 || len(candidates) == 16 {
						return
					}
					switch value := v.(type) {
					case string:
						add(value)
					case []any:
						for _, item := range value {
							walk(item, depth+1)
						}
					case map[string]any:
						keys := make([]string, 0, len(value))
						for k := range value {
							keys = append(keys, k)
						}
						sort.Strings(keys)
						for _, k := range keys {
							walk(value[k], depth+1)
						}
					}
				}
				walk(document, 0)
			} else {
				text := string(data)
				if !strings.Contains(text, "vless://") {
					text = decodeSubscription(text)
				}
				for _, line := range strings.Split(text, "\n") {
					add(line)
				}
			}
			if len(candidates) == 0 {
				t.Fatal("no VLESS entries in bounded sample")
			}
			counts := map[string]int{}
			for _, raw := range candidates {
				result, err := ParseURI(raw)
				if err != nil {
					counts[ErrorCode(err)]++
					if len(result.Config) != 0 {
						t.Fatal("rejected sample created config")
					}
					if u, parseErr := url.Parse(raw); parseErr == nil && u.User != nil && strings.Contains(err.Error(), u.User.Username()) {
						t.Fatal("error leaked sample credential")
					}
				} else {
					counts["PARSED_NOT_VERIFIED"]++
				}
			}
			t.Logf("sample=%d; parser results=%v; no proxy connections or writes", len(candidates), counts)
		})
	}
}
