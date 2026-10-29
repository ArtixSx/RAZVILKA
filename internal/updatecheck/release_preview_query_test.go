package updatecheck

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func previewFetchFixture(t *testing.T, prerelease bool) []byte {
	t.Helper()
	tag := "v0.20.0-rc.98"
	if !prerelease {
		tag = "v0.20.0"
	}
	version := strings.TrimPrefix(tag, "v")
	assets := []map[string]any{}
	for i, name := range []string{"RAZVILKA-" + version + "-entware.tar.gz", "razvilka-linux-arm64"} {
		assets = append(assets, map[string]any{"id": int64(100 + i), "name": name, "size": 1024, "digest": "sha256:" + strings.Repeat("a", 64), "state": "uploaded", "browser_download_url": "https://github.com/" + officialRepository + "/releases/download/" + tag + "/" + name})
	}
	raw, err := json.Marshal(map[string]any{"id": int64(99), "tag_name": tag, "prerelease": prerelease, "published_at": "2026-10-29T00:00:00Z", "html_url": "https://github.com/" + officialRepository + "/releases/tag/" + tag, "assets": assets})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestFetchReleaseChannelPreviewUsesExactBoundedOfficialQuery(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: updateTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() != officialPreviewEndpoint || r.Method != http.MethodGet || r.Header.Get("X-GitHub-Api-Version") != "2022-11-28" {
			t.Fatal("unexpected metadata request", r.URL, r.Method)
		}
		return updateResponse(append(append([]byte("["), previewFetchFixture(t, true)...), ']')), nil
	})}
	release, err := FetchReleaseChannel(context.Background(), client, "0.20.0-rc.97", "arm64", 0, "preview")
	if err != nil || calls != 1 || release.ID != 99 || release.Tag != "v0.20.0-rc.98" {
		t.Fatalf("preview request did not reach validated metadata: calls=%d release=%+v err=%v", calls, release, err)
	}
}

func TestOfficialGETPreviewQueryCannotAuthorizeOtherRequests(t *testing.T) {
	base := "https://api.github.com/repos/" + officialRepository + "/releases"
	for _, raw := range []string{
		base + "?per_page=31", base + "?per_page=030", base + "?per_page=30&per_page=30", base + "?per_page=30&page=1", base + "?page=1&per_page=30", base + "?%70er_page=30", base + "?per_page=%33%30", base + "?per_page=30&", base + "?", base + "/?per_page=30", base + "/latest?per_page=30", base + "/99?per_page=30",
		"https://api.github.com/repos/other/RAZVILKA/releases?per_page=30",
		"https://api.github.com/repos/" + officialRepository + "/%72eleases?per_page=30",
		"https://api.github.com:443/repos/" + officialRepository + "/releases?per_page=30",
		"https://github.com/" + officialRepository + "/releases/download/v0.20.0/razvilka-linux-arm64?per_page=30",
		"https://api.github.com/repos/" + officialRepository + "/releases/assets/100?per_page=30",
		base + "?per_page=30#fragment", "https://user@api.github.com/repos/" + officialRepository + "/releases?per_page=30",
	} {
		t.Run(raw, func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: updateTransport(func(*http.Request) (*http.Response, error) { calls++; return updateResponse(nil), nil })}
			resp, err := officialGET(context.Background(), client, raw)
			if resp != nil {
				resp.Body.Close()
			}
			if err == nil || err.Error() != "release-url-refused" || calls != 0 {
				t.Fatalf("invalid query reached transport: calls=%d err=%v", calls, err)
			}
		})
	}
}

func TestFetchReleaseChannelPinnedAndStableRemainQueryFree(t *testing.T) {
	for _, channel := range []string{"stable", "preview"} {
		for _, id := range []int64{0, 99} {
			if channel == "preview" && id == 0 {
				continue
			}
			t.Run(channel+"/"+map[bool]string{true: "pinned", false: "latest"}[id > 0], func(t *testing.T) {
				want := "https://api.github.com/repos/" + officialRepository + "/releases/latest"
				if id > 0 {
					want = "https://api.github.com/repos/" + officialRepository + "/releases/99"
				}
				calls := 0
				client := &http.Client{Transport: updateTransport(func(r *http.Request) (*http.Response, error) {
					calls++
					if r.URL.String() != want || r.URL.RawQuery != "" || r.URL.ForceQuery {
						t.Fatal("pinned/stable URL changed", r.URL)
					}
					return updateResponse(previewFetchFixture(t, channel == "preview")), nil
				})}
				if _, err := FetchReleaseChannel(context.Background(), client, "0.19.3", "arm64", id, channel); err != nil || calls != 1 {
					t.Fatal("query-free metadata refused", err, calls)
				}
			})
		}
	}
}
