package updatecheck

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestChannelOrderAndDowngradeBoundaries(t *testing.T) {
	for _, c := range []struct {
		current, target, channel string
		want                     bool
	}{
		{"0.18.2-rc.6", "v0.18.2-rc.10", "preview", true},
		{"0.18.2-rc.10", "v0.18.2-rc.6", "preview", false},
		{"0.18.2", "v0.18.2-rc.10", "preview", false},
		{"0.18.2-rc.6", "v0.18.2", "stable", true},
		{"0.18.2-rc.6", "v0.18.2-rc.10", "", false},
		{"0.18.2-rc.6", "v0.18.3-rc.1", "evil", false},
		{"0.18.2", "v0.18.3-rc.01", "preview", false},
		{"0.18.2", "v00.19.0", "preview", false},
		{"0.18.2-1", "v0.18.2-alpha", "preview", true},
		{"0.18.2-rc.1", "v0.18.2-rc.1.1", "preview", true},
		{"0.18.2", "v0.18.3+foo", "preview", false},
	} {
		t.Run(c.current+"/"+c.target+"/"+c.channel, func(t *testing.T) {
			if got := CanUpgradeChannel(c.current, c.target, c.channel); got != c.want {
				t.Fatalf("got=%v want=%v", got, c.want)
			}
		})
	}
}
func releaseMeta(tag string, pre bool) map[string]any {
	return map[string]any{"tag_name": tag, "prerelease": pre, "html_url": "https://github.com/ArtixSx/RAZVILKA/releases/tag/" + tag}
}
func TestPreviewOptInETagRateLimitAndStaleLastGood(t *testing.T) {
	count := 0
	rate := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count++
		if r.URL.Path == "/latest" {
			json.NewEncoder(w).Encode(releaseMeta("v0.18.0", false))
			return
		}
		if r.URL.Query().Get("per_page") != "30" {
			t.Error("unbounded query")
		}
		if rate {
			w.Header().Set("Retry-After", "600")
			w.WriteHeader(429)
			return
		}
		if count > 2 {
			if r.Header.Get("If-None-Match") != "\"p1\"" {
				t.Error("missing etag")
			}
			w.WriteHeader(304)
			return
		}
		w.Header().Set("ETag", "\"p1\"")
		bad := releaseMeta("v99.0.0", false)
		bad["draft"] = true
		json.NewEncoder(w).Encode([]any{releaseMeta("v0.18.2-rc.6", true), releaseMeta("v0.18.2-rc.10", true), bad})
	}))
	defer server.Close()
	m := New("0.18.2-rc.6")
	m.Endpoint = server.URL + "/latest"
	m.Client = server.Client()
	if r := m.Check(context.Background(), true); r.Channel != "stable" || r.UpdateAvailable {
		t.Fatal("implicit preview", r)
	}
	first := m.CheckChannel(context.Background(), true, "preview")
	if first.ReleaseTag != "v0.18.2-rc.10" || !first.CanPrepare {
		t.Fatal(first)
	}
	if r := m.CheckChannel(context.Background(), true, "preview"); r.ReleaseTag != first.ReleaseTag || r.MetadataStale {
		t.Fatal(r)
	}
	rate = true
	r := m.CheckChannel(context.Background(), true, "preview")
	if r.State != "check-failed" || !r.MetadataStale || r.CanPrepare || r.UpdateAvailable || r.RetryAt == "" {
		t.Fatal(r)
	}
	attempts := count
	m.CheckChannel(context.Background(), true, "preview")
	if count != attempts {
		t.Fatal("force bypassed provider pause")
	}
}
func TestChannelCollectionRejectedIdentities(t *testing.T) {
	for _, raw := range []string{`{}`, `[]`, `[{"tag_name":"v9.0.0","html_url":"https://evil.example/x"}]`, `[{"tag_name":"v9.0.0","prerelease":true,"html_url":"https://github.com/ArtixSx/RAZVILKA/releases/tag/v9.0.0"}]`} {
		if _, err := selectChannelMetadata([]byte(raw), "preview"); err == nil {
			t.Fatal(raw)
		}
	}
}
func TestUpdateRetryBounded(t *testing.T) {
	now := time.Now()
	for _, v := range []string{"-1", "garbage", "9223372036854775807", "0", "86400"} {
		h := http.Header{}
		h.Set("Retry-After", v)
		n := updateRetryAfter(h, now)
		if !n.After(now) || n.After(now.Add(24*time.Hour)) {
			t.Fatal(v, n)
		}
	}
	if safeUpdateETag("a\r\nx") == "a\r\nx" || safeUpdateETag(strings.Repeat("a", 513)) != "" {
		t.Fatal("header")
	}
}
