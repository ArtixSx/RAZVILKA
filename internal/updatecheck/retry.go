package updatecheck

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

func safeUpdateETag(s string) string {
	if len(s) > 512 || strings.IndexFunc(s, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
		return ""
	}
	return s
}
func updateRetryAfter(h http.Header, now time.Time) time.Time {
	until := now.Add(time.Minute)
	if n, e := strconv.ParseInt(h.Get("Retry-After"), 10, 64); e == nil && n >= 0 {
		until = now.Add(time.Duration(min(n, 86400)) * time.Second)
	} else if t, e := http.ParseTime(h.Get("Retry-After")); e == nil {
		until = t
	}
	if h.Get("X-RateLimit-Remaining") == "0" {
		if n, e := strconv.ParseInt(h.Get("X-RateLimit-Reset"), 10, 64); e == nil {
			if t := time.Unix(n, 0); t.After(until) {
				until = t
			}
		}
	}
	if until.Before(now.Add(time.Second)) {
		until = now.Add(time.Second)
	}
	if until.After(now.Add(24 * time.Hour)) {
		until = now.Add(24 * time.Hour)
	}
	return until
}
