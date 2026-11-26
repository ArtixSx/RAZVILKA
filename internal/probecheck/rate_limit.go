package probecheck

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// A server can defer this service, never the coordinator or a route mutation.
// Retain only bounded seconds, not arbitrary response headers, in diagnostics.
func RateLimitDelaySeconds(raw string, now time.Time) int {
	const fallback = 5 * 60
	if len(raw) > 128 {
		return fallback
	}
	raw = strings.TrimSpace(raw)
	if seconds, err := strconv.ParseUint(raw, 10, 32); err == nil {
		return int(max(uint64(30), min(seconds, uint64(30*60))))
	}
	if date, err := http.ParseTime(raw); err == nil && date.After(now) {
		return int(max(30*time.Second, min(date.Sub(now), 30*time.Minute)) / time.Second)
	}
	return fallback
}
