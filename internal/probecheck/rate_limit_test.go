package probecheck

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestRateLimitDelayIsBounded(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	for raw, want := range map[string]int{
		"": 300, "invalid": 300, "-1": 300, "0": 30, "1": 30, "120": 120,
		"4294967295": 1800, "999999999999999999999999": 300,
		now.Add(2 * time.Minute).Format(http.TimeFormat): 120,
		now.Add(-time.Minute).Format(http.TimeFormat):    300,
		"Fri, 31 Dec 9999 23:59:59 GMT":                  1800,
		strings.Repeat("9", 129):                         300,
	} {
		if got := RateLimitDelaySeconds(raw, now); got != want {
			t.Fatalf("%q: got %d, want %d", raw, got, want)
		}
	}
}
