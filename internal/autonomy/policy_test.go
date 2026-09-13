package autonomy

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func validPolicy() Policy {
	p := Default()
	p.SetupComplete = true
	p.Enabled = true
	p.AllLAN = false
	p.DefaultSources = []string{"192.168.1.50/32"}
	p.SourceIDs = []string{"feed-fixture"}
	return p
}
func TestPolicyValidation(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Policy)
		valid  bool
	}{
		{"valid_defaults", func(*Policy) {}, true},
		{"all_lan_explicit", func(p *Policy) { p.AllLAN = true; p.DefaultSources = nil }, true},
		{"no_implicit_lan", func(p *Policy) { p.DefaultSources = nil }, false},
		{"no_ambiguous_scope", func(p *Policy) { p.AllLAN = true }, false},
		{"invalid_timezone", func(p *Policy) { p.Timezone = "No/SuchZone" }, false},
		{"empty_timezone", func(p *Policy) { p.Timezone = "" }, false},
		{"local_timezone", func(p *Policy) { p.Timezone = "Local" }, false},
		{"timezone_with_dst", func(p *Policy) { p.Timezone = "Europe/Berlin" }, true},
		{"setup_required", func(p *Policy) { p.SetupComplete = false }, false},
		{"empty_sources", func(p *Policy) { p.SourceIDs = nil }, false},
		{"unknown_source_syntax", func(p *Policy) { p.SourceIDs = []string{"https://example.org/sub?secret"} }, false},
		{"duplicate_sources", func(p *Policy) { p.SourceIDs = []string{"feed-x", "feed-x"} }, false},
		{"max_sources", func(p *Policy) { p.SourceIDs = make([]string, MaxSources+1) }, false},
		{"minimum_interval", func(p *Policy) { p.CheckSeconds = 59 }, false},
		{"maximum_interval", func(p *Policy) { p.CheckSeconds = 3601 }, false},
		{"reserve_slower", func(p *Policy) { p.ReserveSeconds = 60 }, false},
		{"reserve_too_large", func(p *Policy) { p.ReserveTarget = 5 }, false},
		{"zero_reserve", func(p *Policy) { p.ReserveTarget = 0 }, false},
		{"bounded_candidates", func(p *Policy) { p.CandidatesPerRound = 5 }, false},
		{"no_zero_gap", func(p *Policy) { p.FailureConfirmSeconds = 0 }, false},
		{"bounded_switches", func(p *Policy) { p.MaxSwitchesPerHour = 21 }, false},
		{"no_unimplemented_protocol", func(p *Policy) { p.Protocols = []string{"trojan"} }, false},
		{"duplicate_protocol", func(p *Policy) { p.Protocols = []string{"vless", "vless"} }, false},
		{"no_empty_protocol", func(p *Policy) { p.Protocols = nil }, false},
		{"no_unsupported_preferred", func(p *Policy) { p.PreferredRoutes = []string{"custom-shell"} }, false},
		{"no_duplicate_preferred", func(p *Policy) { p.PreferredRoutes = []string{"usque", "usque"} }, false},
		{"no_auto_install", func(p *Policy) { p.Application.Mode = "install" }, false},
		{"application_prepare", func(p *Policy) { p.Application.Mode = "prepare" }, true},
		{"no_component_prepare", func(p *Policy) { p.Components.Mode = "prepare" }, false},
		{"no_empty_days", func(p *Policy) { p.Application.Days = nil }, false},
		{"no_duplicate_days", func(p *Policy) { p.Application.Days = []int{1, 1} }, false},
		{"no_equal_window", func(p *Policy) { p.Application.End = p.Application.Start }, false},
		{"revision_overflow", func(p *Policy) { p.Revision = ^uint64(0) }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := validPolicy()
			tt.change(&p)
			if got := Validate(p) == nil; got != tt.valid {
				t.Fatalf("valid=%v want %v", got, tt.valid)
			}
		})
	}
}
func TestScopeBoundaries(t *testing.T) {
	for _, text := range []string{"0.0.0.0/0", "::/0", "127.0.0.1", "::1", "224.0.0.1", "192.168.1.2/24", "service.example", "/opt/key", "192.168.1.999"} {
		t.Run(text, func(t *testing.T) {
			if ValidateScope(false, []string{text}) == nil {
				t.Fatal("unsafe scope accepted")
			}
		})
	}
	for _, text := range []string{"192.168.1.2", "192.168.1.0/24", "fd00:1234::/64", "2001:db8::1"} {
		t.Run(text, func(t *testing.T) {
			if ValidateScope(false, []string{text}) != nil {
				t.Fatal("valid exact scope rejected")
			}
		})
	}
}
func TestCloneIsolationAndRoundTrip(t *testing.T) {
	p := validPolicy()
	q := Clone(p)
	q.SourceIDs[0] = "other"
	q.Protocols[0] = "bad"
	q.Application.Days[0] = 4
	q.DefaultSources[0] = "bad"
	q.PreferredRoutes[0] = "bad"
	if Validate(p) != nil {
		t.Fatal("clone aliases policy")
	}
	b, e := json.Marshal(p)
	if e != nil {
		t.Fatal(e)
	}
	var r Policy
	if json.Unmarshal(b, &r) != nil || !reflect.DeepEqual(p, r) {
		t.Fatal("round trip failed")
	}
	if strings.Contains(string(b), "vless://") {
		t.Fatal("credentials stored in policy")
	}
}
func parseUTC(t *testing.T, s string) time.Time {
	t.Helper()
	v, e := time.Parse(time.RFC3339, s)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func TestMidnightWindowBelongsToStartingDay(t *testing.T) {
	w := Window{Mode: "check", Start: "23:30", End: "01:00", Days: []int{1}}
	cases := []struct {
		stamp  string
		inside bool
	}{{"2026-09-07T23:29:00Z", false}, {"2026-09-07T23:30:00Z", true}, {"2026-09-08T00:59:00Z", true}, {"2026-09-08T01:00:00Z", false}, {"2026-09-08T23:45:00Z", false}}
	for _, c := range cases {
		t.Run(c.stamp, func(t *testing.T) {
			key, ok := WindowKey(w, "UTC", parseUTC(t, c.stamp))
			if ok != c.inside {
				t.Fatalf("inside=%v", ok)
			}
			if ok && !strings.HasPrefix(key, "2026-09-07/") {
				t.Fatal(key)
			}
		})
	}
}
func TestDSTRepeatedHourOnlyOneSlot(t *testing.T) {
	w := Window{Mode: "check", Start: "02:00", End: "03:00", Days: []int{0}}
	a, ok := WindowKey(w, "Europe/Berlin", parseUTC(t, "2026-10-25T00:20:00Z"))
	b, ok2 := WindowKey(w, "Europe/Berlin", parseUTC(t, "2026-10-25T01:20:00Z"))
	if !ok || !ok2 || a != b {
		t.Fatal("DST repeated slot was not deduplicated")
	}
}
func TestDSTGapAndNoCatchUp(t *testing.T) {
	w := Window{Mode: "check", Start: "02:10", End: "02:40", Days: []int{0}}
	n := parseUTC(t, "2026-03-29T01:00:00Z")
	if _, ok := WindowKey(w, "Europe/Berlin", n); ok {
		t.Fatal("nonexistent hour executed")
	}
	next := NextWindow(w, "Europe/Berlin", n)
	if want := parseUTC(t, "2026-04-05T00:10:00Z"); !next.Equal(want) {
		t.Fatalf("next=%v want=%v", next, want)
	}
	w.Mode = "off"
	if !NextWindow(w, "UTC", n).IsZero() {
		t.Fatal("disabled window scheduled")
	}
}
func TestInvalidClockTimes(t *testing.T) {
	for _, s := range []string{"3:00", "24:00", "03:60", "03:0x", "03:00:01", "", "-1:00"} {
		t.Run(s, func(t *testing.T) {
			if _, e := Minute(s); e == nil {
				t.Fatal("invalid clock accepted")
			}
		})
	}
}
