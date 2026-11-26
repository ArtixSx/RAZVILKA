package autonomy

import (
	"testing"
	"time"
)

func BenchmarkNextWindowWeekAhead(b *testing.B) {
	w := Window{Mode: "check", Start: "03:00", End: "05:00", Days: []int{1}}
	now := time.Date(2026, 9, 28, 5, 1, 0, 0, time.UTC) // Monday, just after the window
	for b.Loop() {
		if NextWindow(w, "Europe/Moscow", now).IsZero() {
			b.Fatal("no window")
		}
	}
}

// NextWindow must stay the first minute that WindowKey (the dispatch rule)
// accepts, including across DST gaps and overlaps.
func TestNextWindowMatchesDispatchRule(t *testing.T) {
	reference := func(w Window, timezone string, now time.Time) time.Time {
		n := now.Truncate(time.Minute)
		for i := 0; i < 8*24*60; i++ {
			if _, ok := WindowKey(w, timezone, n); ok {
				return n
			}
			n = n.Add(time.Minute)
		}
		return time.Time{}
	}
	windows := []Window{
		{Mode: "check", Start: "03:00", End: "05:00", Days: []int{1}},
		{Mode: "prepare", Start: "23:30", End: "01:15", Days: []int{0, 6}},
		{Mode: "check", Start: "02:10", End: "02:50", Days: []int{0, 1, 2, 3, 4, 5, 6}},
	}
	starts := []time.Time{
		time.Date(2026, 3, 28, 22, 7, 31, 0, time.UTC),  // before the EU spring gap
		time.Date(2026, 10, 24, 23, 59, 0, 0, time.UTC), // before the EU autumn overlap
		time.Date(2026, 9, 28, 5, 1, 0, 0, time.UTC),
	}
	for _, timezone := range []string{"Europe/Berlin", "Europe/Moscow", "America/New_York", "UTC"} {
		for _, w := range windows {
			for _, start := range starts {
				for step := range 6 {
					now := start.Add(time.Duration(step) * 97 * time.Minute)
					if got, want := NextWindow(w, timezone, now), reference(w, timezone, now); !got.Equal(want) {
						t.Fatalf("%s %+v at %s: got %s, want %s", timezone, w, now, got, want)
					}
				}
			}
		}
	}
	if !NextWindow(windows[0], "Not/AZone", starts[0]).IsZero() || !NextWindow(windows[0], "UTC", time.Time{}).IsZero() {
		t.Fatal("invalid timezone or zero time produced a window")
	}
}
