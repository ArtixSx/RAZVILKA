package app

import (
	"testing"
	"time"
)

func TestNFQWS2HookSettleSlidesThenCaps(t *testing.T) {
	start := time.Now()
	s := nfqws2HookSettle{timing: nfqws2HookHintDefaults}
	if _, pending := s.due(); pending || s.fire(start, func() bool { t.Fatal("idle settle woke"); return true }) {
		t.Fatal("idle settle is pending")
	}
	s.event(start)
	if at, _ := s.due(); !at.Equal(start.Add(1500 * time.Millisecond)) {
		t.Fatal("single event does not settle for 1.5 s", at.Sub(start))
	}
	// Each event slides the quiet period, never past 5 s after the first.
	for _, offset := range []time.Duration{time.Second, 2 * time.Second, 3 * time.Second} {
		s.event(start.Add(offset))
		if at, _ := s.due(); !at.Equal(start.Add(offset + 1500*time.Millisecond)) {
			t.Fatal("event did not slide the settle", offset, at.Sub(start))
		}
	}
	s.event(start.Add(4 * time.Second))
	if at, _ := s.due(); !at.Equal(start.Add(5 * time.Second)) {
		t.Fatal("burst exceeded the hard settle limit", at.Sub(start))
	}
	wakes := 0
	wake := func() bool { wakes++; return true }
	if s.fire(start.Add(5*time.Second-time.Millisecond), wake) || wakes != 0 {
		t.Fatal("woke before the settle")
	}
	if !s.fire(start.Add(5*time.Second), wake) || wakes != 1 || s.fire(start.Add(6*time.Second), wake) || wakes != 1 {
		t.Fatal("one burst did not produce exactly one wake", wakes)
	}
}

func TestNFQWS2HookSettleRateLimitsWakes(t *testing.T) {
	start := time.Now()
	s := nfqws2HookSettle{timing: nfqws2HookHintDefaults}
	wakes := 0
	wake := func() bool { wakes++; return true }
	s.event(start)
	s.fire(start.Add(1500*time.Millisecond), wake)
	// A new event right after a wake waits for the 2 s interval, not 1.5 s.
	s.event(start.Add(1600 * time.Millisecond))
	if at, _ := s.due(); !at.Equal(start.Add(3500 * time.Millisecond)) {
		t.Fatal("interval after a wake", at.Sub(start))
	}
	if s.fire(start.Add(3499*time.Millisecond), wake) || !s.fire(start.Add(3500*time.Millisecond), wake) || wakes != 2 {
		t.Fatal("rate-limited wake", wakes)
	}
	s = nfqws2HookSettle{timing: nfqws2HookHintDefaults, woke: start}
	s.event(start.Add(100 * time.Millisecond))
	if at, _ := s.due(); !at.Equal(start.Add(2 * time.Second)) {
		t.Fatal("two wakes inside 2 s", at.Sub(start))
	}
}

func TestNFQWS2HookSettleRetriesWhileRecoveryRuns(t *testing.T) {
	start := time.Now()
	s := nfqws2HookSettle{timing: nfqws2HookHintDefaults}
	calls := 0
	running := func() bool { calls++; return false }
	s.event(start)
	at := start.Add(1500 * time.Millisecond)
	if s.fire(at, running) || calls != 1 {
		t.Fatal("refused wake reported success")
	}
	next, pending := s.due()
	if !pending || !next.Equal(at.Add(2*time.Second)) {
		t.Fatal("refused wake was not retried after the interval", next.Sub(at), pending)
	}
	// The retry stops after retryFor; the 30-second schedule remains.
	for now := next; now.Before(start.Add(3 * time.Minute)); now = now.Add(2 * time.Second) {
		s.fire(now, running)
	}
	if _, pending := s.due(); pending || calls > 1+int(2*time.Minute/(2*time.Second))+1 {
		t.Fatal("refused hint was retried without bound", calls, pending)
	}
	s.event(start.Add(4 * time.Minute))
	if !s.fire(start.Add(4*time.Minute+1500*time.Millisecond), func() bool { return true }) {
		t.Fatal("a new hint after a dropped one did not wake")
	}
}
