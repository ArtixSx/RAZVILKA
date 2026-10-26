package app

import "time"

// NDM executes the stock nfqws2-keenetic netfilter hook after it rewrites a
// table, and executing it opens the file. An open is only a hint: it names
// no table, family or process and carries no authority. A settled hint makes
// node-recovery due; the round decides everything from fresh reads.
type nfqws2HookHintTiming struct {
	quiet    time.Duration // sliding settle after the latest event
	max      time.Duration // hard settle limit after the first event
	interval time.Duration // at most one wake per interval
	retryFor time.Duration // keep a hint while node-recovery runs, then drop it
	rearmMin time.Duration // first delay before re-adding a lost watch
	rearmMax time.Duration
}

var nfqws2HookHintDefaults = nfqws2HookHintTiming{quiet: 1500 * time.Millisecond, max: 5 * time.Second, interval: 2 * time.Second, retryFor: 2 * time.Minute, rearmMin: time.Second, rearmMax: 5 * time.Minute}

// nfqws2HookSettle coalesces a burst of hook executions (NDM rewrites mangle
// and nat separately, and an IPsec or WAN reconnect rewrites several times
// a second) into one wake after the burst, or at most max after it began.
type nfqws2HookSettle struct {
	timing      nfqws2HookHintTiming
	first, last time.Time
	woke        time.Time
	pending     bool
}

func (s *nfqws2HookSettle) event(now time.Time) {
	if !s.pending {
		s.pending, s.first = true, now
	}
	s.last = now
}

// due is the time of the pending wake, never earlier than the rate limit.
func (s *nfqws2HookSettle) due() (time.Time, bool) {
	if !s.pending {
		return time.Time{}, false
	}
	at := s.last.Add(s.timing.quiet)
	if limit := s.first.Add(s.timing.max); limit.Before(at) {
		at = limit
	}
	if limit := s.woke.Add(s.timing.interval); !s.woke.IsZero() && at.Before(limit) {
		at = limit
	}
	return at, true
}

// fire wakes once a pending hint is due. A refused wake (node-recovery is
// already running) stays pending and is retried after the interval, until
// retryFor after its first event; the 30-second schedule covers the rest.
func (s *nfqws2HookSettle) fire(now time.Time, wake func() bool) bool {
	at, pending := s.due()
	if !pending || now.Before(at) {
		return false
	}
	s.woke = now
	woke := wake()
	if woke || now.Sub(s.first) >= s.timing.retryFor {
		s.pending = false
	}
	return woke
}
