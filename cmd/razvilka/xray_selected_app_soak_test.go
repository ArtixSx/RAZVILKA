package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

const (
	xraySelectedSoakMinimum            = time.Hour
	xraySelectedSoakMaximum            = 70 * time.Minute
	xraySelectedSoakInterval           = 30 * time.Second
	xraySelectedSoakPoll               = time.Second
	xraySelectedSoakObservationTimeout = 8 * time.Second
)

// This protocol coordinates a test only. It never contains engine grants,
// profiles, endpoints, process IDs, source receipts or a runtime-health proof.
type xraySelectedSoakStatus struct {
	RunID, Phase, Code                    string
	ActivatedAt, ObservedUntil, UpdatedAt time.Time
	Elapsed                               time.Duration
	Observations                          uint64
}

func (s xraySelectedSoakStatus) text() []byte {
	return []byte(fmt.Sprintf("qa_coordination_only=1\nrun_id=%s\nphase=%s\nactive_at_utc=%s\nowner_observed_until_utc=%s\nupdated_at_utc=%s\nactive_elapsed_ns=%d\nobservations=%d\ncode=%s\n",
		s.RunID, s.Phase, s.ActivatedAt.UTC().Format(time.RFC3339Nano), s.ObservedUntil.UTC().Format(time.RFC3339Nano), s.UpdatedAt.UTC().Format(time.RFC3339Nano), s.Elapsed.Nanoseconds(), s.Observations, s.Code))
}

func xraySelectedSoakCommand(data []byte, runID string) (string, error) {
	if len(data) == 0 {
		return "", nil
	}
	if len(data) > 128 || strings.ContainsRune(string(data), '\r') {
		return "", errors.New("soak_control_invalid")
	}
	for _, verb := range []string{"STOP", "ABORT"} {
		if string(data) == verb+" "+runID || string(data) == verb+" "+runID+"\n" {
			return verb, nil
		}
	}
	return "", errors.New("soak_control_invalid_or_stale")
}

type xraySelectedSoakHooks struct {
	Now     func() time.Time
	Wait    func(context.Context, time.Duration) error
	Command func() ([]byte, error)
	Publish func(xraySelectedSoakStatus) error
	Observe func(context.Context) error
}

func xraySelectedSoakWait(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// Admission/request contexts have already completed. Observe must call the
// SAME production manager's existing retained-owner observer, never renew a
// check, replay Apply, manufacture history or acquire a replacement owner.
func xraySelectedHold(ctx context.Context, runID string, h xraySelectedSoakHooks) (s xraySelectedSoakStatus, retErr error) {
	s.RunID = runID
	update := func() {
		s.UpdatedAt = h.Now()
		if !s.ActivatedAt.IsZero() {
			s.Elapsed = s.UpdatedAt.Sub(s.ActivatedAt)
		}
	}
	fail := func(code string) (xraySelectedSoakStatus, error) {
		update()
		s.Phase, s.Code = "failed", code
		_ = h.Publish(s) // preserve a fenced control directory on publication failure
		return s, errors.New(code)
	}
	observe := func() error {
		bounded, cancel := context.WithTimeout(ctx, xraySelectedSoakObservationTimeout)
		defer cancel()
		if err := h.Observe(bounded); err != nil || bounded.Err() != nil {
			return errors.New("soak_owner_observation_failed")
		}
		s.Observations++
		s.ObservedUntil = h.Now()
		return nil
	}
	if ctx.Err() != nil {
		return fail("soak_canceled")
	}
	if err := observe(); err != nil {
		return fail("soak_owner_observation_failed")
	}
	s.ActivatedAt = s.ObservedUntil // Go's monotonic component governs the complete hold
	nextObservation := s.ActivatedAt.Add(xraySelectedSoakInterval)
	s.Phase = "active_observed"
	update()
	if h.Publish(s) != nil {
		return fail("soak_status_unconfirmed")
	}
	for {
		update()
		if ctx.Err() != nil {
			return fail("soak_canceled")
		}
		if s.Elapsed < 0 || s.Elapsed >= xraySelectedSoakMaximum {
			return fail("soak_control_expired")
		}
		data, err := h.Command()
		if err != nil {
			return fail("soak_control_unconfirmed")
		}
		command, err := xraySelectedSoakCommand(data, runID)
		clear(data)
		if err != nil {
			return fail("soak_control_invalid_or_stale")
		}
		if command == "ABORT" {
			return fail("soak_aborted")
		}
		if command == "STOP" {
			if s.Elapsed < xraySelectedSoakMinimum {
				return fail("soak_stop_before_full_hour")
			}
			if observe() != nil {
				return fail("soak_owner_observation_failed")
			}
			update()
			if ctx.Err() != nil || s.Elapsed >= xraySelectedSoakMaximum {
				return fail("soak_stop_incomplete")
			}
			s.Phase = "stop_requested"
			if h.Publish(s) != nil {
				return fail("soak_status_unconfirmed")
			}
			return s, nil // production Stop/Wait/retirement is still required
		}
		if !s.UpdatedAt.Before(nextObservation) {
			if observe() != nil {
				return fail("soak_owner_observation_failed")
			}
			update()
			if s.Elapsed >= xraySelectedSoakMaximum {
				return fail("soak_control_expired")
			}
			nextObservation = s.UpdatedAt.Add(xraySelectedSoakInterval)
			if h.Publish(s) != nil {
				return fail("soak_status_unconfirmed")
			}
		}
		remaining := xraySelectedSoakMaximum - s.Elapsed
		if h.Wait(ctx, min(xraySelectedSoakPoll, remaining)) != nil {
			return fail("soak_canceled")
		}
	}
}

// Drive the actual hold loop across its hour boundary without a real hour or
// production runtime. Commands arrive through the same bounded wire parser;
// snapshots fail independently of command delivery. No test issues a grant.
func TestXraySelectedSoakHourCoordination(t *testing.T) {
	const runID = "0123456789abcdef0123456789abcdef"
	for _, scenario := range []struct {
		name              string
		at                time.Duration
		command, wantCode string
		breakOwner        bool
	}{
		{"delayed-stop-after-full-hour", time.Hour + 4*time.Second, "STOP " + runID + "\n", "", false},
		{"early-stop", time.Hour - time.Second, "STOP " + runID, "soak_stop_before_full_hour", false},
		{"stale-run-control", time.Hour + time.Second, "STOP fedcba9876543210fedcba9876543210", "soak_control_invalid_or_stale", false},
		{"no-stop-at-one-hour", 0, "", "soak_control_expired", false},
		{"stop-at-expired-ceiling", 70 * time.Minute, "STOP " + runID, "soak_control_expired", false},
		{"owner-lost-before-stop", time.Hour + 4*time.Second, "STOP " + runID, "soak_owner_observation_failed", true},
		{"abort", 2 * time.Second, "ABORT " + runID, "soak_aborted", false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			now := time.Now()
			start := now
			var phases []xraySelectedSoakStatus
			s, err := xraySelectedHold(context.Background(), runID, xraySelectedSoakHooks{
				Now:  func() time.Time { return now },
				Wait: func(_ context.Context, d time.Duration) error { now = now.Add(d); return nil },
				Command: func() ([]byte, error) {
					if now.Sub(start) >= scenario.at {
						return []byte(scenario.command), nil
					}
					return nil, nil
				},
				Publish: func(s xraySelectedSoakStatus) error { phases = append(phases, s); return nil },
				Observe: func(ctx context.Context) error {
					if _, ok := ctx.Deadline(); !ok {
						t.Fatal("owner observation lost its bound")
					}
					if scenario.breakOwner && now.Sub(start) >= time.Hour {
						return errors.New("private runtime detail must not escape")
					}
					return nil
				},
			})
			if scenario.wantCode == "" {
				if err != nil || s.Phase != "stop_requested" || s.Elapsed != scenario.at || s.Observations < 121 {
					t.Fatal("full hold/delayed explicit Stop was not confirmed", s.Code)
				}
			} else if err == nil || err.Error() != scenario.wantCode || s.Code != scenario.wantCode || s.Phase != "failed" {
				t.Fatal("partial, stale, expired or unowned hold became successful", s.Code)
			}
			for _, published := range phases {
				if len(published.text()) > 4096 || strings.Contains(string(published.text()), "private runtime detail") {
					t.Fatal("status lost its bound/privacy")
				}
				if published.Elapsed == time.Hour && published.Phase == "stop_requested" {
					t.Fatal("harness stopped at 3600s before delayed PC completion")
				}
			}
		})
	}
}

func TestXraySelectedSoakCanceledAndUnconfirmedControl(t *testing.T) {
	for _, cut := range []string{"cancel", "control", "publication"} {
		t.Run(cut, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			now := time.Now()
			s, err := xraySelectedHold(ctx, "private-run-id", xraySelectedSoakHooks{
				Now:  func() time.Time { return now },
				Wait: func(_ context.Context, d time.Duration) error { now = now.Add(d); cancel(); return ctx.Err() },
				Command: func() ([]byte, error) {
					if cut == "control" {
						return nil, errors.New("secret")
					}
					return nil, nil
				},
				Publish: func(xraySelectedSoakStatus) error {
					if cut == "publication" {
						return errors.New("secret")
					}
					return nil
				},
				Observe: func(context.Context) error { return nil },
			})
			if err == nil || s.Phase != "failed" || strings.Contains(err.Error(), "secret") {
				t.Fatal("canceled/unconfirmed control became a completed hold")
			}
		})
	}
	values := map[string]string{}
	for _, key := range []string{"ROOT", "PROFILE", "CATALOG", "SOURCES", "SCOPE"} {
		values[key] = t.TempDir()
	}
	values["HTTPS_IPV4"], values["CLIENT_IPV4"] = "149.154.167.99", "192.168.1.100"
	get := func(key string) string { return values[strings.TrimPrefix(key, "RAZVILKA_NATIVE_XRAY_SELECTED_")] }
	for _, value := range []string{"true", "0", "1\n", "70m", "vless://private"} {
		values["SOAK"] = value
		if _, err := xraySelectedParseInput(get); err == nil {
			t.Fatal("implicit/unbounded soak input accepted")
		}
	}
	values["SOAK"] = "1"
	if in, err := xraySelectedParseInput(get); err != nil || !in.Soak {
		t.Fatal("explicit soak input rejected")
	}
}
