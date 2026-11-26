package warp

import (
	"context"
	"errors"
	"time"

	"github.com/ArtixSx/razvilka/internal/cloudflareprovider"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

var (
	ErrAutomaticInitialConsent = errors.New("automatic first WARP profile is not authorized")
	ErrAutomaticInitialChanged = errors.New("WARP service scope changed during profile preparation")
	ErrAutomaticInitialDraft   = errors.New("WARP file slot already contains a different profile or draft")
	ErrAutomaticInitialBudget  = errors.New("automatic WARP registration is waiting for its attempt budget")
)

// PrepareAutomaticInitial recovers or makes the first profile under the native
// enrollment owner. The caller holds the application admission for the current
// service and supplies a guard that does not reenter this manager. Registration
// creates no route. Application still needs its own isolated and live checks.
func (m *Manager) PrepareAutomaticInitial(ctx context.Context, expected HealthPolicy, guard func(context.Context) error) (Result, error) {
	return m.prepareAutomaticInitial(ctx, expected, guard, nil)
}

// PrepareAutopilotInitial uses the caller's saved first-registration consent.
// The caller must bind guard to that exact policy and its current service scope.
// It preserves the existing health policy and its registration budget; it never
// grants account replacement, rotation or automatic application permissions.
// A valid live profile may be reused without permission to create an account.
func (m *Manager) PrepareAutopilotInitial(ctx context.Context, expected HealthPolicy, allowed bool, guard func(context.Context) error) (Result, error) {
	return m.prepareAutomaticInitial(ctx, expected, guard, &allowed)
}

func (m *Manager) prepareAutomaticInitial(ctx context.Context, expected HealthPolicy, guard func(context.Context) error, autopilotConsent *bool) (Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.EngineConfigs == nil || m.nativeAPI == nil || guard == nil {
		return Result{}, ErrAutomaticInitialConsent
	}
	doc, err := m.loadHealthLocked()
	if err != nil {
		return Result{}, err
	}
	if doc.Policy != expected || autopilotConsent == nil && (!expected.Enabled || !expected.AcceptTOS || !expected.AutoPrepareInitial) {
		return Result{}, ErrAutomaticInitialConsent
	}
	check := func(c context.Context) error {
		if c.Err() != nil || guard(c) != nil {
			return ErrAutomaticInitialChanged
		}
		return nil
	}
	if err := check(ctx); err != nil {
		return Result{}, err
	}
	initial, err := m.EngineConfigs.ReadExpert("warp-wg", "main")
	if err != nil {
		return Result{}, ErrAutomaticInitialDraft
	}
	if initial.Source == "live" {
		if ValidateProfile([]byte(initial.Content)) != nil {
			return Result{}, ErrAutomaticInitialDraft
		}
		return Result{OK: true, Source: "live", SHA256: initial.SHA256}, nil
	}
	if autopilotConsent != nil && !*autopilotConsent {
		return Result{}, ErrAutomaticInitialConsent
	}
	reserve := func(c context.Context, api cloudflareprovider.RegistrationAPI) error {
		if err := check(c); err != nil {
			return err
		}
		// An unrelated editor draft or a legacy account cannot be replaced by
		// a first-start registration.
		slotEmpty := func() bool {
			current, err := m.EngineConfigs.ReadExpert("warp-wg", "main")
			return err == nil && current.Source == "missing" && initial.Source == "missing" && !regularFile(m.accountPath())
		}
		if !slotEmpty() {
			return ErrAutomaticInitialDraft
		}
		now := m.healthClock()
		attempts := pruneRotations(doc.State.Attempts, now.Add(-24*time.Hour))
		if len(attempts) >= expected.MaxRotationsPerDay {
			return ErrAutomaticInitialBudget
		}
		if len(attempts) > 0 {
			last, _ := time.Parse(time.RFC3339, attempts[len(attempts)-1])
			if now.Sub(last) < time.Duration(expected.CooldownHours)*time.Hour {
				return ErrAutomaticInitialBudget
			}
		}
		if autopilotConsent != nil {
			// Do not leave an unresolved account reservation when even the
			// read-only route to the registrar is unavailable. The enrollment
			// owner calls reserve only for a new POST, after considering any
			// saved or pending registration. HTTP status proves reachability,
			// regardless of the endpoint's support for HEAD.
			if prober, ok := api.(interface {
				ProbeEndpoint(context.Context) (int, error)
			}); ok {
				probe, cancel := context.WithTimeout(c, 6*time.Second)
				status, err := prober.ProbeEndpoint(probe)
				cancel()
				if err != nil || status < 100 || status > 599 {
					return ErrRegistrationEndpointUnavailable
				}
				if err := check(c); err != nil {
					return err
				}
				if !slotEmpty() {
					return ErrAutomaticInitialDraft
				}
			}
		}
		doc.State.Attempts = append(attempts, now.Format(time.RFC3339))
		doc.State.LastDecision = "initial-registration-attempt-reserved"
		return m.saveHealthLocked(doc)
	}
	stage := func(c context.Context, profile []byte) error {
		if err := check(c); err != nil {
			return err
		}
		current, err := m.EngineConfigs.ReadExpert("warp-wg", "main")
		if err != nil {
			return ErrAutomaticInitialDraft
		}
		if current.Source == "staged" && current.SHA256 == digest(profile) {
			return nil // Already prepared from this durable enrollment.
		}
		if current.Source != "missing" {
			return ErrAutomaticInitialDraft
		}
		if _, err := m.EngineConfigs.StageIfMissing(c, "warp-wg", "main", string(profile)); err != nil {
			if errors.Is(err, restorejournal.ErrConflict) {
				return ErrAutomaticInitialDraft
			}
			return err
		}
		return nil
	}
	result, err := m.prepareNativeLocked(ctx, true, false, reserve, stage)
	if err != nil {
		return Result{}, err
	}
	result.Source = "staged"
	return result, nil
}
