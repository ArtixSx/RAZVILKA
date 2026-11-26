package warp

import (
	"context"
	"errors"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"path/filepath"
	"testing"
	"time"
)

func healthFixture(t *testing.T) (*Manager, *time.Time, HealthPolicy) {
	t.Helper()
	m := newNativeTestManager(t)
	now := time.Now().UTC()
	m.healthNow = func() time.Time { return now }
	p := defaultHealthPolicy()
	p.Enabled = true
	p.AcceptTOS = true
	p.AutoGenerateCandidate = true
	p.AllowAccountRefresh = true
	p.MinFailedServices = 1
	p.FailureThreshold = 2
	if _, err := m.UpdateHealthPolicy(p); err != nil {
		t.Fatal(err)
	}
	return m, &now, p
}
func observedFailure(m *Manager) (HealthDecision, error) {
	return m.ObserveHealth([]HealthEvidence{{ServiceID: "custom-site", Status: "fail", RouteConfirmed: true, Level: evidence.Route, NetworkProfile: "net-one"}})
}
func TestAutomaticAttemptChargedBeforeUncertainRemoteRegistration(t *testing.T) {
	m, now, p := healthFixture(t)
	calls := 0
	installNativeTestAPI(m, &calls, false, context.DeadlineExceeded)
	_, _ = observedFailure(m)
	*now = now.Add(31 * time.Second)
	d, err := observedFailure(m)
	if err != nil || !d.ShouldGenerate {
		t.Fatal("not eligible", err)
	}
	_, err = m.GenerateAutomatic(context.Background(), p)
	if !errors.Is(err, ErrEnrollmentPending) || calls != 1 {
		t.Fatal("remote", err, calls)
	}
	if len(m.Health().State.Attempts) != 1 {
		t.Fatal("attempt not persisted")
	}
	restarted := New(m.Root, m.BackupRoot, m.EngineConfigs)
	restarted.ProfilePaths = m.ProfilePaths
	installNativeTestAPI(restarted, &calls, true, nil)
	if _, err := restarted.GenerateAutomatic(context.Background(), p); err == nil || calls != 1 {
		t.Fatal("restarted registration repeated", err, calls)
	}
}
func TestAutomaticGenerationStagesWithoutTouchingLiveAndHonorsPolicy(t *testing.T) {
	m, now, p := healthFixture(t)
	calls := 0
	installNativeTestAPI(m, &calls, true, nil)
	_, _ = observedFailure(m)
	*now = now.Add(31 * time.Second)
	_, _ = observedFailure(m)
	wrong := p
	wrong.AllowAccountRefresh = false
	if _, err := m.GenerateAutomatic(context.Background(), wrong); err == nil || calls != 0 {
		t.Fatal("stale consent accepted")
	}
	result, err := m.GenerateAutomatic(context.Background(), p)
	if err != nil || !result.OK || calls != 1 {
		t.Fatal(err, calls)
	}
	if !m.Health().State.RouteEvidenceConfirmed || len(m.Health().State.Attempts) != 1 {
		t.Fatal("state lost")
	}
	if len(m.ProfilePaths) != 1 || m.ProfilePaths[0] != filepath.Join(filepath.Dir(m.Root), "live.conf") {
		t.Fatal("profile path altered")
	}
}
func TestHealthIndependentRoundAndNetworkReset(t *testing.T) {
	m, now, _ := healthFixture(t)
	_, _ = observedFailure(m)
	d, err := observedFailure(m)
	if err != nil || d.ShouldGenerate || d.State.ConsecutiveFailedRounds != 1 {
		t.Fatal("same event counted twice")
	}
	*now = now.Add(31 * time.Second)
	d, err = m.ObserveHealth([]HealthEvidence{{ServiceID: "custom-site", Status: "fail", RouteConfirmed: true, Level: evidence.Route, NetworkProfile: "net-two"}})
	if err != nil || d.State.ConsecutiveFailedRounds != 1 {
		t.Fatal("network retained old quorum")
	}
}
func TestWorkingSecondServicePreventsAccountRotation(t *testing.T) {
	m, now, _ := healthFixture(t)
	_, _ = observedFailure(m)
	*now = now.Add(31 * time.Second)
	d, err := m.ObserveHealth([]HealthEvidence{{ServiceID: "custom-site", Status: "fail", RouteConfirmed: true, Level: evidence.Route, NetworkProfile: "net-one"}, {ServiceID: "another", Status: "pass", RouteConfirmed: true, Level: evidence.Service, NetworkProfile: "net-one"}})
	if err != nil || d.ShouldGenerate || d.State.ConsecutiveFailedRounds != 0 {
		t.Fatal("healthy tunnel re-registered", err)
	}
}
func TestCheckIntervalValidationAndOptIn(t *testing.T) {
	m, _, p := healthFixture(t)
	for _, v := range []int{-1, 1, 59, 3601} {
		p.CheckIntervalSeconds = v
		if _, err := m.UpdateHealthPolicy(p); err == nil {
			t.Fatal("invalid interval", v)
		}
	}
	p.CheckIntervalSeconds = 180
	if _, err := m.UpdateHealthPolicy(p); err != nil {
		t.Fatal(err)
	}
	if p.CheckInterval() != 3*time.Minute {
		t.Fatal("wrong duration")
	}
}
