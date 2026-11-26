package warp

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/cloudflareprovider"
)

type initialTestProber struct {
	cloudflareprovider.RegistrationAPI
	probe func(context.Context) (int, error)
	ready bool
}

func (p *initialTestProber) ProbeEndpoint(ctx context.Context) (int, error) {
	status, err := p.probe(ctx)
	p.ready = err == nil && status >= 100 && status <= 599
	return status, err
}

func (p *initialTestProber) Register(ctx context.Context, request cloudflareprovider.RegistrationRequest) (cloudflareprovider.RegistrationResponse, error) {
	if !p.ready {
		return cloudflareprovider.RegistrationResponse{}, errors.New("a different API instance received the POST")
	}
	return p.RegistrationAPI.Register(ctx, request)
}

func TestAutopilotRegistrationPreflightPreservesAdmissionAndKnownAccounts(t *testing.T) {
	ctx := context.Background()
	m := newNativeTestManager(t)
	policy := initialTestPolicy(t, m)
	var posts, probes int
	installNativeTestAPI(m, &posts, true, nil)
	factory := m.nativeAPI
	reachable, permission, revoke := false, true, false
	m.nativeAPI = func(checkpoint func([]byte) error) cloudflareprovider.RegistrationAPI {
		return &initialTestProber{RegistrationAPI: factory(checkpoint), probe: func(probe context.Context) (int, error) {
			probes++
			if deadline, ok := probe.Deadline(); !ok || time.Until(deadline) > 6*time.Second {
				t.Fatal("registration preflight has no usable deadline")
			}
			if !reachable {
				return 0, context.DeadlineExceeded
			}
			if revoke {
				permission = false
			}
			return http.StatusMethodNotAllowed, nil
		}}
	}
	guard := func(context.Context) error {
		if !permission {
			return context.Canceled
		}
		return nil
	}
	if _, err := m.PrepareAutopilotInitial(ctx, policy, true, guard); !errors.Is(err, ErrRegistrationEndpointUnavailable) || probes != 1 || posts != 0 ||
		len(m.Health().State.Attempts) != 0 || m.hasNativeStateLocked() {
		t.Fatalf("preflight failure reserved an account: err=%v probes=%d posts=%d", err, probes, posts)
	}
	reachable, revoke = true, true
	if _, err := m.PrepareAutopilotInitial(ctx, policy, true, guard); !errors.Is(err, ErrAutomaticInitialChanged) || probes != 2 || posts != 0 ||
		len(m.Health().State.Attempts) != 0 || m.hasNativeStateLocked() {
		t.Fatalf("preflight result missed later revocation: err=%v probes=%d posts=%d", err, probes, posts)
	}
	revoke, permission = false, true
	first, err := m.PrepareAutopilotInitial(ctx, policy, true, guard)
	if err != nil || first.Source != "staged" || probes != 3 || posts != 1 {
		t.Fatalf("reachable endpoint could not register: err=%v probes=%d posts=%d", err, probes, posts)
	}
	reachable = false
	second, err := m.PrepareAutopilotInitial(ctx, policy, true, guard)
	if err != nil || second.SHA256 != first.SHA256 || probes != 3 || posts != 1 {
		t.Fatalf("reusing saved credentials probed or registered again: err=%v probes=%d posts=%d", err, probes, posts)
	}
}

func TestAutopilotUnknownRegistrationDoesNotRepeatPreflightOrPost(t *testing.T) {
	m := newNativeTestManager(t)
	policy := initialTestPolicy(t, m)
	var posts, probes int
	installNativeTestAPI(m, &posts, false, context.DeadlineExceeded)
	factory := m.nativeAPI
	m.nativeAPI = func(checkpoint func([]byte) error) cloudflareprovider.RegistrationAPI {
		return &initialTestProber{RegistrationAPI: factory(checkpoint), probe: func(context.Context) (int, error) {
			probes++
			return http.StatusUnauthorized, nil
		}}
	}
	guard := func(context.Context) error { return nil }
	for i := 0; i < 2; i++ {
		if _, err := m.PrepareAutopilotInitial(context.Background(), policy, true, guard); !errors.Is(err, ErrEnrollmentPending) || probes != 1 || posts != 1 {
			t.Fatalf("uncertain POST result repeated after reservation: err=%v probes=%d posts=%d", err, probes, posts)
		}
	}
}

func initialTestPolicy(t *testing.T, m *Manager) HealthPolicy {
	t.Helper()
	m.EngineConfigs.LiveRoot = filepath.Join(t.TempDir(), "live")
	policy := defaultHealthPolicy()
	policy.Enabled, policy.AcceptTOS, policy.AutoPrepareInitial = true, true, true
	if _, err := m.UpdateHealthPolicy(policy); err != nil {
		t.Fatal(err)
	}
	return policy
}

func TestPrepareAutomaticInitialNeedsExplicitConsentAndReusesEnrollment(t *testing.T) {
	ctx := context.Background()
	m := newNativeTestManager(t)
	policy := initialTestPolicy(t, m)
	var calls int
	installNativeTestAPI(m, &calls, true, nil)
	authorize := func(context.Context) error { return nil }
	recoveryOnly := policy
	recoveryOnly.AutoPrepareInitial = false
	recoveryOnly.AutoGenerateCandidate, recoveryOnly.AllowAccountRefresh = true, true
	if _, err := m.UpdateHealthPolicy(recoveryOnly); err != nil {
		t.Fatal(err)
	}
	if _, err := m.PrepareAutomaticInitial(ctx, recoveryOnly, authorize); !errors.Is(err, ErrAutomaticInitialConsent) || calls != 0 {
		t.Fatalf("replacement policy authorized first registration: calls=%d err=%v", calls, err)
	}
	if _, err := m.UpdateHealthPolicy(policy); err != nil {
		t.Fatal(err)
	}
	first, err := m.PrepareAutomaticInitial(ctx, policy, authorize)
	if err != nil || !first.OK || first.Source != "staged" || first.SHA256 == "" || calls != 1 {
		t.Fatalf("first registration=%+v calls=%d err=%v", first, calls, err)
	}
	second, err := m.PrepareAutomaticInitial(ctx, policy, authorize)
	if err != nil || second.SHA256 != first.SHA256 || calls != 1 || len(m.Health().State.Attempts) != 1 {
		t.Fatalf("prepared candidate was not reused: calls=%d err=%v", calls, err)
	}
	if err := m.EngineConfigs.Discard("warp-wg", "main"); err != nil {
		t.Fatal(err)
	}
	rebuilt, err := m.PrepareAutomaticInitial(ctx, policy, authorize)
	if err != nil || rebuilt.SHA256 != first.SHA256 || calls != 1 {
		t.Fatalf("local enrollment was not restored without enrollment: calls=%d err=%v", calls, err)
	}
}

func TestPrepareAutopilotInitialDoesNotGrantHealthRecovery(t *testing.T) {
	m := newNativeTestManager(t)
	m.EngineConfigs.LiveRoot = filepath.Join(t.TempDir(), "live")
	policy := m.Health().Policy
	var calls int
	installNativeTestAPI(m, &calls, true, nil)
	guard := func(context.Context) error { return nil }
	if _, err := m.PrepareAutopilotInitial(context.Background(), policy, false, guard); !errors.Is(err, ErrAutomaticInitialConsent) || calls != 0 {
		t.Fatal("missing Auto permission reached the registrar", err, calls)
	}
	if _, err := m.PrepareAutopilotInitial(context.Background(), policy, true, nil); !errors.Is(err, ErrAutomaticInitialConsent) || calls != 0 {
		t.Fatal("missing current-policy guard reached the registrar", err, calls)
	}
	first, err := m.PrepareAutopilotInitial(context.Background(), policy, true, guard)
	if err != nil || !first.OK || first.Source != "staged" || calls != 1 || m.Health().Policy != policy {
		t.Fatal("Auto preparation changed health authority or failed", first, err, calls)
	}
	second, err := m.PrepareAutopilotInitial(context.Background(), policy, true, guard)
	if err != nil || second.SHA256 != first.SHA256 || calls != 1 {
		t.Fatal("Auto repeated an existing registration", second, err, calls)
	}
	if _, err := m.PrepareAutomaticInitial(context.Background(), policy, guard); !errors.Is(err, ErrAutomaticInitialConsent) || calls != 1 {
		t.Fatal("Auto registration silently granted legacy health permission", err, calls)
	}
	if _, err := m.GenerateAutomatic(context.Background(), policy); err == nil || calls != 1 {
		t.Fatal("Auto registration silently granted account replacement", err, calls)
	}
}

func TestPrepareAutopilotInitialRejectsRevokedConsentBeforePublication(t *testing.T) {
	m := newNativeTestManager(t)
	m.EngineConfigs.LiveRoot = filepath.Join(t.TempDir(), "live")
	policy := m.Health().Policy
	var calls int
	installNativeTestAPI(m, &calls, true, nil)
	allowed := true
	originalAPI := m.nativeAPI
	m.nativeAPI = func(checkpoint func([]byte) error) cloudflareprovider.RegistrationAPI {
		api := originalAPI(checkpoint)
		return nativeTestAPI(func(c context.Context, request cloudflareprovider.RegistrationRequest) (cloudflareprovider.RegistrationResponse, error) {
			result, err := api.Register(c, request)
			allowed = false
			return result, err
		})
	}
	guard := func(context.Context) error {
		if !allowed {
			return context.Canceled
		}
		return nil
	}
	if _, err := m.PrepareAutopilotInitial(context.Background(), policy, true, guard); !errors.Is(err, ErrAutomaticInitialChanged) || calls != 1 {
		t.Fatal("revocation did not reject the late registration result", err, calls)
	}
	profile, err := m.EngineConfigs.ReadExpert("warp-wg", "main")
	if err != nil || profile.Source != "missing" || m.Health().Policy != policy {
		t.Fatal("revoked preparation published a profile or changed health policy", profile.Source, err)
	}
}

func TestPrepareAutopilotInitialReusesLiveWithoutRegistrationConsent(t *testing.T) {
	m := newNativeTestManager(t)
	m.EngineConfigs.LiveRoot = filepath.Join(t.TempDir(), "live")
	policy := m.Health().Policy
	var calls int
	installNativeTestAPI(m, &calls, true, nil)
	guard := func(context.Context) error { return nil }
	profile, err := m.EngineConfigs.ReadExpert("warp-wg", "main")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(profile.Path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(profile.Path, []byte(validProfile), 0600); err != nil {
		t.Fatal(err)
	}
	result, err := m.PrepareAutopilotInitial(context.Background(), policy, false, guard)
	if err != nil || !result.OK || result.Source != "live" || calls != 0 || m.Health().Policy != policy {
		t.Fatal("a committed profile required new registration consent", result, err, calls)
	}
	if _, err := m.PrepareAutomaticInitial(context.Background(), policy, guard); !errors.Is(err, ErrAutomaticInitialConsent) {
		t.Fatal("reusing a profile altered the legacy health contract", err)
	}
	if _, err := m.EngineConfigs.Stage("warp-wg", "main", validProfile); err != nil {
		t.Fatal(err)
	}
	if _, err := m.PrepareAutopilotInitial(context.Background(), policy, false, guard); !errors.Is(err, ErrAutomaticInitialConsent) || calls != 0 {
		t.Fatal("an unrelated draft was treated as an approved live profile", err, calls)
	}
	staged, err := m.EngineConfigs.ReadExpert("warp-wg", "main")
	if err != nil || staged.Source != "staged" || staged.Content != validProfile {
		t.Fatal("an unrelated draft was changed", staged.Source, err)
	}
}

func TestPrepareAutomaticInitialPreservesConcurrentEditorDraft(t *testing.T) {
	ctx := context.Background()
	m := newNativeTestManager(t)
	policy := initialTestPolicy(t, m)
	var calls int
	installNativeTestAPI(m, &calls, true, nil)
	originalAPI := m.nativeAPI
	m.nativeAPI = func(checkpoint func([]byte) error) cloudflareprovider.RegistrationAPI {
		api := originalAPI(checkpoint)
		return nativeTestAPI(func(c context.Context, request cloudflareprovider.RegistrationRequest) (cloudflareprovider.RegistrationResponse, error) {
			if _, err := m.EngineConfigs.Stage("warp-wg", "main", validProfile); err != nil {
				return cloudflareprovider.RegistrationResponse{}, err
			}
			return api.Register(c, request)
		})
	}
	authorize := func(context.Context) error { return nil }
	if _, err := m.PrepareAutomaticInitial(ctx, policy, authorize); !errors.Is(err, ErrAutomaticInitialDraft) || calls != 1 {
		t.Fatalf("editor draft did not block publication: calls=%d err=%v", calls, err)
	}
	old, err := m.EngineConfigs.ReadExpert("warp-wg", "main")
	if err != nil || old.Source != "staged" || old.Content != validProfile {
		t.Fatalf("original editor draft lost: %v", err)
	}
	if _, err := m.PrepareAutomaticInitial(ctx, policy, authorize); !errors.Is(err, ErrAutomaticInitialDraft) || calls != 1 {
		t.Fatalf("recovering registration overwrote the draft or retried: calls=%d err=%v", calls, err)
	}
}

func TestPrepareAutomaticInitialGuardsRevocationAndUncertainPOST(t *testing.T) {
	m := newNativeTestManager(t)
	policy := initialTestPolicy(t, m)
	ctx := context.Background()
	var calls int
	installNativeTestAPI(m, &calls, false, context.DeadlineExceeded)
	if _, err := m.PrepareAutomaticInitial(ctx, policy, func(context.Context) error { return context.Canceled }); !errors.Is(err, ErrAutomaticInitialChanged) || calls != 0 {
		t.Fatalf("revoked scope reached registrar: calls=%d err=%v", calls, err)
	}
	authorize := func(context.Context) error { return nil }
	if _, err := m.PrepareAutomaticInitial(ctx, policy, authorize); !errors.Is(err, ErrEnrollmentPending) || calls != 1 {
		t.Fatalf("uncertain POST did not become pending: calls=%d err=%v", calls, err)
	}
	restarted := New(m.Root, m.BackupRoot, m.EngineConfigs)
	installNativeTestAPI(restarted, &calls, true, nil)
	if _, err := restarted.PrepareAutomaticInitial(ctx, policy, authorize); !errors.Is(err, ErrEnrollmentPending) || calls != 1 {
		t.Fatalf("uncertain POST was retried after restart: calls=%d err=%v", calls, err)
	}
}
