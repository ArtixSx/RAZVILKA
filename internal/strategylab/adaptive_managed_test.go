package strategylab

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

type adaptiveFoundationValidatorFunc func(context.Context, []string) Validation

func (f adaptiveFoundationValidatorFunc) Validate(ctx context.Context, args []string) Validation {
	return f(ctx, args)
}

type adaptiveFoundationExecutor struct{ calls int }

func (x *adaptiveFoundationExecutor) Execute(context.Context, Candidate, ProbeTarget) (Evidence, error) {
	x.calls++
	return Evidence{}, errors.New("modeled executor must not be adopted")
}

func adaptiveFoundationFixture(t *testing.T) (*Manager, *managerAdaptiveFoundation, Candidate, adaptiveCandidateBinding) {
	t.Helper()
	m, err := New(filepath.Join(t.TempDir(), "strategy-lab.json"))
	if err != nil {
		t.Fatal(err)
	}
	m.Now = func() time.Time { return time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC) }
	candidate, err := m.AddCandidate("tcp-tls", "bound candidate", "--filter-tcp=443 --lua-desync=fake:blob=0x00000000", "expert")
	if err != nil {
		t.Fatal(err)
	}
	foundation, err := newManagerAdaptiveFoundation(m)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := foundation.bind(adaptiveCandidateDetached(candidate))
	if err != nil {
		t.Fatal(err)
	}
	return m, foundation, candidate, binding
}

// Configuration-shape model only: these paths have no launch files/control
// authority. Tests never invoke this provider or synthesize compatibility PASS.
func adaptiveFoundationOwnedConfig(t *testing.T, m *Manager) CompatibleValidator {
	t.Helper()
	review := compatibilityRecordFixture(t).DryRun.Command.Review
	provider := &SupervisedCompatibilityProvider{manager: m, review: review}
	return CompatibleValidator{Binary: review.Binary.Path, BaseArguments: slices.Clone(review.BaseArguments), TrustedAssets: true, Provider: provider}
}

func adaptiveFoundationBytes(t *testing.T, m *Manager) []byte {
	t.Helper()
	data, err := os.ReadFile(m.Path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestAdaptiveFoundationBindsExactIdentityWithEqualArguments(t *testing.T) {
	m, foundation, first, firstBinding := adaptiveFoundationFixture(t)
	second, err := m.AddCandidate(first.PoolID, "other identity", first.Arguments, "migration:z2k")
	if err != nil {
		t.Fatal(err)
	}
	secondBinding, err := foundation.bind(second)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID == second.ID || firstBinding.candidate.ID != first.ID || secondBinding.candidate.ID != second.ID || secondBinding.candidate.Origin != second.Origin {
		t.Fatal("equal argv collapsed exact candidate/provenance bindings")
	}
	for _, change := range []struct {
		name string
		edit func(*Candidate)
	}{
		{"id", func(c *Candidate) { c.ID = second.ID }},
		{"pool", func(c *Candidate) { c.PoolID = "http" }},
		{"name", func(c *Candidate) { c.Name += " changed" }},
		{"arguments", func(c *Candidate) { c.Arguments += " --filter-tcp=8443" }},
		{"origin", func(c *Candidate) { c.Origin = "another owner" }},
		{"created-at", func(c *Candidate) { c.CreatedAt = "2026-10-04T12:01:00Z" }},
	} {
		t.Run(change.name, func(t *testing.T) {
			expected := adaptiveCandidateDetached(first)
			change.edit(&expected)
			if _, err := foundation.bind(expected); !errors.Is(err, errAdaptiveCandidateChanged) {
				t.Fatalf("changed identity admitted: %v", err)
			}
		})
	}
	// Validation is deliberately outside the immutable definition/provenance.
	expected := adaptiveCandidateDetached(first)
	expected.Validation = Validation{Code: "older modeled rejection"}
	if _, err := foundation.bind(expected); err != nil {
		t.Fatal("non-identity validation difference rejected", err)
	}
	if _, err := foundation.validateBound(context.Background(), firstBinding); !errors.Is(err, errAdaptiveManagedValidator) {
		t.Fatal("default legacy validator admitted for first bound ID", err)
	}
	if _, err := foundation.validateBound(context.Background(), secondBinding); !errors.Is(err, errAdaptiveManagedValidator) {
		t.Fatal("default legacy validator admitted for second bound ID", err)
	}
}

func TestAdaptiveFoundationRefusesRemovedReboundAndForeignBindings(t *testing.T) {
	for _, mutation := range []string{"removed", "rebound", "other-manager"} {
		t.Run(mutation, func(t *testing.T) {
			m, foundation, candidate, binding := adaptiveFoundationFixture(t)
			calls := 0
			m.Validator = adaptiveFoundationValidatorFunc(func(context.Context, []string) Validation {
				calls++
				return Validation{Code: "MODELED_REJECTED"}
			})
			switch mutation {
			case "removed":
				if err := m.DeleteCandidate(candidate.ID); err != nil {
					t.Fatal(err)
				}
			case "rebound":
				rebound, err := m.AddCandidate(candidate.PoolID, candidate.Name, candidate.Arguments, "changed provenance")
				if err != nil || rebound.ID != candidate.ID {
					t.Fatal("fixture did not rebind ID", err)
				}
			case "other-manager":
				other, err := New(m.Path)
				if err != nil {
					t.Fatal(err)
				}
				foundation, err = newManagerAdaptiveFoundation(other)
				if err != nil {
					t.Fatal(err)
				}
			}
			before := adaptiveFoundationBytes(t, m)
			if _, err := foundation.validateBound(context.Background(), binding); !errors.Is(err, errAdaptiveCandidateChanged) {
				t.Fatalf("stale/foreign binding admitted: %v", err)
			}
			if calls != 0 || m.nativeRunning || !bytes.Equal(before, adaptiveFoundationBytes(t, m)) {
				t.Fatal("refused binding entered validation or rewrote state")
			}
		})
	}
}

func TestAdaptiveFoundationRefusesPackMembershipInference(t *testing.T) {
	for _, receipt := range []bool{false, true} {
		t.Run(map[bool]string{false: "no-receipt", true: "whole-payload-receipt"}[receipt], func(t *testing.T) {
			m, foundation, candidate, _ := adaptiveFoundationFixture(t)
			candidate.Origin = "pack:publisher:pack-id"
			m.state.Candidates[candidate.ID] = candidate
			if receipt {
				m.state.PackReceipts = map[string]PackReceipt{"publisher:pack-id": {Sequence: 3, SHA256: strings.Repeat("a", 64)}}
			}
			before := adaptiveFoundationBytes(t, m)
			if _, err := foundation.bind(candidate); !errors.Is(err, errAdaptivePackBinding) {
				t.Fatal("whole payload hash became candidate membership authority", err)
			}
			if !bytes.Equal(before, adaptiveFoundationBytes(t, m)) {
				t.Fatal("binding rewrote receipts")
			}
		})
	}
}

func TestAdaptiveFoundationRequiresExactConcreteValidator(t *testing.T) {
	cases := []struct {
		name      string
		configure func(*Manager, CompatibleValidator) Validator
	}{
		{"nil", func(*Manager, CompatibleValidator) Validator { return nil }},
		{"exec-value", func(*Manager, CompatibleValidator) Validator { return ExecValidator{} }},
		{"exec-pointer", func(*Manager, CompatibleValidator) Validator { return &ExecValidator{} }},
		{"compatible-typed-nil", func(*Manager, CompatibleValidator) Validator { return (*CompatibleValidator)(nil) }},
		{"missing-provider", func(_ *Manager, v CompatibleValidator) Validator { v.Provider = nil; return v }},
		{"direct-process", func(_ *Manager, v CompatibleValidator) Validator {
			v.Provider = &CompatibilityProcessProvider{}
			return v
		}},
		{"supervised-typed-nil", func(_ *Manager, v CompatibleValidator) Validator {
			v.Provider = (*SupervisedCompatibilityProvider)(nil)
			return v
		}},
		{"foreign-manager", func(_ *Manager, v CompatibleValidator) Validator {
			p := v.Provider.(*SupervisedCompatibilityProvider)
			p.manager = &Manager{}
			return v
		}},
		{"binary-different", func(_ *Manager, v CompatibleValidator) Validator { v.Binary += "-different"; return v }},
		{"base-absent", func(_ *Manager, v CompatibleValidator) Validator { v.BaseArguments = nil; return v }},
		{"base-reordered", func(_ *Manager, v CompatibleValidator) Validator {
			v.BaseArguments[0], v.BaseArguments[1] = v.BaseArguments[1], v.BaseArguments[0]
			return v
		}},
		{"untrusted-assets", func(_ *Manager, v CompatibleValidator) Validator { v.TrustedAssets = false; return v }},
		{"invalid-review", func(_ *Manager, v CompatibleValidator) Validator {
			v.Provider.(*SupervisedCompatibilityProvider).review.Binary.SHA256 = "not-a-digest"
			return v
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, foundation, candidate, binding := adaptiveFoundationFixture(t)
			m.Validator = tc.configure(m, adaptiveFoundationOwnedConfig(t, m))
			before := adaptiveFoundationBytes(t, m)
			if _, err := foundation.validateBound(context.Background(), binding); !errors.Is(err, errAdaptiveManagedValidator) {
				t.Fatalf("unsupported validator admitted: %v", err)
			}
			if m.nativeRunning || !compatibilityJSONEqual(m.state.Candidates[candidate.ID], candidate) || !bytes.Equal(before, adaptiveFoundationBytes(t, m)) {
				t.Fatal("validator refusal admitted work or changed candidate")
			}
		})
	}
	for _, kind := range []string{"custom-validator", "custom-provider"} {
		t.Run(kind, func(t *testing.T) {
			m, foundation, _, binding := adaptiveFoundationFixture(t)
			calls := 0
			if kind == "custom-validator" {
				m.Validator = adaptiveFoundationValidatorFunc(func(context.Context, []string) Validation { calls++; return Validation{Code: "MODELED_REJECTED"} })
			} else {
				v := adaptiveFoundationOwnedConfig(t, m)
				v.Provider = compatibilityProviderFunc(func(context.Context, string, ...string) (CompatibilityCompletion, error) {
					calls++
					return CompatibilityCompletion{}, errors.New("must not run")
				})
				m.Validator = v
			}
			if _, err := foundation.validateBound(context.Background(), binding); !errors.Is(err, errAdaptiveManagedValidator) || calls != 0 || m.nativeRunning {
				t.Fatalf("custom interface created validation authority: calls=%d err=%v", calls, err)
			}
		})
	}
}

func TestAdaptiveFoundationConcreteConfigurationCheckDetachesBase(t *testing.T) {
	for _, pointer := range []bool{false, true} {
		t.Run(map[bool]string{false: "value", true: "pointer"}[pointer], func(t *testing.T) {
			m, _, _, _ := adaptiveFoundationFixture(t)
			v := adaptiveFoundationOwnedConfig(t, m)
			if pointer {
				m.Validator = &v
			} else {
				m.Validator = v
			}
			m.mu.Lock()
			checked, err := adaptiveManagedValidatorLocked(m)
			m.mu.Unlock()
			if err != nil {
				t.Fatal("configuration shape rejected", err)
			}
			// Checking structure is not a launch or an owned quiescence proof.
			copy := checked.(CompatibleValidator)
			copy.BaseArguments[0] = "changed copy"
			if v.BaseArguments[0] == "changed copy" || v.Provider.(*SupervisedCompatibilityProvider).review.BaseArguments[0] == "changed copy" || m.nativeRunning {
				t.Fatal("configuration check shared mutable base or admitted work")
			}
		})
	}
}

func TestAdaptiveFoundationCancelledContextDoesNotAdmit(t *testing.T) {
	for _, kind := range []string{"cancelled", "deadline", "nil"} {
		t.Run(kind, func(t *testing.T) {
			m, foundation, candidate, binding := adaptiveFoundationFixture(t)
			m.Validator = adaptiveFoundationOwnedConfig(t, m)
			before := adaptiveFoundationBytes(t, m)
			var ctx context.Context
			var expected error
			switch kind {
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(context.Background())
				cancel()
				expected = context.Canceled
			case "deadline":
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(context.Background(), time.Unix(1, 0))
				defer cancel()
				expected = context.DeadlineExceeded
			}
			_, err := foundation.validateBound(ctx, binding)
			if err == nil || (expected != nil && !errors.Is(err, expected)) {
				t.Fatal("context refusal missing", err)
			}
			if m.nativeRunning || !bytes.Equal(before, adaptiveFoundationBytes(t, m)) || !compatibilityJSONEqual(m.state.Candidates[candidate.ID], candidate) {
				t.Fatal("closed context admitted work or wrote result")
			}
		})
	}
}

func TestAdaptiveFoundationGlobalUnknownFencesOldAndNewBindings(t *testing.T) {
	for _, kind := range []string{"private-sticky", "schema2", "foreign-candidate", "finalizing", "session-unknown", "write-blocked"} {
		t.Run(kind, func(t *testing.T) {
			m, foundation, candidate, binding := adaptiveFoundationFixture(t)
			calls := 0
			m.Validator = adaptiveFoundationValidatorFunc(func(context.Context, []string) Validation { calls++; return Validation{Code: "MODELED_REJECTED"} })
			switch kind {
			case "private-sticky":
				m.compatibilityUnknown = true
			case "schema2":
				m.state.SchemaVersion = compatibilityUnknownSchema
			case "foreign-candidate":
				m.state.Candidates["other"] = Candidate{ID: "other", Validation: Validation{QuiescenceUnknown: true}}
			case "finalizing":
				m.state.CompatibilityFinalizing = true
			case "session-unknown":
				session := compatibilityRecordFixture(t)
				session.Unknown = true
				m.state.CompatibilitySession = &session
			case "write-blocked":
				m.writeBlocked = true
			}
			before := adaptiveFoundationBytes(t, m)
			if _, err := newManagerAdaptiveFoundation(m); !errors.Is(err, ErrCompatibilityQuiescenceUnknown) {
				t.Fatal("fresh foundation cleared fence", err)
			}
			if _, err := foundation.bind(candidate); !errors.Is(err, ErrCompatibilityQuiescenceUnknown) {
				t.Fatal("fresh binding cleared fence", err)
			}
			if _, err := foundation.validateBound(context.Background(), binding); !errors.Is(err, ErrCompatibilityQuiescenceUnknown) {
				t.Fatal("old binding cleared fence", err)
			}
			if calls != 0 || m.nativeRunning || !bytes.Equal(before, adaptiveFoundationBytes(t, m)) {
				t.Fatal("fenced call admitted or rewrote state")
			}
		})
	}
	m, foundation, candidate, _ := adaptiveFoundationFixture(t)
	candidate.Validation.QuiescenceUnknown = true
	if _, err := foundation.bind(candidate); !errors.Is(err, ErrCompatibilityQuiescenceUnknown) || m.nativeRunning {
		t.Fatal("caller-retained unknown ignored", err)
	}
}

func TestAdaptiveFoundationNeverAdoptsProbeExecutorsOrEvidence(t *testing.T) {
	for _, kind := range []string{"stock", "custom"} {
		t.Run(kind, func(t *testing.T) {
			m, foundation, candidate, binding := adaptiveFoundationFixture(t)
			stock := &SystemProbeExecutor{}
			custom := &adaptiveFoundationExecutor{}
			if kind == "stock" {
				m.Executor = stock
			} else {
				m.Executor = custom
			}
			m.state.Evidence = []Evidence{{CandidateID: candidate.ID, ServiceID: "preserved", Stages: []StageEvidence{{Stage: "modeled", Status: "rejected"}}}}
			m.state.Selections["preserved"] = Selection{CandidateID: candidate.ID, Status: "modeled rejected"}
			evidence, selections := m.state.Evidence, m.state.Selections
			if _, err := foundation.bind(candidate); err != nil {
				t.Fatal(err)
			}
			if _, err := foundation.validateBound(context.Background(), binding); !errors.Is(err, errAdaptiveManagedValidator) {
				t.Fatal(err)
			}
			if stock.gate != nil || custom.calls != 0 || !compatibilityJSONEqual(evidence, m.state.Evidence) || !compatibilityJSONEqual(selections, m.state.Selections) {
				t.Fatal("validation foundation adopted a probe or changed evidence")
			}
		})
	}
}

func TestAdaptiveFoundationLegacyValidationPreservesIdentityDuringWork(t *testing.T) {
	for _, mutation := range []string{"removed", "rebound"} {
		t.Run(mutation, func(t *testing.T) {
			m, foundation, candidate, binding := adaptiveFoundationFixture(t)
			entered, release := make(chan struct{}), make(chan struct{})
			m.Validator = adaptiveFoundationValidatorFunc(func(context.Context, []string) Validation {
				close(entered)
				<-release
				return Validation{Code: "MODELED_REJECTED"}
			})
			done := make(chan error, 1)
			go func() { _, err := m.Validate(context.Background(), candidate.ID); done <- err }()
			<-entered
			if _, err := foundation.validateBound(context.Background(), binding); !errors.Is(err, errCompatibilityBusy) {
				t.Fatal("shared admission ignored busy validation", err)
			}
			if mutation == "removed" {
				if err := m.DeleteCandidate(candidate.ID); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := m.AddCandidate(candidate.PoolID, candidate.Name, candidate.Arguments, "new provenance"); err != nil {
					t.Fatal(err)
				}
				m.mu.Lock()
				current := m.state.Candidates[candidate.ID]
				current.Validation = Validation{Code: "NEWER_MODELED_REJECTION", Arguments: []string{"newer detached data"}}
				m.state.Candidates[candidate.ID] = current
				err := m.saveLocked()
				m.mu.Unlock()
				if err != nil {
					t.Fatal(err)
				}
			}
			before := adaptiveFoundationBytes(t, m)
			close(release)
			if err := <-done; !errors.Is(err, errAdaptiveCandidateChanged) || errors.Is(err, ErrCompatibilityQuiescenceUnknown) {
				t.Fatal("settled mismatch became uncertainty or overwrote identity", err)
			}
			if m.nativeRunning || m.Snapshot().QuiescenceUnknown || !bytes.Equal(before, adaptiveFoundationBytes(t, m)) {
				t.Fatal("settled mismatch changed durable state or fence")
			}
		})
	}
}

func TestAdaptiveFoundationUnknownPersistsAfterDeletedOrReboundCandidate(t *testing.T) {
	for _, schema := range []string{"schema1", "finalized-schema3"} {
		for _, mutation := range []string{"removed", "rebound"} {
			t.Run(schema+"/"+mutation, func(t *testing.T) {
				m, _, candidate, _ := adaptiveFoundationFixture(t)
				var historical compatibilitySession
				if schema == "finalized-schema3" {
					historical = compatibilityRecordFixture(t)
					// Historical acknowledged rejection, not mocked compatibility PASS.
					compatibilityRecordReceipt(historical.DryRun, "reaped", true, 7)
					m.mu.Lock()
					m.state.SchemaVersion = compatibilitySupervisedSchema
					m.state.CompatibilitySession = &historical
					err := m.saveLocked()
					m.mu.Unlock()
					if err != nil || m.Snapshot().QuiescenceUnknown {
						t.Fatal("known historical session fixture failed", err)
					}
				}
				entered, release := make(chan struct{}), make(chan struct{})
				m.Validator = adaptiveFoundationValidatorFunc(func(context.Context, []string) Validation {
					close(entered)
					<-release
					return Validation{QuiescenceUnknown: true, Code: "MODELED_UNKNOWN"}
				})
				done := make(chan error, 1)
				go func() { _, err := m.Validate(context.Background(), candidate.ID); done <- err }()
				<-entered
				if mutation == "removed" {
					if err := m.DeleteCandidate(candidate.ID); err != nil {
						t.Fatal(err)
					}
				} else {
					if _, err := m.AddCandidate(candidate.PoolID, candidate.Name, candidate.Arguments, "new provenance"); err != nil {
						t.Fatal(err)
					}
					m.mu.Lock()
					current := m.state.Candidates[candidate.ID]
					current.Validation = Validation{Code: "NEWER_MODELED_REJECTION", Arguments: []string{"preserve newer data"}}
					m.state.Candidates[candidate.ID] = current
					err := m.saveLocked()
					m.mu.Unlock()
					if err != nil {
						t.Fatal(err)
					}
				}
				m.mu.RLock()
				newer, exists := m.state.Candidates[candidate.ID]
				m.mu.RUnlock()
				close(release)
				if err := <-done; !errors.Is(err, ErrCompatibilityQuiescenceUnknown) || !errors.Is(err, errAdaptiveCandidateChanged) {
					t.Fatal("unknown identity mismatch lost errors", err)
				}
				reopened, err := New(m.Path)
				if err != nil || !reopened.Snapshot().QuiescenceUnknown || m.nativeRunning {
					t.Fatal("reopen cleared retained unknown", err)
				}
				got, gotExists := reopened.state.Candidates[candidate.ID]
				if gotExists != exists || (exists && !compatibilityJSONEqual(got, newer)) {
					t.Fatal("retention restored deleted/old candidate or replaced newer validation")
				}
				if _, err := newManagerAdaptiveFoundation(reopened); !errors.Is(err, ErrCompatibilityQuiescenceUnknown) {
					t.Fatal("new foundation cleared durable unknown", err)
				}
				if schema == "finalized-schema3" {
					if reopened.state.SchemaVersion != compatibilitySupervisedSchema || !reopened.state.CompatibilityFinalizing || !reopened.state.CompatibilitySession.Unknown {
						t.Fatal("schema 3 did not retain existing-session fence")
					}
					actual := *reopened.state.CompatibilitySession
					actual.Unknown = false
					if !compatibilityJSONEqual(actual, historical) {
						t.Fatal("unknown retention changed historical command/receipt")
					}
				} else if reopened.state.SchemaVersion != compatibilityUnknownSchema {
					t.Fatal("legacy unknown did not persist schema 2 fence")
				}
			})
		}
	}
}

func TestAdaptiveFoundationUnknownRetentionDoesNotOverwriteForeignImage(t *testing.T) {
	m, _, candidate, _ := adaptiveFoundationFixture(t)
	session := compatibilityRecordFixture(t)
	compatibilityRecordReceipt(session.DryRun, "reaped", true, 7)
	m.mu.Lock()
	m.state.SchemaVersion = compatibilitySupervisedSchema
	m.state.CompatibilitySession = &session
	err := m.saveLocked()
	m.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	m.Validator = adaptiveFoundationValidatorFunc(func(context.Context, []string) Validation {
		close(entered)
		<-release
		return Validation{QuiescenceUnknown: true, Code: "MODELED_UNKNOWN"}
	})
	done := make(chan error, 1)
	go func() { _, err := m.Validate(context.Background(), candidate.ID); done <- err }()
	<-entered
	if err := m.DeleteCandidate(candidate.ID); err != nil {
		t.Fatal(err)
	}
	foreign, err := New(m.Path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := foreign.AddCandidate("http", "foreign draft", "--filter-tcp=80", "foreign writer"); err != nil {
		t.Fatal(err)
	}
	foreignBytes := adaptiveFoundationBytes(t, foreign)
	close(release)
	err = <-done
	if !errors.Is(err, ErrCompatibilityQuiescenceUnknown) || !errors.Is(err, restorejournal.ErrConflict) || !m.writeBlocked || !m.Snapshot().QuiescenceUnknown || m.nativeRunning {
		t.Fatal("uncertain retention did not latch recovery fence", err)
	}
	if !bytes.Equal(foreignBytes, adaptiveFoundationBytes(t, foreign)) {
		t.Fatal("retention overwrote foreign exact image")
	}
}

func TestAdaptiveFoundationValidationSlicesAreDetached(t *testing.T) {
	m, foundation, candidate, binding := adaptiveFoundationFixture(t)
	candidate.Validation.Arguments = slices.Clone(candidate.Validation.Arguments)
	candidate.Validation.Arguments[0] = "caller changed"
	if binding.candidate.Validation.Arguments[0] == "caller changed" {
		t.Fatal("binding retained caller slice")
	}
	binding.candidate.Validation.Arguments[0] = "binding changed"
	if m.state.Candidates[candidate.ID].Validation.Arguments[0] == "binding changed" {
		t.Fatal("binding retained Manager slice")
	}
	var retained []string
	m.Validator = adaptiveFoundationValidatorFunc(func(_ context.Context, args []string) Validation {
		retained = args
		args[0] = "validator changed"
		return Validation{Code: "MODELED_REJECTED", Arguments: args}
	})
	validated, err := m.Validate(context.Background(), candidate.ID)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := parseArguments(candidate.Arguments)
	if err != nil || !slices.Equal(validated.Validation.Arguments, canonical) {
		t.Fatal("validator altered authoritative parsed argv", err)
	}
	retained[0] = "later validator mutation"
	validated.Validation.Arguments[0] = "returned candidate changed"
	if !slices.Equal(m.state.Candidates[candidate.ID].Validation.Arguments, canonical) {
		t.Fatal("stored validation shared returned/validator slice")
	}
	if _, err := foundation.bind(adaptiveCandidateDetached(m.state.Candidates[candidate.ID])); err != nil {
		t.Fatal("validation update changed identity", err)
	}
}

func TestAdaptiveFoundationNilObjectsRefuse(t *testing.T) {
	if _, err := newManagerAdaptiveFoundation(nil); err == nil {
		t.Fatal("nil Manager accepted")
	}
	var foundation *managerAdaptiveFoundation
	if _, err := foundation.bind(Candidate{}); !errors.Is(err, errAdaptiveCandidateChanged) {
		t.Fatal(err)
	}
	if _, err := foundation.validateBound(context.Background(), adaptiveCandidateBinding{}); !errors.Is(err, errAdaptiveCandidateChanged) {
		t.Fatal(err)
	}
}
