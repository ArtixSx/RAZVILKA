package strategylab

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// These tests use acknowledged receipt data from the store model fixture.
// Native=true is modeled candidate data only: no process, NFQWS binary or Lua
// is executed and no test result establishes genuine compatibility.
func compatibilityPublicationCall(m *Manager, ctx context.Context, candidate Candidate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.publishCompatibilityValidationLocked(ctx, candidate)
}

func compatibilityPublicationAssertUnknown(t *testing.T, m *Manager, id string) {
	t.Helper()
	if !m.Snapshot().QuiescenceUnknown || !m.state.CompatibilityFinalizing {
		t.Fatal("live publication lost its retained unknown fence")
	}
	validation := m.state.Candidates[id].Validation
	if validation.OK || validation.Native || validation.LuaChecked {
		t.Fatalf("live unknown retained accepted modeled validation: %+v", validation)
	}
	reopened, err := New(m.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !reopened.Snapshot().QuiescenceUnknown || !reopened.state.CompatibilityFinalizing {
		t.Fatal("reopen accepted publication after authority loss")
	}
	validation = reopened.state.Candidates[id].Validation
	if validation.OK || validation.Native || validation.LuaChecked {
		t.Fatalf("durable unknown retained accepted modeled validation: %+v", validation)
	}
	if _, err := reopened.Validate(context.Background(), id); !errors.Is(err, ErrCompatibilityQuiescenceUnknown) {
		t.Fatalf("reopened unknown permitted another validation: %v", err)
	}
}

func TestCompatibilityPublicationAuthorityLossAtPreparedAndWritten(t *testing.T) {
	for _, stage := range []string{"prepared", "written"} {
		for _, cause := range []string{"deadline", "cancel", "stop"} {
			t.Run(stage+"/"+cause, func(t *testing.T) {
				m, provider, candidate, validation := compatibilityStoreFinalizationFixture(t, "lua-init", 0)
				candidate.Validation = validation
				before := compatibilityStoreBytes(t, m)
				ctx, cancel := context.WithCancel(context.Background())
				if cause == "deadline" {
					cancel()
					ctx, cancel = context.WithTimeout(context.Background(), time.Second)
				}
				defer cancel()
				entered, release := make(chan struct{}), make(chan struct{})
				var releaseOnce sync.Once
				unblock := func() { releaseOnce.Do(func() { close(release) }) }
				defer unblock()
				m.compatibilityPublicationHook = func(at string) {
					if at == stage {
						close(entered)
						<-release
					}
				}
				done := make(chan error, 1)
				go func() { done <- compatibilityPublicationCall(m, ctx, candidate) }()
				watchdog := time.NewTimer(5 * time.Second)
				defer watchdog.Stop()
				select {
				case <-entered:
				case err := <-done:
					t.Fatalf("publication returned before %s barrier: %v", stage, err)
				case <-watchdog.C:
					t.Fatalf("publication never reached %s barrier", stage)
				}
				switch cause {
				case "deadline":
					<-ctx.Done()
					if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
						t.Fatal(ctx.Err())
					}
				case "cancel":
					cancel()
				case "stop":
					stop, err := operationgate.RequestSelfUpdateStop(context.Background(), provider.review.ControlPath, strings.Repeat("e", 32), 1)
					if err != nil || !stop.Stopped || stop.Sequence <= provider.review.Sequence {
						t.Fatalf("isolated authority did not durably change epoch: %+v %v", stop, err)
					}
				}
				if stage == "prepared" && !bytes.Equal(before, compatibilityStoreBytes(t, m)) {
					t.Fatal("prepared barrier already published a cleared marker")
				}
				unblock()
				select {
				case err := <-done:
					if !errors.Is(err, ErrCompatibilityQuiescenceUnknown) {
						t.Fatalf("authority loss became an accepted result: %v", err)
					}
				case <-watchdog.C:
					t.Fatal("publication failed to finish bounded unknown repair")
				}
				if stage == "prepared" && !bytes.Equal(before, compatibilityStoreBytes(t, m)) {
					t.Fatal("refused prepared publication rewrote its durable crash fence")
				}
				compatibilityPublicationAssertUnknown(t, m, candidate.ID)
				if stage == "written" && (!m.state.CompatibilitySession.Unknown || !m.state.Candidates[candidate.ID].Validation.QuiescenceUnknown) {
					t.Fatal("post-write repair did not persist explicit invocation/candidate unknown")
				}
			})
		}
	}
}

func TestCompatibilityPublicationNormalAtomicModeledResult(t *testing.T) {
	for _, outcome := range []struct {
		name, phase string
		exit        int
	}{{"modeled-lua-pass", "lua-init", 0}, {"known-lua-rejection", "lua-init", 7}, {"known-dry-rejection", "dry-run", 7}} {
		t.Run(outcome.name, func(t *testing.T) {
			m, _, candidate, validation := compatibilityStoreFinalizationFixture(t, outcome.phase, outcome.exit)
			candidate.Validation = validation
			before := compatibilityStoreBytes(t, m)
			var stages []string
			m.compatibilityPublicationHook = func(stage string) {
				stages = append(stages, stage)
				if stage == "prepared" {
					if !m.state.CompatibilityFinalizing || m.state.Candidates[candidate.ID].Validation.Native || !bytes.Equal(before, compatibilityStoreBytes(t, m)) {
						t.Fatal("preparing the atomic image cleared the existing crash fence")
					}
				} else if stage == "written" {
					reopened, err := New(m.Path)
					if err != nil || reopened.state.CompatibilityFinalizing || !compatibilityJSONEqual(reopened.state.Candidates[candidate.ID].Validation, validation) {
						t.Fatalf("candidate and marker were not one atomic image: %v", err)
					}
				}
			}
			if err := compatibilityPublicationCall(m, context.Background(), candidate); err != nil {
				t.Fatal(err)
			}
			if !compatibilityJSONEqual(stages, []string{"prepared", "written"}) || m.state.CompatibilityFinalizing || m.Snapshot().QuiescenceUnknown || !bytes.Equal(m.image.Data, compatibilityStoreBytes(t, m)) {
				t.Fatal("normal modeled publication did not finish exact known image")
			}
			reopened, err := New(m.Path)
			if err != nil || reopened.Snapshot().QuiescenceUnknown || !compatibilityJSONEqual(reopened.state.Candidates[candidate.ID].Validation, validation) {
				t.Fatalf("normal modeled result did not survive restart: %v", err)
			}
		})
	}
}

func TestCompatibilityPublicationStaleCASRetainsIndependentCrashFence(t *testing.T) {
	m, _, candidate, validation := compatibilityStoreFinalizationFixture(t, "lua-init", 0)
	candidate.Validation = validation
	independent, err := decodeCompatibilityState(m.image)
	if err != nil {
		t.Fatal(err)
	}
	other := independent.Candidates[candidate.ID]
	other.Name = "independent update before publication acquired its lease"
	independent.Candidates[candidate.ID] = other
	// The external writer runs before publisher OpenFileTarget. Once the
	// prepared barrier owns that lease, a second CAS writer cannot acquire it.
	changed := compatibilityStoreRawState(t, m, independent)
	err = compatibilityPublicationCall(m, context.Background(), candidate)
	if !errors.Is(err, ErrCompatibilityQuiescenceUnknown) || !errors.Is(err, restorejournal.ErrConflict) || !m.writeBlocked || !bytes.Equal(changed.Data, compatibilityStoreBytes(t, m)) {
		t.Fatalf("stale publication overwrote independent protected state: %v", err)
	}
	compatibilityPublicationAssertUnknown(t, m, candidate.ID)
	reopened, err := New(m.Path)
	if err != nil || reopened.state.Candidates[candidate.ID].Name != other.Name {
		t.Fatalf("independent candidate data was discarded: %v", err)
	}
}
