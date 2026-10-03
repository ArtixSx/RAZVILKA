package operationgate

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const controlTestID = "0123456789abcdef0123456789abcdef"
const controlOtherID = "fedcba9876543210fedcba9876543210"

func controlTestRoot(t *testing.T) string { t.Helper(); return filepath.Join(t.TempDir(), "authority") }

func TestSelfUpdateStopReadMissingCreatesNothing(t *testing.T) {
	path := controlTestRoot(t)
	if _, present, err := ReadSelfUpdateStop(context.Background(), path); err != nil || present {
		t.Fatal("missing readonly record", present, err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("read created directory", err)
	}
	if err := CheckSelfUpdateStop(context.Background(), path, controlTestID); !errors.Is(err, ErrSelfUpdateStopJournal) {
		t.Fatal("missing control authorized effect", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := InitializeSelfUpdateControl(ctx, path); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("canceled initialization created state", err)
	}
}

func TestSelfUpdateStopIndependentEpochPersistsAndNeverResets(t *testing.T) {
	ctx, path := context.Background(), controlTestRoot(t)
	ready, err := InitializeSelfUpdateControl(ctx, path)
	if err != nil || ready.Stopped || ready.Sequence != 1 {
		t.Fatal(ready, err)
	}
	starts := 0
	begin := func() error { starts++; return nil }
	if err = WithSelfUpdateEffectAdmission(ctx, path, controlTestID, ready.Sequence, "start-candidate-panel", begin); err != nil || starts != 1 {
		t.Fatal(starts, err)
	}
	if err = WithSelfUpdateEffectAdmission(ctx, path, controlTestID, ready.Sequence+1, "start-candidate-panel", begin); !errors.Is(err, ErrSelfUpdateStopChanged) || starts != 1 {
		t.Fatal("stale epoch admitted", starts, err)
	}
	stop, err := RequestSelfUpdateStop(ctx, path, controlTestID, 12)
	if err != nil || !stop.Stopped || stop.Sequence != 2 || stop.InstallationID != ready.InstallationID || stop.State != "requested" {
		t.Fatal(stop, err)
	}
	current := filepath.Join(path, selfControlCurrent)
	before, _ := os.ReadFile(current)
	again, err := RequestSelfUpdateStop(ctx, path, controlTestID, 12)
	after, _ := os.ReadFile(current)
	if err != nil || again != stop || !bytes.Equal(before, after) {
		t.Fatal("repeat changed revocation", again, err)
	}
	for _, id := range []string{controlTestID, controlOtherID} {
		if err = CheckSelfUpdateStop(ctx, path, id); !errors.Is(err, ErrSelfUpdateStopped) {
			t.Fatal("matching/other helper revived", id, err)
		}
		if err = WithSelfUpdateEffectAdmission(ctx, path, id, stop.Sequence, "start-rollback-panel", begin); !errors.Is(err, ErrSelfUpdateStopped) || starts != 1 {
			t.Fatal("Stop admitted new effect", starts, err)
		}
	}
	if _, err = InitializeSelfUpdateControl(ctx, path); !errors.Is(err, ErrSelfUpdateStopped) {
		t.Fatal("bootstrap cleared Stop", err)
	}
	if _, err = RequestSelfUpdateStop(ctx, path, controlOtherID, 12); !errors.Is(err, ErrSelfUpdateStopChanged) {
		t.Fatal("other ID overwrote Stop", err)
	}
	if _, err = RequestSelfUpdateStop(ctx, path, controlTestID, 13); !errors.Is(err, ErrSelfUpdateStopChanged) {
		t.Fatal("other revision overwrote Stop", err)
	}
	final, _ := os.ReadFile(current)
	if !bytes.Equal(before, final) {
		t.Fatal("refused request rewrote record")
	}
}

func TestSelfUpdateStopSerializesWithActualEffectBegin(t *testing.T) {
	path := controlTestRoot(t)
	ready, err := InitializeSelfUpdateControl(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		finished <- WithSelfUpdateEffectAdmission(context.Background(), path, controlTestID, ready.Sequence, "start-candidate-panel", func() error { close(entered); <-release; return nil })
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("begin not admitted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	stopped := make(chan error, 1)
	go func() { _, err := RequestSelfUpdateStop(ctx, path, controlTestID, 12); stopped <- err }()
	select {
	case err := <-stopped:
		t.Fatal("Stop ACK preceded admitted begin release", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if err := <-stopped; err != nil {
		t.Fatal(err)
	}
	late := false
	if err := WithSelfUpdateEffectAdmission(context.Background(), path, controlTestID, ready.Sequence, "late-child", func() error { late = true; return nil }); !errors.Is(err, ErrSelfUpdateStopped) || late {
		t.Fatal("late begin passed Stop admission", late, err)
	}
}

func TestSelfUpdateStopDoesNotBorrowInstallerGate(t *testing.T) {
	path := controlTestRoot(t)
	var gate Gate
	release, err := gate.Exclusive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, err := RequestSelfUpdateStop(ctx, path, controlTestID, 12)
	if err != nil || !r.Stopped || !gate.Snapshot().Exclusive {
		t.Fatal("Stop waited for installer admission or released it", r, err)
	}
}

func TestSelfUpdateStopInterruptedReceiptFencesAndMatchingRetrySettles(t *testing.T) {
	for _, boundary := range []string{"stop-current-durable", "stop-intent-durable"} {
		t.Run(boundary, func(t *testing.T) {
			path := controlTestRoot(t)
			_, err := InitializeSelfUpdateControl(context.Background(), path)
			if err != nil {
				t.Fatal(err)
			}
			fault := errors.New("interrupted durable boundary")
			if _, err = requestSelfUpdateStop(context.Background(), path, controlTestID, 12, func(at string) error {
				if at == boundary {
					return fault
				}
				return nil
			}); !errors.Is(err, fault) {
				t.Fatal("interruption not reported", err)
			}
			called := false
			if err = WithSelfUpdateEffectAdmission(context.Background(), path, controlOtherID, 1, "start-candidate-panel", func() error { called = true; return nil }); err == nil || called {
				t.Fatal("partial Stop authorized begin", err)
			}
			r, err := RequestSelfUpdateStop(context.Background(), path, controlTestID, 12)
			if err != nil || !r.Stopped || r.Sequence != 2 {
				t.Fatal("matching receipt retry failed or advanced epoch", r, err)
			}
			if read, present, err := ReadSelfUpdateStop(context.Background(), path); err != nil || !present || read != r {
				t.Fatal(read, present, err)
			}
		})
	}
}

func TestSelfUpdateStopCorruptUnknownAndIncompleteNeverAuthorize(t *testing.T) {
	for _, bad := range []string{"future-schema", "duplicate-field", "digest", "marker", "missing-current", "missing-request", "preexisting-empty"} {
		t.Run(bad, func(t *testing.T) {
			path := controlTestRoot(t)
			if bad == "preexisting-empty" {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := RequestSelfUpdateStop(context.Background(), path, controlTestID, 12); err != nil {
					t.Fatal(err)
				}
				current := filepath.Join(path, selfControlCurrent)
				raw, err := os.ReadFile(current)
				if err != nil {
					t.Fatal(err)
				}
				switch bad {
				case "future-schema":
					raw = bytes.Replace(raw, []byte(`"schema":1`), []byte(`"schema":2`), 1)
				case "duplicate-field":
					raw = append([]byte(`{"schema":1,`), raw[1:]...)
				case "digest":
					raw = bytes.Replace(raw, []byte(`"stopped":true`), []byte(`"stopped":false`), 1)
				case "marker":
					if err = os.WriteFile(filepath.Join(path, selfControlLock), []byte("foreign lock"), 0600); err != nil {
						t.Fatal(err)
					}
				case "missing-current":
					if err = os.Remove(current); err != nil {
						t.Fatal(err)
					}
				case "missing-request":
					if err = os.Remove(filepath.Join(path, "stop-"+controlTestID+".json")); err != nil {
						t.Fatal(err)
					}
				}
				if bad == "future-schema" || bad == "duplicate-field" || bad == "digest" {
					if err = os.WriteFile(current, raw, 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			if _, _, err := ReadSelfUpdateStop(context.Background(), path); !errors.Is(err, ErrSelfUpdateStopJournal) {
				t.Fatal("unknown reader outcome", err)
			}
			started := false
			if err := WithSelfUpdateEffectAdmission(context.Background(), path, controlTestID, 1, "start-candidate-panel", func() error { started = true; return nil }); err == nil || started {
				t.Fatal("unknown control admitted effect", err)
			}
			if _, err := InitializeSelfUpdateControl(context.Background(), path); err == nil {
				t.Fatal("bootstrap silently reset unknown authority")
			}
		})
	}
}

func TestSelfUpdateStopObservationNeedsTwoFreshOwnedChecks(t *testing.T) {
	path := controlTestRoot(t)
	stop, err := RequestSelfUpdateStop(context.Background(), path, controlTestID, 12)
	if err != nil {
		t.Fatal(err)
	}
	checks := 0
	if _, err = RecordSelfUpdateStopped(context.Background(), path, controlTestID, stop.Sequence, func(context.Context) error {
		checks++
		if checks == 2 {
			return errors.New("late owned process observed")
		}
		return nil
	}); err == nil {
		t.Fatal("failed second observation reported stopped")
	}
	r, present, err := ReadSelfUpdateStop(context.Background(), path)
	if err != nil || !present || r.State != "cleanup-unknown" || !r.Stopped {
		t.Fatal("failed observation stored positive confirmation", r, err)
	}
	checks = 0
	r, err = RecordSelfUpdateStopped(context.Background(), path, controlTestID, stop.Sequence, func(context.Context) error { checks++; return nil })
	if err != nil || r.State != "observed-stopped" || checks != 2 || !r.Stopped {
		t.Fatal(r, checks, err)
	}
	if err = CheckSelfUpdateStop(context.Background(), path, controlOtherID); !errors.Is(err, ErrSelfUpdateStopped) {
		t.Fatal("cleanup confirmation revived authority", err)
	}
	if _, err = RecordSelfUpdateStopped(context.Background(), path, controlOtherID, stop.Sequence, func(context.Context) error { return nil }); !errors.Is(err, ErrSelfUpdateStopChanged) {
		t.Fatal("observation not bound to request", err)
	}
}

func TestSelfUpdateStopStrictIdentityAndCallbackValidation(t *testing.T) {
	path := controlTestRoot(t)
	for _, id := range []string{"", strings.ToUpper(controlTestID), "../../outside", controlTestID + "x"} {
		if _, err := RequestSelfUpdateStop(context.Background(), path, id, 12); !errors.Is(err, ErrSelfUpdateStopChanged) {
			t.Fatal(id, err)
		}
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("invalid input created authority", err)
	}
	r, err := InitializeSelfUpdateControl(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	for _, effect := range []string{"", "Start", "start /tmp/foreign", strings.Repeat("a", 65)} {
		if err := WithSelfUpdateEffectAdmission(context.Background(), path, controlTestID, r.Sequence, effect, func() error { t.Fatal("bad effect invoked"); return nil }); !errors.Is(err, ErrSelfUpdateStopChanged) {
			t.Fatal(effect, err)
		}
	}
	if err := WithSelfUpdateEffectAdmission(context.Background(), path, controlTestID, r.Sequence, "start-candidate-panel", nil); !errors.Is(err, ErrSelfUpdateStopChanged) {
		t.Fatal(err)
	}
}

func TestSelfUpdateReadyMissingMarkerCannotBeRecreatedForAdmission(t *testing.T) {
	path := controlTestRoot(t)
	r, err := InitializeSelfUpdateControl(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(path, selfControlLock)
	if err = os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	called := false
	if err = WithSelfUpdateEffectAdmission(context.Background(), path, controlTestID, r.Sequence, "start-candidate-panel", func() error { called = true; return nil }); !errors.Is(err, ErrSelfUpdateStopJournal) || called {
		t.Fatal("missing marker restored effect authority", called, err)
	}
	if _, err = InitializeSelfUpdateControl(context.Background(), path); !errors.Is(err, ErrSelfUpdateStopJournal) {
		t.Fatal("initialization rebuilt missing marker", err)
	}
	if _, err = RequestSelfUpdateStop(context.Background(), path, controlTestID, 12); !errors.Is(err, ErrSelfUpdateStopJournal) {
		t.Fatal("Stop silently rebuilt incomplete established authority", err)
	}
	if _, err = os.Lstat(marker); !os.IsNotExist(err) {
		t.Fatal("missing marker was recreated", err)
	}
}
