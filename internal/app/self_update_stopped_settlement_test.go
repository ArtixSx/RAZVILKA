package app

import (
	"bytes"
	"context"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

type stoppedSettlementTraceKey struct{}

type helperStopSettlementProof struct {
	*stoppedSettlementProof
	control string
	mode    string
}

func (p *helperStopSettlementProof) Run(ctx context.Context, id, command string) error {
	if p.mode == "after-start-intent" && command == "start-rollback-panel" {
		stop, err := operationgate.RequestSelfUpdateStop(ctx, p.control, id, p.revision)
		p.stop = stop
		return errors.Join(operationgate.ErrSelfUpdateStopped, err)
	}
	if err := p.fileUpdateProof.Run(ctx, id, command); err != nil {
		return err
	}
	if command == "restore-private-state" && p.mode != "after-start-intent" {
		actualID, revision := id, p.revision
		if p.mode == "wrong-job" {
			actualID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		}
		if p.mode == "wrong-revision" {
			revision++
		}
		stop, err := operationgate.RequestSelfUpdateStop(ctx, p.control, actualID, revision)
		p.stop = stop
		return err
	}
	return nil
}

// Actual control and file journal, model process provider. Native tests own
// the real H/S Wait, missing ledger and runtime observer proof separately.
func TestSelfUpdateOriginalHelperSettlesOnlyExactStopBeforeRollbackIntent(t *testing.T) {
	for _, mode := range []string{"matching", "wrong-job", "wrong-revision", "independent-guard", "after-start-intent"} {
		t.Run(mode, func(t *testing.T) {
			a, file := fileUpdateHTTPFixture(t)
			fileUpdateEnableControl(t, a)
			cause := errors.New("candidate did not pass live acceptance")
			file.liveError = cause
			base := &stoppedSettlementProof{fileUpdateProof: file, installation: a.SelfUpdateFiles.Installation, directory: a.SelfUpdateFiles.Directory, eligible: true}
			p := &helperStopSettlementProof{stoppedSettlementProof: base, control: a.SelfUpdateFiles.ControlRoot, mode: mode}
			a.SelfUpdateFiles.Adapter = p
			a.SelfUpdateFiles.JournalReadGuard = func(c context.Context, reader int) error {
				p.readerCalls++
				if reader != 3 || c.Value(stoppedSettlementTraceKey{}) != "original-provider-context" {
					return errSelfUpdateRecovery
				}
				return c.Err()
			}
			guard := func(context.Context) error {
				if mode == "independent-guard" && p.stop.Stopped {
					return errors.New("independent recovery fence")
				}
				return nil
			}
			err := a.SelfUpdateFiles.RunHelper(context.Background(), fileUpdateID, guard)
			if err == nil || !errors.Is(err, cause) {
				t.Fatal("stopped rollback reported live upgrade success", err)
			}
			r, present, readErr := a.SelfUpdateFiles.Current()
			if readErr != nil || !present {
				t.Fatal(readErr)
			}
			if mode == "matching" {
				if p.calls != 1 || p.readerCalls == 0 || r.Phase != "rolled-back-stopped" || r.Schema != selfupdatejournal.StoppedSchema {
					t.Fatal("matching original helper did not settle", p.calls, p.readerCalls, r.Phase)
				}
				stop, present, err := operationgate.ReadSelfUpdateStop(context.Background(), p.control)
				if err != nil || !present || stop != p.stop {
					t.Fatal("settlement changed exact Stop", err)
				}
			} else if p.calls != 0 || r.Phase == "rolled-back-stopped" {
				t.Fatal("unrelated/unknown failure reached settlement", mode, p.calls, r.Phase)
			}
			if mode == "after-start-intent" && (r.Phase != "command-started" || r.Command != "start-rollback-panel") {
				t.Fatal("unknown start intent was cleared", r.Phase, r.Command)
			}
			if len(p.finishes) != 0 || len(p.lives) != 1 || p.lives[0] {
				t.Fatal("Stop reached rollback live acceptance", p.lives, p.finishes)
			}
		})
	}
}

// Actual HTTP/auth/config/file journal; the optional provider below models
// only supervised process/private/runtime evidence. It is not native D11 PASS.
type stoppedSettlementProof struct {
	*fileUpdateProof
	installation, directory string
	stop                    operationgate.SelfUpdateStop
	eligible                bool
	calls                   int
	readerCalls             int
	cut                     bool
	inactiveError           error
	before                  func(context.Context, updatecheck.SelfUpdateStoppedSettlementAuthority) error
}

func (p *stoppedSettlementProof) StoppedSettlementEligibility(context.Context, string) (bool, error) {
	return p.eligible, nil
}

func (p *stoppedSettlementProof) SettleStoppedRollback(ctx context.Context, id string, authority updatecheck.SelfUpdateStoppedSettlementAuthority) error {
	p.calls++
	ctx = context.WithValue(ctx, stoppedSettlementTraceKey{}, "original-provider-context")
	if p.before != nil {
		if err := p.before(ctx, authority); err != nil {
			return err
		}
	}
	store, err := selfupdatejournal.Open(p.installation, p.directory)
	if err != nil {
		return err
	}
	defer store.Close()
	check := func(c context.Context) error {
		return authority.Check(c, id, p.stop.InstallationID, p.stop.Sequence-1, p.revision)
	}
	readers := func(c context.Context) error { return authority.AdmitReaders(c, id, 3) }
	inactive := func(context.Context) error { return p.inactiveError }
	binding := selfupdatejournal.StoppedBinding{InstallationID: p.stop.InstallationID, PreStopSequence: p.stop.Sequence - 1, StopSequence: p.stop.Sequence, Revision: p.revision, RequiredReader: 3}
	if err := store.SettleStoppedRollback(ctx, id, binding, check, readers, inactive); err != nil {
		return err
	}
	if p.cut {
		p.cut = false
		return errors.New("model helper publication interrupted after file terminal")
	}
	return nil
}

func stoppedSettlementFixture(t *testing.T) (*App, *stoppedSettlementProof) {
	t.Helper()
	a, file := fileUpdateHTTPFixture(t)
	fileUpdateEnableControl(t, a)
	for _, action := range []string{"prepare", "stop-old-panel", "prepare-private-state", "quiesce-old-runtime", "install", "restore", "restore-private-state"} {
		if err := fileUpdateAction(t, a, action); err != nil {
			t.Fatal(action, err)
		}
	}
	stop, err := operationgate.RequestSelfUpdateStop(context.Background(), a.SelfUpdateFiles.ControlRoot, fileUpdateID, file.revision)
	if err != nil {
		t.Fatal(err)
	}
	p := &stoppedSettlementProof{fileUpdateProof: file, installation: a.SelfUpdateFiles.Installation, directory: a.SelfUpdateFiles.Directory, stop: stop, eligible: true}
	a.SelfUpdateFiles.Adapter = p
	a.SelfUpdateFiles.JournalReadGuard = func(c context.Context, reader int) error {
		p.readerCalls++
		if reader != 3 || c.Value(stoppedSettlementTraceKey{}) != "original-provider-context" {
			return errors.New("provider callback context or required reader was replaced")
		}
		store, err := selfupdatejournal.Open(p.installation, p.directory)
		if err != nil {
			return err
		}
		defer store.Close()
		// Exercise the actual writerObservation bridge while the provider owns
		// the writer. Replacing c with Background would break Windows reads.
		version, err := store.RequiredReadVersion(c)
		if err != nil || version > reader {
			return errors.Join(errSelfUpdateRecovery, err)
		}
		return c.Err()
	}
	return a, p
}

func stoppedSettlementControlImage(t *testing.T, a *App) map[string][]byte {
	t.Helper()
	image := map[string][]byte{}
	for _, name := range []string{"current-v1.json", "stop-" + fileUpdateID + ".json"} {
		data, err := os.ReadFile(filepath.Join(a.SelfUpdateFiles.ControlRoot, name))
		if err != nil {
			t.Fatal(err)
		}
		image[name] = data
	}
	return image
}

func TestSelfUpdateStoppedSettlementHTTPPreservesStopAndRetry(t *testing.T) {
	a, p := stoppedSettlementFixture(t)
	s := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer s.Close()
	stop := stoppedSettlementControlImage(t, a)
	cfg := a.Store.Get()
	runs, effects := append([]string(nil), p.runs...), append([]string(nil), p.effects...)
	p.cut = true
	body := fileUpdateBody(a, "settle-stopped-rollback")
	if code, data := componentHTTP(t, s, "POST", "/api/v1/self-update/recovery", body, componentRecoveryToken, s.URL); code != 409 || bytes.Contains(data, []byte("model helper")) {
		t.Fatal("interrupted terminal publication accepted or leaked", code, string(data))
	}
	for i := 0; i < 2; i++ {
		code, data := componentHTTP(t, s, "POST", "/api/v1/self-update/recovery", body, componentRecoveryToken, s.URL)
		if code != 200 || !bytes.Contains(data, []byte(`"stopped_settlement_completed":true`)) || !bytes.Contains(data, []byte(`"recovery_required":true`)) || !bytes.Contains(data, []byte(`"live_accepted":false`)) || !bytes.Contains(data, []byte(`"rollback_accepted":false`)) {
			t.Fatal("data-only retry acquired live permission", code, string(data))
		}
	}
	if p.calls != 3 || p.readerCalls == 0 || !reflect.DeepEqual(runs, p.runs) || !reflect.DeepEqual(effects, p.effects) || len(p.lives) != 0 || len(p.finishes) != 0 {
		t.Fatal("settlement replayed commands or omitted reader proof")
	}
	if !reflect.DeepEqual(stop, stoppedSettlementControlImage(t, a)) || !reflect.DeepEqual(cfg, a.Store.Get()) || !a.PendingSelfUpdateRecovery() {
		t.Fatal("settlement changed Stop/config or cleared recovery")
	}
	assertFileUpdateImages(t, a, p.fileUpdateProof, true)
	resume := selfUpdateStopBody(a)
	resume["action"], resume["confirm"] = "resume", "RESUME_OWNED_ROUTES"
	if code, _ := componentHTTP(t, s, "POST", "/api/v1/service-control/runtime", resume, componentRecoveryToken, s.URL); code < 400 {
		t.Fatal("stopped settlement allowed Resume")
	}
}

func TestSelfUpdateStoppedSettlementHTTPAdmissionRefusals(t *testing.T) {
	for _, refusal := range []string{"auth", "origin", "dto", "id", "revision", "provider", "reader", "legacy2", "independent", "inactive", "epoch", "unknown"} {
		t.Run(refusal, func(t *testing.T) {
			a, p := stoppedSettlementFixture(t)
			s := httptest.NewServer(a.Handler(http.NotFoundHandler()))
			defer s.Close()
			body := fileUpdateBody(a, "settle-stopped-rollback")
			token, origin := componentRecoveryToken, s.URL
			switch refusal {
			case "auth":
				token = ""
			case "origin":
				origin = "https://foreign.example"
			case "dto":
				body["installation_id"] = p.stop.InstallationID
			case "id":
				body["transaction_id"] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
			case "revision":
				body["expected_revision"] = p.revision + 1
			case "provider":
				a.SelfUpdateFiles.Adapter = p.fileUpdateProof
			case "reader":
				a.SelfUpdateFiles.JournalReadGuard = nil
			case "legacy2":
				p.eligible = false
			case "independent":
				a.SelfUpdateFiles.RecoveryGuard = func(context.Context) error { return errors.New("independent recovery remains fenced") }
			case "inactive":
				p.inactiveError = errors.New("model complete runtime/ECHILD proof is unavailable")
			case "epoch":
				p.before = func(c context.Context, authority updatecheck.SelfUpdateStoppedSettlementAuthority) error {
					return authority.Check(c, fileUpdateID, p.stop.InstallationID, math.MaxUint64, p.revision)
				}
			case "unknown":
				store, err := selfupdatejournal.Open(p.installation, p.directory)
				if err != nil {
					t.Fatal(err)
				}
				check := func(context.Context) error { return nil }
				if err := store.Execute(context.Background(), fileUpdateID, "start-rollback-panel", check, func(context.Context) error { return errors.New("unknown command model") }); err == nil {
					t.Fatal("unknown command model was accepted")
				}
				store.Close()
			}
			control := stoppedSettlementControlImage(t, a)
			receiptPath := filepath.Join(p.directory, fileUpdateID, "receipt.json")
			before, err := os.ReadFile(receiptPath)
			if err != nil {
				t.Fatal(err)
			}
			code, data := componentHTTP(t, s, "POST", "/api/v1/self-update/recovery", body, token, origin)
			if code < 400 || bytes.Contains(data, []byte(`"stopped_settlement_completed":true`)) {
				t.Fatal("unreviewed settlement accepted", code, string(data))
			}
			after, err := os.ReadFile(receiptPath)
			if err != nil || !bytes.Equal(before, after) || !reflect.DeepEqual(control, stoppedSettlementControlImage(t, a)) {
				t.Fatal("refused settlement changed retained receipt/Stop", err)
			}
		})
	}
}

func TestSelfUpdateStoppedSettlementRequiresPresentIndependentStop(t *testing.T) {
	a, p := stoppedSettlementFixture(t)
	control := stoppedSettlementControlImage(t, a)
	original := a.SelfUpdateFiles.ControlRoot
	a.SelfUpdateFiles.ControlRoot = filepath.Join(filepath.Dir(original), "missing-control")
	guard := func(c context.Context) error { return a.selfUpdateFileAuthority(c, p.revision) }
	if err := a.SelfUpdateFiles.Action(context.Background(), fileUpdateID, "settle-stopped-rollback", p.revision, guard); err == nil || p.calls != 0 {
		t.Fatal("missing independent Stop became settlement authority")
	}
	if _, err := os.Stat(a.SelfUpdateFiles.ControlRoot); !os.IsNotExist(err) {
		t.Fatal("settlement initialized a control epoch", err)
	}
	a.SelfUpdateFiles.ControlRoot = original
	if !reflect.DeepEqual(control, stoppedSettlementControlImage(t, a)) {
		t.Fatal("missing-root request changed the original Stop")
	}
}

func TestSelfUpdateStoppedSettlementClosingContextAndConfig(t *testing.T) {
	for _, boundary := range []string{"reader-cancel", "reader-config", "recovery-config", "stop-drift"} {
		t.Run(boundary, func(t *testing.T) {
			a, p := stoppedSettlementFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch boundary {
			case "reader-cancel":
				a.SelfUpdateFiles.JournalReadGuard = func(context.Context, int) error { cancel(); return nil }
			case "reader-config":
				a.SelfUpdateFiles.JournalReadGuard = func(context.Context, int) error { return a.Store.SetSafeMode(true) }
			case "recovery-config":
				a.SelfUpdateFiles.RecoveryGuard = func(context.Context) error { return a.Store.SetSafeMode(true) }
			case "stop-drift":
				p.before = func(c context.Context, authority updatecheck.SelfUpdateStoppedSettlementAuthority) error {
					_, err := operationgate.RecordSelfUpdateStopped(c, a.SelfUpdateFiles.ControlRoot, fileUpdateID, p.stop.Sequence, func(context.Context) error { return nil })
					if err != nil {
						return err
					}
					return authority.Check(c, fileUpdateID, p.stop.InstallationID, p.stop.Sequence-1, p.revision)
				}
			}
			receiptPath := filepath.Join(p.directory, fileUpdateID, "receipt.json")
			before, err := os.ReadFile(receiptPath)
			if err != nil {
				t.Fatal(err)
			}
			guard := func(c context.Context) error { return a.selfUpdateFileAuthority(c, p.revision) }
			if err := a.SelfUpdateFiles.Action(ctx, fileUpdateID, "settle-stopped-rollback", p.revision, guard); err == nil {
				t.Fatal("closing callback drift became terminal")
			}
			after, err := os.ReadFile(receiptPath)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("closing refusal changed file terminal", err)
			}
		})
	}
}
