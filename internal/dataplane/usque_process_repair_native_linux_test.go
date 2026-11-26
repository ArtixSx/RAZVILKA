//go:build linux && razvilka_native_fixture

package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/routeidentity"
	"github.com/ArtixSx/razvilka/internal/usquediag"
)

func TestUSQUECommittedProcessAbsenceRequiresActualDeadPIDAndFreeListener(t *testing.T) {
	f := newUSQUELifecycleFixture(t)
	a := f.a
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	a.EngineBin = filepath.Join(f.base, "usque")
	in, err := os.Open(self)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.OpenFile(a.EngineBin, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0500)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); errors.Join(err, out.Close()) != nil {
		t.Fatal("copy local fixture under its expected executable name", err)
	}
	t.Setenv("RAZVILKA_USQUE_CANARY_LOCAL_CHILD", "1")
	if err := os.MkdirAll(a.runtimeRoot(), 0700); err != nil {
		t.Fatal(err)
	}
	config := []byte(`{"private_key":"fixture-key","endpoint_pub_key":"fixture-pub","id":"fixture-device","access_token":"fixture-token"}`)
	if err := os.WriteFile(a.engineConfigPath(), config, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	spec := a.engineProcessWithTransport(usqueTransport{HTTP2: true})
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(a.SOCKSPort))
	child, err := (OSProcessController{}).StartOriginal(ctx, spec, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, finish := context.WithTimeout(context.Background(), 6*time.Second)
		defer finish()
		if err := child.StopAndJoin(cleanup); err != nil {
			t.Error("clean owned native fixture child", err)
		}
	}()
	seen := false
	if err := child.withObservedLive(ctx, func() error { seen = true; return nil }); err != nil || !seen {
		t.Fatal("refresh exact live witness after initial root handle closed", err)
	}
	argv := strings.Join(append([]string{spec.Binary}, spec.Args...), "\x00") + "\x00"
	session := committedUSQUESession{sha: routeidentity.Hash(config), argsSHA: routeidentity.Hash([]byte(argv))}
	for ctx.Err() == nil {
		passport, err := routeidentity.Verify(spec.Dir, "usque", addr)
		if err == nil {
			session.runtimeID = passport.ID
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := verifyRestartedUSQUEChild(ctx, child, session); err != nil {
		t.Fatal("fresh live passport did not certify retained original child", err)
	}
	foreign := session
	foreign.runtimeID += "-different"
	if err := verifyRestartedUSQUEChild(ctx, child, foreign); !errors.Is(err, ErrReviewChanged) {
		t.Fatal("same-config foreign passport certified original child", err)
	}
	if _, err := observeCommittedUSQUEProcessAbsence(ctx, spec, a.SOCKSPort, session); !errors.Is(err, ErrUSQUELocalProcessUnconfirmed) {
		t.Fatal("live original process counted as locally failed", err)
	}
	if err := child.child.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	select {
	case <-child.done:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := child.withObservedLive(ctx, func() error { t.Error("dead child ran live observation"); return nil }); err == nil {
		t.Fatal("dead original child passed live observation")
	}
	dead, err := observeCommittedUSQUEProcessAbsence(ctx, spec, a.SOCKSPort, session)
	if err != nil || dead.pid != child.child.Pid || dead.current(ctx, spec, a.SOCKSPort, session) != nil {
		t.Fatal("exact same-boot joined loss not positively observed", err)
	}
	listener, err := net.Listen("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := dead.current(ctx, spec, a.SOCKSPort, session); !errors.Is(err, ErrUSQUELocalProcessUnconfirmed) {
		t.Fatal("foreign listener did not invalidate fresh local absence", err)
	}
}

func TestUSQUERepairJoinedFailureRetainsOriginalInactiveProofForSamePath(t *testing.T) {
	f := newUSQUELifecycleFixture(t)
	a := f.a
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	a.EngineBin = self
	t.Setenv("RAZVILKA_USQUE_CANARY_LOCAL_CHILD", "1")
	if err := os.MkdirAll(a.runtimeRoot(), 0700); err != nil {
		t.Fatal(err)
	}
	old, err := a.Configs.ReadExpert("usque", "main")
	if err != nil || os.MkdirAll(filepath.Dir(old.Path), 0700) != nil || os.WriteFile(old.Path, []byte(old.Content), 0600) != nil {
		t.Fatal("prepare owned live fixture session", err)
	}
	raw, _, err := a.buildEngineCandidate([]byte(old.Content), a.SOCKSPort)
	if err != nil || os.WriteFile(a.engineConfigPath(), raw, 0600) != nil {
		t.Fatal("prepare canonical active session", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 24*time.Second)
	defer cancel()
	controlRoot := filepath.Join(f.base, "control")
	if _, err := operationgate.InitializeSelfUpdateControl(ctx, controlRoot); err != nil {
		t.Fatal(err)
	}
	gate := &operationgate.Gate{}
	held, release, err := gate.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	control, err := gate.ReviewControlEpoch(held, controlRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	transport := usqueTransport{HTTP2: true}
	spec := a.engineProcessWithTransport(transport)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(a.SOCKSPort))
	core, err := usqueInitialExecutableAt(spec.Binary)
	if err != nil {
		t.Fatal(err)
	}
	coreSHA, err := core.digest(held)
	if err != nil {
		t.Fatal(err)
	}
	identity := usquediag.OwnedRuntimeIdentity{SessionSHA256: routeidentity.Hash(raw), ArgsSHA256: committedUSQUEArgsHash(spec), BinarySHA256: coreSHA}
	historical := usquediag.OwnedRuntimeEvidence{Identity: identity, ProtocolPath: "HTTP/2"}
	evidence, _ := json.Marshal(historical.CanaryEvidence())
	selection, _ := json.Marshal(transport)
	if os.WriteFile(a.transportPath(), selection, 0600) != nil || os.WriteFile(a.evidencePath(), evidence, 0600) != nil {
		t.Fatal("prepare previously observed session and transport")
	}
	session, err := a.committedUSQUESession()
	if err != nil {
		t.Fatal(err)
	}
	starter := OSProcessController{}
	start := func(c context.Context, admission *operationgate.ControlEpochReview) *OriginalProcess {
		t.Helper()
		child, err := starter.startOriginalUnderControl(c, spec, addr, admission)
		if err != nil {
			t.Fatal(err)
		}
		return child
	}
	previous := start(held, control)
	if err := previous.child.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	select {
	case <-previous.done:
	case <-held.Done():
		t.Fatal(held.Err())
	}
	dead, err := observeCommittedUSQUEProcessAbsence(held, spec, a.SOCKSPort, session)
	if err != nil {
		t.Fatal(err)
	}
	if err := control.Close(); err != nil {
		t.Fatal(err)
	}
	if child, err := starter.startOriginalUnderControl(held, spec, addr, control); child != nil || err == nil || dead.current(held, spec, a.SOCKSPort, session) != nil {
		t.Fatal("revoked admission started a child or changed the previous exact receipt", err)
	}
	control, err = gate.ReviewControlEpoch(held, controlRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	failed := start(held, control)
	if err := failed.StopAndJoin(held); err != nil {
		t.Fatal(err)
	}
	if _, err := observeCommittedUSQUEProcessAbsence(held, spec, a.SOCKSPort, session); !errors.Is(err, ErrUSQUELocalProcessUnconfirmed) {
		t.Fatal("ordinary absence unexpectedly manufactured removed process metadata", err)
	}
	m := New(filepath.Join(f.base, "manager"))
	repair := &usqueLocalRepair{control: control, root: controlRoot, result: USQUECommittedHealthResult{RestartAttempted: true},
		anchor: &usqueRepairRetry{adapter: a, plan: []byte("committed"), state: []byte("same rules"), session: session, core: core, dead: dead, epoch: control.Reference(), controlRoot: controlRoot}}
	repair.retainAfterJoin(held, m)
	if !repair.result.RetryAvailable || repair.result.Restarted || m.usqueRepairRetry == nil {
		t.Fatal("joined failure lost its exact retry proof or reported success", repair.result)
	}
	if _, err := os.Lstat(spec.PIDPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("retained proof synthesized a PID file", err)
	}
	release()
	fresh, finish, err := gate.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer finish()
	newControl, err := gate.ReviewControlEpoch(fresh, controlRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer newControl.Close()
	next := &usqueLocalRepair{control: newControl, root: controlRoot}
	if m.usqueRepairRetry.matches(a, []byte("changed"), []byte("same rules"), session, next) ||
		!m.usqueRepairRetry.matches(a, []byte("committed"), []byte("same rules"), session, next) ||
		m.usqueRepairRetry.dead.currentAfterJoin(fresh, spec, a.SOCKSPort, session) != nil {
		t.Fatal("retained proof escaped its live committed scope or failed to admit the same path")
	}
	retried := start(fresh, newControl)
	if err := retried.StopAndJoin(fresh); err != nil {
		t.Fatal(err)
	}
}
