package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/routeidentity"
	"github.com/ArtixSx/razvilka/internal/usquediag"
)

var ErrUSQUELocalProcessUnconfirmed = errors.New("original USQUE process absence or surviving TUN is unconfirmed")
var ErrUSQUEProviderUnconfirmed = errors.New("owned USQUE network or service confirmation failed")
var ErrUSQUERestartBudget = errors.New("managed USQUE process restart budget is exhausted")

type USQUECommittedHealthResult struct {
	RestartAttempted bool
	Restarted        bool
	RetryAvailable   bool
}

type usqueLocalRepair struct {
	result     USQUECommittedHealthResult
	control    *operationgate.ControlEpochReview
	root       string
	canRestart bool
	anchor     *usqueRepairRetry
}

// A joined failure leaves the process metadata absent. Retain the old proven
// inactive identity under the Manager gate, without reinstalling or inventing
// a PID file. A subsequent round must independently observe current absence.
type usqueRepairRetry struct {
	adapter     *ProxyTunnelAdapter
	plan, state []byte
	session     committedUSQUESession
	core        usqueInitialExecutable
	dead        deadCommittedUSQUEProcess
	epoch       operationgate.ControlEpochReference
	controlRoot string
}

func (r *usqueRepairRetry) matches(a *ProxyTunnelAdapter, plan, state []byte, session committedUSQUESession, owner *usqueLocalRepair) bool {
	return r != nil && r.adapter == a && bytes.Equal(r.plan, plan) && bytes.Equal(r.state, state) && r.session.sameMaterial(session) &&
		owner.control != nil && owner.control.Reference() == r.epoch && owner.root == r.controlRoot && owner.control.MatchesControlRoot(r.controlRoot)
}

// MonitorCommittedUSQUEHealth can restart just the missing original engine.
// Unsupported and ambiguous runtime states leave the active plan untouched.
func (m *Manager) MonitorCommittedUSQUEHealth(ctx context.Context, expected Plan, configs *engineconfig.Manager, control *operationgate.ControlEpochReview, controlRoot string, canRestart bool) (USQUECommittedHealthResult, error) {
	repair := &usqueLocalRepair{control: control, root: controlRoot, canRestart: canRestart}
	err := m.checkCommittedUSQUEHealth(ctx, expected, configs, repair)
	if soleUSQUENetworkRejection(err) {
		err = errors.Join(ErrUSQUEProviderUnconfirmed, err)
	}
	return repair.result, err
}

func soleUSQUENetworkRejection(err error) bool {
	for n := 0; err != nil && n < 16; n++ {
		if usquediag.OwnedUSQUEProbeRejected(err) {
			return true
		}
		join, ok := err.(interface{ Unwrap() []error })
		if !ok || len(join.Unwrap()) != 1 {
			return false
		}
		err = join.Unwrap()[0]
	}
	return false
}

func (r *usqueLocalRepair) restart(ctx context.Context, m *Manager, a *ProxyTunnelAdapter, plan []byte, session committedUSQUESession, state PolicyState, verify func() error) (*OriginalProcess, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	spec := a.engineProcessWithTransport(session.transport)
	if a.Processes.Running(spec) {
		return nil, nil // A live path stays on the normal owned-health branch.
	}
	controller, ok := a.Processes.(OSProcessController)
	if !ok || runtime.GOOS != "linux" || !r.control.MatchesControlRoot(r.root) || r.control.Current(ctx) != nil || !a.Processes.Running(a.sidecarProcess()) {
		return nil, ErrUSQUELocalProcessUnconfirmed
	}
	if committedUSQUEArgsHash(spec) != session.argsSHA {
		return nil, ErrUSQUELocalProcessUnconfirmed
	}
	if err := a.verifyForwarding(ctx, state); err != nil {
		return nil, errors.Join(ErrUSQUELocalProcessUnconfirmed, err)
	}
	if err := verifyPolicyEvidence(ctx, a.Runner, a.ip(), state); err != nil {
		return nil, errors.Join(ErrUSQUELocalProcessUnconfirmed, err)
	}
	core, err := usqueInitialExecutableAt(spec.Binary)
	if err != nil {
		return nil, ErrUSQUELocalProcessUnconfirmed
	}
	digest, err := core.digest(ctx)
	if err != nil || digest != session.binarySHA || !usquediag.OwnedUSQUENativeBinaryAudited(digest, runtime.GOARCH) {
		return nil, ErrUSQUELocalProcessUnconfirmed
	}
	encodedState, err := json.Marshal(state)
	if err != nil {
		return nil, ErrReviewChanged
	}
	var dead deadCommittedUSQUEProcess
	var absence func(context.Context, ProcessSpec, int, committedUSQUESession) error
	if retained := m.usqueRepairRetry; retained.matches(a, plan, encodedState, session, r) {
		dead = retained.dead
		if !retained.core.same(core.info) || dead.currentAfterJoin(ctx, spec, a.SOCKSPort, session) != nil {
			return nil, ErrUSQUELocalProcessUnconfirmed
		}
		absence = dead.currentAfterJoin
	} else {
		m.usqueRepairRetry = nil
		dead, err = observeCommittedUSQUEProcessAbsence(ctx, spec, a.SOCKSPort, session)
		if err != nil {
			return nil, err
		}
		absence = dead.current
	}
	if !r.canRestart {
		return nil, ErrUSQUERestartBudget
	}
	if err := verify(); err != nil {
		return nil, err
	}
	current, err := a.committedUSQUESession()
	if err != nil || current != session || !a.Processes.Running(a.sidecarProcess()) {
		return nil, ErrReviewChanged
	}
	if !core.current() || absence(ctx, spec, a.SOCKSPort, session) != nil || r.control.Current(ctx) != nil {
		return nil, ErrUSQUELocalProcessUnconfirmed
	}
	r.anchor = &usqueRepairRetry{adapter: a, plan: slices.Clone(plan), state: encodedState, session: session, core: core, dead: dead, epoch: r.control.Reference(), controlRoot: r.root}
	r.result.RestartAttempted = true
	startCtx, cancel := context.WithTimeout(ctx, min(a.timeout(), 2*time.Second))
	defer cancel()
	child, startErr := controller.startOriginalUnderControl(startCtx, spec, net.JoinHostPort("127.0.0.1", strconv.Itoa(a.SOCKSPort)), r.control)
	if startErr != nil {
		return child, startErr
	}
	if child == nil {
		return nil, ErrOriginalProcessCleanup
	}
	if err := child.withObservedLive(ctx, nil); err != nil {
		return child, errors.Join(ErrReviewChanged, ctx.Err())
	}
	return child, errors.Join(verify(), r.control.Current(ctx))
}

func (r *usqueLocalRepair) retainAfterJoin(ctx context.Context, m *Manager) {
	if !r.result.RestartAttempted || r.anchor == nil {
		return
	}
	anchor := r.anchor
	m.usqueRepairRetry = nil
	a, session := anchor.adapter, anchor.session
	if !anchor.core.current() || anchor.dead.currentAfterJoin(ctx, a.engineProcessWithTransport(session.transport), a.SOCKSPort, session) != nil {
		return
	}
	if current, err := a.committedUSQUESession(); err == nil && current.sameMaterial(session) {
		m.usqueRepairRetry = anchor
		r.result.RetryAvailable = true
	}
}

type deadCommittedUSQUEProcess struct {
	pid     int
	receipt []byte
	root    os.FileInfo
	boot    string
}

func committedUSQUEProcessRecord(root *ownedfs.Root, spec ProcessSpec, session committedUSQUESession, boot string) (deadCommittedUSQUEProcess, error) {
	var empty deadCommittedUSQUEProcess
	pidName, err := filepath.Rel(spec.Dir, spec.PIDPath)
	if err != nil || pidName != "engine.pid" || spec.ID != "usque-engine" || spec.MatchArg != filepath.Join(spec.Dir, "engine.json") || !spec.RouteProof {
		return empty, ErrUSQUELocalProcessUnconfirmed
	}
	pidRaw, err := root.ReadLimited(pidName, 64)
	raw, readErr := root.ReadLimited(pidName+routeidentity.ReceiptSuffix, 4096)
	var record routeidentity.Receipt
	if err != nil || readErr != nil || json.Unmarshal(raw, &record) != nil || record.PID <= 1 || record.Version != 1 || record.BootID == "" || record.BootID != boot ||
		!bytes.Equal(pidRaw, []byte(strconv.Itoa(record.PID)+"\n")) || record.Executable != spec.Binary || record.ConfigHash != session.sha {
		return empty, ErrUSQUELocalProcessUnconfirmed
	}
	encoded, err := json.Marshal(record)
	ticks, parseErr := strconv.ParseUint(record.StartTicks, 10, 64)
	if err != nil || !bytes.Equal(raw, encoded) || parseErr != nil || ticks == 0 || record.ArgsHash != committedUSQUEArgsHash(spec) || record.ArgsHash != session.argsSHA {
		return empty, ErrUSQUELocalProcessUnconfirmed
	}
	return deadCommittedUSQUEProcess{pid: record.PID, receipt: raw, boot: boot}, nil
}

func committedUSQUEArgsHash(spec ProcessSpec) string {
	argv := strings.Join(append([]string{spec.Binary}, spec.Args...), "\x00") + "\x00"
	return routeidentity.Hash([]byte(argv))
}
