package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// ErrNFQWS2FirstStartRepairUnavailable means no repair effect was attempted.
// An unknown runtime, including an orphaned firewall graph, stays fenced.
var ErrNFQWS2FirstStartRepairUnavailable = errors.New("committed NFQWS2 stock restart unavailable")

func nfqws2FirstStartRepairPlan(plan Plan) bool {
	if !nfqws2HookPlan(plan) || len(plan.Adapters) != 1 ||
		len(plan.RetiringAdapters) != 0 || plan.DNS != nil || plan.DomainPolicy != nil ||
		plan.SyntheticDNS != nil || plan.SuspendDNS || plan.DiscardDNS {
		return false
	}
	seen := make(map[string]bool, len(plan.Routes))
	for _, route := range plan.Routes {
		if route.ServiceID == "" || seen[route.ServiceID] || route.Resolved != "nfqws2" ||
			len(route.Domains) == 0 || len(route.CIDRs) != 0 || len(route.Sources) != 0 || len(route.Ingress) != 0 {
			return false
		}
		seen[route.ServiceID] = true
	}
	return true
}

// RepairCommittedNFQWS2FirstStart restarts the exact committed stock profile
// after a positively observed same-boot process loss. The caller supplies its
// current applied-intent review for the whole shared plan and holds its normal
// App control admission. No plan rewrite, fallback selection or foreign cleanup is done.
func (m *Manager) RepairCommittedNFQWS2FirstStart(ctx context.Context, expected Plan) error {
	if m == nil || m.StateRoot == "" || ctx == nil || !nfqws2FirstStartRepairPlan(expected) {
		return ErrNFQWS2FirstStartRepairUnavailable
	}
	if source, _ := ctx.Value(recoveryReviewSourceKey{}).(func(Plan) error); source == nil {
		return ErrNFQWS2FirstStartRepairUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if !m.tryBeginOperation() {
		return ErrNFQWS2FirstStartRepairUnavailable
	}
	defer m.endOperation()
	a, err := m.committedNFQWS2(expected)
	if err != nil || a.activeOwner() {
		return errors.Join(ErrNFQWS2FirstStartRepairUnavailable, err)
	}
	if err := m.checkNFQWS2BootHookJournal(); err != nil {
		return errors.Join(ErrNFQWS2FirstStartRepairUnavailable, err)
	}
	if retired, _, err := m.completedBootRetirement(); retired || err != nil {
		return errors.Join(ErrNFQWS2FirstStartRepairUnavailable, err)
	}
	ctx, err = m.reviewedRecoveryContext(ctx, expected)
	if err != nil {
		return errors.Join(ErrNFQWS2FirstStartRepairUnavailable, err)
	}
	if err := m.checkPlanNetwork(ctx, expected); err != nil {
		return errors.Join(ErrNFQWS2FirstStartRepairUnavailable, err)
	}
	unlock, err := a.lockResources()
	if err != nil {
		return errors.Join(ErrNFQWS2FirstStartRepairUnavailable, err)
	}
	defer unlock()
	lease, err := a.readLease()
	if err != nil || lease == nil || lease.FirstStart == nil || lease.FirstStart.Process == nil ||
		(lease.FirstStart.Phase != nfqws2FirstRunning && lease.FirstStart.Phase != nfqws2FirstStopped) || a.inactivity == nil ||
		lease.FirstStart.Process.BootID != a.inactivity.identity.BootID {
		return errors.Join(ErrNFQWS2FirstStartRepairUnavailable, err)
	}
	if _, err := a.verifyOwnedLists(false); err != nil {
		return errors.Join(ErrNFQWS2FirstStartRepairUnavailable, err)
	}
	return a.reconcileAbsentFirstStart(ctx, expected, lease, func(c context.Context) error {
		return a.verifyFirstStartRepairAbsence(c, lease.FirstStart.Process.PID)
	})
}

func (a *NFQWS2Adapter) verifyFirstStartRepairAbsence(ctx context.Context, pid int) error {
	// Never adopt a process that reused the original PID, even when its
	// executable looks unrelated. Pair absence around the complete inventory.
	if err := a.firstStartRepairPIDAbsent(pid); err != nil {
		return errors.Join(ErrNFQWS2FirstStartRepairUnavailable, ErrNFQWSManagedProcessUnknown, err)
	}
	if err := a.firstStartRuntimeAbsent(ctx); err != nil {
		return errors.Join(ErrNFQWS2FirstStartRepairUnavailable, err)
	}
	if err := a.firstStartRepairPIDAbsent(pid); err != nil {
		return errors.Join(ErrNFQWS2FirstStartRepairUnavailable, ErrNFQWSManagedProcessUnknown, err)
	}
	return ctx.Err()
}

func (a *NFQWS2Adapter) firstStartRepairPIDAbsent(pid int) error {
	if pid <= 1 || a.inactivity == nil {
		return ErrNFQWSManagedProcessUnknown
	}
	var err error
	if a.firstStartProcessRead != nil {
		_, err = a.readFirstStartProcess(pid)
	} else {
		// A missing executable or cmdline is not a missing process. Inspect
		// the actual PID directory under the original inventory's proc mount.
		root := a.inactivity.platform.procRoot
		if !filepath.IsAbs(root) {
			return ErrNFQWSManagedProcessUnknown
		}
		_, err = os.Lstat(filepath.Join(root, strconv.Itoa(pid)))
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return errors.Join(ErrNFQWSManagedProcessUnknown, err)
}
