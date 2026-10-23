package dataplane

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// This extends the existing resource intent, not the separate managed-process
// receipt. Stock daemon ownership is never presented as a Wait/parent ACK.
type nfqws2FirstStartLease struct {
	PriorInitHash string                                  `json:"prior_init_hash"`
	StockInitHash string                                  `json:"stock_init_hash"`
	Phase         string                                  `json:"phase"` // prepared -> starting -> running -> stopped; starting has no cleanup authority.
	Process       *components.NFQWSRuntimeProcessIdentity `json:"process,omitempty"`
}

const (
	nfqws2FirstPrepared = "prepared"
	nfqws2FirstStarting = "starting"
	nfqws2FirstRunning  = "running"
	nfqws2FirstStopped  = "stopped"
	nfqws2FirstRetiring = "retiring"
)

type nfqws2RemovalIntentKey struct{}
type nfqws2RemovalIntent struct{}

var nfqws2Removal = &nfqws2RemovalIntent{}

func withNFQWS2Removal(ctx context.Context) context.Context {
	return context.WithValue(ctx, nfqws2RemovalIntentKey{}, nfqws2Removal)
}
func isNFQWS2Removal(ctx context.Context) bool {
	intent, _ := ctx.Value(nfqws2RemovalIntentKey{}).(*nfqws2RemovalIntent)
	return intent == nfqws2Removal
}

func nfqws2OriginalInitialInit(raw []byte) ([]byte, error) {
	if nfqws2Hash(raw) == engineconfig.NFQWSFirstStartStockInitSHA256 {
		return slices.Clone(raw), nil
	}
	owner, err := engineconfig.NFQWSFirstStartInitOwner(raw)
	if err != nil {
		return nil, err
	}
	return engineconfig.NFQWSFirstStartOriginalInit(raw, owner)
}

func (a *NFQWS2Adapter) firstStartConfig(plan Plan, config []byte) ([]byte, error) {
	owner, err := a.owner()
	if err != nil {
		return nil, err
	}
	original, err := engineconfig.NFQWSFirstStartOriginalConfig(config, owner)
	if err != nil {
		return nil, err
	}
	for _, route := range plan.Routes {
		if adapterID(route.Resolved) == a.ID() && !plan.SiteExclusions.excludesService(route.ServiceID) && (len(route.Sources) != 0 || len(route.Domains) == 0 || len(route.CIDRs) != 0) {
			return nil, engineconfig.ErrNFQWSFirstStart
		}
	}
	lists := nfqws2PlanLists(plan, a.ID())
	domains, addresses := nfqws2PlanExclusions(plan, a.ID())
	prefixes := []string{}
	for _, value := range addresses {
		prefix, err := siteExclusionPrefix(value)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, prefix.String())
	}
	return engineconfig.NFQWSFirstStartConfigForRecipe(original, owner, lists[0], domains, prefixes, plan.NFQWSFirstStartRecipe)
}

func (a *NFQWS2Adapter) prepareFirstStartSnapshot(ctx context.Context, plan Plan, s *nfqws2Snapshot) error {
	if a.stockNativeOwner == nil {
		if plan.NFQWSFirstStartRecipe != "" {
			return engineconfig.ErrNFQWSFirstStart
		}
		return nil
	}
	owner, err := a.owner()
	if err != nil {
		return err
	}
	init, exists, err := nfqws2Read(a.InitPath)
	if err != nil || !exists {
		return engineconfig.ErrNFQWSFirstStart
	}
	running, runningExists, err := nfqws2Read(a.ConfigPath + ".run")
	if err != nil {
		return err
	}
	initial := s.Lease == nil && engineconfig.NFQWSFirstStartStockConfig(s.Config) == nil
	owned := s.Lease != nil && s.Lease.FirstStart != nil
	if owned && s.Lease.FirstStart.Phase != nfqws2FirstRunning && s.Lease.FirstStart.Phase != nfqws2FirstStopped {
		return errors.New("NFQWS2 lifecycle is unsettled; preserve its ownership fence")
	}
	if !initial && !owned {
		if plan.NFQWSFirstStartRecipe != "" {
			return engineconfig.ErrNFQWSFirstStart
		}
		// Existing expert mode remains available, but status must never source an
		// unknown script or executable configuration before native validation.
		if nfqws2Hash(init) != engineconfig.NFQWSFirstStartStockInitSHA256 {
			return engineconfig.ErrNFQWSFirstStart
		}
		base, _, err := removeManagedBlock(string(s.Config))
		if err != nil {
			return err
		}
		block, err := nfqws2Block(s.Config)
		if err != nil {
			return err
		}
		if len(block) > 0 {
			if s.Lease == nil {
				return engineconfig.ErrNFQWSFirstStart
			}
			if err := a.verifyOwnedRuntime(s.Lease, false); err != nil {
				return err
			}
			expected, err := a.exclusionConfig([]byte(base), plan)
			if err != nil || !bytes.Equal(expected, s.Config) {
				return engineconfig.ErrNFQWSFirstStart
			}
		}
		if _, err := engineconfig.NFQWSStartupArguments(base, nil); err != nil {
			return err
		}
		if runningExists {
			return engineconfig.NFQWSRunningConfigMatches(base, string(running))
		}
		return nil
	}
	if s.ConfigDraft {
		return engineconfig.ErrNFQWSFirstStart
	}
	for _, draft := range s.ListDraft {
		if draft {
			return engineconfig.ErrNFQWSFirstStart
		}
	}
	if _, err := a.firstStartConfig(plan, s.Config); err != nil {
		return err
	}
	if err := a.reviewFirstStartScope(ctx, s.Config, false); err != nil {
		return err
	}
	if initial {
		if _, err := nfqws2OriginalInitialInit(init); err != nil {
			return err
		}
	} else if _, err := engineconfig.NFQWSFirstStartOriginalInit(init, owner); err != nil {
		return err
	}
	if initial {
		if runningExists {
			return engineconfig.ErrNFQWSFirstStart
		}
		if _, exists, err := nfqws2Read(a.firstStartPIDPath()); err != nil || exists {
			return engineconfig.ErrNFQWSFirstStart
		}
		probe, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		if err := a.observeFirstStartAbsent(probe, true); err != nil {
			return err
		}
	} else {
		if err := a.verifyOwnedRuntime(s.Lease, false); err != nil {
			return err
		}
		if runningExists {
			if err := engineconfig.NFQWSFirstStartRunningConfig(s.Config, owner, running); err != nil {
				return err
			}
		}
	}
	info, err := os.Lstat(a.InitPath)
	if err != nil {
		return err
	}
	s.FirstStart, s.Init, s.InitMode = true, init, info.Mode().Perm()
	s.RunningConfig, s.RunningConfigExisted = running, runningExists
	return nil
}

func (a *NFQWS2Adapter) stageFirstStart(plan Plan, root string, s nfqws2Snapshot) ([]byte, error) {
	owner, err := a.owner()
	if err != nil {
		return nil, err
	}
	original, err := engineconfig.NFQWSFirstStartOriginalInit(s.Init, owner)
	if s.Lease == nil {
		original, err = nfqws2OriginalInitialInit(s.Init)
	}
	if err != nil {
		return nil, err
	}
	init, err := engineconfig.NFQWSFirstStartInit(original, owner)
	if err != nil {
		return nil, err
	}
	if err := writeAtomic(filepath.Join(root, "S51nfqws2.staged"), init, 0600); err != nil {
		return nil, err
	}
	return a.firstStartConfig(plan, s.Config)
}

func (a *NFQWS2Adapter) activateFirstStartInit(ctx context.Context, root string) error {
	s, err := readNFQWS2Snapshot(root)
	if err != nil || !s.FirstStart {
		return err
	}
	current, exists, err := nfqws2Read(a.InitPath)
	if err != nil || !exists || !bytes.Equal(current, s.Init) {
		return ErrReviewChanged
	}
	running, exists, err := nfqws2Read(a.ConfigPath + ".run")
	if err != nil || exists != s.RunningConfigExisted || !bytes.Equal(running, s.RunningConfig) {
		return ErrReviewChanged
	}
	// A fresh whole inventory is still required immediately before the first
	// owned write. A stopped status is not a grant to replace foreign runtime.
	if s.Lease == nil {
		if err := a.firstStartRuntimeAbsent(ctx); err != nil {
			return err
		}
	}
	staged, exists, err := nfqws2Read(filepath.Join(root, "S51nfqws2.staged"))
	if err != nil || !exists {
		return engineconfig.ErrNFQWSFirstStart
	}
	lease, err := a.readLease()
	if err != nil || lease == nil || nfqws2Hash(staged) != lease.InitHash {
		return ErrReviewChanged
	}
	before, present := nfqws2SnapshotResources(s)
	for index, path := range a.globalResources() {
		current, exists, err := nfqws2Read(path)
		if err != nil || exists != present[index] || !bytes.Equal(current, before[index]) {
			return ErrReviewChanged
		}
	}
	return firstStartReplace(a.InitPath, current, true, staged, true, s.InitMode)
}

func (a *NFQWS2Adapter) installFirstStartResources(root string, s nfqws2Snapshot) error {
	lease, err := a.readLease()
	if err != nil || lease == nil || lease.FirstStart == nil {
		return ErrReviewChanged
	}
	before, present := nfqws2SnapshotResources(s)
	for index, path := range a.globalResources() {
		stage := "nfqws2.conf.staged"
		mode := os.FileMode(0600)
		if index > 0 {
			stage = nfqws2ListStages[index-1]
			mode = 0644
		}
		data, exists, err := nfqws2Read(filepath.Join(root, stage))
		if err != nil || !exists {
			return ErrReviewChanged
		}
		if index == 0 {
			if nfqws2Hash(data) != lease.ConfigHash {
				return ErrReviewChanged
			}
		} else {
			block, err := nfqws2Block(data)
			if err != nil || nfqws2Hash(block) != lease.Lists[index-1].BlockHash {
				return ErrReviewChanged
			}
		}
		if err := firstStartReplace(path, before[index], present[index], data, true, mode); err != nil {
			return err
		}
	}
	return nil
}

// Same concrete source and complete kernel/process predicates as the ordinary
// inactivity check. Here the exact file intent is still present: it is checked
// separately, before any action, instead of pretending a legacy lease is ACKed.
func (a *NFQWS2Adapter) firstStartRuntimeAbsent(parent context.Context) error {
	if a.firstStartObservation != nil {
		return a.firstStartObservation(parent, false)
	}
	s := a.inactivity
	if s == nil || s.adapter != a || s.self != s || s.provider == nil {
		return nfqws2InactiveAt("source", nil)
	}
	return a.firstStartRuntimeAbsentWithSources(parent, s.platform, s.provider.WithCurrent, s.frozen.Read)
}

// Private source model seam. Production retains the original bound platform,
// provider and frozen collector above; no caller can replace their authority.
func (a *NFQWS2Adapter) firstStartRuntimeAbsentWithSources(parent context.Context, platform nfqws2InactivePlatform,
	withCurrent func(context.Context, func(context.Context, netidentity.Identity) error) error,
	read func(context.Context, netidentity.Identity) (BackendInventorySnapshot, error)) error {
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	s := a.inactivity
	if s == nil || s.adapter != a || s.self != s || withCurrent == nil || read == nil {
		return nfqws2InactiveAt("source", nil)
	}
	if err := s.current(ctx); err != nil {
		return err
	}
	err := withCurrent(ctx, func(c context.Context, id netidentity.Identity) error {
		if id != s.identity {
			return nfqws2InactiveAt("identity", nil)
		}
		if err := nfqws2InactiveProcesses(c, platform, a); err != nil {
			return nfqws2InactiveAt("processes", err)
		}
		reader := nfqws2InactiveKernelReader{read: func(c context.Context, id netidentity.Identity) (BackendInventorySnapshot, error) {
			image, err := read(c, id)
			if err != nil || image.Scope.Network != id || image.Scope.ToolReviewID != s.frozen.review || image.IPTables != s.frozen.reader.IPTables || image.IP6Tables != s.frozen.reader.IP6Tables {
				return BackendInventorySnapshot{}, nfqws2InactiveAt("inventory.source", err)
			}
			return image, nil
		}, queues: platform.queues, sockets: platform.sockets}
		if err := reader.check(c, id); err != nil {
			return nfqws2InactiveAt("kernel", err)
		}
		if err := nfqws2InactiveProcesses(c, platform, a); err != nil {
			return nfqws2InactiveAt("processes", err)
		}
		return nil
	})
	if err := errors.Join(err, s.current(ctx), ctx.Err()); err != nil {
		return nfqws2InactiveAt("observation", err)
	}
	return nil
}

func (a *NFQWS2Adapter) observeFirstStartAbsent(ctx context.Context, full bool) error {
	if a.firstStartObservation != nil {
		return a.firstStartObservation(ctx, full)
	}
	if full {
		return a.VerifyRuntimeInactive(ctx)
	}
	return a.firstStartRuntimeAbsent(ctx)
}

// Resource locks include .run and init. The complete expected bytes are
// checked immediately before atomic replacement; foreign edits never become
// rollback content. Modes come only from the protected original init.
func firstStartReplace(path string, before []byte, beforeExists bool, after []byte, afterExists bool, mode os.FileMode) error {
	current, exists, err := nfqws2Read(path)
	if err != nil || exists != beforeExists || !bytes.Equal(current, before) {
		return ErrReviewChanged
	}
	return restoreOptionalMode(path, after, afterExists, mode)
}

func (a *NFQWS2Adapter) stopFirstStart(ctx context.Context, lease *nfqws2Lease) error {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if lease == nil || lease.FirstStart == nil {
		return engineconfig.ErrNFQWSFirstStart
	}
	if lease.FirstStart.Phase == nfqws2FirstPrepared {
		return a.firstStartRuntimeAbsent(ctx)
	}
	if lease.FirstStart.Phase == nfqws2FirstStopped {
		return a.firstStartRuntimeAbsent(ctx)
	}
	if lease.FirstStart.Process == nil {
		return errors.New("NFQWS2 start outcome is unknown; ownership fence retained")
	}
	if a.inactivity != nil && lease.FirstStart.Process.BootID != a.inactivity.identity.BootID {
		if err := a.firstStartRuntimeAbsent(ctx); err != nil {
			return err
		}
		return a.recordFirstStartStopped(lease)
	}
	current, err := a.readFirstStartProcess(lease.FirstStart.Process.PID)
	if errors.Is(err, os.ErrNotExist) {
		if err := a.firstStartRuntimeAbsent(ctx); err != nil {
			return err
		}
		return a.recordFirstStartStopped(lease)
	}
	if err != nil || current != *lease.FirstStart.Process {
		return errors.New("NFQWS2 process identity changed; ownership fence retained")
	}
	if err := a.reviewFirstStartProcess(ctx, current); err != nil {
		return err
	}
	if err := a.verifyOwnedRuntime(lease, true); err != nil {
		return err
	}
	owner, err := a.owner()
	if err != nil {
		return err
	}
	init, _, err := nfqws2Read(a.InitPath)
	if err != nil {
		return err
	}
	if _, err := engineconfig.NFQWSFirstStartOriginalInit(init, owner); err != nil {
		return err
	}
	config, _, err := nfqws2Read(a.ConfigPath)
	if err != nil {
		return err
	}
	running, runningExists, err := nfqws2Read(a.ConfigPath + ".run")
	if err != nil {
		return err
	}
	if runningExists {
		// Interrupted activation can still hold the original stock main. Only the
		// exact staged closed main from this transaction may explain its overlay.
		candidate := config
		if nfqws2Hash(config) != lease.ConfigHash {
			candidate, _, err = nfqws2Read(filepath.Join(lease.Transaction, "nfqws2.conf.staged"))
			if err != nil || nfqws2Hash(candidate) != lease.ConfigHash {
				return ErrReviewChanged
			}
		}
		if err := engineconfig.NFQWSFirstStartRunningConfig(candidate, owner, running); err != nil {
			return err
		}
	}
	output, err := a.run(ctx, a.InitPath, "owned_stop")
	if err != nil && !(strings.Contains(strings.ToLower(string(output)), "not running") && !runningOutput(string(output))) {
		return err
	}
	if err := a.waitFirstStartExit(ctx, *lease.FirstStart.Process); err != nil {
		return err
	}
	if err := a.firstStartRuntimeAbsent(ctx); err != nil {
		return err
	}
	return a.recordFirstStartStopped(lease)
}

func (a *NFQWS2Adapter) waitFirstStartExit(ctx context.Context, receipt components.NFQWSRuntimeProcessIdentity) error {
	wait, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for {
		current, err := a.readFirstStartProcess(receipt.PID)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil || current != receipt {
			return ErrNFQWSManagedProcessUnknown
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-wait.Done():
			timer.Stop()
			return wait.Err()
		case <-timer.C:
		}
	}
}

func (a *NFQWS2Adapter) recordFirstStartStopped(lease *nfqws2Lease) error {
	current, err := a.readLease()
	if err != nil || !reflect.DeepEqual(current, lease) {
		return ErrReviewChanged
	}
	updated := *lease
	first := *lease.FirstStart
	first.Phase = nfqws2FirstStopped
	updated.FirstStart = &first
	if err := a.writeLease(&updated); err != nil {
		return err
	}
	*lease = updated
	return nil
}

func (a *NFQWS2Adapter) rollbackFirstStart(ctx context.Context, root string, s nfqws2Snapshot, lease *nfqws2Lease) error {
	before := make([][]byte, 0, 6)
	present := make([]bool, 0, 6)
	for _, path := range append(a.globalResources(), a.InitPath) {
		data, exists, err := nfqws2Read(path)
		if err != nil {
			return err
		}
		before = append(before, data)
		present = append(present, exists)
	}
	if err := a.stopFirstStart(ctx, lease); err != nil {
		return err
	}
	// mayRollback checked all before/staged images under these same locks;
	// stop may remove .run, but never edits the main/init/list documents.
	if err := firstStartReplace(a.ConfigPath, before[0], present[0], s.Config, s.ConfigExisted, 0600); err != nil {
		return err
	}
	for index, path := range a.ownedListPaths() {
		original, originalPresent := s.ownedList(index)
		if err := firstStartReplace(path, before[index+1], present[index+1], original, originalPresent, 0644); err != nil {
			return err
		}
	}
	if err := firstStartReplace(a.InitPath, before[5], present[5], s.Init, true, s.InitMode); err != nil {
		return err
	}
	running, exists, err := nfqws2Read(a.ConfigPath + ".run")
	if err != nil {
		return err
	}
	if exists {
		owner, _ := a.owner()
		candidate, _, e := nfqws2Read(filepath.Join(root, "nfqws2.conf.staged"))
		if e != nil || engineconfig.NFQWSFirstStartRunningConfig(candidate, owner, running) != nil {
			return ErrReviewChanged
		}
	}
	if err := firstStartReplace(a.ConfigPath+".run", running, exists, s.RunningConfig, s.RunningConfigExisted, 0600); err != nil {
		return err
	}
	if err := a.writeLease(s.Lease); err != nil {
		return err
	}
	if s.WasRunning {
		// Drop the candidate's component writer lock before reacquiring a fresh
		// review for the exact prior argv/assets. Fixed-argv authority cannot be
		// reused across recipes, including a v2 candidate restoring v1.
		if a.firstStartReview != nil {
			review := a.firstStartReview
			a.firstStartReview, a.firstStartReviewRoot = nil, ""
			if err := review.Close(); err != nil {
				return err
			}
		}
		expected, first := *s.Lease, *s.Lease.FirstStart
		first.Phase = nfqws2FirstStopped
		expected.FirstStart = &first
		if err := a.writeLease(&expected); err != nil {
			return err
		}
		return a.restartFirstStartSnapshot(ctx, root, s, &expected)
	}
	return nil
}

func nfqws2RollbackLeaseEqual(current, before *nfqws2Lease) bool {
	if current == nil || before == nil || current.FirstStart == nil || before.FirstStart == nil {
		return reflect.DeepEqual(current, before)
	}
	a, b := *current, *before
	af, bf := *a.FirstStart, *b.FirstStart
	if af.Process == nil || bf.Process == nil {
		return reflect.DeepEqual(current, before)
	}
	af.Process, bf.Process = nil, nil
	a.FirstStart, b.FirstStart = &af, &bf
	return reflect.DeepEqual(a, b)
}

func (a *NFQWS2Adapter) deactivateFirstStart(ctx context.Context, lease *nfqws2Lease) error {
	if lease.FirstStart.Phase == nfqws2FirstRetiring {
		return errors.New("NFQWS2 removal is incomplete; retry explicit retirement")
	}
	// Stop keeps the closed configuration, inert init and settled lease. A
	// later boot cannot silently return to the owner's broad stock recipe.
	if _, err := a.verifyOwnedLists(false); err != nil {
		return err
	}
	owner, err := a.owner()
	if err != nil {
		return err
	}
	config, exists, err := nfqws2Read(a.ConfigPath)
	if err != nil || !exists {
		return ErrReviewChanged
	}
	if err := a.stopFirstStart(ctx, lease); err != nil {
		return err
	}
	if _, err := a.verifyOwnedLists(false); err != nil {
		return err
	}
	running, exists, err := nfqws2Read(a.ConfigPath + ".run")
	if err != nil {
		return err
	}
	if exists && engineconfig.NFQWSFirstStartRunningConfig(config, owner, running) != nil {
		return ErrReviewChanged
	}
	if err := firstStartReplace(a.ConfigPath+".run", running, exists, nil, false, 0600); err != nil {
		return err
	}
	pid, exists, err := nfqws2Read(a.firstStartPIDPath())
	if err != nil {
		return err
	}
	if exists {
		if lease.FirstStart.Process == nil || strings.TrimSpace(string(pid)) != strconv.Itoa(lease.FirstStart.Process.PID) {
			return ErrReviewChanged
		}
		if err := firstStartReplace(a.firstStartPIDPath(), pid, true, nil, false, 0600); err != nil {
			return err
		}
	}
	current, err := a.readLease()
	if err != nil || !reflect.DeepEqual(current, lease) {
		return ErrReviewChanged
	}
	proof, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	return a.observeFirstStartAbsent(proof, true)
}

// Availability is data-only. Actual Apply repeats all file, component and
// fresh runtime checks; this method grants no shell or network authority.
func (m *Manager) NFQWS2FirstStartAvailable() bool {
	if m == nil {
		return false
	}
	adapter, _ := m.adapter("nfqws2")
	a, ok := adapter.(*NFQWS2Adapter)
	if !ok || a.stockNativeOwner == nil || a.inactivity == nil {
		return false
	}
	lease, err := a.readLease()
	if err != nil || lease != nil {
		return false
	}
	config, exists, err := nfqws2Read(a.ConfigPath)
	if err != nil || !exists || engineconfig.NFQWSFirstStartStockConfig(config) != nil {
		return false
	}
	init, exists, err := nfqws2Read(a.InitPath)
	if err != nil || !exists {
		return false
	}
	if _, err := nfqws2OriginalInitialInit(init); err != nil {
		return false
	}
	_, exists, err = nfqws2Read(a.ConfigPath + ".run")
	return err == nil && !exists
}

func (a *NFQWS2Adapter) firstStartScriptSafe(action string) error {
	lease, err := a.readLease()
	if err != nil {
		return err
	}
	if lease == nil || lease.FirstStart == nil {
		return nil
	}
	if err := a.verifyOwnedRuntime(lease, action != "restart" && action != "start" && action != "owned_start"); err != nil {
		return err
	}
	owner, err := a.owner()
	if err != nil {
		return err
	}
	init, _, err := nfqws2Read(a.InitPath)
	if err != nil {
		return err
	}
	if _, err := engineconfig.NFQWSFirstStartOriginalInit(init, owner); err != nil {
		return err
	}
	config, _, err := nfqws2Read(a.ConfigPath)
	if err != nil {
		return err
	}
	running, exists, err := nfqws2Read(a.ConfigPath + ".run")
	if err != nil {
		return err
	}
	if exists {
		if nfqws2Hash(config) != lease.ConfigHash {
			config, _, err = nfqws2Read(filepath.Join(lease.Transaction, "nfqws2.conf.staged"))
			if err != nil || nfqws2Hash(config) != lease.ConfigHash {
				return ErrReviewChanged
			}
		}
		return engineconfig.NFQWSFirstStartRunningConfig(config, owner, running)
	}
	return nil
}

func (a *NFQWS2Adapter) firstStartPIDPath() string {
	return filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(a.InitPath))), "var", "run", "nfqws2.pid")
}

func (a *NFQWS2Adapter) readFirstStartProcess(pid int) (components.NFQWSRuntimeProcessIdentity, error) {
	if a.firstStartProcessRead != nil {
		return a.firstStartProcessRead(pid)
	}
	return components.ReadNFQWSRuntimeProcessIdentity(pid)
}

// Readback binds the daemonised stock child to the reviewed exact argv and
// PID file after independently observing no prior process. It is not a child
// Wait receipt. A failed or ambiguous read is fenced, never guessed as owned.
func (a *NFQWS2Adapter) captureFirstStartProcess(config []byte) (*components.NFQWSRuntimeProcessIdentity, error) {
	pidRaw, exists, err := nfqws2Read(a.firstStartPIDPath())
	if err != nil || !exists {
		return nil, errors.New("NFQWS2 start has no exact PID readback")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(pidRaw)))
	if err != nil || pid <= 1 || strconv.Itoa(pid) != strings.TrimSpace(string(pidRaw)) {
		return nil, engineconfig.ErrNFQWSFirstStart
	}
	owner, err := a.owner()
	if err != nil {
		return nil, err
	}
	effective, err := engineconfig.NFQWSFirstStartEffectiveConfig(config, owner)
	if err != nil {
		return nil, err
	}
	args, err := engineconfig.NFQWSStartupArguments(effective, nil)
	if err != nil {
		return nil, err
	}
	program := filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(a.InitPath))), "usr", "bin", "nfqws2")
	expected := components.NFQWSRuntimeArgumentsSHA256(program, append([]string{"--daemon", "--pidfile=" + a.firstStartPIDPath()}, args...))
	identity, err := a.readFirstStartProcess(pid)
	if err != nil || identity.PID != pid || identity.Executable != program || identity.ArgumentsSHA256 != expected || identity.Start == "" || identity.BootID == "" {
		return nil, errors.New("NFQWS2 process does not match reviewed stock launch")
	}
	if a.firstStartProcessRead == nil && (a.inactivity == nil || identity.BootID != a.inactivity.identity.BootID) {
		return nil, ErrNFQWSManagedProcessUnknown
	}
	return &identity, nil
}

func (a *NFQWS2Adapter) startFirstStart(ctx context.Context, root string) error {
	if err := checkFirstStartReviewGuard(ctx); err != nil {
		return err
	}
	if a.firstStartReview == nil {
		return components.ErrStockNFQWSNative
	}
	owner, err := a.owner()
	if err != nil {
		return err
	}
	if err := a.firstStartReview.CheckCurrentWithOwnedInit(ctx, owner); err != nil {
		return err
	}
	lease, err := a.readLease()
	if err != nil || lease == nil || lease.FirstStart == nil {
		return ErrReviewChanged
	}
	config, _, err := nfqws2Read(a.ConfigPath)
	if err != nil || nfqws2Hash(config) != lease.ConfigHash {
		return ErrReviewChanged
	}
	if err := a.firstStartReview.ReviewClosedFirstStartParameters(ctx, config, owner); err != nil {
		return err
	}
	if err := a.reviewFirstStartScope(ctx, config, false); err != nil {
		return err
	}
	if lease.FirstStart.Phase == nfqws2FirstRunning || lease.FirstStart.Phase == nfqws2FirstStopped {
		if err := a.stopFirstStart(ctx, lease); err != nil {
			return err
		}
	}
	if err := a.firstStartRuntimeAbsent(ctx); err != nil {
		return err
	}
	updated := *lease
	first := *lease.FirstStart
	updated.FirstStart = &first
	if first.Phase == nfqws2FirstStarting {
		return errors.New("NFQWS2 start outcome is unknown; ownership fence retained")
	}
	if first.Phase != nfqws2FirstPrepared && first.Phase != nfqws2FirstStopped {
		return ErrReviewChanged
	}
	if err := checkFirstStartReviewGuard(ctx); err != nil {
		return err
	}
	first.Phase, first.Process = nfqws2FirstStarting, nil
	if err := a.writeLease(&updated); err != nil {
		return err
	}
	if err := a.firstStartReview.CheckCurrentWithOwnedInit(ctx, owner); err != nil {
		return err
	}
	if err := checkFirstStartReviewGuard(ctx); err != nil {
		return err
	}
	output, startErr := a.run(ctx, a.InitPath, "owned_start")
	identity, readErr := a.captureFirstStartProcess(config)
	if readErr != nil {
		return errors.Join(errors.New("NFQWS2 start outcome unconfirmed; ownership fence retained"), startErr, readErr)
	}
	first.Process = identity
	first.Phase = nfqws2FirstRunning
	if err := a.writeLease(&updated); err != nil {
		return err
	}
	if a.firstStartReceiptReady != nil {
		a.firstStartReceiptReady()
	}
	if err := a.reviewFirstStartScope(ctx, config, true); err != nil {
		return err
	}
	if err := a.firstStartReview.CheckCurrentWithOwnedInit(ctx, owner); err != nil {
		return err
	}
	if startErr != nil {
		return errors.New("start NFQWS2: " + shortOutput(output, startErr))
	}
	return nil
}

func checkFirstStartReviewGuard(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if guard, ok := ctx.Value(reviewGuardKey{}).(func(context.Context) error); ok && guard != nil {
		return guard(ctx)
	}
	return nil
}

func (m *Manager) closeFirstStartNativeReview() error {
	if m == nil {
		return nil
	}
	adapter, _ := m.adapter("nfqws2")
	a, ok := adapter.(*NFQWS2Adapter)
	if !ok || a.firstStartReview == nil {
		return nil
	}
	review := a.firstStartReview
	a.firstStartReview, a.firstStartReviewRoot = nil, ""
	return review.Close()
}

func (a *NFQWS2Adapter) verifyFirstStartRunning(ctx context.Context) error {
	lease, err := a.readLease()
	if err != nil {
		return err
	}
	if lease == nil || lease.FirstStart == nil {
		return nil
	}
	if lease.FirstStart.Phase != nfqws2FirstRunning || lease.FirstStart.Process == nil {
		return errors.New("NFQWS2 first-start runtime has no confirmed running receipt")
	}
	config, _, err := nfqws2Read(a.ConfigPath)
	if err != nil {
		return err
	}
	actual, err := a.captureFirstStartProcess(config)
	if err != nil || *actual != *lease.FirstStart.Process {
		return errors.New("NFQWS2 first-start process identity changed")
	}
	return nil
}

// This is an advisory data/readback check for the app's pre-probe ordering.
// It never grants execution: Apply independently repeats the whole review.
func (m *Manager) NFQWS2FirstStartNeedsApply(serviceID string, domains []string) bool {
	if m == nil || serviceID == "" || len(domains) == 0 {
		return false
	}
	for _, domain := range domains {
		if !validManagedDomain(domain) {
			return false
		}
	}
	if m.NFQWS2FirstStartAvailable() {
		return true
	}
	adapter, _ := m.adapter("nfqws2")
	a, ok := adapter.(*NFQWS2Adapter)
	if !ok || a.stockNativeOwner == nil {
		return false
	}
	lease, err := a.readLease()
	if err != nil || lease == nil || lease.FirstStart == nil || lease.FirstStart.Phase != nfqws2FirstRunning && lease.FirstStart.Phase != nfqws2FirstStopped {
		return false
	}
	if err := a.verifyOwnedRuntime(lease, false); err != nil {
		return false
	}
	if lease.FirstStart.Phase == nfqws2FirstRunning {
		if err := a.verifyFirstStartRunning(context.Background()); err != nil {
			return false
		}
	}
	committed, exists, err := m.Committed()
	if err != nil || !exists || committed.State != "committed" {
		return false
	}
	config, _, err := nfqws2Read(a.ConfigPath)
	if err != nil {
		return false
	}
	expected, err := a.firstStartConfig(committed, config)
	if err != nil || !bytes.Equal(expected, config) {
		return false
	}
	if lease.FirstStart.Phase == nfqws2FirstStopped {
		return true
	}
	for _, route := range committed.Routes {
		if route.ServiceID == serviceID && adapterID(route.Resolved) == a.ID() && !committed.SiteExclusions.excludesService(serviceID) {
			return !slices.Equal(sortedUnique(domains), sortedUnique(route.Domains))
		}
	}
	return true
}
