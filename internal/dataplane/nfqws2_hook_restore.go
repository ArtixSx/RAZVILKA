package dataplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

// Classes of the owned first-start mangle graph in one observation.
const (
	NFQWS2HooksFull  = "full"
	NFQWS2HooksLoss  = "loss"
	NFQWS2HooksOther = "other"
)

// Fixed restoration refusal and failure codes. They name no row, path,
// address, interface, queue or process value and may be audited as they are.
const (
	NFQWS2HookReasonPlan    = "plan-changed"
	NFQWS2HookReasonBusy    = "busy"
	NFQWS2HookReasonOwner   = "managed-owner-active"
	NFQWS2HookReasonSource  = "source-unavailable"
	NFQWS2HookReasonContext = "context"
	NFQWS2HookReasonGuard   = "review-guard"
	NFQWS2HookReasonLease   = "lease-not-running"
	NFQWS2HookReasonBinding = "transaction-binding"
	NFQWS2HookReasonFiles   = "files-changed"
	NFQWS2HookReasonProcess = "process-identity"
	NFQWS2HookReasonScope   = "scope-changed"
	NFQWS2HookReasonGraph   = "graph-outside-scope"
	NFQWS2HookReasonKernel  = "kernel-unreadable"
	NFQWS2HookReasonOther   = "kernel-other"
	NFQWS2HookReasonNative  = "native-review"
	NFQWS2HookReasonQueue   = "queue-binding"
	NFQWS2HookReasonChanged = "kernel-changed"
	NFQWS2HookReasonWrite   = "write-failed"
	NFQWS2HookReasonVerify  = "verify-failed"
)

var (
	// ErrNFQWS2HookRestore marks every refused or failed restoration. The
	// result's Reason holds its fixed code; foreign text stays behind Unwrap.
	ErrNFQWS2HookRestore = errors.New("NFQWS2 owned hook restoration did not complete")
	// ErrNFQWS2HookBusy is another dataplane operation or another live holder
	// of the shared NFQWS2 resources. A background caller skips; never queues.
	ErrNFQWS2HookBusy = errors.New("NFQWS2 owned hook restoration is busy")
	// ErrNFQWS2HookUncertain is a cleanup that could not prove or remove every
	// object this attempt created. Foreign objects are retained untouched.
	ErrNFQWS2HookUncertain = errors.New("NFQWS2 owned hook cleanup is uncertain; review is required")
)

type nfqws2HookRestoreError struct {
	reason, detail string
	cause          error
}

func (e *nfqws2HookRestoreError) Error() string {
	text := "NFQWS2 owned hook restoration refused: " + e.reason
	if e.detail != "" {
		text += " (" + e.detail + ")"
	}
	return text
}

func (e *nfqws2HookRestoreError) Unwrap() []error { return []error{ErrNFQWS2HookRestore, e.cause} }

// NFQWS2HookRestore is a detached report of one restoration attempt or one
// observation. It is neither a receipt nor a grant: every later effect
// repeats the whole admission and fresh kernel reads.
type NFQWS2HookRestore struct {
	Class      string // full, loss or other; empty before a kernel observation
	Families   []NFQWS2HookFamilyState
	Restored   []int               // Families whose graph was written and verified.
	Commands   []NFQWS2HookCommand // Every attempted write in order, cleanup included.
	Queue      *NFQWS2HookQueue    // Recorded before a write, never required.
	Reason     string              // Fixed code; empty on success or on a FULL no-op.
	RolledBack bool                // Cleanup proved every created object removed.
	Uncertain  bool                // Cleanup could not prove it; foreign objects retained.
	// Instance names the lease transaction and its running receipt once the
	// lease was read. It is a comparison value for a caller's in-memory
	// backoff, never a grant, and carries no path or process value.
	Instance string
}

type NFQWS2HookFamilyState struct {
	Family int
	Class  string
	Reason string // Fixed classifier code, only for other.
}

type NFQWS2HookCommand struct {
	Family int
	Args   []string
}

// NFQWS2HookQueue records the stock daemon's queue copy parameters. Their
// values are not reviewed; only the socket binding is required.
type NFQWS2HookQueue struct {
	Number    uint16
	CopyMode  uint8
	CopyRange uint32
}

// nfqws2HookSource is the restoration's only fact and tool source: the
// reviewed iptables/ip6tables paths, the complete -S inventory and the queue
// binding of the original bound inactivity source.
type nfqws2HookSource struct {
	iptables, ip6tables string
	read                func(context.Context) (BackendInventorySnapshot, error)
	queue               func(context.Context, uint16, components.NFQWSRuntimeProcessIdentity) (nfqws2FirstStartQueue, error)
}

func (s nfqws2HookSource) binary(family int) string {
	if family == 6 {
		return s.ip6tables
	}
	return s.iptables
}

var errNFQWS2HookSource = errors.New("NFQWS2 owned hook source is unavailable")

// Production binds only the original startup source; firstStartHookModel is
// a private deterministic test model and never bound by startup.
func (a *NFQWS2Adapter) firstStartHookSource() (nfqws2HookSource, error) {
	var none nfqws2HookSource
	if a.firstStartHookModel != nil {
		return a.firstStartHookModel(), nil
	}
	s := a.inactivity
	if s == nil || s.self != s || s.adapter != a || s.provider == nil {
		return none, errNFQWS2HookSource
	}
	return nfqws2HookSource{iptables: s.frozen.reader.IPTables, ip6tables: s.frozen.reader.IP6Tables, read: s.hookInventory,
		queue: func(ctx context.Context, queue uint16, receipt components.NFQWSRuntimeProcessIdentity) (nfqws2FirstStartQueue, error) {
			return nfqws2FirstStartQueueObserve(ctx, a, s, queue, receipt)
		}}, nil
}

// hookInventory is one complete inventory through the frozen admitted
// collector. Read itself captures every registered table of both families
// twice and fails unless both captures are byte-identical.
func (s *NFQWSRuntimeInactiveSource) hookInventory(ctx context.Context) (BackendInventorySnapshot, error) {
	var none BackendInventorySnapshot
	if err := s.current(ctx); err != nil {
		return none, err
	}
	image, err := s.frozen.Read(ctx, s.identity)
	if err != nil || image.Scope.Network != s.identity || image.Scope.ToolReviewID != s.frozen.review || image.IPTables != s.frozen.reader.IPTables || image.IP6Tables != s.frozen.reader.IP6Tables {
		return none, nfqws2InactiveAt("inventory.source", err)
	}
	return image, s.current(ctx)
}

// nfqws2HookPlan admits only a settled first-start plan: no LAN owner, one
// nfqws2 adapter and at least one route it resolves.
func nfqws2HookPlan(plan Plan) bool {
	if plan.State != "committed" || plan.SafeMode || !plan.Ready || plan.Noop || plan.LAN != nil || plan.PlanID == "" || len(plan.Routes) == 0 {
		return false
	}
	count := 0
	for _, id := range plan.Adapters {
		if id == "nfqws2" {
			count++
		}
	}
	return count == 1 && slices.ContainsFunc(plan.Routes, func(route Route) bool { return adapterID(route.Resolved) == "nfqws2" })
}

func (m *Manager) committedNFQWS2(expected Plan) (*NFQWS2Adapter, error) {
	current, exists, err := m.Committed()
	if err != nil || !exists || !reflect.DeepEqual(current, expected) {
		return nil, errors.Join(ErrReviewChanged, err)
	}
	registered, exists := m.adapter("nfqws2")
	a, ok := registered.(*NFQWS2Adapter)
	if !exists || !ok || a == nil {
		return nil, ErrReviewChanged
	}
	return a, nil
}

func nfqws2HookRefused(reason string, cause error) (NFQWS2HookRestore, error) {
	return NFQWS2HookRestore{Reason: reason}, &nfqws2HookRestoreError{reason: reason, cause: cause}
}

// RestoreCommittedNFQWS2Hooks re-creates only the owned first-start mangle
// graph that a firmware rewrite removed under the same live stock
// process. It never starts, stops or restarts NFQWS2, never flushes or inserts,
// and never adopts a partial or foreign graph. The exact empty IPv4 NAT graph
// may be recreated only when it and IPv4 mangle are entirely absent. The caller
// must hold its configuration/stop/revision operation lease; WithReviewGuard binds
// that authority before and after every effect. A busy dataplane or busy
// shared resources are skipped, never waited for.
func (m *Manager) RestoreCommittedNFQWS2Hooks(ctx context.Context, expected Plan) (NFQWS2HookRestore, error) {
	if m == nil || m.StateRoot == "" || ctx == nil || !nfqws2HookPlan(expected) {
		return nfqws2HookRefused(NFQWS2HookReasonPlan, ErrReviewChanged)
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if !m.tryBeginOperation() {
		return nfqws2HookRefused(NFQWS2HookReasonBusy, ErrNFQWS2HookBusy)
	}
	defer m.endOperation()
	verify := func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		current, exists, err := m.Committed()
		if err != nil || !exists || !reflect.DeepEqual(current, expected) {
			return errors.Join(ErrReviewChanged, err)
		}
		return m.checkPlanNetwork(ctx, expected)
	}
	if err := verify(ctx); err != nil {
		return nfqws2HookRefused(NFQWS2HookReasonPlan, err)
	}
	a, err := m.committedNFQWS2(expected)
	if err != nil {
		return nfqws2HookRefused(NFQWS2HookReasonPlan, err)
	}
	return a.restoreFirstStartHooks(ctx, expected, verify)
}

// ObserveCommittedNFQWS2Hooks classifies the owned graph read-only: no
// operation gate, resource lock, native review or write. A caller may skip
// its own admission only for full; every restoration repeats the whole check.
func (m *Manager) ObserveCommittedNFQWS2Hooks(ctx context.Context, expected Plan) (NFQWS2HookRestore, error) {
	if m == nil || m.StateRoot == "" || ctx == nil || !nfqws2HookPlan(expected) {
		return nfqws2HookRefused(NFQWS2HookReasonPlan, ErrReviewChanged)
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	a, err := m.committedNFQWS2(expected)
	if err != nil {
		return nfqws2HookRefused(NFQWS2HookReasonPlan, err)
	}
	return a.observeFirstStartHooks(ctx)
}

func (a *NFQWS2Adapter) activeOwner() bool {
	nfqws2ActiveAdapterMu.Lock()
	defer nfqws2ActiveAdapterMu.Unlock()
	return a.activeExecution != nil || a.activeProcess != nil
}

func (a *NFQWS2Adapter) observeFirstStartHooks(ctx context.Context) (NFQWS2HookRestore, error) {
	if a.activeOwner() {
		return nfqws2HookRefused(NFQWS2HookReasonOwner, ErrNFQWSScopedOwner)
	}
	if !nfqws2InactiveFinite(ctx) {
		return nfqws2HookRefused(NFQWS2HookReasonContext, ErrReviewChanged)
	}
	source, err := a.firstStartHookSource()
	if err != nil || source.read == nil {
		return nfqws2HookRefused(NFQWS2HookReasonSource, errors.Join(errNFQWS2HookSource, err))
	}
	lease, err := a.readLease()
	if err != nil || lease == nil || lease.FirstStart == nil || lease.FirstStart.Phase != nfqws2FirstRunning || lease.FirstStart.Process == nil {
		return nfqws2HookRefused(NFQWS2HookReasonLease, errors.Join(ErrReviewChanged, err))
	}
	instance := nfqws2HookInstance(lease)
	refused := func(reason string, cause error) (NFQWS2HookRestore, error) {
		result, err := nfqws2HookRefused(reason, cause)
		result.Instance = instance
		return result, err
	}
	owner, err := a.owner()
	if err != nil {
		return refused(NFQWS2HookReasonFiles, err)
	}
	config, configExists, configErr := nfqws2Read(a.ConfigPath)
	running, runningExists, runningErr := nfqws2Read(a.ConfigPath + ".run")
	if err := errors.Join(configErr, runningErr); err != nil || !configExists || !runningExists || nfqws2Hash(config) != lease.ConfigHash {
		return refused(NFQWS2HookReasonFiles, errors.Join(ErrReviewChanged, err))
	}
	graph, err := nfqws2FirstStartHookGraph(config, running, owner)
	if err != nil {
		return refused(NFQWS2HookReasonGraph, err)
	}
	snapshot, err := source.read(ctx)
	if err != nil {
		return refused(NFQWS2HookReasonKernel, err)
	}
	result := NFQWS2HookRestore{Instance: instance}
	nfqws2HookReport(&result, nfqws2ClassifyHookGraph(graph, snapshot))
	return result, nil
}

// nfqws2HookInstance digests the lease transaction and its running receipt
// {BootID, Start, PID}. A restarted process or another transaction is a new
// instance, so a caller's backoff and audit deduplication start over.
func nfqws2HookInstance(lease *nfqws2Lease) string {
	if lease == nil || lease.FirstStart == nil || lease.FirstStart.Process == nil {
		return ""
	}
	p := lease.FirstStart.Process
	digest := sha256.Sum256([]byte(lease.Transaction + "\x00" + p.BootID + "\x00" + p.Start + "\x00" + strconv.Itoa(p.PID)))
	return hex.EncodeToString(digest[:12])
}

// NFQWS2HookHintPath is the stock NDM netfilter hook that the package
// installs beside the registered adapter's init script. Data only: watching
// it is a wake-up hint and grants no admission, review or write.
func (m *Manager) NFQWS2HookHintPath() string {
	registered, exists := m.adapter("nfqws2")
	a, ok := registered.(*NFQWS2Adapter)
	if !exists || !ok || a == nil || !filepath.IsAbs(a.InitPath) || filepath.Clean(a.InitPath) != a.InitPath {
		return ""
	}
	return filepath.Join(filepath.Dir(filepath.Dir(a.InitPath)), "ndm", "netfilter.d", "100-nfqws2.sh")
}

func nfqws2HookClassName(class nfqws2HookClass) string {
	switch class {
	case nfqws2HookFull:
		return NFQWS2HooksFull
	case nfqws2HookLoss:
		return NFQWS2HooksLoss
	}
	return NFQWS2HooksOther
}

// Only the classifier's fixed vocabulary leaves the package.
func nfqws2HookReasonCode(err error) string {
	var reason nfqws2HookReason
	switch {
	case err == nil:
		return ""
	case errors.As(err, &reason):
		return string(reason)
	case errors.Is(err, errNFQWS2HookGraph):
		return NFQWS2HookReasonGraph
	}
	return "unknown"
}

func nfqws2HookReport(result *NFQWS2HookRestore, c nfqws2HookClassification) {
	result.Class, result.Families = nfqws2HookClassName(c.Class), nil
	for _, family := range c.Families {
		result.Families = append(result.Families, NFQWS2HookFamilyState{Family: family.Family, Class: nfqws2HookClassName(family.Class), Reason: nfqws2HookReasonCode(family.Reason)})
	}
}

// restoreFirstStartHooks is the Manager path: no managed owner, the shared
// resource locks (busy skips), then the same locked restoration as boot.
func (a *NFQWS2Adapter) restoreFirstStartHooks(ctx context.Context, plan Plan, review func(context.Context) error) (NFQWS2HookRestore, error) {
	if a.activeOwner() {
		return nfqws2HookRefused(NFQWS2HookReasonOwner, ErrNFQWSScopedOwner)
	}
	unlock, err := a.lockResources()
	if errors.Is(err, errNFQWS2ResourceBusy) {
		return nfqws2HookRefused(NFQWS2HookReasonBusy, errors.Join(ErrNFQWS2HookBusy, err))
	}
	if err != nil {
		return nfqws2HookRefused(NFQWS2HookReasonFiles, err)
	}
	defer unlock()
	lease, err := a.readLease()
	if err != nil {
		return nfqws2HookRefused(NFQWS2HookReasonLease, err)
	}
	return a.restoreFirstStartHooksLocked(ctx, plan, lease, review)
}

// nfqws2HookAttempt is one bounded restoration under lockResources. Every
// field is detached data read by this attempt; none is a reusable grant.
type nfqws2HookAttempt struct {
	a         *NFQWS2Adapter
	plan      Plan
	lease     *nfqws2Lease
	review    func(context.Context) error
	source    nfqws2HookSource
	owner     string
	config    []byte
	running   []byte
	graph     nfqws2HookGraph
	receipt   components.NFQWSRuntimeProcessIdentity
	files     []nfqws2HookFile
	initial   BackendInventorySnapshot
	families  []nfqws2HookFamily
	natLoss   bool
	queue     nfqws2FirstStartQueue
	native    *components.StockNFQWSNativeReview
	order     []int
	attempted map[int][]BackendInventoryRow
	// A failed command is not an ownership receipt, even if its exact row
	// appears afterwards: it may be a timed-out effect or a concurrent writer.
	unacknowledged []BackendInventoryRow
	detail         string
	result         NFQWS2HookRestore
}

// restoreFirstStartHooksLocked re-creates the owned mangle graph of every
// family in LOSS when no family is OTHER (decisions 1-3). The caller holds
// lockResources and its operation gate; review re-proves its authority before
// every command. FULL is a no-op; anything else refuses before the first
// write. Complete IPv4 loss also permits its exact empty NAT graph. After the
// first write any failure, cancellation or guard refusal
// removes only this attempt's exact objects.
func (a *NFQWS2Adapter) restoreFirstStartHooksLocked(ctx context.Context, plan Plan, lease *nfqws2Lease, review func(context.Context) error) (NFQWS2HookRestore, error) {
	t := &nfqws2HookAttempt{a: a, plan: plan, lease: lease, review: review, attempted: map[int][]BackendInventoryRow{}}
	reason, err := t.admit(ctx)
	if err == nil && t.result.Class == NFQWS2HooksLoss {
		reason, err = t.prepare(ctx)
		if err == nil {
			reason, err = t.write(ctx)
			if err != nil && len(t.order) != 0 {
				err = errors.Join(err, t.rollback(ctx))
			}
		}
	}
	// The retained component review only spans this attempt's own checks.
	if t.native != nil {
		if closeErr := t.native.Close(); closeErr != nil && err == nil {
			reason, err = NFQWS2HookReasonNative, closeErr
		}
	}
	if err != nil {
		failure := t.fail(reason, err)
		return t.result, failure
	}
	return t.result, nil
}

func (t *nfqws2HookAttempt) fail(reason string, cause error) error {
	t.result.Reason = reason
	return &nfqws2HookRestoreError{reason: reason, detail: t.detail, cause: cause}
}

// The adapter state root is <manager root>/runtime/nfqws2, so the committed
// transaction is derived from it, never from caller data.
func (a *NFQWS2Adapter) firstStartTransaction(plan Plan) (string, bool) {
	runtime := filepath.Dir(a.StateRoot)
	if !filepath.IsAbs(a.StateRoot) || filepath.Clean(a.StateRoot) != a.StateRoot || filepath.Base(a.StateRoot) != a.ID() || filepath.Base(runtime) != "runtime" ||
		plan.PlanID == "" || filepath.Base(plan.PlanID) != plan.PlanID || plan.PlanID == "." || plan.PlanID == ".." {
		return "", false
	}
	return filepath.Join(filepath.Dir(runtime), "transactions", plan.PlanID, a.ID()), true
}

type nfqws2HookFile struct {
	data   []byte
	exists bool
}

// Lease, live and staged files and the PID file must stay byte-identical for
// the whole attempt: a restoration never consumes or rewrites any of them.
func (a *NFQWS2Adapter) firstStartHookFiles(transaction string) ([]nfqws2HookFile, error) {
	lists := a.ownedListPaths()
	paths := []string{filepath.Join(a.StateRoot, nfqws2LeaseFile), a.ConfigPath, a.ConfigPath + ".run", a.InitPath, a.firstStartPIDPath(),
		filepath.Join(transaction, "nfqws2.conf.staged"), filepath.Join(transaction, "S51nfqws2.staged"), lists[0], lists[1], lists[2], lists[3]}
	files := make([]nfqws2HookFile, 0, len(paths))
	for _, path := range paths {
		data, exists, err := nfqws2Read(path)
		if err != nil {
			return nil, err
		}
		files = append(files, nfqws2HookFile{data: data, exists: exists})
	}
	return files, nil
}

func (t *nfqws2HookAttempt) admit(ctx context.Context) (string, error) {
	a := t.a
	if a.activeOwner() {
		return NFQWS2HookReasonOwner, ErrNFQWSScopedOwner
	}
	if !nfqws2InactiveFinite(ctx) {
		return NFQWS2HookReasonContext, ErrReviewChanged
	}
	source, err := a.firstStartHookSource()
	if err != nil || a.Runner == nil || source.read == nil || source.queue == nil || !filepath.IsAbs(source.iptables) || !filepath.IsAbs(source.ip6tables) || source.iptables == source.ip6tables {
		return NFQWS2HookReasonSource, errors.Join(errNFQWS2HookSource, err)
	}
	t.source = source
	if t.review == nil {
		return NFQWS2HookReasonGuard, ErrReviewChanged
	}
	if err := t.review(ctx); err != nil {
		return NFQWS2HookReasonGuard, err
	}
	if reason, err := t.bind(); err != nil {
		return reason, err
	}
	if reason, err := t.identity(ctx); err != nil {
		return reason, err
	}
	snapshot, err := t.source.read(ctx)
	if err != nil {
		return NFQWS2HookReasonKernel, err
	}
	c := nfqws2ClassifyHookGraph(t.graph, snapshot)
	nfqws2HookReport(&t.result, c)
	switch c.Class {
	case nfqws2HookFull:
		return "", nil
	case nfqws2HookLoss:
		t.natLoss = c.NATLoss
		for _, family := range t.graph.Families {
			if slices.Contains(c.restore(), family.Family) {
				t.families = append(t.families, family)
			}
		}
		if len(t.families) == 0 {
			return NFQWS2HookReasonOther, errNFQWS2HookGraph
		}
		t.initial = snapshot
		return "", nil
	}
	t.detail = nfqws2HookReasonCode(c.Reason)
	return NFQWS2HookReasonOther, c.Reason
}

// bind proves the running lease of exactly this committed transaction and
// the closed files it owns, then renders the expected graph from them.
func (t *nfqws2HookAttempt) bind() (string, error) {
	a, lease := t.a, t.lease
	if lease == nil || lease.FirstStart == nil || lease.FirstStart.Phase != nfqws2FirstRunning || lease.FirstStart.Process == nil {
		return NFQWS2HookReasonLease, errors.New("NFQWS2 first-start runtime has no confirmed running receipt")
	}
	t.result.Instance = nfqws2HookInstance(lease)
	current, err := a.readLease()
	if err != nil || !reflect.DeepEqual(current, lease) {
		return NFQWS2HookReasonLease, errors.Join(ErrReviewChanged, err)
	}
	transaction, ok := a.firstStartTransaction(t.plan)
	if !ok || lease.Transaction != transaction {
		return NFQWS2HookReasonBinding, ErrReviewChanged
	}
	staged, exists, err := nfqws2Read(filepath.Join(transaction, "nfqws2.conf.staged"))
	if err != nil || !exists || nfqws2Hash(staged) != lease.ConfigHash {
		return NFQWS2HookReasonBinding, errors.Join(ErrReviewChanged, err)
	}
	init, exists, err := nfqws2Read(filepath.Join(transaction, "S51nfqws2.staged"))
	if err != nil || !exists || nfqws2Hash(init) != lease.InitHash {
		return NFQWS2HookReasonBinding, errors.Join(ErrReviewChanged, err)
	}
	owned, err := a.verifyOwnedLists(false)
	if err != nil || !reflect.DeepEqual(owned, lease) {
		return NFQWS2HookReasonFiles, errors.Join(ErrReviewChanged, err)
	}
	if err := a.firstStartScriptSafe("status"); err != nil {
		return NFQWS2HookReasonFiles, err
	}
	owner, err := a.owner()
	if err != nil {
		return NFQWS2HookReasonFiles, err
	}
	config, exists, err := nfqws2Read(a.ConfigPath)
	if err != nil || !exists {
		return NFQWS2HookReasonFiles, errors.Join(ErrReviewChanged, err)
	}
	expected, err := a.firstStartConfig(t.plan, config)
	if err != nil || !bytes.Equal(expected, config) {
		return NFQWS2HookReasonFiles, errors.Join(ErrReviewChanged, err)
	}
	running, exists, err := nfqws2Read(a.ConfigPath + ".run")
	if err != nil || !exists {
		return NFQWS2HookReasonFiles, errors.Join(ErrReviewChanged, err)
	}
	if err := engineconfig.NFQWSFirstStartRunningAllLAN(config, owner, running); err != nil {
		return NFQWS2HookReasonFiles, err
	}
	graph, err := nfqws2FirstStartHookGraph(config, running, owner)
	if err != nil {
		return NFQWS2HookReasonGraph, err
	}
	files, err := a.firstStartHookFiles(transaction)
	if err != nil {
		return NFQWS2HookReasonFiles, err
	}
	t.owner, t.config, t.running, t.graph, t.files, t.receipt = owner, config, running, graph, files, *lease.FirstStart.Process
	return "", nil
}

// identity re-proves the same live receipt as the only NFQ process and the
// closed scope on the fresh WAN.
func (t *nfqws2HookAttempt) identity(ctx context.Context) (string, error) {
	if err := t.a.verifyFirstStartRunning(ctx); err != nil {
		return NFQWS2HookReasonProcess, err
	}
	if err := t.a.reviewFirstStartProcess(ctx, t.receipt); err != nil {
		return NFQWS2HookReasonProcess, err
	}
	if err := t.a.reviewFirstStartScope(ctx, t.config, true); err != nil {
		return NFQWS2HookReasonScope, err
	}
	return "", nil
}

// prepare opens the original component writer review and holds it, with the
// update journal lock, across every write. No DryRun: nothing is executed, so
// only currentness of the retained binary, guarded init and assets is
// rechecked. It then binds the queue to the receipt and requires a second
// kernel read identical to the admitted one.
func (t *nfqws2HookAttempt) prepare(ctx context.Context) (string, error) {
	a := t.a
	if a.stockNativeOwner == nil || a.firstStartReview != nil {
		return NFQWS2HookReasonNative, components.ErrStockNFQWSNative
	}
	effective, err := engineconfig.NFQWSFirstStartEffectiveConfig(t.config, t.owner)
	if err != nil {
		return NFQWS2HookReasonNative, err
	}
	arguments, err := engineconfig.NFQWSStartupArguments(effective, nil)
	if err != nil {
		return NFQWS2HookReasonNative, err
	}
	nativeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	review, err := a.stockNativeOwner.ReviewStockNFQWSNative(nativeCtx, arguments)
	cancel()
	if err != nil {
		return NFQWS2HookReasonNative, err
	}
	t.native = review
	if err := review.CheckCurrentWithOwnedInit(ctx, t.owner); err != nil {
		return NFQWS2HookReasonNative, err
	}
	queue, err := t.source.queue(ctx, t.graph.Queue, t.receipt)
	if err != nil || queue.Number != t.graph.Queue {
		return NFQWS2HookReasonQueue, errors.Join(errNFQWS2FirstStartQueue, err)
	}
	t.queue = queue
	t.result.Queue = &NFQWS2HookQueue{Number: queue.Number, CopyMode: queue.CopyMode, CopyRange: queue.CopyRange}
	second, err := t.source.read(ctx)
	if err != nil {
		return NFQWS2HookReasonKernel, err
	}
	if !nfqws2HookSameRows(second.Rows, t.initial.Rows) {
		return NFQWS2HookReasonChanged, ErrReviewChanged
	}
	return t.current(ctx)
}

// guard runs before every command: the caller's authority, cancellation and
// the unchanged lease. It is never consulted during cleanup.
func (t *nfqws2HookAttempt) guard(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := t.review(ctx); err != nil {
		return err
	}
	lease, err := t.a.readLease()
	if err != nil || !reflect.DeepEqual(lease, t.lease) {
		return errors.Join(ErrReviewChanged, err)
	}
	return ctx.Err()
}

// current is the full checkpoint before the first write, before the jumps
// and after the last write: authority, files, process, scope, native
// currentness and the same queue binding.
func (t *nfqws2HookAttempt) current(ctx context.Context) (string, error) {
	if err := t.guard(ctx); err != nil {
		return NFQWS2HookReasonGuard, err
	}
	files, err := t.a.firstStartHookFiles(t.lease.Transaction)
	if err != nil || !reflect.DeepEqual(files, t.files) {
		return NFQWS2HookReasonFiles, errors.Join(ErrReviewChanged, err)
	}
	if reason, err := t.identity(ctx); err != nil {
		return reason, err
	}
	if t.native == nil {
		return NFQWS2HookReasonNative, components.ErrStockNFQWSNative
	}
	if err := t.native.CheckCurrentWithOwnedInit(ctx, t.owner); err != nil {
		return NFQWS2HookReasonNative, err
	}
	queue, err := t.source.queue(ctx, t.graph.Queue, t.receipt)
	if err != nil || queue != t.queue {
		return NFQWS2HookReasonQueue, errors.Join(errNFQWS2FirstStartQueue, err)
	}
	if err := t.guard(ctx); err != nil {
		return NFQWS2HookReasonGuard, err
	}
	return "", nil
}

// exec records only acknowledged effects as cleanup receipts. An ambiguous
// outcome must be independently absent before cleanup may remove other effects.
func (t *nfqws2HookAttempt) exec(ctx context.Context, family int, tokens ...string) (string, error) {
	return t.execTable(ctx, family, "mangle", tokens...)
}

func (t *nfqws2HookAttempt) execTable(ctx context.Context, family int, table string, tokens ...string) (string, error) {
	if err := t.guard(ctx); err != nil {
		return NFQWS2HookReasonGuard, err
	}
	if !slices.Contains(t.order, family) {
		t.order = append(t.order, family)
	}
	row := BackendInventoryRow{Family: family, Table: table, Tokens: slices.Clone(tokens)}
	args := append([]string{"-t", table}, tokens...)
	t.result.Commands = append(t.result.Commands, NFQWS2HookCommand{Family: family, Args: slices.Clone(args)})
	if _, err := runFirewallCommand(ctx, t.a.Runner, t.source.binary(family), args...); err != nil {
		t.unacknowledged = append(t.unacknowledged, row)
		return NFQWS2HookReasonWrite, err
	}
	t.attempted[family] = append(t.attempted[family], row)
	return "", nil
}

// write appends chains and bodies first; the jumps follow, last in their
// built-in chains as stock appends them, only after an exact readback and a
// full checkpoint. A completely lost empty NAT graph follows the same order.
// Nothing is flushed or inserted.
func (t *nfqws2HookAttempt) write(ctx context.Context) (string, error) {
	if t.natLoss {
		if reason, err := t.execTable(ctx, 4, "nat", t.graph.NAT[0].Tokens...); err != nil {
			return reason, err
		}
	}
	for _, g := range t.families {
		for _, chain := range g.Chains {
			if reason, err := t.exec(ctx, g.Family, "-N", chain); err != nil {
				return reason, err
			}
		}
		for _, rule := range g.Bodies {
			if reason, err := t.exec(ctx, g.Family, rule.tokens()...); err != nil {
				return reason, err
			}
		}
	}
	if reason, err := t.readback(ctx, false); err != nil {
		return reason, err
	}
	if reason, err := t.current(ctx); err != nil {
		return reason, err
	}
	if t.natLoss {
		if reason, err := t.execTable(ctx, 4, "nat", t.graph.NAT[1].Tokens...); err != nil {
			return reason, err
		}
	}
	for _, g := range t.families {
		for _, jump := range g.Jumps {
			if reason, err := t.exec(ctx, g.Family, jump.tokens()...); err != nil {
				return reason, err
			}
		}
	}
	if reason, err := t.readback(ctx, true); err != nil {
		return reason, err
	}
	if reason, err := t.saveReachable(ctx); err != nil {
		return reason, err
	}
	if reason, err := t.current(ctx); err != nil {
		return reason, err
	}
	for _, g := range t.families {
		t.result.Restored = append(t.result.Restored, g.Family)
	}
	return "", nil
}

// readback requires the fresh inventory to be the admitted one plus exactly
// this attempt's rows. Unattached, each owned body is exact and in order;
// attached, the whole graph classifies FULL.
func (t *nfqws2HookAttempt) readback(ctx context.Context, attached bool) (string, error) {
	snapshot, err := t.source.read(ctx)
	if err != nil {
		return NFQWS2HookReasonKernel, err
	}
	var created []BackendInventoryRow
	for _, family := range t.order {
		created = append(created, t.attempted[family]...)
	}
	remainder, ok := nfqws2HookWithout(snapshot.Rows, created)
	if !ok || !nfqws2HookSameRows(remainder, t.initial.Rows) {
		return NFQWS2HookReasonChanged, ErrReviewChanged
	}
	if attached {
		if c := nfqws2ClassifyHookGraph(t.graph, snapshot); c.Class != nfqws2HookFull {
			t.detail = nfqws2HookReasonCode(c.Reason)
			return NFQWS2HookReasonVerify, errors.Join(ErrReviewChanged, c.Reason)
		}
		return "", nil
	}
	for _, g := range t.families {
		image, ok := nfqws2RowsMangleImage(snapshot.Rows, g.Family)
		if !ok {
			return NFQWS2HookReasonChanged, ErrReviewChanged
		}
		for _, chain := range g.Chains {
			if !slices.EqualFunc(image.rules[chain], g.bodyArgs(chain), slices.Equal[[]string]) {
				return NFQWS2HookReasonChanged, ErrReviewChanged
			}
		}
	}
	return "", nil
}

func (a *NFQWS2Adapter) iptablesSavePath() string {
	if a.IPTablesSave != "" {
		return a.IPTablesSave
	}
	return findExecutable("/opt/sbin/iptables-save", "/opt/bin/iptables-save", "iptables-save")
}

// saveReachable repeats Health's own IPv4 proof of both owned hooks.
func (t *nfqws2HookAttempt) saveReachable(ctx context.Context) (string, error) {
	path := t.a.iptablesSavePath()
	if path == "" {
		return NFQWS2HookReasonVerify, errors.New("iptables-save is unavailable")
	}
	output, err := t.a.run(ctx, path)
	if err != nil || !nfqws2ClosedReachableQueueRule(output, t.config, t.running, t.owner) || !nfqws2ClosedReachablePreRule(output, t.config, t.running, t.owner) {
		return NFQWS2HookReasonVerify, errors.Join(errors.New("restored NFQWS2 hooks were not confirmed"), err)
	}
	return "", nil
}

// rollback removes only this attempt's exact objects under its own bounded
// context. It first proves that every owned mangle row of each written family
// is one of them; a single foreign owned object retains everything.
func (t *nfqws2HookAttempt) rollback(parent context.Context) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 30*time.Second)
	defer cancel()
	uncertain := func(err error) error {
		t.result.Uncertain = true
		return errors.Join(ErrNFQWS2HookUncertain, err)
	}
	// A firmware rewrite racing the attempt makes one capture pair unstable;
	// only a few bounded rereads are made, never a guess.
	var snapshot BackendInventorySnapshot
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(time.Duration(attempt) * 250 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return uncertain(errors.Join(err, ctx.Err()))
			case <-timer.C:
			}
		}
		if snapshot, err = t.source.read(ctx); err == nil {
			break
		}
	}
	if err != nil {
		return uncertain(err)
	}
	for _, row := range snapshot.Rows {
		if slices.ContainsFunc(t.unacknowledged, func(unknown BackendInventoryRow) bool {
			return nfqws2HookSameRow(row, unknown)
		}) {
			return uncertain(errors.New("an unacknowledged firewall effect is present; nothing was removed"))
		}
	}
	removals, ok := nfqws2HookCleanup(snapshot.Rows, t.order, t.attempted, t.unacknowledged...)
	if !ok {
		return uncertain(errors.New("a foreign owned object is present; nothing was removed"))
	}
	var failures []error
	for _, row := range removals {
		args := nfqws2HookRemoval(row)
		t.result.Commands = append(t.result.Commands, NFQWS2HookCommand{Family: row.Family, Args: slices.Clone(args)})
		if _, err := runFirewallCommand(ctx, t.a.Runner, t.source.binary(row.Family), args...); err != nil {
			failures = append(failures, err)
		}
	}
	after, err := t.source.read(ctx)
	if err != nil {
		return uncertain(errors.Join(append(failures, err)...))
	}
	if residue, ok := nfqws2HookCleanup(after.Rows, t.order, t.attempted, t.unacknowledged...); !ok || len(residue) != 0 {
		return uncertain(errors.Join(failures...))
	}
	t.result.RolledBack = true
	return nil
}

// nfqws2HookCleanup lists the present rows of each written family's exact
// attempt in reverse order: jumps, then bodies, then chains. It refuses when
// any owned row in a touched table of such a family is not one of them.
func nfqws2HookCleanup(rows []BackendInventoryRow, order []int, attempted map[int][]BackendInventoryRow, unacknowledged ...BackendInventoryRow) ([]BackendInventoryRow, bool) {
	var removals []BackendInventoryRow
	for i := len(order) - 1; i >= 0; i-- {
		family, pending := order[i], attempted[order[i]]
		tables := map[string]bool{"mangle": true}
		for _, row := range pending {
			tables[row.Table] = true
		}
		for _, row := range unacknowledged {
			if row.Family == family {
				tables[row.Table] = true
			}
		}
		present := make([]bool, len(pending))
		for _, row := range rows {
			if row.Family != family || !tables[row.Table] || !nfqws2HookOwnedRow(row) {
				continue
			}
			index := -1
			for j, candidate := range pending {
				if !present[j] && nfqws2HookSameRow(candidate, row) {
					index = j
					break
				}
			}
			if index < 0 {
				return nil, false
			}
			present[index] = true
		}
		for j := len(pending) - 1; j >= 0; j-- {
			if present[j] {
				removals = append(removals, pending[j])
			}
		}
	}
	return removals, true
}

// nfqws2HookRemoval is the exact inverse of one attempted row: -D of
// the same rule, or -X of a created chain once its bodies are gone.
func nfqws2HookRemoval(row BackendInventoryRow) []string {
	op := "-D"
	if row.Tokens[0] == "-N" {
		op = "-X"
	}
	return append([]string{"-t", row.Table, op}, row.Tokens[1:]...)
}

// nfqws2HookWithout removes each listed row exactly once, keeping kernel
// order; a listed row that is absent fails.
func nfqws2HookWithout(rows, remove []BackendInventoryRow) ([]BackendInventoryRow, bool) {
	pending := slices.Clone(remove)
	kept := make([]BackendInventoryRow, 0, len(rows))
	for _, row := range rows {
		index := slices.IndexFunc(pending, func(candidate BackendInventoryRow) bool { return nfqws2HookSameRow(candidate, row) })
		if index >= 0 {
			pending = slices.Delete(pending, index, index+1)
			continue
		}
		kept = append(kept, row)
	}
	return kept, len(pending) == 0
}

func nfqws2HookSameRow(left, right BackendInventoryRow) bool {
	return left.Family == right.Family && left.Table == right.Table && slices.Equal(left.Tokens, right.Tokens)
}

func nfqws2HookSameRows(left, right []BackendInventoryRow) bool {
	return slices.EqualFunc(left, right, nfqws2HookSameRow)
}
