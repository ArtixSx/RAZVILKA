package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

type nfqws2InactiveFailure struct {
	stage string
	cause error
}

func (e *nfqws2InactiveFailure) Error() string { return "NFQWS runtime inactivity: " + e.stage }
func (e *nfqws2InactiveFailure) Unwrap() error { return e.cause }
func nfqws2InactiveAt(stage string, err error) error {
	return &nfqws2InactiveFailure{stage: stage, cause: errors.Join(ErrNFQWSManagedKernelOwner, err)}
}

// NFQWSRuntimeInactiveStage reports only private fixed source branch labels.
// Foreign path/process/command text is retained through Unwrap, never formatted.
func NFQWSRuntimeInactiveStage(err error) string {
	stage, remaining := "", 64
	var visit func(error)
	visit = func(err error) {
		if err == nil || remaining == 0 {
			return
		}
		remaining--
		if failure, ok := err.(*nfqws2InactiveFailure); ok && failure != nil {
			stage = failure.stage
		}
		switch e := err.(type) {
		case interface{ Unwrap() []error }:
			for _, cause := range e.Unwrap() {
				visit(cause)
			}
		case interface{ Unwrap() error }:
			visit(e.Unwrap())
		}
	}
	visit(err)
	return stage
}

type nfqws2InactivePlatform struct {
	procRoot  string
	selfPID   int
	readlink  func(string) (string, error)
	protected func(info os.FileInfo, directory, private bool) bool
	queues    func(context.Context) ([]nfqwsScopedQueue, error)
	sockets   func(context.Context) (string, error)
}

// NFQWSRuntimeInactiveSource has no caller-supplied snapshot, predicate,
// callback, queue number or inactive flag. The same concrete collector/provider
// and its frozen admitted tool reader are retained for every fresh observation.
// It is negative runtime evidence only; it cannot activate, stop or clean up.
type NFQWSRuntimeInactiveSource struct {
	self      *NFQWSRuntimeInactiveSource
	adapter   *NFQWS2Adapter
	startup   NFQWS2Adapter
	inventory *BackendInventory
	frozen    BackendInventory
	provider  *netidentity.Provider
	identity  netidentity.Identity
	platform  nfqws2InactivePlatform
	bound     bool // Protected with the adapter association mutex.
}

func nfqws2InactiveFinite(ctx context.Context) bool {
	if ctx == nil || ctx.Err() != nil {
		return false
	}
	d, ok := ctx.Deadline()
	return ok && time.Now().Before(d)
}

// NewNFQWSRuntimeInactiveSource authenticates the actual source at trusted
// startup. This read is not cached as absence: VerifyRuntimeInactive reads the
// complete collector and process/queue inventories again on every invocation.
func NewNFQWSRuntimeInactiveSource(ctx context.Context, a *NFQWS2Adapter, inventory *BackendInventory) (*NFQWSRuntimeInactiveSource, error) {
	if !nfqws2InactiveFinite(ctx) || a == nil || inventory == nil || inventory.reader.Provider == nil || inventory.reader.CheckTools == nil ||
		!sameNetworkPolicyDependency(inventory.reader.Runner, inventory.reader.Runner) || !lanPolicyHash(inventory.review) {
		return nil, nfqws2InactiveAt("source", nil)
	}
	platform, err := nfqws2InactiveSystemPlatform()
	if err != nil {
		return nil, nfqws2InactiveAt("platform", err)
	}
	r := &NFQWSRuntimeInactiveSource{adapter: a, startup: *a, inventory: inventory, frozen: *inventory, provider: inventory.reader.Provider, platform: platform}
	r.self = r
	if !r.coordinates() {
		return nil, nfqws2InactiveAt("coordinates", nil)
	}
	identity, err := r.provider.Observe(ctx)
	if err != nil {
		return nil, nfqws2InactiveAt("identity", err)
	}
	r.identity = identity
	image, err := r.frozen.Read(ctx, identity)
	if err != nil || image.RequireComplete() != nil || image.Scope.Network != identity || image.Scope.ToolReviewID != r.frozen.review ||
		image.IPTables != r.frozen.reader.IPTables || image.IP6Tables != r.frozen.reader.IP6Tables {
		return nil, nfqws2InactiveAt("inventory", err)
	}
	closing, err := r.provider.Observe(ctx)
	if err != nil || closing != identity || !r.coordinates() || ctx.Err() != nil {
		return nil, nfqws2InactiveAt("closure", errors.Join(err, ctx.Err()))
	}
	return r, nil
}

// Bind accepts only the original adapter once. Copies, replacement collectors
// and a second registration cannot reuse or replace this source association.
func (r *NFQWSRuntimeInactiveSource) Bind(a *NFQWS2Adapter) error {
	if r == nil || r.self != r || a == nil || r.adapter != a || !r.coordinates() {
		return nfqws2InactiveAt("source", nil)
	}
	nfqws2ActiveAdapterMu.Lock()
	defer nfqws2ActiveAdapterMu.Unlock()
	if r.bound || a.inactivity != nil {
		return nfqws2InactiveAt("source", nil)
	}
	r.bound, a.inactivity = true, r
	return nil
}

func (r *NFQWSRuntimeInactiveSource) coordinates() bool {
	if r == nil || r.self != r || r.adapter == nil || r.inventory == nil || r.provider == nil || r.frozen.reader.Provider != r.provider ||
		r.inventory.reader.Provider != r.provider || r.inventory.review != r.frozen.review || r.inventory.reader.NFTABI != r.frozen.reader.NFTABI ||
		r.inventory.reader.IPTables != r.frozen.reader.IPTables || r.inventory.reader.IP6Tables != r.frozen.reader.IP6Tables ||
		!sameNetworkPolicyDependency(r.inventory.reader.Runner, r.frozen.reader.Runner) {
		return false
	}
	a, original := r.adapter, &r.startup
	if filepath.Base(original.StateRoot) != "nfqws2" || a.StateRoot != original.StateRoot || a.ConfigPath != original.ConfigPath ||
		a.InitPath != original.InitPath || a.UserListPath != original.UserListPath || a.IPSetListPath != original.IPSetListPath || a.Configs != original.Configs ||
		!sameNetworkPolicyDependency(a.Runner, original.Runner) {
		return false
	}
	seen := map[string]bool{}
	for _, path := range []string{original.StateRoot, original.ConfigPath, original.InitPath, original.UserListPath, original.IPSetListPath} {
		if !nfqws2ManagedPath(path) || path == filepath.VolumeName(path)+string(filepath.Separator) || seen[path] {
			return false
		}
		seen[path] = true
	}
	return true
}

func (r *NFQWSRuntimeInactiveSource) current(ctx context.Context) error {
	if ctx.Err() != nil || !r.coordinates() || !nfqws2ActiveAdapterMu.TryLock() {
		return nfqws2InactiveAt("participants", ctx.Err())
	}
	valid := r.bound && r.adapter.inactivity == r && r.adapter.activeProcess == nil && r.adapter.activeExecution == nil
	nfqws2ActiveAdapterMu.Unlock()
	if !valid {
		return nfqws2InactiveAt("participants", nil)
	}
	return nil
}

func (r *NFQWSRuntimeInactiveSource) verify(parent context.Context, platform nfqws2InactivePlatform) error {
	return r.verifyWithSources(parent, platform, r.provider.WithCurrent, r.frozen.Read)
}

// Private model seam. Exported construction and the adapter method always use
// the concrete provider and frozen collector above, never these as caller input.
func (r *NFQWSRuntimeInactiveSource) verifyWithSources(parent context.Context, platform nfqws2InactivePlatform,
	withCurrent func(context.Context, func(context.Context, netidentity.Identity) error) error,
	read func(context.Context, netidentity.Identity) (BackendInventorySnapshot, error)) error {
	if !nfqws2InactiveFinite(parent) || r == nil || r.identity.Validate() != nil || platform.procRoot == "" || platform.readlink == nil || platform.protected == nil ||
		platform.selfPID < 1 || platform.queues == nil || platform.sockets == nil || withCurrent == nil || read == nil {
		return nfqws2InactiveAt("source", nil)
	}
	ctx, cancel := context.WithTimeout(parent, 16*time.Second)
	defer cancel()
	if err := r.current(ctx); err != nil {
		return err
	}
	var opening nfqws2InactiveFiles
	uses := 0
	err := withCurrent(ctx, func(c context.Context, identity netidentity.Identity) error {
		uses++
		if uses != 1 || !nfqws2InactiveFinite(c) || identity != r.identity {
			return nfqws2InactiveAt("identity", nil)
		}
		if err := r.current(c); err != nil {
			return err
		}
		files, err := nfqws2ReadInactiveFiles(c, r.adapter, platform)
		if err != nil {
			return nfqws2InactiveAt("files", err)
		}
		opening = files
		if err := nfqws2InactiveProcesses(c, platform, r.adapter); err != nil {
			return nfqws2InactiveAt("processes", err)
		}
		readOriginal := func(leaf context.Context, expected netidentity.Identity) (BackendInventorySnapshot, error) {
			image, err := read(leaf, expected)
			if err != nil || image.Scope.Network != expected || image.Scope.ToolReviewID != r.frozen.review ||
				image.IPTables != r.frozen.reader.IPTables || image.IP6Tables != r.frozen.reader.IP6Tables {
				return BackendInventorySnapshot{}, nfqws2InactiveAt("inventory.source", err)
			}
			return image, nil
		}
		reader := nfqws2InactiveKernelReader{read: readOriginal, queues: platform.queues, sockets: platform.sockets}
		if err := reader.check(c, identity); err != nil {
			return nfqws2InactiveAt("kernel", err)
		}
		if err := nfqws2InactiveProcesses(c, platform, r.adapter); err != nil {
			return nfqws2InactiveAt("processes", err)
		}
		closing, err := nfqws2ReadInactiveFiles(c, r.adapter, platform)
		if err != nil || !files.same(closing) {
			return nfqws2InactiveAt("files.closure", err)
		}
		return r.current(c)
	})
	if err != nil || ctx.Err() != nil || uses != 1 {
		return nfqws2InactiveAt("observation", errors.Join(err, ctx.Err()))
	}
	// The provider's closing identity is itself a slow boundary. Finish only
	// with local/file bookends; no callback can manufacture another grant here.
	closing, err := nfqws2ReadInactiveFiles(ctx, r.adapter, platform)
	if err != nil || opening == nil || !opening.same(closing) {
		return nfqws2InactiveAt("closure", err)
	}
	return r.current(ctx)
}
