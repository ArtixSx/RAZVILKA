package dataplane

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/ArtixSx/razvilka/internal/privaterestore"
)

// These are original comparison inputs, not a reconstructed process owner.
// Retain them before the first native observation or sidecar signal. A later
// equal-byte pathname replacement cannot become an acknowledged original.
type mihomoSameBootInputs struct {
	mu                    sync.Mutex
	self                  *mihomoSameBootInputs
	ctx                   context.Context
	private               *privaterestore.OfflineServiceControlSet
	statePath, configPath string
	roots                 []*os.Root
	paths                 []string
	infos                 []os.FileInfo
	records               []*mihomoColdRecord
	before                Execution
	definition            ExecutionMihomoLiveDefinition
	closed                bool
	closeErr              error
}

func holdMihomoSameBootInputs(ctx context.Context, set *privaterestore.OfflineServiceControlSet, statePath, id, digest string) (_ *mihomoSameBootInputs, resultErr error) {
	if ctx == nil || set == nil || !filepath.IsAbs(statePath) || filepath.Clean(statePath) != statePath || !validPlanID(id) || !validPlanDigest(digest) {
		return nil, ErrMihomoLiveRetirement
	}
	configPath, err := set.ConfigurationPath(ctx)
	if err != nil {
		return nil, err
	}
	i := &mihomoSameBootInputs{ctx: ctx, private: set, statePath: statePath, configPath: configPath}
	i.self = i
	keep := false
	defer func() {
		if !keep {
			resultErr = errors.Join(resultErr, i.close())
		}
	}()
	// Each component is opened through its original parent. Opening a named
	// transaction by an arbitrary archive or runtime-derived path is forbidden.
	state, err := i.holdRoot(statePath, nil, "")
	if err != nil {
		return nil, fmt.Errorf("same-boot original state root: %w", err)
	}
	transactions, err := i.holdRoot(filepath.Join(statePath, "transactions"), state, "transactions")
	if err != nil {
		return nil, fmt.Errorf("same-boot original transactions root: %w", err)
	}
	transaction, err := i.holdRoot(filepath.Join(statePath, "transactions", id), transactions, id)
	if err != nil {
		return nil, fmt.Errorf("same-boot original transaction root: %w", err)
	}
	configRoot, err := i.holdRoot(filepath.Dir(configPath), nil, "")
	if err != nil {
		return nil, fmt.Errorf("same-boot original configuration root: %w", err)
	}
	for _, item := range []struct {
		root *os.Root
		name string
	}{{transaction, "execution.json"}, {state, "latest-execution.json"}, {configRoot, filepath.Base(configPath)}} {
		r, err := openMihomoColdRecord(item.root, item.name, nil)
		if err != nil {
			return nil, err
		}
		i.records = append(i.records, r)
	}
	if len(i.records[2].data) > 4<<20 || !bytes.Equal(i.records[0].data, i.records[1].data) {
		return nil, ErrMihomoLiveRetirement
	}
	i.before, i.definition, err = decodeMihomoLiveRetirementIntent(i.records[0].data)
	if err != nil || i.before.PlanID != id || i.before.Digest != digest || i.definition.Observation == nil {
		return nil, errors.Join(ErrMihomoLiveRetirement, err)
	}
	// This first lane refuses in-flight transit and ambiguous publication; it
	// never changes finalizing/unknown state to make recovery admissible.
	if i.before.State != "committed" {
		return nil, ErrMihomoLiveRetirement
	}
	for _, r := range i.before.Resources {
		if r.MihomoLive == nil && (r.State != "removed" || r.NodeTransit == nil) {
			return nil, ErrMihomoLiveRetirement
		}
	}
	if err := i.current(ctx); err != nil {
		return nil, err
	}
	keep = true
	return i, nil
}

func (i *mihomoSameBootInputs) holdRoot(path string, parent *os.Root, name string) (*os.Root, error) {
	var root *os.Root
	var err error
	if parent == nil {
		root, err = openBootRetirementRoot(path)
	} else {
		root, err = openRetirementChild(parent, name)
	}
	if err != nil {
		return nil, err
	}
	i.roots = append(i.roots, root)
	i.paths = append(i.paths, path)
	info, err := root.Stat(".")
	if err != nil {
		return nil, err
	}
	i.infos = append(i.infos, info)
	return root, nil
}

func (i *mihomoSameBootInputs) current(ctx context.Context) error {
	if i == nil || i.self != i {
		return ErrMihomoLiveRetirement
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.currentLocked(ctx)
}
func (i *mihomoSameBootInputs) currentLocked(ctx context.Context) error {
	if i.closed || ctx != i.ctx || len(i.roots) != 4 || len(i.infos) != 4 || len(i.records) != 3 {
		return errors.Join(ErrMihomoLiveRetirement, i.closeErr)
	}
	if err := i.private.Current(i.ctx); err != nil {
		return err
	}
	for n, root := range i.roots {
		held, e1 := root.Stat(".")
		named, e2 := os.Lstat(i.paths[n])
		if e1 != nil || e2 != nil || !networkPolicyPrivateDirectory(held) || !networkPolicyPrivateDirectory(named) || !os.SameFile(held, i.infos[n]) || !os.SameFile(named, i.infos[n]) {
			return errors.Join(ErrMihomoLiveRetirement, e1, e2)
		}
	}
	for _, r := range i.records {
		if err := r.current(); err != nil {
			return err
		}
	}
	return i.private.Current(i.ctx)
}
func (i *mihomoSameBootInputs) close() error {
	if i == nil || i.self != i {
		return ErrMihomoLiveRetirement
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if !i.closed {
		i.closed = true
		for _, r := range i.records {
			i.closeErr = errors.Join(i.closeErr, r.file.Close())
			clear(r.data)
		}
		for n := len(i.roots) - 1; n >= 0; n-- {
			i.closeErr = errors.Join(i.closeErr, i.roots[n].Close())
		}
	}
	return i.closeErr
}
