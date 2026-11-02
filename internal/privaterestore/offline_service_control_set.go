package privaterestore

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"sync"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// OfflineServiceControlSet proves only the CURRENT five original idle private
// lifetimes. It grants no process, packet, restore or native command authority.
// The callback must not Close/reenter coordinators; all five mutexes are held
// by their existing WithOfflineServiceControl stack until this view revokes.
// Configuration bytes need a separate original read-only owner/CAS.
type OfflineServiceControlSet struct {
	mu           sync.Mutex
	self         *OfflineServiceControlSet
	ctx          context.Context
	config       string
	coordinators []*Coordinator
	active       bool
}

func (*OfflineServiceControlSet) String() string   { return "[offline service control set]" }
func (*OfflineServiceControlSet) GoString() string { return "[offline service control set]" }

var offlineServiceControlGenerations = [...]string{"private-restore", "private-restore-nodes-v1", "private-restore-native-v1", "private-restore-feeds-v1", "private-restore-strategylab-v1"}

// WithOfflineServiceControlSet never opens a target or repairs/creates a
// generation. Every input must already be the original existing-only offline
// coordinator. Reordered, duplicate, missing or foreign layouts refuse before
// the callback. The original opening context cannot be renewed.
func WithOfflineServiceControlSet(ctx context.Context, configPath string, coordinators []*Coordinator, use func(context.Context, *OfflineServiceControlSet) error) error {
	if ctx == nil || !reflect.TypeOf(ctx).Comparable() || use == nil || len(coordinators) != len(offlineServiceControlGenerations) || !filepath.IsAbs(configPath) || filepath.Clean(configPath) != configPath {
		return restorejournal.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(restorejournal.ErrAborted, err)
	}
	if _, finite := ctx.Deadline(); !finite {
		return restorejournal.ErrInvalid
	}
	owners := append([]*Coordinator(nil), coordinators...)
	seen := map[*Coordinator]bool{}
	for _, c := range owners {
		if c == nil || seen[c] {
			return restorejournal.ErrInvalid
		}
		seen[c] = true
	}
	var enter func(int) error
	enter = func(index int) error {
		if index < len(owners) {
			return owners[index].WithOfflineServiceControl(ctx, configPath, func(actual context.Context) error {
				if actual != ctx {
					return restorejournal.ErrInvalid
				}
				return enter(index + 1)
			})
		}
		view := &OfflineServiceControlSet{ctx: ctx, config: configPath, coordinators: owners, active: true}
		view.self = view
		return view.use(use)
	}
	return enter(0)
}

func (s *OfflineServiceControlSet) use(callback func(context.Context, *OfflineServiceControlSet) error) (resultErr error) {
	defer func() { resultErr = errors.Join(resultErr, s.revoke()) }() // Also revoke/join on the original panic.
	if err := s.Current(s.ctx); err != nil {
		return err
	}
	return callback(s.ctx, s)
}

// Current serializes the original idle journal reads and joins any in-flight
// reader at revoke. It does NOT reenter Coordinator.mu or acquire another
// lifetime/config lease. A copied/expired view never touches those journals.
func (s *OfflineServiceControlSet) Current(ctx context.Context) error {
	if s == nil || s.self != s {
		return restorejournal.ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.active || ctx == nil || !reflect.TypeOf(ctx).Comparable() || ctx != s.ctx {
		return restorejournal.ErrInvalid
	}
	return s.currentLocked(ctx)
}

// ConfigurationPath is a comparison coordinate only. It is available solely
// inside the original bounded callback; it does not open/own that file.
func (s *OfflineServiceControlSet) ConfigurationPath(ctx context.Context) (string, error) {
	if s == nil || s.self != s {
		return "", restorejournal.ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.active || ctx == nil || !reflect.TypeOf(ctx).Comparable() || ctx != s.ctx {
		return "", restorejournal.ErrInvalid
	}
	if err := s.currentLocked(ctx); err != nil {
		return "", err
	}
	return s.config, nil
}

// All Coordinator.mu locks are held by the original caller stack. No external
// callback runs here. Closing these idle journals is the caller's later duty.
func (s *OfflineServiceControlSet) currentLocked(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return errors.Join(restorejournal.ErrAborted, err)
	}
	if len(s.coordinators) != len(offlineServiceControlGenerations) {
		return restorejournal.ErrInvalid
	}
	base := filepath.Dir(s.config)
	last := s.coordinators[len(s.coordinators)-1]
	if last == nil {
		return restorejournal.ErrInvalid
	}
	full := last.layout
	if full.NodeRoot == "" || full.WarpRoot == "" || full.FeedRoot == "" || full.StrategyLabPath == "" {
		return restorejournal.ErrInvalid
	}
	for i, c := range s.coordinators {
		if c == nil || !c.offlineServiceControl || c.offlineServiceControlContext != ctx || c.closed || c.blocked || c.runtimeStarted || c.journal == nil {
			return restorejournal.ErrRecovery
		}
		l := c.layout
		if l.Config != s.config || l.JournalRoot != filepath.Join(base, offlineServiceControlGenerations[i]) || l.CustomServices != full.CustomServices || l.Devices != full.Devices || l.StageRoot != full.StageRoot || l.ProviderRoot != full.ProviderRoot {
			return restorejournal.ErrInvalid
		}
		node, warp, feed, strategy := "", "", "", ""
		if i >= 1 {
			node = full.NodeRoot
		}
		if i >= 2 {
			warp = full.WarpRoot
		}
		if i >= 3 {
			feed = full.FeedRoot
		}
		if i >= 4 {
			strategy = full.StrategyLabPath
		}
		if l.NodeRoot != node || l.WarpRoot != warp || l.FeedRoot != feed || l.StrategyLabPath != strategy {
			return restorejournal.ErrInvalid
		}
		if err := c.journal.RequireIdle(ctx); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func (s *OfflineServiceControlSet) revoke() error {
	if s == nil || s.self != s {
		return restorejournal.ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock() // Join readers before any Coordinator lock leaves.
	if !s.active {
		return restorejournal.ErrInvalid
	}
	s.active = false
	return s.currentLocked(s.ctx)
}
