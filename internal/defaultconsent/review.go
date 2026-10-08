// Package defaultconsent reads explicit revisioned approval from the original
// configuration/control/source owners. Detached hashes never issue consent.
package defaultconsent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

var ErrChanged = errors.New("explicit default consent owner changed or is unavailable")

type Reference struct {
	Schema             int    `json:"schema"`
	InstallationID     string `json:"installation_id"`
	Sequence           uint64 `json:"sequence"`
	ApprovalRevision   uint64 `json:"approval_revision"`
	PolicyRevision     uint64 `json:"policy_revision"`
	ConsentDigest      string `json:"consent_digest"`
	EngineID           string `json:"engine_id"`
	NodeID             string `json:"node_id"`
	Resolved           string `json:"resolved"`
	NodeGeneration     uint64 `json:"node_generation"`
	NodeMaterialSHA256 string `json:"node_material_sha256"`
}

type anchoredRoot struct {
	path string
	root *ownedfs.Root
	info os.FileInfo
}

// Owner is constructed from concrete existing Stores, actual configured slots
// and retained protected control. configured is denial-only continuity of the
// App's same selected owners; it cannot manufacture saved approval or sources.
type Owner struct {
	self          *Owner
	gate          *operationgate.Gate
	store         *config.Store
	nodes         *nodestore.Store
	storeSlot     **config.Store
	nodesSlot     **nodestore.Store
	control       *operationgate.ControlEpochReview
	roots         []anchoredRoot
	configured    func() bool
	configBinding string
	nodeBinding   string
	mu            sync.Mutex
	changed       *sync.Cond
	closed        bool
	uses          uint64
}

func openAnchor(path string, private bool) (anchoredRoot, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return anchoredRoot{}, ErrChanged
	}
	root, err := ownedfs.Open(path)
	if err != nil {
		return anchoredRoot{}, ErrChanged
	}
	info, err := os.Lstat(path)
	held, heldErr := root.RootInfo()
	if err != nil || heldErr != nil || !os.SameFile(held, info) || !info.IsDir() || !rootProtected(info, private) || info.Mode()&os.ModeSymlink != 0 {
		_ = root.Close()
		return anchoredRoot{}, ErrChanged
	}
	return anchoredRoot{path: path, root: root, info: info}, nil
}

// NewOwner opens only existing roots. The original admission is mandatory and
// actual restore-target bindings corroborate the configured paths. A genuinely
// absent NodeStore needs no node root and cannot review node grants. Its SAME
// nil configured slot remains retained. No Store, authority record, source or
// directory is created here.
func NewOwner(ctx context.Context, gate *operationgate.Gate, storeSlot **config.Store, nodesSlot **nodestore.Store, configPath, nodeRoot, controlRoot string, configured func() bool) (*Owner, error) {
	if gate == nil || storeSlot == nil || nodesSlot == nil || *storeSlot == nil || configured == nil || *nodesSlot == nil && nodeRoot != "" {
		return nil, ErrChanged
	}
	o := &Owner{gate: gate, store: *storeSlot, nodes: *nodesSlot, storeSlot: storeSlot, nodesSlot: nodesSlot, configured: configured}
	o.self = o
	o.changed = sync.NewCond(&o.mu)
	keep := false
	defer func() {
		if !keep {
			_ = o.Close()
		}
	}()
	err := gate.WithExclusiveContext(ctx, func() error {
		if !configured() {
			return ErrChanged
		}
		cfgBinding, err := config.RestoreBinding(configPath)
		if err != nil {
			return ErrChanged
		}
		actualCfgBinding, err := o.store.OwnerBinding(ctx)
		if err != nil {
			return ErrChanged
		}
		if actualCfgBinding != cfgBinding {
			return ErrChanged
		}
		o.configBinding = cfgBinding
		paths := []string{filepath.Dir(configPath)}
		var nodeInfo os.FileInfo
		if o.nodes != nil {
			nodeBinding, err := nodestore.RestoreBinding(nodeRoot)
			if err != nil {
				return ErrChanged
			}
			actualNodeBinding, info, err := o.nodes.OwnerRoot(ctx)
			if err != nil || actualNodeBinding != nodeBinding {
				return ErrChanged
			}
			o.nodeBinding, nodeInfo = nodeBinding, info
			paths = append(paths, nodeRoot)
		}
		for i, path := range paths {
			a, err := openAnchor(path, i == 1)
			if err != nil {
				return err
			}
			o.roots = append(o.roots, a)
		}
		if o.nodes != nil && !os.SameFile(nodeInfo, o.roots[1].info) {
			return ErrChanged
		}
		o.control, err = gate.ReviewControlEpoch(ctx, controlRoot)
		if err != nil {
			return err
		}
		return o.bindings(ctx)
	})
	if err != nil {
		return nil, errors.Join(ErrChanged, err)
	}
	keep = true
	return o, nil
}

func (o *Owner) bindings(ctx context.Context) error {
	if o.self != o || *o.storeSlot != o.store || *o.nodesSlot != o.nodes || !o.configured() {
		return ErrChanged
	}
	for i, a := range o.roots {
		current, err := os.Lstat(a.path)
		held, heldErr := a.root.RootInfo()
		if err != nil || heldErr != nil || !os.SameFile(a.info, held) || !os.SameFile(held, current) || !current.IsDir() || !rootProtected(current, i == 1) || current.Mode()&os.ModeSymlink != 0 {
			return ErrChanged
		}
	}
	actualConfigBinding, err := o.store.OwnerBinding(ctx)
	if err != nil || actualConfigBinding != o.configBinding {
		return ErrChanged
	}
	if o.nodes != nil {
		actualNodeBinding, nodeInfo, err := o.nodes.OwnerRoot(ctx)
		if err != nil || actualNodeBinding != o.nodeBinding || !os.SameFile(nodeInfo, o.roots[1].info) {
			return ErrChanged
		}
	}
	return nil
}

func (o *Owner) withOwner(ctx context.Context, use func() error) error {
	if o == nil || o.self != o || ctx == nil || use == nil {
		return ErrChanged
	}
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		return ErrChanged
	}
	o.uses++
	o.mu.Unlock()
	defer func() {
		o.mu.Lock()
		o.uses--
		if o.uses == 0 {
			o.changed.Broadcast()
		}
		o.mu.Unlock()
	}()
	return o.gate.WithExclusiveContext(ctx, func() error {
		if err := o.bindings(ctx); err != nil {
			return err
		}
		err := use()
		return errors.Join(err, o.bindings(ctx))
	})
}

func (o *Owner) Close() error {
	if o == nil {
		return nil
	}
	if o.self != o {
		return ErrChanged
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return nil
	}
	o.closed = true
	for o.uses != 0 {
		o.changed.Wait()
	}
	var err error
	if o.control != nil {
		err = o.control.Close()
	}
	for _, a := range o.roots {
		err = errors.Join(err, a.root.Close())
	}
	return err
}

type Review struct {
	self      *Review
	owner     *Owner
	ref       Reference
	cfg       config.Config
	cfgMu     sync.RWMutex
	grant     config.DefaultRouteGrant
	node      nodestore.Node
	scopeOnly bool
}

func (*Review) String() string   { return "[private explicit default consent]" }
func (*Review) GoString() string { return "[private explicit default consent]" }

// Review reads actual saved explicit approval for one exact resolved path.
// Legacy AllExceptAllowed alone, unknown node/source/protocol and stale grants
// refuse. Provider consent is permission only, never account/route health.
func (o *Owner) Review(ctx context.Context, resolved string) (*Review, error) {
	return o.review(ctx, resolved, false)
}

func (o *Owner) review(ctx context.Context, resolved string, scopeOnly bool) (*Review, error) {
	r := &Review{owner: o, scopeOnly: scopeOnly}
	r.self = r
	err := o.withOwner(ctx, func() error {
		r.cfg = o.store.Get()
		if !config.CurrentDefaultRouteScopeConsent(r.cfg) || r.cfg.SafeMode || r.cfg.ServiceControl.Stopped {
			return ErrChanged
		}
		c := r.cfg.DefaultRouteConsent
		epoch := o.control.Reference()
		if c.InstallationID != epoch.InstallationID || c.Sequence != epoch.Sequence {
			return ErrChanged
		}
		found := scopeOnly && resolved == ""
		for _, g := range c.Grants {
			if !scopeOnly && g.Resolved == resolved {
				r.grant = g
				found = true
				break
			}
		}
		if !found {
			return ErrChanged
		}
		r.ref = Reference{Schema: 1, InstallationID: c.InstallationID, Sequence: c.Sequence, ApprovalRevision: c.ApprovalRevision, PolicyRevision: r.cfg.NetworkPolicy.Revision, ConsentDigest: c.Digest, Resolved: resolved, EngineID: resolved}
		if engine, id, ok := strings.Cut(resolved, ":"); ok {
			r.ref.EngineID = engine
			if engine == "xray" || engine == "sing-box" {
				r.ref.NodeID = id
			}
		}
		if r.ref.NodeID != "" {
			if o.nodes == nil {
				return ErrChanged
			}
			snapshot, err := o.nodes.Snapshot(ctx, time.Now().UTC())
			if err != nil {
				return ErrChanged
			}
			for _, node := range snapshot.Nodes {
				if node.ID == r.ref.NodeID {
					r.node = node
					break
				}
			}
			if snapshot.Generation == 0 || !allowedNode(r.node, r.grant, snapshot.Sources, time.Now().UTC()) {
				return ErrChanged
			}
			r.ref.NodeGeneration = snapshot.Generation
			if err := o.nodes.WithSecret(ctx, r.ref.NodeID, func(material []byte) error { r.ref.NodeMaterialSHA256 = materialDigest(material); return nil }); err != nil {
				return ErrChanged
			}
		}
		return r.current(ctx)
	})
	if err != nil {
		return nil, errors.Join(ErrChanged, err)
	}
	return r, nil
}

func (r *Review) Reference() Reference {
	if r == nil || r.self != r {
		return Reference{}
	}
	return r.ref
}
func (r *Review) MatchesNodeStore(store *nodestore.Store) bool {
	return r != nil && r.self == r && r.owner != nil && r.owner.nodes == store && r.owner.nodesSlot != nil && *r.owner.nodesSlot == store
}
func (r *Review) Current(ctx context.Context) error {
	if r == nil || r.self != r || r.owner == nil {
		return ErrChanged
	}
	return r.owner.withOwner(ctx, func() error { return r.current(ctx) })
}
func (r *Review) WithCurrent(ctx context.Context, use func() error) error {
	if r == nil || r.self != r || r.owner == nil || use == nil {
		return ErrChanged
	}
	return r.owner.withOwner(ctx, func() error {
		if err := r.current(ctx); err != nil {
			return err
		}
		err := use()
		return errors.Join(err, r.current(ctx))
	})
}

func (r *Review) current(ctx context.Context) error {
	o := r.owner
	expected := r.expectedConfig()
	if err := o.control.Current(ctx); err != nil {
		return err
	}
	cfg := o.store.Get()
	if !reflect.DeepEqual(cfg, expected) || !config.CurrentDefaultRouteScopeConsent(cfg) || cfg.SafeMode || cfg.ServiceControl.Stopped {
		return ErrChanged
	}
	if err := o.store.WithRevisionObservation(ctx, cfg.Revision, func() error { return nil }); err != nil {
		return ErrChanged
	}
	if r.ref.NodeID != "" {
		if err := r.currentNode(ctx); err != nil {
			return err
		}
		if err := o.nodes.WithSecret(ctx, r.ref.NodeID, func(material []byte) error {
			if !allowedMaterial(material, r.grant) {
				return ErrChanged
			}
			if materialDigest(material) != r.ref.NodeMaterialSHA256 || !allowedMaterial(material, r.grant) {
				return ErrChanged
			}
			return nil
		}); err != nil {
			return ErrChanged
		}
		if err := r.currentNode(ctx); err != nil {
			return err
		}
	}
	if !reflect.DeepEqual(o.store.Get(), expected) {
		return ErrChanged
	}
	if err := o.store.WithRevisionObservation(ctx, cfg.Revision, func() error { return nil }); err != nil {
		return ErrChanged
	}
	return o.control.Current(ctx)
}

func (r *Review) expectedConfig() config.Config {
	r.cfgMu.RLock()
	defer r.cfgMu.RUnlock()
	return r.cfg
}

func (r *Review) currentNode(ctx context.Context) error {
	snapshot, err := r.owner.nodes.Snapshot(ctx, time.Now().UTC())
	if err != nil || snapshot.Generation != r.ref.NodeGeneration {
		return ErrChanged
	}
	for _, node := range snapshot.Nodes {
		if node.ID == r.ref.NodeID {
			if reflect.DeepEqual(node, r.node) && allowedNode(node, r.grant, snapshot.Sources, time.Now().UTC()) {
				return nil
			}
			return ErrChanged
		}
	}
	return ErrChanged
}

func materialDigest(material []byte) string {
	sum := sha256.Sum256(material)
	return hex.EncodeToString(sum[:])
}

func allowedNode(node nodestore.Node, g config.DefaultRouteGrant, sources []nodestore.Source, now time.Time) bool {
	if node.ID == "" || node.ID != g.ProviderID || node.Disabled {
		return false
	}
	for _, origin := range node.Origins {
		if now.Before(origin.ReceivedAt) || !now.Before(origin.ExpiresAt) {
			continue
		}
		for i, id := range g.SourceIDs {
			if id != origin.SourceID {
				continue
			}
			for _, source := range sources {
				if source.ID == id && source.Kind == g.SourceKinds[i] {
					return true
				}
			}
		}
	}
	return false
}

// Permission follows the canonical private outbound type. Public Node.Protocol
// is a presentation label (e.g. VLESS), never protocol admission authority.
func allowedMaterial(material []byte, g config.DefaultRouteGrant) bool {
	var outbound struct {
		Type string `json:"type"`
	}
	return json.Unmarshal(material, &outbound) == nil && slices.Contains(g.Protocols, outbound.Type)
}
