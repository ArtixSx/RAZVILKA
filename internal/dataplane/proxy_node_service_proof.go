package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/nodestore"
)

var ErrNodeServiceProof = errors.New("original node service eligibility changed or is unavailable")

// NodeServiceProofReference describes an EXISTING exact service/WAN check and
// privately compiled Xray material from the same original node-store revision.
// It is compiler comparison data. It supplies no current native path health,
// process/command admission, LAN witness or permission to install a route.
type NodeServiceProofReference struct {
	Schema                                             int
	EngineID, NodeID, ServiceID, WANProfile            string
	NodeGeneration                                     uint64
	CompiledMaterialSHA256, ServiceSHA256, ProofSHA256 string
	CheckedAt, ExpiresAt                               time.Time
}

type nodeServiceProofState struct {
	ref   NodeServiceProofReference
	check nodestore.CheckRecord
}

// There is no constructor from CheckRecord, Health, digest or public reference.
// The original source supplies its actual open Store; caller intent freezes
// only the predicate that the real runtime must subsequently probe again.
type NodeServiceProofReview struct {
	self      *NodeServiceProofReview
	mu        sync.Mutex
	closed    atomic.Bool
	invalid   bool
	closeDone chan struct{}
	ctx       context.Context
	cancel    context.CancelFunc
	source    *NodeDefaultSourceReview
	service   catalog.Service
	wan       string
	state     nodeServiceProofState
	now       func() time.Time
}

func (*NodeServiceProofReview) String() string { return "[private original node service eligibility]" }
func (*NodeServiceProofReview) GoString() string {
	return "[private original node service eligibility]"
}

func ReviewNodeServiceProof(ctx context.Context, original *NodeDefaultSourceReview, service catalog.Service, wan string) (*NodeServiceProofReview, error) {
	return reviewNodeServiceProof(ctx, original, service, wan, time.Now)
}

func reviewNodeServiceProof(ctx context.Context, original *NodeDefaultSourceReview, service catalog.Service, wan string, now func() time.Time) (*NodeServiceProofReview, error) {
	if nodeDefaultSourceContext(ctx) != nil || original == nil || !original.valid() || original.ref.EngineID != "xray" || now == nil || len(service.Domains) != 0 || len(service.CIDRs) == 0 {
		return nil, ErrNodeServiceProof
	}
	frozen, err := FrozenProbeService(Route{LogicalServiceID: service.ID, ProbeService: &service, ProbeURL: service.ProbeURL})
	if err != nil {
		return nil, errors.Join(ErrNodeServiceProof, err)
	}
	lifetime, cancel := context.WithCancel(ctx)
	r := &NodeServiceProofReview{ctx: lifetime, cancel: cancel, source: original, service: frozen, wan: wan, now: now, closeDone: make(chan struct{})}
	r.self = r
	r.state, err = r.readState(ctx)
	if err != nil {
		_ = r.Close()
		return nil, errors.Join(ErrNodeServiceProof, err)
	}
	if err := r.Current(ctx); err != nil {
		_ = r.Close()
		return nil, err
	}
	return r, nil
}

func (r *NodeServiceProofReview) readState(ctx context.Context) (nodeServiceProofState, error) {
	if r.closed.Load() || r.ctx.Err() != nil || nodeDefaultSourceContext(ctx) != nil || r.source.Current(ctx) != nil {
		return nodeServiceProofState{}, ErrNodeServiceProof
	}
	now := r.now().UTC()
	ref := r.source.Reference()
	snapshot, err := r.source.store.Snapshot(ctx, now)
	if err != nil || snapshot.Generation != ref.NodeGeneration {
		return nodeServiceProofState{}, errors.Join(ErrNodeServiceProof, err)
	}
	var check nodestore.CheckRecord
	found := false
	for _, node := range snapshot.Nodes {
		if node.ID != ref.NodeID {
			continue
		}
		// History is the original Store's newest-first bounded check list.
		// The latest exact failure fences older PASS, even when aggregate
		// health refers to a different service, engine or WAN.
		for _, candidate := range node.Health.History {
			if candidate.ServiceID == r.service.ID && candidate.NetworkProfile == r.wan && candidate.RoutePathID == ref.Resolved {
				check, found = candidate, true
				break
			}
		}
		break
	}
	if !found || !routeNodeServiceCheckUsable(check, ref, r.service.ID, r.wan, now) {
		return nodeServiceProofState{}, ErrNodeServiceProof
	}
	resolved, err := r.source.store.ResolveRouteForEngine(ctx, "xray", ref.NodeID, r.service.ID, r.wan, "", time.Time{}, now)
	if err != nil || resolved.NodeID != ref.NodeID || resolved.Route != ref.Resolved {
		return nodeServiceProofState{}, errors.Join(ErrNodeServiceProof, err)
	}
	material, err := r.source.store.MaterializeXray(ctx, []nodestore.RouteBinding{{ServiceID: r.service.ID, NodeID: ref.NodeID, NetworkProfile: r.wan, Destinations: append([]string(nil), r.service.CIDRs...)}}, now)
	defer clear(material.Config)
	if err != nil || material.EngineID != "xray" || len(material.Config) == 0 {
		return nodeServiceProofState{}, errors.Join(ErrNodeServiceProof, err)
	}
	state := nodeServiceProofState{check: check, ref: NodeServiceProofReference{Schema: 1, EngineID: "xray", NodeID: ref.NodeID, ServiceID: r.service.ID,
		WANProfile: r.wan, NodeGeneration: ref.NodeGeneration, CompiledMaterialSHA256: nodeDefaultSourceMaterialHash(material.Config),
		ServiceSHA256: nodeServiceProofDigest(r.service), CheckedAt: check.CheckedAt, ExpiresAt: check.ExpiresAt}}
	state.ref.ProofSHA256 = nodeServiceProofDigest(struct {
		Source  NodeDefaultSourceReference
		Service catalog.Service
		Check   nodestore.CheckRecord
	}{ref, r.service, check})
	if !validNetworkPolicyGeneration(state.ref.ServiceSHA256) || !validNetworkPolicyGeneration(state.ref.ProofSHA256) || r.source.Current(ctx) != nil || ctx.Err() != nil || r.ctx.Err() != nil {
		return nodeServiceProofState{}, ErrNodeServiceProof
	}
	return state, nil
}

func nodeServiceProofDigest(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return nodeDefaultSourceMaterialHash(data)
}

func routeNodeServiceCheckUsable(check nodestore.CheckRecord, ref NodeDefaultSourceReference, service, wan string, now time.Time) bool {
	return ref.EngineID == "xray" && check.ServiceID == service && check.NetworkProfile == wan && check.RoutePathID == "xray:"+ref.NodeID &&
		check.TestLevel == "service" && check.Verdict == "PASS" && check.State == "available" && !check.DirectLeak &&
		!now.Before(check.CheckedAt) && now.Before(check.ExpiresAt)
}

func (r *NodeServiceProofReview) currentLocked(ctx context.Context) error {
	if r.invalid || r.closed.Load() {
		return ErrNodeServiceProof
	}
	deadline, _ := r.ctx.Deadline()
	c, cancel := context.WithDeadline(ctx, deadline)
	stop := context.AfterFunc(r.ctx, cancel)
	defer func() { stop(); cancel() }()
	state, err := r.readState(c)
	if err != nil || !reflect.DeepEqual(state, r.state) {
		r.invalid = true
		return errors.Join(ErrNodeServiceProof, err)
	}
	return nil
}

func (r *NodeServiceProofReview) Current(ctx context.Context) error {
	if r == nil || r.self != r || nodeDefaultSourceContext(ctx) != nil || r.closed.Load() {
		return ErrNodeServiceProof
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.currentLocked(ctx)
}

func (r *NodeServiceProofReview) Observation(ctx context.Context) (NodeServiceProofReference, error) {
	if r == nil || r.self != r || nodeDefaultSourceContext(ctx) != nil || r.closed.Load() {
		return NodeServiceProofReference{}, ErrNodeServiceProof
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.currentLocked(ctx); err != nil {
		return NodeServiceProofReference{}, err
	}
	return r.state.ref, nil
}

func (r *NodeServiceProofReview) Close() error {
	if r == nil || r.self != r {
		return ErrNodeServiceProof
	}
	if !r.closed.CompareAndSwap(false, true) {
		<-r.closeDone
		return nil
	}
	r.cancel()
	r.mu.Lock()
	defer r.mu.Unlock()
	close(r.closeDone)
	return nil // original NodeDefaultSourceReview and Store remain caller-owned
}
