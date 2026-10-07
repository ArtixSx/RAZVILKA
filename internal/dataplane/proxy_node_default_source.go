package dataplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/providerprofile"
	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

var ErrNodeDefaultSource = errors.New("exact default node source changed or is unavailable")

// NodeDefaultSourceReference is detached, versioned source metadata. It is
// suitable for a compiler source digest, never a transport proof, public-node
// consent, service PASS, process passport or permission to install a route.
// WAN/profile, transport/consent proof and final compiled LAN/plan bindings
// belong to their separate owners and are deliberately absent here.
type NodeDefaultSourceReference struct {
	Schema         int    `json:"schema"`
	EngineID       string `json:"engine_id"`
	NodeID         string `json:"node_id"`
	Resolved       string `json:"resolved"`
	NodeGeneration uint64 `json:"node_generation"`
	MaterialSHA256 string `json:"material_sha256"`
}

// NodeDefaultSourceReview retains the concrete open Store that issued the
// source observation. There is no constructor from a reference or user DTO.
// Imported, unchecked material can be reviewed, but this review does not
// promote its health or bypass the existing service route materializers.
type NodeDefaultSourceReview struct {
	store *nodestore.Store
	ref   NodeDefaultSourceReference
	state nodeDefaultSourceState
	now   func() time.Time
}

type nodeDefaultSourceState struct {
	generation uint64
	origins    []nodestore.Origin
	sources    []nodestore.Source
}

func (*NodeDefaultSourceReview) String() string   { return "[private exact node source review]" }
func (*NodeDefaultSourceReview) GoString() string { return "[private exact node source review]" }

// ReviewNodeDefaultSource reads one exact node and its compiler-supported
// private material from the actual Store, closing on the same generation and
// provenance. It performs no network, process, configuration or history write.
func ReviewNodeDefaultSource(ctx context.Context, store *nodestore.Store, resolved string) (*NodeDefaultSourceReview, error) {
	return reviewNodeDefaultSource(ctx, store, resolved, time.Now)
}

func reviewNodeDefaultSource(ctx context.Context, store *nodestore.Store, resolved string, now func() time.Time) (*NodeDefaultSourceReview, error) {
	engine, id, found := strings.Cut(resolved, ":")
	if store == nil || now == nil || !found || engine != "xray" && engine != "sing-box" || !exactNodeIDPattern.MatchString(id) {
		return nil, ErrNodeDefaultSource
	}
	r := &NodeDefaultSourceReview{store: store, now: now,
		ref: NodeDefaultSourceReference{Schema: 1, EngineID: engine, NodeID: id, Resolved: resolved}}
	state, err := r.readState(ctx)
	if err != nil {
		return nil, err
	}
	r.state, r.ref.NodeGeneration = state, state.generation
	err = store.WithSecret(ctx, id, func(material []byte) error {
		if err := nodeDefaultSourceContext(ctx); err != nil {
			return err
		}
		if !nodeDefaultSourceSupported(engine, material) {
			return ErrNodeDefaultSource
		}
		r.ref.MaterialSHA256 = nodeDefaultSourceMaterialHash(material)
		return r.checkState(ctx)
	})
	if err != nil || nodeDefaultSourceContext(ctx) != nil {
		return nil, errors.Join(ErrNodeDefaultSource, nodeDefaultSourceContextError(ctx))
	}
	return r, nil
}

// Reference returns values only; changing them cannot change the held review.
func (r *NodeDefaultSourceReview) Reference() NodeDefaultSourceReference {
	if r == nil {
		return NodeDefaultSourceReference{}
	}
	return r.ref
}

// Current re-reads the original Store/root-backed owner and compiler-supported
// material using a fresh finite operation context and the owner's clock.
// Store close or recovery fencing fails its actual reads. The Store's held
// descriptors preserve its original root; this review never selects a new
// Store or reopens a replacement pathname. A later admission owner must also
// check that this remains its current configured Store/root.
func (r *NodeDefaultSourceReview) Current(ctx context.Context) error {
	if !r.valid() {
		return ErrNodeDefaultSource
	}
	if err := r.checkState(ctx); err != nil {
		return err
	}
	err := r.store.WithSecret(ctx, r.ref.NodeID, func(material []byte) error {
		if err := nodeDefaultSourceContext(ctx); err != nil {
			return err
		}
		if nodeDefaultSourceMaterialHash(material) != r.ref.MaterialSHA256 || !nodeDefaultSourceSupported(r.ref.EngineID, material) {
			return ErrNodeDefaultSource
		}
		return r.checkState(ctx)
	})
	if err != nil {
		return errors.Join(ErrNodeDefaultSource, nodeDefaultSourceContextError(ctx))
	}
	return nodeDefaultSourceContext(ctx)
}

// WithMaterial supplies only a bounded private copy, cleared by the Store on
// return (including callback error/panic). The caller must not retain it.
// Opening and closing Current checks surround the callback; an error never
// grants authority or undoes caller effects. This is for private compilation,
// not an effect-admission callback, and must not perform live mutations.
func (r *NodeDefaultSourceReview) WithMaterial(ctx context.Context, use func([]byte) error) error {
	if use == nil {
		return ErrNodeDefaultSource
	}
	if err := r.Current(ctx); err != nil {
		return err
	}
	err := r.store.WithSecret(ctx, r.ref.NodeID, func(material []byte) error {
		if nodeDefaultSourceMaterialHash(material) != r.ref.MaterialSHA256 || !nodeDefaultSourceSupported(r.ref.EngineID, material) {
			return ErrNodeDefaultSource
		}
		if err := r.checkState(ctx); err != nil {
			return err
		}
		return use(material)
	})
	// Read the actual material again, rather than trusting the potentially
	// edited callback copy or a generation-only closing observation.
	return errors.Join(err, r.Current(ctx))
}

func (r *NodeDefaultSourceReview) valid() bool {
	return r != nil && r.store != nil && r.now != nil && r.ref.Schema == 1 &&
		(r.ref.EngineID == "xray" || r.ref.EngineID == "sing-box") && exactNodeIDPattern.MatchString(r.ref.NodeID) &&
		r.ref.Resolved == r.ref.EngineID+":"+r.ref.NodeID && r.ref.NodeGeneration > 0 &&
		r.state.generation == r.ref.NodeGeneration && validNetworkPolicyGeneration(r.ref.MaterialSHA256)
}

func (r *NodeDefaultSourceReview) readState(ctx context.Context) (nodeDefaultSourceState, error) {
	if err := nodeDefaultSourceContext(ctx); err != nil {
		return nodeDefaultSourceState{}, err
	}
	now := r.now().UTC()
	if now.IsZero() {
		return nodeDefaultSourceState{}, ErrNodeDefaultSource
	}
	snapshot, err := r.store.Snapshot(ctx, now)
	if err != nil || snapshot.Generation == 0 {
		return nodeDefaultSourceState{}, errors.Join(ErrNodeDefaultSource, nodeDefaultSourceContextError(ctx))
	}
	if err := nodeDefaultSourceContext(ctx); err != nil {
		return nodeDefaultSourceState{}, err
	}
	for _, node := range snapshot.Nodes {
		if node.ID != r.ref.NodeID {
			continue
		}
		if node.Disabled || len(node.Origins) == 0 {
			return nodeDefaultSourceState{}, ErrNodeDefaultSource
		}
		state := nodeDefaultSourceState{generation: snapshot.Generation, origins: node.Origins}
		fresh := false
		for _, origin := range node.Origins {
			fresh = fresh || !now.Before(origin.ReceivedAt) && now.Before(origin.ExpiresAt)
			found := false
			for _, source := range snapshot.Sources {
				if source.ID == origin.SourceID {
					state.sources = append(state.sources, source)
					found = true
					break
				}
			}
			if !found {
				return nodeDefaultSourceState{}, ErrNodeDefaultSource
			}
		}
		if fresh {
			return state, nil
		}
		break
	}
	return nodeDefaultSourceState{}, ErrNodeDefaultSource
}

func (r *NodeDefaultSourceReview) checkState(ctx context.Context) error {
	state, err := r.readState(ctx)
	if err != nil || !reflect.DeepEqual(state, r.state) {
		return errors.Join(ErrNodeDefaultSource, nodeDefaultSourceContextError(ctx))
	}
	return nil
}

func nodeDefaultSourceContext(ctx context.Context) error {
	if ctx == nil {
		return ErrNodeDefaultSource
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrNodeDefaultSource, err)
	}
	if _, finite := ctx.Deadline(); !finite {
		return ErrNodeDefaultSource
	}
	return nil
}

func nodeDefaultSourceContextError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}

func nodeDefaultSourceMaterialHash(material []byte) string {
	hash := sha256.Sum256(material)
	return hex.EncodeToString(hash[:])
}

func nodeDefaultSourceSupported(engine string, material []byte) bool {
	if len(material) == 0 || len(material) > providerprofile.MaxProfileBytes {
		return false
	}
	if engine == "xray" {
		profile, err := providerprofile.VLESSProfileFromJSON(material)
		if err != nil {
			return false
		}
		compiled, _, err := providerprofile.CompileXrayConfig(profile)
		defer clear(compiled)
		return err == nil
	}
	var outbound map[string]any
	if engine != "sing-box" || json.Unmarshal(material, &outbound) != nil || !providerprofile.SingBoxSupportsOutbound(outbound) {
		return false
	}
	compiled, err := json.Marshal(map[string]any{"outbounds": []any{outbound}})
	defer clear(compiled)
	if err != nil {
		return false
	}
	_, err = routeidentity.ConfigOutbound(engine, compiled)
	return err == nil
}
