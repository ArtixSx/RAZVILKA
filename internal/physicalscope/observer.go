// Package physicalscope observes selected physical LAN attachments. A detached
// snapshot is a compilation binding; only its original, open Review retains
// the kernel lifecycle fence. The observer performs no configuration writes,
// network effects, registry merges, background reads or scheduling.
package physicalscope

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

var ErrUnknown = errors.New("selected physical LAN observation unavailable or changed")

type failure struct {
	stage string
	cause error
}

func (e *failure) Error() string { return "physical LAN: " + e.stage }
func (e *failure) Unwrap() error { return e.cause }
func at(stage string, err error) error {
	return &failure{stage: stage, cause: errors.Join(ErrUnknown, err)}
}

// Selection is fresh user intent, not evidence of a segment's role. Stock IDs
// must exactly match an NDM native ID or native name. Linux IDs are explicitly
// selected OS bridge names. Revisions are retained even when the ID set matches.
type Selection struct {
	// Revisions are actual physical-selection/policy revisions. They stay
	// frozen and are compared exactly. An unrelated global config/plan CAS
	// is fenced by the caller's control owner, not adopted by this observer.
	// Supplying an old cached revision to conceal changed intent is invalid.
	Revision       uint64 `json:"revision"`
	PolicyRevision uint64 `json:"policy_revision"`
	// Stock can retain exactly the configured segment set. Its Home/guest
	// roles are resolved only from fresh NDM: one private bridge, remaining
	// explicitly selected protected bridges. Empty/ambiguous sets refuse.
	SegmentIDs      []string `json:"segment_ids"`
	HomeSegmentID   string   `json:"home_segment_id"`
	GuestSegmentIDs []string `json:"guest_segment_ids"`
}
type SelectionReader func(context.Context) (Selection, error)

type Segment struct {
	ID                  string   `json:"id"`
	NativeName          string   `json:"native_name"`
	NativeInterfaceName string   `json:"native_interface_name"`
	NativeIndex         uint32   `json:"native_index"`
	Interface           string   `json:"interface"`
	IfIndex             int      `json:"ifindex"`
	MAC                 string   `json:"mac"`
	Prefixes            []string `json:"prefixes"`
	LinkAddresses       []string `json:"link_addresses"`
	Members             []Link   `json:"members"`
	// Actual NTF_ROUTER mappings and other mappings sharing their observed MAC
	// are negative facts only. Their flags are retained exactly; none is a client.
	RouterNeighbors []RouterNeighbor `json:"router_neighbors"`
	Home            bool             `json:"home"`
	Guest           bool             `json:"guest"`
}

type RouterNeighbor struct {
	Address string `json:"address"`
	MAC     string `json:"mac"`
	Flags   uint8  `json:"flags"`
	Type    uint8  `json:"type"`
}
type Link struct {
	Interface           string `json:"interface"`
	IfIndex             int    `json:"ifindex"`
	MAC                 string `json:"mac"`
	Kind                string `json:"kind"`
	NativeID            string `json:"native_id"`
	NativeName          string `json:"native_name"`
	NativeInterfaceName string `json:"native_interface_name"`
	NativeType          string `json:"native_type"`
	// Physical facts are value types: Snapshot cannot mutate the held Review.
	Origin           string     `json:"origin"`
	LinkType         uint16     `json:"link_type"`
	Flags            uint32     `json:"flags"`
	MasterIfIndex    int        `json:"master_ifindex"`
	ParentIfIndex    int        `json:"parent_ifindex"`
	ForeignParent    bool       `json:"foreign_parent"`
	SlaveKind        string     `json:"slave_kind"`
	BridgeStateKnown bool       `json:"bridge_state_known"`
	BridgePortState  uint8      `json:"bridge_port_state"`
	VLAN             VLANFacts  `json:"vlan"`
	Parent           ParentLink `json:"parent"`
}

type VLANFacts struct {
	Known       bool   `json:"known"`
	ID          uint16 `json:"id"`
	Protocol    uint16 `json:"protocol"`
	FlagsKnown  bool   `json:"flags_known"`
	Flags       uint32 `json:"flags"`
	FlagsMask   uint32 `json:"flags_mask"`
	Unsupported bool   `json:"unsupported"`
	InfoSHA256  string `json:"info_sha256"`
}

type ParentLink struct {
	Known         bool   `json:"known"`
	Interface     string `json:"interface"`
	IfIndex       int    `json:"ifindex"`
	MAC           string `json:"mac"`
	Kind          string `json:"kind"`
	LinkType      uint16 `json:"link_type"`
	Flags         uint32 `json:"flags"`
	MasterIfIndex int    `json:"master_ifindex"`
	ParentIfIndex int    `json:"parent_ifindex"`
	ForeignParent bool   `json:"foreign_parent"`
}
type Device struct {
	ID                 string   `json:"id"`
	MAC                string   `json:"mac"`
	Interface          string   `json:"interface"`
	IfIndex            int      `json:"ifindex"`
	SegmentID          string   `json:"segment_id"`
	Addresses          []string `json:"addresses"`
	LinkLocalAddresses []string `json:"link_local_addresses"`
}
type Snapshot struct {
	// ReviewID distinguishes one opened continuity fence from another. It is
	// a detached binding only; it does not assert an interface's birth time.
	ReviewID  string               `json:"review_id"`
	Identity  netidentity.Identity `json:"identity"`
	Selection Selection            `json:"selection"`
	Segments  []Segment            `json:"segments"`
	Devices   []Device             `json:"devices"`
}

type lifecycleFence interface {
	check(context.Context, []Segment, []Device) error
	close() error
}
type observerSource struct {
	current func(context.Context, func(context.Context, netidentity.Identity) error) error
	open    func(context.Context) (lifecycleFence, error)
	capture func(context.Context, Selection) ([]Segment, []Device, error)
}
type Observer struct {
	selection SelectionReader
	source    observerSource
}
type Review struct {
	state *reviewState
}
type reviewState struct {
	self            *Review
	mu              sync.Mutex
	issuer          *Observer
	fence           lifecycleFence
	snapshot        Snapshot
	closed          bool
	invalid         bool // forward selection/physical revocation; never restored
	physicalInvalid bool // independent sticky physical failure, including unknown facts
	closeErr        error
}

// NewLinux requires explicit interface intent and the actual proc-net provider.
// NewReviewedStockNC1812 requires actual NDM roles under the reviewed provider.
// Neither constructor accepts a fact reader, executable, scope DTO or epoch.
func NewLinux(provider *netidentity.Provider, selection SelectionReader) *Observer {
	return newObserver(provider, selection, false)
}
func NewReviewedStockNC1812(provider *netidentity.Provider, selection SelectionReader) *Observer {
	return newObserver(provider, selection, true)
}
func newObserver(provider *netidentity.Provider, selection SelectionReader, stock bool) *Observer {
	if provider == nil || selection == nil {
		return &Observer{}
	}
	return &Observer{selection: selection, source: platformSource(provider, stock)}
}

var segmentID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,63}$`)
var interfaceName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,14}$`)

func canonicalSelection(s Selection) (Selection, error) {
	if len(s.SegmentIDs) > 0 {
		if s.HomeSegmentID != "" || len(s.GuestSegmentIDs) != 0 || len(s.SegmentIDs) > 16 {
			return Selection{}, ErrUnknown
		}
		s.SegmentIDs = slices.Clone(s.SegmentIDs)
		seen := map[string]bool{}
		for _, id := range s.SegmentIDs {
			if !segmentID.MatchString(id) || seen[id] {
				return Selection{}, ErrUnknown
			}
			seen[id] = true
		}
		sort.Strings(s.SegmentIDs)
		return s, nil
	}
	if !segmentID.MatchString(s.HomeSegmentID) || len(s.GuestSegmentIDs) > 15 {
		return Selection{}, ErrUnknown
	}
	s.GuestSegmentIDs = slices.Clone(s.GuestSegmentIDs)
	seen := map[string]bool{s.HomeSegmentID: true}
	for _, id := range s.GuestSegmentIDs {
		if !segmentID.MatchString(id) || seen[id] {
			return Selection{}, ErrUnknown
		}
		seen[id] = true
	}
	sort.Strings(s.GuestSegmentIDs)
	return s, nil
}
func operationContext(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if ctx == nil {
		return nil, nil, at("context.missing", nil)
	}
	if ctx.Err() != nil {
		return nil, nil, boundary("context.done", ctx.Err())
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, nil, at("context.deadline.missing", nil)
	}
	c, cancel := context.WithTimeout(ctx, 12*time.Second)
	return c, cancel, nil
}
func (o *Observer) readSelection(ctx context.Context) (Selection, error) {
	s, err := o.selection(ctx)
	if err != nil || ctx.Err() != nil {
		return Selection{}, boundary("selection.read", errors.Join(err, ctx.Err()))
	}
	s, err = canonicalSelection(s)
	if err != nil {
		return Selection{}, boundary("selection.canonical", err)
	}
	return s, nil
}
func (o *Observer) ready() bool {
	return o != nil && o.selection != nil && o.source.current != nil && o.source.open != nil && o.source.capture != nil
}

// Observe opens the continuity socket before the first facts, captures twice,
// and closes both selection and network identity. No deadline survives as an
// admission context; each later Verify needs its caller's fresh bounded context.
func (o *Observer) Observe(ctx context.Context) (*Review, error) {
	if !o.ready() {
		return nil, at("observe.dependencies", nil)
	}
	c, cancel, err := operationContext(ctx)
	if err != nil {
		return nil, boundary("observe.context", err)
	}
	defer cancel()
	selection, err := o.readSelection(c)
	if err != nil {
		return nil, boundary("observe.selection", err)
	}
	var fence lifecycleFence
	var identity netidentity.Identity
	err = o.source.current(c, func(held context.Context, id netidentity.Identity) error {
		identity = id
		var err error
		fence, err = o.source.open(held)
		if err != nil {
			return boundary("observe.fence.open", err)
		}
		return nil
	})
	if err != nil || fence == nil {
		if fence != nil {
			_ = fence.close()
		}
		if err != nil {
			return nil, boundary("observe.initial.current", err)
		}
		return nil, at("observe.fence.missing", nil)
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		_ = fence.close()
		return nil, at("observe.nonce", err)
	}
	r := &Review{state: &reviewState{issuer: o, fence: fence}}
	r.state.self = r
	r.state.snapshot, err = o.capture(c, selection, identity, fence, nil)
	if err != nil {
		_ = r.Close()
		return nil, boundary("observe.capture", err)
	}
	r.state.snapshot.ReviewID = hex.EncodeToString(nonce[:])
	return r, nil
}
func (o *Observer) capture(ctx context.Context, selection Selection, expected netidentity.Identity, fence lifecycleFence, baseline *Snapshot) (Snapshot, error) {
	snapshot, _, err := o.captureObservation(ctx, selection, expected, fence, baseline, true)
	return snapshot, err
}

// Only forward observations reread user selection. Both paths retain identical
// physical capture passes and closing original NI/fence checks. physicalFailed
// distinguishes actual physical uncertainty from a selection-only refusal.
func (o *Observer) captureObservation(ctx context.Context, selection Selection, expected netidentity.Identity, fence lifecycleFence, baseline *Snapshot, checkSelection bool) (snapshot Snapshot, physicalFailed bool, err error) {
	var result Snapshot
	for pass := 0; pass < 2; pass++ {
		stage := [2]string{"capture.initial", "capture.pass"}[pass]
		var segments []Segment
		var devices []Device
		err := o.source.current(ctx, func(held context.Context, id netidentity.Identity) error {
			if err := id.Validate(); err != nil {
				return at(stage+".identity.invalid", err)
			}
			if id != expected {
				return at(stage+".identity.changed", nil)
			}
			original := baseline
			if original == nil && pass > 0 {
				original = &result
			}
			if original != nil {
				if err := fence.check(held, original.Segments, original.Devices); err != nil {
					return boundary(stage+".fence.before", err)
				}
			}
			var err error
			segments, devices, err = o.source.capture(held, selection)
			if err != nil {
				return boundary(stage+".facts", err)
			}
			if original != nil {
				err = fence.check(held, original.Segments, original.Devices)
			} else {
				err = fence.check(held, segments, devices)
			}
			if err != nil {
				return boundary(stage+".fence.after", err)
			}
			return nil
		})
		if err != nil {
			return Snapshot{}, true, boundary(stage+".current", err)
		}
		current := Snapshot{Identity: expected, Selection: selection, Segments: segments, Devices: devices}
		if pass == 0 {
			result = current
		} else if !reflect.DeepEqual(result, current) {
			return Snapshot{}, true, boundary("capture.pass.snapshot", at(snapshotDifference(result, current), nil))
		}
	}
	// A later selection refusal must not hide physical drift already observed
	// against the original baseline, even if both capture passes agree.
	if baseline != nil {
		originalComparison := result
		originalComparison.ReviewID = baseline.ReviewID
		physicalFailed = !reflect.DeepEqual(originalComparison, *baseline)
	}
	if checkSelection {
		closing, err := o.readSelection(ctx)
		if err != nil {
			return Snapshot{}, physicalFailed, boundary("capture.closing.selection.read", err)
		}
		if !reflect.DeepEqual(selection, closing) {
			return Snapshot{}, physicalFailed, at("capture.closing.selection.changed", nil)
		}
	}
	// Catch queued churn during the closing selection read in the same scope.
	if err := o.source.current(ctx, func(c context.Context, id netidentity.Identity) error {
		if id != expected {
			return at("capture.closing.identity.changed", nil)
		}
		original := &result
		if baseline != nil {
			original = baseline
		}
		if err := fence.check(c, original.Segments, original.Devices); err != nil {
			return boundary("capture.closing.fence", err)
		}
		return nil
	}); err != nil {
		return Snapshot{}, true, boundary("capture.closing.current", err)
	}
	return result, physicalFailed, nil
}

// Verify uses only the same live Review, original selection and original kernel
// fence. A changed/unknown attempt permanently invalidates this Review; fresh
// facts or a restored tuple cannot refresh it. This is a read before an effect,
// not a wrapper around the whole Apply, a policy owner or cleanup admission.
func (o *Observer) Verify(ctx context.Context, r *Review) error {
	if !o.ready() || r == nil || r.state == nil || r.state.self != r {
		return at("verify.dependencies", nil)
	}
	c, cancel, err := operationContext(ctx)
	if err != nil {
		return boundary("verify.context", err)
	}
	defer cancel()
	s := r.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.issuer != o || s.closed || s.invalid || s.physicalInvalid || s.fence == nil {
		return at("verify.review.unavailable", nil)
	}
	selection, err := o.readSelection(c)
	if err != nil || !reflect.DeepEqual(selection, s.snapshot.Selection) {
		s.invalid = true
		if err != nil {
			return boundary("verify.selection.read", err)
		}
		return at("verify.selection.changed", nil)
	}
	snapshot, physicalFailed, err := o.captureObservation(c, selection, s.snapshot.Identity, s.fence, &s.snapshot, true)
	snapshot.ReviewID = s.snapshot.ReviewID
	if err != nil || !reflect.DeepEqual(snapshot, s.snapshot) {
		s.invalid = true
		s.physicalInvalid = physicalFailed || err == nil
		if err != nil {
			return boundary("verify.capture", err)
		}
		return boundary("verify.snapshot", at(snapshotDifference(s.snapshot, snapshot), nil))
	}
	return nil
}
func cloneSnapshot(s Snapshot) Snapshot {
	s.Selection.SegmentIDs = slices.Clone(s.Selection.SegmentIDs)
	s.Selection.GuestSegmentIDs = slices.Clone(s.Selection.GuestSegmentIDs)
	s.Segments = slices.Clone(s.Segments)
	for i := range s.Segments {
		s.Segments[i].Prefixes = slices.Clone(s.Segments[i].Prefixes)
		s.Segments[i].LinkAddresses = slices.Clone(s.Segments[i].LinkAddresses)
		s.Segments[i].Members = slices.Clone(s.Segments[i].Members)
		s.Segments[i].RouterNeighbors = slices.Clone(s.Segments[i].RouterNeighbors)
	}
	s.Devices = slices.Clone(s.Devices)
	for i := range s.Devices {
		s.Devices[i].Addresses = slices.Clone(s.Devices[i].Addresses)
		s.Devices[i].LinkLocalAddresses = slices.Clone(s.Devices[i].LinkLocalAddresses)
	}
	return s
}
func (r *Review) Snapshot() Snapshot {
	if r == nil || r.state == nil || r.state.self != r {
		return Snapshot{}
	}
	r.state.mu.Lock()
	defer r.state.mu.Unlock()
	return cloneSnapshot(r.state.snapshot)
}

// Close revokes forward verification and releases the descriptor. The caller
// keeps the review until its separately admitted cleanup has actually settled.
func (r *Review) Close() error {
	if r == nil {
		return nil
	}
	if r.state == nil || r.state.self != r {
		return ErrUnknown
	}
	s := r.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return s.closeErr
	}
	s.closed = true
	if s.fence != nil {
		s.closeErr = s.fence.close()
	}
	return s.closeErr
}
