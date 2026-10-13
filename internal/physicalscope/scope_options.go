package physicalscope

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"slices"
	"strings"
	"time"
)

const ScopeOptionsTimeout = 3 * time.Second
const ScopeOptionsFreshness = time.Minute

// Scope options are display facts for an explicit policy review. They contain
// no Review, principal, retained identity, effect grant or executable scope.
type ScopeSegmentOption struct {
	ID                 string  `json:"id"`
	Label              string  `json:"label"`
	NativeName         *string `json:"native_name"`
	Interface          *string `json:"interface"`
	State              string  `json:"state"`
	Code               string  `json:"code"`
	SelectionCandidate bool    `json:"selection_candidate"`
}

type ScopeDeviceOption struct {
	ID                 string  `json:"id"`
	Label              string  `json:"label"`
	SegmentID          *string `json:"segment_id"`
	State              string  `json:"state"`
	Code               string  `json:"code"`
	SelectionCandidate bool    `json:"selection_candidate"`
}

type ScopeOptionsObservation struct {
	State      string               `json:"state"`
	Code       string               `json:"code"`
	ObservedAt *time.Time           `json:"observed_at"`
	FreshUntil *time.Time           `json:"fresh_until"`
	Segments   []ScopeSegmentOption `json:"segments"`
	Devices    []ScopeDeviceOption  `json:"devices"`
}

func unavailableScopeOptions(code string) ScopeOptionsObservation {
	return ScopeOptionsObservation{State: "unavailable", Code: code, Segments: []ScopeSegmentOption{}, Devices: []ScopeDeviceOption{}}
}

// ObserveReviewedStockNC1812ScopeOptions has one aggregate read budget. It does
// not open the full Observer, its continuity fence or a policy/control owner.
func ObserveReviewedStockNC1812ScopeOptions(ctx context.Context) ScopeOptionsObservation {
	if ctx == nil {
		return unavailableScopeOptions("SOURCE_UNAVAILABLE")
	}
	c, cancel := context.WithTimeout(ctx, ScopeOptionsTimeout)
	defer cancel()
	r, err := readScopeOptions(c)
	if err != nil || c.Err() != nil {
		code := "SOURCE_UNAVAILABLE"
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(c.Err(), context.DeadlineExceeded) {
			code = "SOURCE_TIMEOUT"
		} else if errors.Is(err, context.Canceled) || errors.Is(c.Err(), context.Canceled) {
			code = "SOURCE_CANCELED"
		}
		return unavailableScopeOptions(code)
	}
	return r
}

type scopeOptionsInput struct {
	native                   []byte
	links, addresses, routes []message
}

type scopeOptionsBindingFacts struct {
	devices           []Device
	unknownRouter     bool
	rejectedCandidate bool
}

type scopeOptionsBindings func(context.Context, []Segment) (scopeOptionsBindingFacts, error)

// Both callers and tests must explicitly supply current read facts. Cached
// discovery labels never enter this classifier or provide an association.
func scopeOptionsFromFacts(ctx context.Context, in scopeOptionsInput, bindings scopeOptionsBindings) (ScopeOptionsObservation, error) {
	r := unavailableScopeOptions("SOURCE_UNAVAILABLE")
	if err := ctx.Err(); err != nil {
		return r, err
	}
	native, err := parseNDM(in.native)
	if err != nil || bindings == nil {
		return r, errOrUnknown(err)
	}
	r.State, r.Code = "available", "OBSERVED"
	seenDevices := map[string]bool{}
	for _, v := range native {
		if v.kind != "Bridge" || v.global == "yes" || v.security == "protected" || v.security == "public" {
			continue
		}
		if len(r.Segments) == 16 {
			return unavailableScopeOptions("BOUNDS_EXCEEDED"), nil
		}
		name := v.name
		option := ScopeSegmentOption{ID: v.id, Label: name, NativeName: &name, State: "unavailable", Code: "HOME_UNAVAILABLE"}
		resolved, resolveErr := resolveNative(native, v.id)
		_, aliasErr := resolveNative(native, v.name)
		if resolveErr != nil || aliasErr != nil || resolved.id != v.id {
			return unavailableScopeOptions("ALIAS_CONFLICT"), nil
		}
		if v.global != "no" || v.security != "private" {
			option.State, option.Code = "unknown", "HOME_ROLE_UNKNOWN"
			r.State, r.Code = "partial", "HOME_ROLE_UNKNOWN"
			r.Segments = append(r.Segments, option)
			continue
		}
		segments, assembleErr := assembleSegments(Selection{SegmentIDs: []string{v.id}}, native, true, in.links, in.addresses, in.routes)
		if assembleErr != nil || len(segments) != 1 || !segments[0].Home || segments[0].ID != v.id {
			r.State, r.Code = "partial", "HOME_UNAVAILABLE"
			r.Segments = append(r.Segments, option)
			continue
		}
		segment := segments[0]
		iface := segment.Interface
		option.Interface, option.State, option.Code, option.SelectionCandidate = &iface, "observed", "OBSERVED_HOME", true
		r.Segments = append(r.Segments, option)
		facts, bindingErr := bindings(ctx, segments)
		if err := ctx.Err(); err != nil {
			return unavailableScopeOptions("SOURCE_UNAVAILABLE"), err
		}
		if bindingErr != nil {
			r.State, r.Code = "partial", "BINDINGS_UNAVAILABLE"
			continue
		}
		if facts.unknownRouter {
			r.State, r.Code = "partial", "BINDINGS_ROUTER_UNKNOWN"
		}
		if facts.rejectedCandidate {
			r.State, r.Code = "partial", "BINDINGS_CONFLICT"
		}
		devices := facts.devices
		if len(devices) > 512-len(r.Devices) {
			return unavailableScopeOptions("BOUNDS_EXCEEDED"), nil
		}
		for _, d := range devices {
			mac, macErr := net.ParseMAC(d.MAC)
			id := "mac-" + strings.ReplaceAll(d.MAC, ":", "-")
			if macErr != nil || len(mac) != 6 || !validMAC(d.MAC) || mac.String() != d.MAC || d.ID != id || seenDevices[d.ID] || d.SegmentID != segment.ID || d.Interface != segment.Interface || d.IfIndex != segment.IfIndex {
				return unavailableScopeOptions("AMBIGUOUS_BINDINGS"), nil
			}
			seenDevices[d.ID] = true
			segmentID := segment.ID
			r.Devices = append(r.Devices, ScopeDeviceOption{ID: d.ID, Label: d.ID, SegmentID: &segmentID, State: "observed", Code: "OBSERVED_DEVICE", SelectionCandidate: true})
		}
	}
	if err := ctx.Err(); err != nil {
		return unavailableScopeOptions("SOURCE_UNAVAILABLE"), err
	}
	if len(r.Segments) == 0 {
		r.Code = "NO_HOME_CANDIDATES"
	}
	slices.SortFunc(r.Segments, func(a, b ScopeSegmentOption) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(r.Devices, func(a, b ScopeDeviceOption) int { return strings.Compare(a.ID, b.ID) })
	now := time.Now().UTC()
	until := now.Add(ScopeOptionsFreshness)
	r.ObservedAt, r.FreshUntil = &now, &until
	return r, nil
}

// This display-only binder has no Selection, revisions, finite purpose,
// Snapshot or issuer. UNKNOWN router rows remain in the local conflict input;
// they never supply a device identity or complete negative MAC coverage.
func bindScopeOptionsKernelNeighbors(ctx context.Context, segments []Segment, frames map[byte][]message) (scopeOptionsBindingFacts, error) {
	var facts scopeOptionsBindingFacts
	if len(segments) != 1 || !segments[0].Home || segments[0].Guest || segments[0].ID == "" || segments[0].Interface == "" || segments[0].IfIndex <= 0 {
		return facts, at("scope-options.bindings.segment", nil)
	}
	segment := segments[0]
	infraMACs := map[string]bool{}
	addInfra := func(mac string) error {
		if !validMAC(mac) {
			return at("scope-options.bindings.infrastructure", nil)
		}
		infraMACs[mac] = true
		return nil
	}
	if err := addInfra(segment.MAC); err != nil {
		return facts, err
	}
	for _, member := range segment.Members {
		if err := addInfra(member.MAC); err != nil {
			return facts, err
		}
		if member.Parent.Known {
			if err := addInfra(member.Parent.MAC); err != nil {
				return facts, err
			}
		}
	}
	var neighbors, foreign []kernelNeighbor
	routerMACs, foreignMACs, candidates := map[string]bool{}, map[string]bool{}, map[string]bool{}
	seen := map[string]bool{}
	totalBytes, totalRecords := 0, 0
	for _, family := range []byte{2, 10} {
		messages, ok := frames[family]
		if !ok {
			return scopeOptionsBindingFacts{}, at("kernel.bindings.neighbor.family-missing", nil)
		}
		for _, m := range messages {
			if err := ctx.Err(); err != nil {
				return scopeOptionsBindingFacts{}, err
			}
			totalBytes += len(m.data)
			totalRecords++
			if totalBytes > 1<<20 || totalRecords > 4096 {
				return scopeOptionsBindingFacts{}, at("kernel.bindings.neighbor.limit", nil)
			}
			if len(m.data) < 12 {
				return scopeOptionsBindingFacts{}, at("kernel.bindings.neighbor.header", nil)
			}
			if m.data[0] != family {
				return scopeOptionsBindingFacts{}, at("kernel.bindings.neighbor.dump-family", nil)
			}
			selected := int(int32(binary.NativeEndian.Uint32(m.data[4:8]))) == segment.IfIndex
			var n kernelNeighbor
			var bookkeeping bool
			var err error
			if selected {
				n, bookkeeping, err = decodeSegmentNeighbor(m, segment)
			} else {
				n, bookkeeping, err = decodeForeignKernelNeighbor(m, segments)
				// Foreign router rows use the same exact UNKNOWN classifier.
				if err == nil && !bookkeeping && n.flags&128 != 0 {
					err = validateUnicastNeighbor(n)
				}
			}
			unknown := scopeOptionsUnknownRouter(n, err)
			if err != nil && !unknown {
				return scopeOptionsBindingFacts{}, err
			}
			facts.unknownRouter = facts.unknownRouter || unknown
			if selected {
				key := n.address.String()
				if seen[key] {
					return scopeOptionsBindingFacts{}, at("kernel.bindings.neighbor.duplicate", nil)
				}
				seen[key] = true
			}
			if bookkeeping {
				continue
			}
			if n.flags&128 != 0 && n.mac != "" {
				routerMACs[n.mac] = true
			}
			if !selected {
				foreign = append(foreign, n)
				if n.mac != "" {
					foreignMACs[n.mac] = true
				}
				continue
			}
			neighbors = append(neighbors, n)
			if n.flags&128 == 0 && n.state != 1 && n.state != 32 {
				candidates[n.mac] = true
				if len(candidates) > 512 {
					return scopeOptionsBindingFacts{}, at("scope-options.bindings.device-limit", nil)
				}
			}
		}
	}
	allowed := map[string]bool{}
	for mac := range candidates {
		if err := ctx.Err(); err != nil {
			return scopeOptionsBindingFacts{}, err
		}
		if infraMACs[mac] || routerMACs[mac] {
			continue
		}
		if foreignMACs[mac] {
			facts.rejectedCandidate = true
			continue
		}
		// Reuse only the pure conflict checker, with an actually observed MAC.
		// No user Selection or physical permission is manufactured from it.
		p := &SelectedDeviceProjection{DeviceIDs: []string{physicalDeviceID(mac)}}
		_, err := validateProjectedNeighbors(p, segments, neighbors, foreign, routerMACs)
		if err != nil {
			f, closed := err.(*failure)
			if closed && (f.stage == "projection.bindings.address-conflict" || f.stage == "projection.bindings.role-state" || f.stage == "projection.bindings.ingress") {
				facts.rejectedCandidate = true
				continue
			}
			return scopeOptionsBindingFacts{}, err
		}
		allowed[mac] = true
	}
	rows := kernelNeighborRows{segment.Interface: {false: {}, true: {}}}
	for _, n := range neighbors {
		if allowed[n.mac] {
			family := n.address.Is6()
			rows[segment.Interface][family] = append(rows[segment.Interface][family], []byte(n.row())...)
		}
	}
	devices, err := bindDevices(ctx, segments, rows)
	if err != nil {
		return scopeOptionsBindingFacts{}, err
	}
	facts.devices = devices
	return facts, nil
}

func scopeOptionsUnknownRouter(n kernelNeighbor, err error) bool {
	f, ok := err.(*failure)
	return ok && f != nil && f.stage == "kernel.bindings.neighbor.router-state" && n.kind == 1 && n.address.Is6() &&
		!n.address.IsMulticast() && n.mac == "" && n.flags&128 != 0 && (n.state == 1 || n.state == 32)
}

func errOrUnknown(err error) error {
	if err != nil {
		return err
	}
	return ErrUnknown
}
