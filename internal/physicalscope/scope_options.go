package physicalscope

import (
	"context"
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

type scopeOptionsBindings func(context.Context, []Segment) ([]Device, error)

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
		devices, bindingErr := bindings(ctx, segments)
		if err := ctx.Err(); err != nil {
			return unavailableScopeOptions("SOURCE_UNAVAILABLE"), err
		}
		if bindingErr != nil {
			r.State, r.Code = "partial", "BINDINGS_UNAVAILABLE"
			continue
		}
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

func errOrUnknown(err error) error {
	if err != nil {
		return err
	}
	return ErrUnknown
}
