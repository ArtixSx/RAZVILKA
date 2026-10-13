package physicalscope

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func scopeOptionsFixture() (scopeOptionsInput, scopeOptionsBindings) {
	links, addresses, routes := kernelFixture()
	input := scopeOptionsInput{native: []byte(ndmFixture()), links: links, addresses: addresses, routes: routes}
	bind := func(_ context.Context, segments []Segment) (scopeOptionsBindingFacts, error) {
		s := segments[0]
		return scopeOptionsBindingFacts{devices: []Device{{ID: "mac-02-00-00-00-00-40", MAC: "02:00:00:00:00:40", Interface: s.Interface, IfIndex: s.IfIndex, SegmentID: s.ID}}}, nil
	}
	return input, bind
}

func TestScopeOptionsNativeIDAndCurrentAssociationAreDisplayFacts(t *testing.T) {
	in, bind := scopeOptionsFixture()
	r, err := scopeOptionsFromFacts(context.Background(), in, bind)
	if err != nil || r.State != "available" || len(r.Segments) != 1 || len(r.Devices) != 1 {
		t.Fatal("model observation unavailable", r.State, r.Code, err)
	}
	s, d := r.Segments[0], r.Devices[0]
	if s.ID != "Bridge0" || s.NativeName == nil || *s.NativeName != "Home" || s.Interface == nil || *s.Interface != "Home" || s.ID == *s.Interface || !s.SelectionCandidate || d.SegmentID == nil || *d.SegmentID != s.ID || !d.SelectionCandidate {
		t.Fatal("native identity was guessed or association lost")
	}
	if r.ObservedAt == nil || r.FreshUntil == nil || r.FreshUntil.Sub(*r.ObservedAt) != time.Minute {
		t.Fatal("display freshness absent")
	}
}

func TestScopeOptionsRefusesAliasAndBindingConflictsWithoutFallback(t *testing.T) {
	for _, kind := range []string{"alias", "foreign-ifindex", "foreign-segment", "foreign-interface", "noncanonical-id", "duplicate-binding", "malformed-native"} {
		t.Run(kind, func(t *testing.T) {
			in, original := scopeOptionsFixture()
			if kind == "alias" {
				in.native = append(in.native, []byte(ndmObject("Home", "Foreign0", "foreign", "Bridge")+ndmField("global", "yes"))...)
			}
			if kind == "malformed-native" {
				in.native = []byte("not the reviewed native format")
			}
			bind := func(ctx context.Context, segments []Segment) (scopeOptionsBindingFacts, error) {
				facts, err := original(ctx, segments)
				devices := facts.devices
				switch kind {
				case "foreign-ifindex":
					devices[0].IfIndex++
				case "foreign-segment":
					devices[0].SegmentID = "Home"
				case "foreign-interface":
					devices[0].Interface = "foreign"
				case "noncanonical-id":
					devices[0].ID = "cached-name"
				case "duplicate-binding":
					devices = append(devices, devices[0])
				}
				facts.devices = devices
				return facts, err
			}
			r, err := scopeOptionsFromFacts(context.Background(), in, bind)
			if kind == "malformed-native" && err == nil || r.State != "unavailable" || len(r.Devices) != 0 || len(r.Segments) != 0 {
				t.Fatal("uncertain facts produced candidates", r.State, r.Code, err)
			}
		})
	}
}

func TestScopeOptionsEmptyAndPartialAreExplicit(t *testing.T) {
	in, bind := scopeOptionsFixture()
	in.native = []byte(strings.Replace(ndmFixture(), ndmField("security-level", "private"), ndmField("security-level", "protected"), 1))
	r, err := scopeOptionsFromFacts(context.Background(), in, bind)
	if err != nil || r.State != "available" || r.Code != "NO_HOME_CANDIDATES" || len(r.Segments) != 0 || len(r.Devices) != 0 {
		t.Fatal("guest/WAN became a home candidate", r.State, r.Code, err)
	}
	in.native = []byte(strings.Replace(ndmFixture(), ndmField("security-level", "private"), "", 1))
	r, err = scopeOptionsFromFacts(context.Background(), in, bind)
	if err != nil || r.State != "partial" || r.Code != "HOME_ROLE_UNKNOWN" || r.Segments[0].SelectionCandidate {
		t.Fatal("unknown native role became an empty or eligible home")
	}
	in, bind = scopeOptionsFixture()
	r, err = scopeOptionsFromFacts(context.Background(), in, func(context.Context, []Segment) (scopeOptionsBindingFacts, error) {
		return scopeOptionsBindingFacts{}, ErrUnknown
	})
	if err != nil || r.State != "partial" || r.Code != "BINDINGS_UNAVAILABLE" || len(r.Devices) != 0 || !r.Segments[0].SelectionCandidate {
		t.Fatal("bindings UNKNOWN concealed or became permissions")
	}
	in.native = []byte(strings.Replace(ndmFixture(), ndmField("state", "up"), ndmField("state", "down"), 1))
	r, err = scopeOptionsFromFacts(context.Background(), in, func(context.Context, []Segment) (scopeOptionsBindingFacts, error) {
		t.Fatal("unavailable home reached bindings")
		return scopeOptionsBindingFacts{}, nil
	})
	if err != nil || r.State != "partial" || r.Segments[0].SelectionCandidate || r.Segments[0].Interface != nil {
		t.Fatal("down home produced a live association")
	}
}

func TestScopeOptionsBoundsClearOnlyObservationAndCancelJoinsRead(t *testing.T) {
	in, bind := scopeOptionsFixture()
	r, err := scopeOptionsFromFacts(context.Background(), in, func(ctx context.Context, segments []Segment) (scopeOptionsBindingFacts, error) {
		facts, _ := bind(ctx, segments)
		out := make([]Device, 513)
		for i := range out {
			out[i] = facts.devices[0]
		}
		return scopeOptionsBindingFacts{devices: out}, nil
	})
	if err != nil || r.Code != "BOUNDS_EXCEEDED" || len(r.Devices) != 0 || len(r.Segments) != 0 {
		t.Fatal("device bound silently truncated", r.Code, err)
	}
	var raw strings.Builder
	for i := 0; i < 17; i++ {
		raw.WriteString(strings.ReplaceAll(strings.ReplaceAll(ndmHome(), "Bridge0", fmt.Sprintf("Bridge%d", i)), "Home", fmt.Sprintf("Home%d", i)))
	}
	in.native = []byte(raw.String())
	r, err = scopeOptionsFromFacts(context.Background(), in, bind)
	if err != nil || r.Code != "BOUNDS_EXCEEDED" || len(r.Segments) != 0 {
		t.Fatal("segment bound silently truncated", r.Code, err)
	}
	in, _ = scopeOptionsFixture()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	joined := false
	r, err = scopeOptionsFromFacts(ctx, in, func(ctx context.Context, _ []Segment) (scopeOptionsBindingFacts, error) {
		<-ctx.Done()
		joined = true
		return scopeOptionsBindingFacts{}, ctx.Err()
	})
	if !joined || !errors.Is(err, context.DeadlineExceeded) || len(r.Segments) != 0 {
		t.Fatal("canceled synchronous source escaped", r.State, err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	if got := ObserveReviewedStockNC1812ScopeOptions(ctx); got.Code != "SOURCE_CANCELED" || got.State != "unavailable" {
		t.Fatal("public read ignored prior cancellation", got.State, got.Code)
	}
}

func scopeOptionsKernelFixture() (scopeOptionsInput, map[byte][]message) {
	in, _ := scopeOptionsFixture()
	in.addresses = append(in.addresses, addressFrame(9, "2001:db8::1/64"))
	return in, selectedTestNeighbors()
}

func scopeOptionsRouterUnknownFrame(index int, address string, state uint16) message {
	m := neighborFrame(index, address, "", state)
	m.data[10] = 128
	return m
}

func scopeOptionsSegments(t *testing.T, in scopeOptionsInput) []Segment {
	t.Helper()
	native, err := parseNDM(in.native)
	if err != nil {
		t.Fatal(err)
	}
	segments, err := assembleSegments(Selection{SegmentIDs: []string{"Bridge0"}}, native, true, in.links, in.addresses, in.routes)
	if err != nil {
		t.Fatal(err)
	}
	return segments
}

func observeScopeOptionsKernelFixture(ctx context.Context, in scopeOptionsInput, frames map[byte][]message) (ScopeOptionsObservation, error) {
	return scopeOptionsFromFacts(ctx, in, func(c context.Context, segments []Segment) (scopeOptionsBindingFacts, error) {
		return bindScopeOptionsKernelNeighbors(c, segments, frames)
	})
}

func scopeOptionsHasDevice(r ScopeOptionsObservation, mac string) bool {
	return slices.ContainsFunc(r.Devices, func(d ScopeDeviceOption) bool { return d.ID == physicalDeviceID(mac) && d.SelectionCandidate })
}

// Model the exact closed branch seen in router probe 445, including its two
// unresolved IPv6 rows. Only kernel/native I/O is modeled; the original strict
// decoder, segment assembler, conflict checker and device binder run here.
func TestScopeOptionsDisplayRouterUnknownKeepsResolvedCandidates(t *testing.T) {
	for _, state := range []uint16{1, 32} {
		t.Run(fmt.Sprint(state), func(t *testing.T) {
			in, frames := scopeOptionsKernelFixture()
			frames[10] = append(frames[10], scopeOptionsRouterUnknownFrame(9, "fe80::99", state), scopeOptionsRouterUnknownFrame(9, "2001:db8::99", state))
			segments := scopeOptionsSegments(t, in)
			if _, err := bindSelectedKernelNeighbors(context.Background(), Selection{}, segments, frames); !slices.Contains(DiagnosticStages(err), "kernel.bindings.neighbor.router-state") {
				t.Fatal("original full binder no longer refuses probe 445 branch", err)
			}
			calls := 0
			r, err := scopeOptionsFromFacts(context.Background(), in, func(ctx context.Context, s []Segment) (scopeOptionsBindingFacts, error) {
				calls++
				return bindScopeOptionsKernelNeighbors(ctx, s, frames)
			})
			if err != nil || calls != 1 || r.State != "partial" || r.Code != "BINDINGS_ROUTER_UNKNOWN" || len(r.Segments) != 1 || len(r.Devices) != 2 || !scopeOptionsHasDevice(r, projectionClientMAC) || !scopeOptionsHasDevice(r, projectionExcludedMAC) {
				t.Fatal("UNKNOWN suppressed healthy display candidates or became success", r.State, r.Code, len(r.Devices), err)
			}
			for _, d := range r.Devices {
				if d.SegmentID == nil || *d.SegmentID != "Bridge0" || d.State != "observed" || d.Code != "OBSERVED_DEVICE" {
					t.Fatal("current native association lost")
				}
			}
			if _, err := bindSelectedKernelNeighbors(context.Background(), Selection{}, scopeOptionsSegments(t, in), frames); !slices.Contains(DiagnosticStages(err), "kernel.bindings.neighbor.router-state") {
				t.Fatal("display read altered original full refusal", err)
			}
		})
	}
}

func TestScopeOptionsDisplayBindingConflictsRejectPositiveMAC(t *testing.T) {
	for _, kind := range []string{"foreign-ipv4-mac", "foreign-ipv6-mac", "foreign-ipv4-address", "foreign-ipv6-address", "foreign-unresolved-address", "guest-ingress", "router-role", "foreign-router-role", "bridge-mac", "member-mac", "parent-mac", "infrastructure-address", "failed-client", "incomplete-client"} {
		t.Run(kind, func(t *testing.T) {
			in, frames := scopeOptionsKernelFixture()
			frames[10] = append(frames[10], scopeOptionsRouterUnknownFrame(9, "fe80::99", 32))
			blockedMAC := projectionClientMAC
			switch kind {
			case "foreign-ipv4-mac":
				frames[2] = append(frames[2], neighborFrame(5, "198.51.100.20", blockedMAC, 4))
			case "foreign-ipv6-mac":
				frames[10] = append(frames[10], neighborFrame(5, "2001:db8:1::20", blockedMAC, 4))
			case "foreign-ipv4-address":
				frames[2] = append(frames[2], neighborFrame(5, "192.0.2.20", projectionOtherMAC, 4))
			case "foreign-ipv6-address":
				frames[10] = append(frames[10], neighborFrame(5, "2001:db8::20", projectionOtherMAC, 4))
			case "foreign-unresolved-address":
				frames[10] = append(frames[10], scopeOptionsRouterUnknownFrame(5, "2001:db8::20", 32))
			case "guest-ingress":
				in.native = append(in.native, []byte(ndmObject("Bridge1", "Guest", "guest", "Bridge")+ndmField("global", "no")+ndmField("security-level", "protected"))...)
				frames[2] = append(frames[2], neighborFrame(6, "198.51.100.20", blockedMAC, 4))
			case "router-role", "foreign-router-role":
				index := 9
				if kind == "foreign-router-role" {
					index = 5
				}
				m := neighborFrame(index, "fe80::88", blockedMAC, 4)
				m.data[10] = 128
				frames[10] = append(frames[10], m)
			case "bridge-mac", "member-mac", "parent-mac":
				if kind == "bridge-mac" {
					blockedMAC = "02:00:00:00:00:01"
				} else if kind == "member-mac" {
					blockedMAC = "02:00:00:00:00:02"
				} else {
					segments := scopeOptionsSegments(t, in)
					segments[0].Members[0].Parent = ParentLink{Known: true, MAC: blockedMAC}
					facts, err := bindScopeOptionsKernelNeighbors(context.Background(), segments, frames)
					if err != nil || slices.ContainsFunc(facts.devices, func(d Device) bool { return d.MAC == blockedMAC }) {
						t.Fatal("known parent became a device", err)
					}
					return
				}
				frames[2][0] = neighborFrame(9, "192.0.2.20", blockedMAC, 2)
				frames[10][0] = neighborFrame(9, "2001:db8::20", blockedMAC, 4)
				frames[10][1] = neighborFrame(9, "fe80::20", blockedMAC, 4)
			case "infrastructure-address":
				frames[2][0] = neighborFrame(9, "192.0.2.1", blockedMAC, 2)
			case "failed-client", "incomplete-client":
				state := uint16(32)
				if kind == "incomplete-client" {
					state = 1
				}
				frames[10] = append(frames[10], neighborFrame(9, "fe80::88", blockedMAC, state))
			}
			r, err := observeScopeOptionsKernelFixture(context.Background(), in, frames)
			if err != nil || r.State != "partial" || scopeOptionsHasDevice(r, blockedMAC) || len(r.Segments) != 1 || !r.Segments[0].SelectionCandidate {
				t.Fatal("conflicting or infrastructure MAC became positive", r.State, r.Code, err)
			}
			if kind != "infrastructure-address" && kind != "foreign-router-role" && !scopeOptionsHasDevice(r, projectionExcludedMAC) {
				t.Fatal("unrelated healthy MAC was discarded", r.Code)
			}
		})
	}
}

func TestScopeOptionsDisplayOtherDecoderAndPrefixErrorsStayUnavailable(t *testing.T) {
	for _, kind := range []string{"router-with-mac", "resolved-router-without-mac", "router-wrong-type", "router-bad-flags", "ipv4-router-flag", "duplicate-unknown", "duplicate-client-address", "missing-ipv6", "dump-family", "malformed-foreign", "malformed-foreign-attributes", "foreign-known-failed-router", "missing-client-mac", "off-prefix-ipv4", "off-prefix-ipv6", "ambiguous-prefix"} {
		t.Run(kind, func(t *testing.T) {
			in, frames := scopeOptionsKernelFixture()
			unknown := scopeOptionsRouterUnknownFrame(9, "fe80::99", 32)
			switch kind {
			case "router-with-mac":
				unknown = neighborFrame(9, "fe80::99", projectionOtherMAC, 32)
				unknown.data[10] = 128
			case "resolved-router-without-mac":
				unknown = scopeOptionsRouterUnknownFrame(9, "fe80::99", 2)
			case "router-wrong-type":
				unknown.data[11] = 2
			case "router-bad-flags":
				unknown.data[10] |= 1
			case "ipv4-router-flag":
				frames[2][0].data[10] = 128
			case "duplicate-unknown":
				frames[10] = append(frames[10], unknown)
			case "duplicate-client-address":
				frames[2] = append(frames[2], neighborFrame(9, "192.0.2.20", projectionOtherMAC, 4))
			case "missing-ipv6":
				delete(frames, 10)
			case "dump-family":
				frames[2] = append(frames[2], unknown)
			case "malformed-foreign":
				frames[2] = append(frames[2], message{kind: 28, data: []byte{2}})
			case "malformed-foreign-attributes":
				m := neighborFrame(5, "192.0.2.200", projectionOtherMAC, 4)
				m.data = append(m.data, []byte{3, 0, 1, 0}...)
				frames[2] = append(frames[2], m)
			case "foreign-known-failed-router":
				m := neighborFrame(5, "fe80::99", projectionOtherMAC, 32)
				m.data[10] = 128
				frames[10] = append(frames[10], m)
			case "missing-client-mac":
				frames[2][0] = neighborFrame(9, "192.0.2.20", "", 2)
			case "off-prefix-ipv4":
				frames[2][0] = neighborFrame(9, "198.51.100.20", projectionClientMAC, 2)
			case "off-prefix-ipv6":
				frames[10][0] = neighborFrame(9, "2001:db8:1::20", projectionClientMAC, 4)
			case "ambiguous-prefix":
				in.addresses = append(in.addresses, addressFrame(9, "192.0.2.129/25"))
				frames[2][0] = neighborFrame(9, "192.0.2.140", projectionClientMAC, 2)
			}
			if kind != "missing-ipv6" {
				frames[10] = append(frames[10], unknown)
			}
			r, err := observeScopeOptionsKernelFixture(context.Background(), in, frames)
			if err != nil || r.State != "partial" || len(r.Devices) != 0 || !slices.Contains([]string{"BINDINGS_UNAVAILABLE", "HOME_UNAVAILABLE"}, r.Code) {
				t.Fatal("non-UNKNOWN error produced positive candidates", r.State, r.Code, len(r.Devices), err)
			}
		})
	}
}

func TestScopeOptionsDisplayEmptyBookkeepingAndForeignLinkLocal(t *testing.T) {
	in, frames := scopeOptionsKernelFixture()
	r, err := observeScopeOptionsKernelFixture(context.Background(), in, frames)
	if err != nil || r.State != "available" || len(r.Devices) != 2 {
		t.Fatal("ordinary dual-stack clients or known router classification lost", r.State, r.Code, err)
	}
	frames[10] = append(frames[10], neighborFrame(5, "fe80::20", projectionOtherMAC, 4), scopeOptionsRouterUnknownFrame(5, "fe80::99", 32))
	r, err = observeScopeOptionsKernelFixture(context.Background(), in, frames)
	if err != nil || r.State != "partial" || r.Code != "BINDINGS_ROUTER_UNKNOWN" || len(r.Devices) != 2 {
		t.Fatal("foreign link-local key confused with current home", r.State, r.Code, err)
	}
	frames = map[byte][]message{2: {bookkeepingFrame("224.0.0.1", "01:00:5e:00:00:01", 5)}, 10: {scopeOptionsRouterUnknownFrame(9, "fe80::99", 32)}}
	r, err = observeScopeOptionsKernelFixture(context.Background(), in, frames)
	if err != nil || r.State != "partial" || len(r.Devices) != 0 {
		t.Fatal("UNKNOWN or exact bookkeeping became a device", r.State, r.Code, err)
	}
}

func TestScopeOptionsDisplayBoundsCancellationAndNoMutation(t *testing.T) {
	in, frames := scopeOptionsKernelFixture()
	frames[10] = append(frames[10], scopeOptionsRouterUnknownFrame(9, "fe80::99", 32))
	segments := scopeOptionsSegments(t, in)
	before := scopeOptionsSegments(t, in)
	copyFrames := map[byte][]message{}
	for family, messages := range frames {
		for _, m := range messages {
			copyFrames[family] = append(copyFrames[family], message{kind: m.kind, data: slices.Clone(m.data)})
		}
	}
	if _, err := bindScopeOptionsKernelNeighbors(context.Background(), segments, frames); err != nil || !reflect.DeepEqual(segments, before) || !reflect.DeepEqual(frames, copyFrames) {
		t.Fatal("display read changed kernel/native facts", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if facts, err := bindScopeOptionsKernelNeighbors(ctx, segments, frames); !errors.Is(err, context.Canceled) || len(facts.devices) != 0 {
		t.Fatal("canceled display read produced candidates", err)
	}
	for _, bound := range []string{"devices", "records", "bytes"} {
		t.Run(bound, func(t *testing.T) {
			frames := map[byte][]message{2: {}, 10: {}}
			if bound == "devices" {
				for i := 1; i <= 513; i++ {
					frames[10] = append(frames[10], neighborFrame(9, fmt.Sprintf("2001:db8::%x", i+100), fmt.Sprintf("02:00:00:00:%02x:%02x", i>>8, i&255), 4))
				}
			} else if bound == "records" {
				for i := 1; i <= 4097; i++ {
					frames[10] = append(frames[10], neighborFrame(5, fmt.Sprintf("fe80::%x", i), projectionOtherMAC, 4))
				}
			} else {
				m := neighborFrame(5, "192.0.2.200", projectionOtherMAC, 4)
				m.data = append(m.data, make([]byte, 1<<20)...)
				frames[2] = append(frames[2], m)
			}
			facts, err := bindScopeOptionsKernelNeighbors(context.Background(), segments, frames)
			if err == nil || len(facts.devices) != 0 {
				t.Fatal("bounded source silently truncated or became success", err)
			}
		})
	}
}
