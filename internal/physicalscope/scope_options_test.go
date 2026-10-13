package physicalscope

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func scopeOptionsFixture() (scopeOptionsInput, scopeOptionsBindings) {
	links, addresses, routes := kernelFixture()
	input := scopeOptionsInput{native: []byte(ndmFixture()), links: links, addresses: addresses, routes: routes}
	bind := func(_ context.Context, segments []Segment) ([]Device, error) {
		s := segments[0]
		return []Device{{ID: "mac-02-00-00-00-00-40", MAC: "02:00:00:00:00:40", Interface: s.Interface, IfIndex: s.IfIndex, SegmentID: s.ID}}, nil
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
			bind := func(ctx context.Context, segments []Segment) ([]Device, error) {
				devices, err := original(ctx, segments)
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
				return devices, err
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
	r, err = scopeOptionsFromFacts(context.Background(), in, func(context.Context, []Segment) ([]Device, error) { return nil, ErrUnknown })
	if err != nil || r.State != "partial" || r.Code != "BINDINGS_UNAVAILABLE" || len(r.Devices) != 0 || !r.Segments[0].SelectionCandidate {
		t.Fatal("bindings UNKNOWN concealed or became permissions")
	}
	in.native = []byte(strings.Replace(ndmFixture(), ndmField("state", "up"), ndmField("state", "down"), 1))
	r, err = scopeOptionsFromFacts(context.Background(), in, func(context.Context, []Segment) ([]Device, error) {
		t.Fatal("unavailable home reached bindings")
		return nil, nil
	})
	if err != nil || r.State != "partial" || r.Segments[0].SelectionCandidate || r.Segments[0].Interface != nil {
		t.Fatal("down home produced a live association")
	}
}

func TestScopeOptionsBoundsClearOnlyObservationAndCancelJoinsRead(t *testing.T) {
	in, bind := scopeOptionsFixture()
	r, err := scopeOptionsFromFacts(context.Background(), in, func(ctx context.Context, segments []Segment) ([]Device, error) {
		devices, _ := bind(ctx, segments)
		out := make([]Device, 513)
		for i := range out {
			out[i] = devices[0]
		}
		return out, nil
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
	r, err = scopeOptionsFromFacts(ctx, in, func(ctx context.Context, _ []Segment) ([]Device, error) {
		<-ctx.Done()
		joined = true
		return nil, ctx.Err()
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
