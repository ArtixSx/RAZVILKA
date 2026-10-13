package physicalscope

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

type finiteTestFence struct{ reader *originalFenceCollector }

func (f *finiteTestFence) check(c context.Context, s Snapshot) error {
	return f.reader.checkFinite(c, s)
}
func (f *finiteTestFence) close() error { f.reader.close(); return nil }

func finiteUnknownFrame() message {
	m := neighborFrame(9, "fe80::99", "", 32)
	m.data[10] = 128
	return m
}

// Only I/O is modeled. Real dual-stack assembly, binding, capture bookends,
// original continuous collector, typed issuer and primary readers run here.
func finiteTestPrincipal(t *testing.T) (*FiniteIPv4PacketPrincipal, *observerModel, *map[byte][]message, *fenceTestTransport, context.Context) {
	t.Helper()
	o, m, _ := newModel(t)
	m.identity = netidentity.Identity{Version: 1, Kind: netidentity.ReviewedSingleInitNet, BootID: m.identity.BootID, PlatformReviewSHA256: "f77d10cde0399faf1ab9ab6060bc52aa54e61e25c3d4c2381f4f712e78144733"}
	m.selection = selectedTestSelection()
	frames := selectedTestNeighbors()
	frames[10] = append(frames[10], finiteUnknownFrame())
	transport := newFenceTestTransport()
	opens := 0
	o.source.open = func(context.Context) (lifecycleFence, error) {
		opens++
		if opens != 1 {
			t.Fatal("original collector reopened")
		}
		return &finiteTestFence{newOriginalFenceCollector(transport.source())}, nil
	}
	o.source.capture = func(c context.Context, s Selection) ([]Segment, []Device, error) {
		m.captures++
		if m.onCapture != nil {
			m.onCapture(m.captures)
		}
		native, err := parseNDM([]byte(ndmFixture()))
		if err != nil {
			return nil, nil, err
		}
		links, addresses, routes := kernelFixture()
		addresses = append(addresses, addressFrame(9, "2001:db8::1/64"))
		segments, err := assembleSegments(s, native, true, links, addresses, routes)
		if err != nil {
			return nil, nil, err
		}
		devices, err := bindFiniteIPv4KernelNeighbors(c, s, segments, frames)
		return segments, devices, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	p, err := newFiniteIPv4PacketPrincipal(ctx, o)
	if err != nil {
		t.Fatal(DiagnosticStages(err))
	}
	t.Cleanup(func() {
		if err := p.Close(); err != nil {
			t.Error(err)
		}
	})
	return p, m, &frames, transport, ctx
}

func TestFiniteIPv4PrincipalDoesNotIssueFullCoverage(t *testing.T) {
	p, m, frames, _, ctx := finiteTestPrincipal(t)
	if _, err := captureSelectedTest(ctx, m.selection, *frames); err == nil {
		t.Fatal("full decoder accepted UNKNOWN router")
	}
	before := p.Observation()
	if len(before.UnresolvedRouter) != 1 || before.UnresolvedRouter[0].State != 32 || before.UnresolvedRouter[0].Flags != 128 || before.UnresolvedRouter[0].Type != 1 || len(before.Devices) != 2 {
		t.Fatal("UNKNOWN replaced/positive projection changed")
	}
	if !reflect.DeepEqual(p.review.Snapshot(), Snapshot{}) {
		t.Fatal("finite issuer leaked successful full Snapshot")
	}
	if _, err := p.observer.Observe(ctx); err == nil {
		t.Fatal("finite observer minted full Review")
	}
	if p.observer.Verify(ctx, p.review) == nil || p.observer.VerifyRetainedIncarnation(ctx, p.review) == nil {
		t.Fatal("finite review adopted by full API")
	}
	copy := *p
	if copy.Current(ctx) == nil || copy.Close() == nil {
		t.Fatal("copied principal adopted")
	}
	before.Devices[0].Addresses[0] = "192.0.2.99"
	before.UnresolvedRouter[0].Flags = 0
	if err := p.Current(ctx); err != nil {
		t.Fatal(DiagnosticStages(err))
	}
	if p.Observation().UnresolvedRouter[0].Flags != 128 {
		t.Fatal("detached data mutated issuer")
	}
}

func TestFiniteIPv4OriginalUnknownEventsAndCaptureAreSticky(t *testing.T) {
	for _, change := range []string{"state", "mac", "role", "type", "delete", "new", "dump"} {
		t.Run(change, func(t *testing.T) {
			p, _, frames, transport, ctx := finiteTestPrincipal(t)
			original := finiteUnknownFrame()
			transport.push(fenceTestDatagram{raw: frame(original)})
			waitFenceTestDrained(t, transport, 1)
			if err := p.Current(ctx); err != nil {
				t.Fatal("exact UNKNOWN repeat refused", DiagnosticStages(err))
			}
			changed := finiteUnknownFrame()
			switch change {
			case "state":
				changed.data[8] = 1
			case "mac":
				changed = neighborFrame(9, "fe80::99", projectionOtherMAC, 32)
				changed.data[10] = 128
			case "role":
				changed.data[10] = 0
			case "type":
				changed.data[11] = 2
			case "delete":
				changed.kind = 29
			case "new":
				changed = neighborFrame(9, "fe80::98", "", 32)
				changed.data[10] = 128
			case "dump":
				(*frames)[10] = (*frames)[10][:len((*frames)[10])-1]
			}
			if change != "dump" {
				transport.push(fenceTestDatagram{raw: frame(changed)})
				waitFenceTestCounts(t, transport, 2, 0)
			}
			if err := p.Current(ctx); !errors.Is(err, ErrUnknown) {
				t.Fatal("changed original UNKNOWN accepted")
			}
			if change == "dump" {
				(*frames)[10] = append((*frames)[10], original)
			}
			if p.Current(ctx) == nil || p.CurrentRetained(ctx) == nil {
				t.Fatal("restored tuple revived physical issuer")
			}
		})
	}
}

func TestFiniteIPv4ProjectionKeepsKnownAndForeignConflicts(t *testing.T) {
	for _, change := range []string{"router-client", "foreign-client", "address-collision", "missing-client", "two-ipv4"} {
		t.Run(change, func(t *testing.T) {
			p, _, frames, _, ctx := finiteTestPrincipal(t)
			switch change {
			case "router-client":
				m := neighborFrame(9, "fe80::88", projectionClientMAC, 2)
				m.data[10] = 128
				(*frames)[10] = append((*frames)[10], m)
			case "foreign-client":
				(*frames)[2] = append((*frames)[2], neighborFrame(99, "192.0.2.20", projectionClientMAC, 2))
			case "address-collision":
				(*frames)[2] = append((*frames)[2], neighborFrame(99, "192.0.2.20", projectionOtherMAC, 2))
			case "missing-client":
				(*frames)[2] = (*frames)[2][1:]
			case "two-ipv4":
				(*frames)[2] = append((*frames)[2], neighborFrame(9, "192.0.2.21", projectionClientMAC, 2))
			}
			if p.Current(ctx) == nil || p.CurrentRetained(ctx) == nil {
				t.Fatal("conflicting original binding accepted")
			}
		})
	}
}

func TestFiniteIPv4PrimaryRetainsOriginalFlagsResidenceAndSelectionBoundary(t *testing.T) {
	p, m, _, _, ctx := finiteTestPrincipal(t)
	row := primaryIPv4Frame(9, "192.0.2.1/24", 128)
	primary, err := p.reviewPrimaryIPv4(ctx, "Home", netip.MustParseAddr("192.0.2.1"), func(context.Context) ([]message, error) { return []message{row}, nil })
	if err != nil {
		t.Fatal(DiagnosticStages(err))
	}
	if primary.primary.Current(ctx) == nil || primary.primary.CurrentRetained(ctx) == nil {
		t.Fatal("finite primary adopted as full primary")
	}
	copy := *primary
	if copy.Current(ctx) == nil || copy.CurrentRetained(ctx) == nil {
		t.Fatal("copied primary adopted")
	}
	m.selection.Revision++
	if primary.Current(ctx) == nil {
		t.Fatal("old selection accepted forward")
	}
	if err := primary.CurrentRetained(ctx); err != nil {
		t.Fatal("original cleanup lost on selection revocation", DiagnosticStages(err))
	}
	row = primaryIPv4Cache(row, 0, ^uint32(0), 1, 1)
	if primary.CurrentRetained(ctx) == nil {
		t.Fatal("expired preferred residence accepted")
	}
	row = primaryIPv4Frame(9, "192.0.2.1/24", 128)
	if primary.CurrentRetained(ctx) == nil {
		t.Fatal("restored primary revived")
	}
}
