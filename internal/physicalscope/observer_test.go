package physicalscope

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

type modelFence struct {
	opened, closed, changed bool
	checks                  int
}

func (f *modelFence) check(ctx context.Context, _ []Segment, _ []Device) error {
	f.checks++
	if !f.opened || f.closed || f.changed || ctx.Err() != nil {
		return ErrUnknown
	}
	return nil
}
func (f *modelFence) close() error { f.closed = true; return nil }

type observerModel struct {
	selection       Selection
	identity        netidentity.Identity
	facts           Snapshot
	fence           *modelFence
	reads, captures int
	onCapture       func(int)
	onSelection     func(int)
}

func newModel(t *testing.T) (*Observer, *observerModel, context.Context) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	m := &observerModel{selection: Selection{Revision: 7, PolicyRevision: 3, HomeSegmentID: "Home", GuestSegmentIDs: []string{"iot"}}, identity: netidentity.Identity{Version: 1, Kind: netidentity.ProcNetInode, BootID: "12345678-1234-1234-1234-123456789abc", Inode: 92}, fence: &modelFence{}}
	m.facts = Snapshot{Segments: []Segment{{ID: "Bridge0", NativeName: "Home", Interface: "Home", IfIndex: 9, MAC: "02:00:00:00:00:01", Prefixes: []string{"192.0.2.0/24", "2001:db8::/64"}, LinkAddresses: []string{"192.0.2.1/24", "2001:db8::1/64"}, Members: []Link{{Interface: "eth0", IfIndex: 4, MAC: "02:00:00:00:00:02"}}, Home: true}}, Devices: []Device{{ID: "mac-020000000003", MAC: "02:00:00:00:00:03", Interface: "Home", IfIndex: 9, SegmentID: "Bridge0", Addresses: []string{"192.0.2.20", "2001:db8::20"}, LinkLocalAddresses: []string{"fe80::20"}}}}
	o := &Observer{selection: func(c context.Context) (Selection, error) {
		m.reads++
		if m.onSelection != nil {
			m.onSelection(m.reads)
		}
		return m.selection, c.Err()
	}, source: observerSource{
		current: func(c context.Context, use func(context.Context, netidentity.Identity) error) error {
			if c.Err() != nil {
				return c.Err()
			}
			return use(c, m.identity)
		},
		open: func(context.Context) (lifecycleFence, error) { m.fence.opened = true; return m.fence, nil },
		capture: func(context.Context, Selection) ([]Segment, []Device, error) {
			m.captures++
			if !m.fence.opened || m.fence.closed {
				return nil, nil, ErrUnknown
			}
			if m.onCapture != nil {
				m.onCapture(m.captures)
			}
			s := cloneSnapshot(m.facts)
			return s.Segments, s.Devices, nil
		},
	}}
	return o, m, ctx
}
func TestPhysicalObserveAndVerifyRetainSameFence(t *testing.T) {
	o, m, ctx := newModel(t)
	r, err := o.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if m.captures != 2 || r.Snapshot().ReviewID == "" || r.Snapshot().Identity != m.identity {
		t.Fatal("not a bracketed original review")
	}
	if err := o.Verify(ctx, r); err != nil {
		t.Fatal(err)
	}
	if m.captures != 4 || m.fence.closed {
		t.Fatal("replacement or closed fence")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if !m.fence.closed || o.Verify(ctx, r) == nil {
		t.Fatal("close did not revoke")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
}
func TestPhysicalSnapshotIsDetached(t *testing.T) {
	o, _, ctx := newModel(t)
	r, err := o.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	before := r.Snapshot()
	copy := r.Snapshot()
	copy.Selection.GuestSegmentIDs[0] = "evil"
	copy.Segments[0].Prefixes[0] = "0.0.0.0/0"
	copy.Segments[0].LinkAddresses[0] = "198.51.100.1/24"
	copy.Segments[0].Members[0].IfIndex = 19
	copy.Devices[0].Addresses[0] = "203.0.113.2"
	copy.Devices[0].LinkLocalAddresses[0] = "fe80::21"
	if !reflect.DeepEqual(before, r.Snapshot()) || o.Verify(ctx, r) != nil {
		t.Fatal("detached metadata mutated review")
	}
}
func TestPhysicalOriginalReviewCannotBeReissuedFromDTO(t *testing.T) {
	o, _, ctx := newModel(t)
	r, err := o.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if o.Verify(ctx, &Review{state: &reviewState{snapshot: r.Snapshot()}}) == nil {
		t.Fatal("DTO issued authority")
	}
	copy := *r
	if o.Verify(ctx, &copy) == nil || copy.Close() == nil {
		t.Fatal("value copy adopted original private review")
	}
	other, _, _ := newModel(t)
	if other.Verify(ctx, r) == nil {
		t.Fatal("wrong observer accepted review")
	}
}
func TestPhysicalChangedFactsPermanentlyRevoke(t *testing.T) {
	changes := map[string]func(*observerModel){
		"selection revision": func(m *observerModel) { m.selection.Revision++ },
		"policy revision":    func(m *observerModel) { m.selection.PolicyRevision++ },
		"guest selection":    func(m *observerModel) { m.selection.GuestSegmentIDs = []string{"guest"} },
		"typed identity":     func(m *observerModel) { m.identity.Inode++ },
		"ifindex":            func(m *observerModel) { m.facts.Segments[0].IfIndex++ },
		"MAC":                func(m *observerModel) { m.facts.Segments[0].MAC = "02:00:00:00:00:09" },
		"prefix":             func(m *observerModel) { m.facts.Segments[0].Prefixes[1] = "2001:db8:1::/64" },
		"member":             func(m *observerModel) { m.facts.Segments[0].Members[0].IfIndex++ },
		"Home role":          func(m *observerModel) { m.facts.Segments[0].Home = false },
		"device attachment":  func(m *observerModel) { m.facts.Devices[0].SegmentID = "Bridge1" },
		"device address":     func(m *observerModel) { m.facts.Devices[0].Addresses[0] = "192.0.2.21" },
		"link-local binding": func(m *observerModel) { m.facts.Devices[0].LinkLocalAddresses[0] = "fe80::21" },
		"fence ABA":          func(m *observerModel) { m.fence.changed = true },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			o, m, ctx := newModel(t)
			r, err := o.Observe(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			oldSelection, oldIdentity, oldFacts := m.selection, m.identity, cloneSnapshot(m.facts)
			change(m)
			if o.Verify(ctx, r) == nil {
				t.Fatal("changed facts accepted")
			}
			m.selection, m.identity, m.facts = oldSelection, oldIdentity, oldFacts
			m.fence.changed = false
			if o.Verify(ctx, r) == nil {
				t.Fatal("restored tuple reissued old review")
			}
		})
	}
}
func TestPhysicalClosingChangesCannotPublish(t *testing.T) {
	for _, stage := range []string{"capture", "selection", "identity", "fence"} {
		t.Run(stage, func(t *testing.T) {
			o, m, ctx := newModel(t)
			if stage == "selection" {
				m.onSelection = func(n int) {
					if n == 2 {
						m.selection.Revision++
					}
				}
			} else {
				m.onCapture = func(n int) {
					if n == 2 {
						switch stage {
						case "capture":
							m.facts.Devices[0].Addresses[0] = "192.0.2.21"
						case "identity":
							m.identity.Inode++
						case "fence":
							m.fence.changed = true
						}
					}
				}
			}
			r, err := o.Observe(ctx)
			if err == nil || r != nil || !m.fence.closed {
				t.Fatal("late change published or leaked fence")
			}
		})
	}
}
func TestPhysicalOriginalContextBudgetAndValues(t *testing.T) {
	o, _, _ := newModel(t)
	type key struct{}
	parent, cancel := context.WithTimeout(context.WithValue(context.Background(), key{}, "original"), time.Second)
	defer cancel()
	deadline, _ := parent.Deadline()
	original := o.source.current
	o.source.current = func(c context.Context, use func(context.Context, netidentity.Identity) error) error {
		got, ok := c.Deadline()
		if !ok || got.After(deadline) || c.Value(key{}) != "original" {
			t.Fatal("context refreshed or values lost")
		}
		return original(c, use)
	}
	r, err := o.Observe(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	cancel()
	if o.Verify(parent, r) == nil {
		t.Fatal("cancelled verify accepted")
	}
	if _, err := o.Observe(context.Background()); err == nil {
		t.Fatal("unbounded caller accepted")
	}
}
func TestPhysicalMissingProductionDependenciesRefuse(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, o := range []*Observer{nil, {}, NewLinux(nil, func(context.Context) (Selection, error) { return Selection{}, nil }), NewReviewedStockNC1812(netidentity.NewProcProvider(), nil)} {
		if _, err := o.Observe(ctx); !errors.Is(err, ErrUnknown) {
			t.Fatalf("missing dependency accepted: %v", err)
		}
	}
}
