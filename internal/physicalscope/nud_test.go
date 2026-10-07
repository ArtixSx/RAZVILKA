package physicalscope

import (
	"context"
	"testing"
)

func TestPhysicalBenignNUDRefreshPreservesOriginalBinding(t *testing.T) {
	segments := []Segment{{Interface: "Home", IfIndex: 9}}
	devices := []Device{{MAC: "02:00:00:00:00:03", IfIndex: 9, Addresses: []string{"192.0.2.20", "2001:db8::20"}, LinkLocalAddresses: []string{"fe80::20"}}}
	for _, address := range []string{"192.0.2.20", "2001:db8::20", "fe80::20"} {
		for _, state := range []uint16{2, 4, 8, 16, 64, 128} {
			event := neighborFrame(9, address, devices[0].MAC, state)
			event.seq, event.pid = 91, 73
			if err := checkNotifications([]message{event}, segments, devices); err != nil {
				t.Fatal("same binding NUD poisoned original review", state, err)
			}
		}
	}
}

type packetFence struct {
	events []message
	closed bool
}

func (f *packetFence) check(c context.Context, s []Segment, d []Device) error {
	if f.closed || c.Err() != nil {
		return ErrUnknown
	}
	events := f.events
	f.events = nil
	return checkNotifications(events, s, d)
}
func (f *packetFence) close() error { f.closed = true; return nil }
func TestPhysicalReviewKeepsOriginalTupleAcrossNUDAndRefusesReplacement(t *testing.T) {
	o, m, ctx := newModel(t)
	f := &packetFence{}
	o.source.open = func(context.Context) (lifecycleFence, error) { m.fence.opened = true; return f, nil }
	r, err := o.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for _, state := range []uint16{4, 8, 16, 2} {
		f.events = []message{neighborFrame(9, "192.0.2.20", m.facts.Devices[0].MAC, state)}
		if err := o.Verify(ctx, r); err != nil {
			t.Fatal("benign NUD poisoned same original review", err)
		}
	}
	old := m.facts.Devices[0].MAC
	m.facts.Devices[0].MAC = "02:00:00:00:00:04"
	f.events = []message{neighborFrame(9, "192.0.2.20", m.facts.Devices[0].MAC, 4)}
	if o.Verify(ctx, r) == nil {
		t.Fatal("replacement matched refreshed facts rather than original review")
	}
	m.facts.Devices[0].MAC = old
	f.events = []message{neighborFrame(9, "192.0.2.20", old, 2)}
	if o.Verify(ctx, r) == nil {
		t.Fatal("restored binding renewed invalid original review")
	}
}
func TestPhysicalNUDDoesNotMaskBindingChangesOrLoss(t *testing.T) {
	segments := []Segment{{Interface: "Home", IfIndex: 9}, {Interface: "iot", IfIndex: 10}}
	devices := []Device{{MAC: "02:00:00:00:00:03", IfIndex: 9, Addresses: []string{"192.0.2.20"}}}
	original := neighborFrame(9, "192.0.2.20", devices[0].MAC, 2)
	different := neighborFrame(9, "192.0.2.20", "02:00:00:00:00:04", 4)
	deleted := original
	deleted.kind = 29
	for name, events := range map[string][]message{
		"MAC change and restore": {different, original},
		"delete and restore":     {deleted, original},
		"new address":            {neighborFrame(9, "192.0.2.21", devices[0].MAC, 4)},
		"moved ingress":          {neighborFrame(10, "192.0.2.20", devices[0].MAC, 4)},
		"failed":                 {neighborFrame(9, "192.0.2.20", devices[0].MAC, 32)},
		"incomplete":             {neighborFrame(9, "192.0.2.20", "", 1)},
		"overrun":                {{kind: 4}},
		"unknown family":         {{kind: 28, data: []byte{7}}},
	} {
		t.Run(name, func(t *testing.T) {
			if checkNotifications(events, segments, devices) == nil {
				t.Fatal("changed/unknown original binding survived")
			}
		})
	}
	proxy := original
	proxy.data = append([]byte(nil), original.data...)
	proxy.data[10] = 8
	if checkNotifications([]message{proxy}, segments, devices) == nil {
		t.Fatal("proxy entry became actual client binding")
	}
}
