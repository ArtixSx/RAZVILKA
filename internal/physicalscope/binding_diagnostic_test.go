package physicalscope

import (
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

func requireBindingStage(t *testing.T, err error, branch string) {
	t.Helper()
	want := "physical LAN: kernel.bindings." + branch
	var diagnostic *failure
	if err == nil || !errors.Is(err, ErrUnknown) || !errors.As(err, &diagnostic) || diagnostic.Error() != want {
		t.Fatalf("closed binding diagnostic: got %v, want %s", err, want)
	}
	for _, value := range []string{"192.0.", "02:00:", "Home", "private-input"} {
		if strings.Contains(err.Error(), value) {
			t.Fatal("binding diagnostic contains observed input")
		}
	}
}

func TestPhysicalNeighborDecodeClosedDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		branch string
		change func(*message)
	}{
		{"header", func(m *message) { m.data = nil }},
		{"family", func(m *message) { m.data[0] = 7 }},
		{"attributes", func(m *message) { m.data = append(m.data, attr(1, []byte{192, 0, 2, 20})...) }},
		{"index", func(m *message) { binary.NativeEndian.PutUint32(m.data[4:8], 0) }},
		{"address", func(m *message) { *m = neighborFrame(9, "0.0.0.0", "02:00:00:00:00:03", 2) }},
		{"state", func(m *message) { binary.NativeEndian.PutUint16(m.data[8:10], 2|4) }},
		{"type", func(m *message) { m.data[11] = 0 }},
		{"flags", func(m *message) { m.data[10] = 8 }},
		{"router-flag", func(m *message) { m.data[10] = 128 }},
		{"mac", func(m *message) { *m = neighborFrame(9, "192.0.2.20", "", 2) }},
	} {
		t.Run(tc.branch, func(t *testing.T) {
			m := neighborFrame(9, "192.0.2.20", "02:00:00:00:00:03", 2)
			tc.change(&m)
			_, _, err := decodeNeighbor(m)
			requireBindingStage(t, err, "neighbor."+tc.branch)
		})
	}
}

func TestPhysicalDeviceBindingClosedDiagnostics(t *testing.T) {
	for _, branch := range []string{"devices.context", "devices.observation", "devices.ambiguous", "device.segment", "segment.prefix", "device.prefix.missing", "device.prefix.ambiguous", "device.address.reused"} {
		t.Run(branch, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			segments := []Segment{{ID: "Bridge0", Interface: "Home", IfIndex: 9, Prefixes: []string{"192.0.2.0/24"}}}
			row := []byte("192.0.2.20 lladdr 02:00:00:00:00:03 REACHABLE\n")
			rows := kernelNeighborRows{"Home": {false: row, true: {}}}
			switch branch {
			case "devices.context":
				cancel()
			case "devices.observation":
				rows["Home"][false] = []byte("private-input\n")
			case "devices.ambiguous":
				rows["Home"][false] = append(row, []byte("192.0.2.20 lladdr 02:00:00:00:00:04 STALE\n")...)
			case "device.segment":
				segments[0].IfIndex = 0
			case "segment.prefix":
				segments[0].Prefixes = []string{"private-input"}
			case "device.prefix.missing":
				segments[0].Prefixes = []string{"192.0.3.0/24"}
			case "device.prefix.ambiguous":
				segments[0].Prefixes = append(segments[0].Prefixes, "192.0.2.0/25")
			case "device.address.reused":
				segments = append(segments, Segment{ID: "guest", Interface: "iot", IfIndex: 10, Prefixes: []string{"192.0.2.0/24"}})
				rows["iot"] = map[bool][]byte{false: []byte("192.0.2.20 lladdr 02:00:00:00:00:04 STALE\n"), true: {}}
			}
			_, err := bindDevices(ctx, segments, rows)
			requireBindingStage(t, err, branch)
			if branch == "devices.context" && !errors.Is(err, context.Canceled) {
				t.Fatal("diagnostic discarded original cancellation")
			}
		})
	}
}

func TestPhysicalBindingDiagnosticSurvivesObserveAndClosesFence(t *testing.T) {
	o, model, ctx := newModel(t)
	o.source.capture = func(context.Context, Selection) ([]Segment, []Device, error) {
		_, err := bindDevices(ctx, []Segment{{ID: "Bridge0", Interface: "Home", IfIndex: 9, Prefixes: []string{"192.0.2.0/24"}}}, kernelNeighborRows{"Home": {false: []byte("192.0.3.20 lladdr 02:00:00:00:00:03 STALE\n"), true: {}}})
		return nil, nil, err
	}
	review, err := o.Observe(ctx)
	requireBindingStage(t, err, "device.prefix.missing")
	if review != nil || !model.fence.closed {
		t.Fatal("binding refusal retained a usable physical review/fence")
	}
}
