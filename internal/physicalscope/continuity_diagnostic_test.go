package physicalscope

import (
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// A foreign cause must never be formatted by the closed diagnostics.
type privateDiagnosticCause struct{}

func (*privateDiagnosticCause) Error() string { panic("formatted private observed input") }

func requireClosedContinuity(t *testing.T, err error, stages ...string) {
	t.Helper()
	if err == nil || !errors.Is(err, ErrUnknown) {
		t.Fatal("refusal lost its error identity")
	}
	text := err.Error()
	for _, stage := range stages {
		if !strings.Contains(text, stage) {
			t.Fatalf("closed branch missing %s: %s", stage, text)
		}
	}
	for _, private := range []string{"192.0.", "2001:db8", "02:00:", "Home", "Bridge0", "eth0", "private-input"} {
		if strings.Contains(text, private) {
			t.Fatal("continuity diagnostic exposed observed input")
		}
	}
}

type rejectingDiagnosticFence struct {
	base   *modelFence
	reject int
}

func (f *rejectingDiagnosticFence) close() error { return f.base.close() }
func (f *rejectingDiagnosticFence) check(ctx context.Context, s []Segment, d []Device) error {
	if err := f.base.check(ctx, s, d); err != nil {
		return err
	}
	if f.base.checks == f.reject {
		return at("fence.notifications", at("notifications.neighbor.failed", nil))
	}
	return nil
}

func TestPhysicalClosedObserveDiagnosticsLocateOriginalFailureAndCloseFence(t *testing.T) {
	for _, tc := range []struct {
		name, phase, branch string
		closed              bool
	}{
		{"selection-read", "observe.selection", "selection.read", false},
		{"selection-canonical", "observe.selection", "selection.canonical", false},
		{"initial-current", "observe.initial.current", "observe.initial.current", false},
		{"open", "observe.initial.current", "observe.fence.open", true},
		{"missing-fence", "observe.fence.missing", "observe.fence.missing", false},
		{"initial-provider", "capture.initial.current", "capture.initial.current", true},
		{"initial-identity-invalid", "capture.initial.current", "capture.initial.identity.invalid", true},
		{"initial-identity-changed", "capture.initial.current", "capture.initial.identity.changed", true},
		{"initial-facts", "capture.initial.current", "capture.initial.facts", true},
		{"initial-fence-after", "capture.initial.current", "capture.initial.fence.after", true},
		{"pass-provider", "capture.pass.current", "capture.pass.current", true},
		{"pass-fence-before", "capture.pass.current", "capture.pass.fence.before", true},
		{"pass-facts", "capture.pass.current", "capture.pass.facts", true},
		{"pass-fence-after", "capture.pass.current", "capture.pass.fence.after", true},
		{"closing-selection-read", "capture.closing.selection.read", "selection.read", true},
		{"closing-selection-changed", "capture.closing.selection.changed", "capture.closing.selection.changed", true},
		{"closing-provider", "capture.closing.current", "capture.closing.current", true},
		{"closing-identity", "capture.closing.current", "capture.closing.identity.changed", true},
		{"closing-fence", "capture.closing.current", "capture.closing.fence", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o, m, ctx := newModel(t)
			cause := &privateDiagnosticCause{}
			originalCurrent, originalCapture, originalSelection := o.source.current, o.source.capture, o.selection
			calls, factsCalls := 0, 0
			o.source.current = func(c context.Context, use func(context.Context, netidentity.Identity) error) error {
				calls++
				if tc.name == "initial-current" && calls == 1 || tc.name == "initial-provider" && calls == 2 || tc.name == "pass-provider" && calls == 3 || tc.name == "closing-provider" && calls == 4 {
					return cause
				}
				if tc.name == "initial-identity-invalid" && calls == 2 {
					m.identity.Version = 0
				}
				if tc.name == "initial-identity-changed" && calls == 2 || tc.name == "closing-identity" && calls == 4 {
					m.identity.Inode++
				}
				return originalCurrent(c, use)
			}
			o.source.capture = func(c context.Context, s Selection) ([]Segment, []Device, error) {
				factsCalls++
				if tc.name == "initial-facts" && factsCalls == 1 || tc.name == "pass-facts" && factsCalls == 2 {
					return nil, nil, cause
				}
				return originalCapture(c, s)
			}
			o.selection = func(c context.Context) (Selection, error) {
				s, err := originalSelection(c)
				if tc.name == "selection-read" || tc.name == "closing-selection-read" && m.reads == 2 {
					return s, cause
				}
				if tc.name == "selection-canonical" {
					return Selection{}, nil
				}
				if tc.name == "closing-selection-changed" && m.reads == 2 {
					s.Revision++
				}
				return s, err
			}
			if tc.name == "open" {
				o.source.open = func(context.Context) (lifecycleFence, error) { return m.fence, cause }
			} else if tc.name == "missing-fence" {
				o.source.open = func(context.Context) (lifecycleFence, error) { return nil, nil }
			} else if check := map[string]int{"initial-fence-after": 1, "pass-fence-before": 2, "pass-fence-after": 3, "closing-fence": 4}[tc.name]; check != 0 {
				o.source.open = func(context.Context) (lifecycleFence, error) {
					m.fence.opened = true
					return &rejectingDiagnosticFence{base: m.fence, reject: check}, nil
				}
			}
			r, err := o.Observe(ctx)
			requireClosedContinuity(t, err, tc.phase, tc.branch)
			if r != nil || m.fence.closed != tc.closed {
				t.Fatal("diagnostic failure published review or changed fence cleanup")
			}
			if strings.Contains(tc.name, "fence-") || tc.name == "closing-fence" {
				requireClosedContinuity(t, err, "notifications.neighbor.failed")
			}
			if tc.name == "open" || strings.Contains(tc.name, "provider") || tc.name == "initial-current" || strings.Contains(tc.name, "facts") || strings.Contains(tc.name, "selection-read") {
				if !errors.Is(err, cause) {
					t.Fatal("closed formatting discarded original failure")
				}
			}
		})
	}
}

func TestPhysicalSnapshotDiagnosticsClassifyRefusedValuesWithoutPublishingThem(t *testing.T) {
	for branch, change := range map[string]func(*observerModel){
		"segment-count":  func(m *observerModel) { m.facts.Segments = nil },
		"prefixes":       func(m *observerModel) { m.facts.Segments[0].Prefixes[0] = "192.0.3.0/24" },
		"link-addresses": func(m *observerModel) { m.facts.Segments[0].LinkAddresses[0] = "192.0.2.2/24" },
		"members":        func(m *observerModel) { m.facts.Segments[0].Members[0].MAC = "02:00:00:00:00:09" },
		"router-neighbors": func(m *observerModel) {
			m.facts.Segments[0].RouterNeighbors = []RouterNeighbor{{Address: "2001:db8::5", MAC: "02:00:00:00:00:05", Flags: 128, Type: 1}}
		},
		"segment-binding":   func(m *observerModel) { m.facts.Segments[0].IfIndex++ },
		"device-count":      func(m *observerModel) { m.facts.Devices = nil },
		"device-addresses":  func(m *observerModel) { m.facts.Devices[0].Addresses[0] = "192.0.2.21" },
		"device-link-local": func(m *observerModel) { m.facts.Devices[0].LinkLocalAddresses[0] = "fe80::21" },
		"device-binding":    func(m *observerModel) { m.facts.Devices[0].MAC = "02:00:00:00:00:09" },
	} {
		t.Run(branch, func(t *testing.T) {
			o, m, ctx := newModel(t)
			m.onCapture = func(n int) {
				if n == 2 {
					change(m)
				}
			}
			r, err := o.Observe(ctx)
			requireClosedContinuity(t, err, "capture.pass.snapshot", "snapshot."+branch)
			if r != nil || !m.fence.closed || m.captures != 2 {
				t.Fatal("snapshot classification changed exact refusal or retried")
			}
		})
	}
}

func TestPhysicalContinuityDiagnosticIsBoundedAndPreservesOriginalCause(t *testing.T) {
	cause := &privateDiagnosticCause{}
	leaf := at("kernel.bindings.neighbor.mac", errors.Join(cause, context.Canceled))
	err := boundary("observe.capture", boundary("capture.initial.facts", leaf))
	requireClosedContinuity(t, err, "observe.capture > capture.initial.facts > kernel.bindings.neighbor.mac", "context.canceled")
	var diagnostic *failure
	if !errors.As(err, &diagnostic) || diagnostic != leaf || !errors.Is(err, cause) || !errors.Is(err, context.Canceled) {
		t.Fatal("new boundary adopted the leaf failure or lost its cause")
	}
	for range 100 {
		err = boundary("observe.capture", err)
	}
	if text := err.Error(); len(text) > 4096 || strings.Contains(text, "private-input") {
		t.Fatal("diagnostic exceeded its bound or formatted foreign input")
	}
}

func TestPhysicalNotificationDiagnosticsRetainFailClosedClassification(t *testing.T) {
	for branch, frame := range map[string]message{
		"neighbor.delete":                 {kind: 29, data: neighborFrame(9, "192.0.2.20", "02:00:00:00:00:03", 2).data},
		"neighbor.incomplete":             neighborFrame(9, "192.0.2.20", "", 1),
		"neighbor.failed":                 neighborFrame(9, "192.0.2.20", "02:00:00:00:00:03", 32),
		"neighbor.client.address-changed": neighborFrame(9, "192.0.2.21", "02:00:00:00:00:03", 2),
		"neighbor.client.mac-changed":     neighborFrame(9, "192.0.2.20", "02:00:00:00:00:04", 2),
		"neighbor.binding.unknown":        neighborFrame(9, "192.0.2.30", "02:00:00:00:00:04", 2),
		"neighbor.header":                 {kind: 28},
		"neighbor.flags":                  {kind: 28, flags: 2},
		"link.tracked-index":              linkFrame(4, "eth0", "", "02:00:00:00:00:02", 9),
		"link.selected-master":            linkFrame(5, "eth1", "", "02:00:00:00:00:04", 9),
		"link.tracked-name":               linkFrame(5, "eth0", "", "02:00:00:00:00:04", 0),
		"address.tracked":                 addressFrame(9, "192.0.2.2/24"),
		"address.header":                  {kind: 20},
		"route.tracked":                   routeFrame(9),
		"route.flags":                     {kind: 24, flags: 2},
		"kind":                            {kind: 4},
	} {
		t.Run(branch, func(t *testing.T) {
			_, m, _ := newModel(t)
			err := checkNotifications([]message{frame}, m.facts.Segments, m.facts.Devices)
			requireClosedContinuity(t, err, "notifications."+branch)
		})
	}
	_, m, _ := newModel(t)
	router := neighborFrame(9, "2001:db8::5", "02:00:00:00:00:05", 2)
	m.facts.Segments[0].RouterNeighbors = []RouterNeighbor{
		{Address: "192.0.2.5", MAC: "02:00:00:00:00:05", Type: 1},
		{Address: "2001:db8::5", MAC: "02:00:00:00:00:05", Flags: 128, Type: 1},
	}
	requireClosedContinuity(t, checkNotifications([]message{router}, m.facts.Segments, m.facts.Devices), "notifications.neighbor.router.flags-changed")
	invalid := neighborFrame(9, "192.0.2.20", "02:00:00:00:00:03", 2)
	binary.NativeEndian.PutUint16(invalid.data[8:10], 2|4)
	requireClosedContinuity(t, checkNotifications([]message{invalid}, m.facts.Segments, m.facts.Devices), "notifications.neighbor.decode > kernel.bindings.neighbor.state")
}
