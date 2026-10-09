package physicalscope

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestPhysicalRefusedLinkShapePreservesRefusalAndOmitsPayload(t *testing.T) {
	_, model, _ := newModel(t)
	m := linkFrame(4, "eth0", "", "02:00:00:00:00:02", 9)
	m.data = append(m.data, attr(18, attr(0x8005, attr(1, []byte("private-driver-payload"))))...)
	err := checkNotifications([]message{m}, model.facts.Segments, model.facts.Devices)
	if !errors.Is(err, ErrUnknown) || !reflect.DeepEqual(DiagnosticStages(err), []string{"notifications.link.tracked-index"}) {
		t.Fatal("diagnostic changed refusal", err)
	}
	report := DiagnosticLinkRefusal(err)
	var d linkFailureDiagnostic
	if json.Unmarshal([]byte(report), &d) != nil || d.Kind != 16 || d.Role != "member" || d.Truncated {
		t.Fatal("missing bounded diagnostic", report)
	}
	for _, forbidden := range []string{"eth0", "02:00:00:00:00:02", "private-driver-payload", "ifindex", "sequence", "pid"} {
		if strings.Contains(report, forbidden) {
			t.Fatal("private input exposed", forbidden)
		}
	}
	want := linkAttributeShape{Path: "18/5", Type: 0x8005, Bytes: uint16(len(attr(1, []byte("private-driver-payload"))))}
	found := false
	for _, a := range d.Attributes {
		found = found || a == want
	}
	if !found {
		t.Fatal("nested shape flags omitted")
	}
	// The error must own only the metadata, not the decoder's backing bytes.
	for i := range m.data {
		m.data[i] = 0
	}
	if DiagnosticLinkRefusal(err) != report {
		t.Fatal("diagnostic retained mutable source payload")
	}
}

type linkDiagnosticForeignError struct{}

func (linkDiagnosticForeignError) Error() string   { panic("foreign text must not be formatted") }
func (e linkDiagnosticForeignError) Unwrap() error { return e }

func TestPhysicalRefusedLinkShapeBoundedAndForeignTextNeverFormatted(t *testing.T) {
	if DiagnosticLinkRefusal(linkDiagnosticForeignError{}) != "" {
		t.Fatal("foreign diagnostic accepted")
	}
	d := &linkFailureDiagnostic{}
	var raw []byte
	for i := 0; i < 200; i++ {
		raw = append(raw, attr(uint16(100+i), []byte("untrusted"))...)
	}
	d.shapes(raw, "")
	if len(d.Attributes) != 96 || !d.Truncated || len(DiagnosticLinkRefusal(d)) > 8192 || strings.Contains(DiagnosticLinkRefusal(d), "untrusted") {
		t.Fatal("unbounded or unfiltered shape")
	}
}
