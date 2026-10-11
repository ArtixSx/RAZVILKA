//go:build linux

package physicalscope

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

type nativeSelectedNeighborAttribute struct {
	Kind  uint16 `json:"kind"`
	Bytes int    `json:"bytes"`
}

// Every field is a closed classification, length, count or kernel enum. No
// actual ifindex, interface name, address, MAC, intent ID or raw data escapes.
type nativeSelectedNeighborShape struct {
	DumpFamily         byte                              `json:"dump_family"`
	NDMFamily          byte                              `json:"ndm_family"`
	HeaderBytes        int                               `json:"ndm_bytes"`
	HeaderComplete     bool                              `json:"header_complete"`
	Ingress            string                            `json:"ingress"`
	IndexPositive      bool                              `json:"index_positive"`
	State              uint16                            `json:"state"`
	Flags              byte                              `json:"flags"`
	Type               byte                              `json:"type"`
	AttributesDecoded  bool                              `json:"attributes_decoded"`
	Attributes         []nativeSelectedNeighborAttribute `json:"attributes"`
	AttributesOmitted  int                               `json:"attributes_omitted"`
	DestinationPresent bool                              `json:"destination_present"`
	DestinationBytes   int                               `json:"destination_bytes"`
	AddressDecoded     bool                              `json:"address_decoded"`
	AddressClass       string                            `json:"address_class"`
	LLAddressBytes     int                               `json:"lladdr_bytes"`
	LLAddressClass     string                            `json:"lladdr_class"`
	LLAddressUnicast   bool                              `json:"lladdr_valid_unicast"`
	IntentMACMatch     bool                              `json:"intent_mac_match"`
	Bookkeeping        bool                              `json:"selected_bookkeeping"`
	ForeignBookkeeping bool                              `json:"foreign_bookkeeping"`
	ParseStages        []string                          `json:"parse_stages"`
	SelectedStages     []string                          `json:"selected_decoder_stages"`
	ProductionStages   []string                          `json:"production_stages"`
}

func nativeSelectedNeighborClass(family byte, m message, segments map[int]Segment, wanted map[string]bool) nativeSelectedNeighborShape {
	s := nativeSelectedNeighborShape{DumpFamily: family, HeaderBytes: len(m.data), Ingress: "unknown", AddressClass: "unavailable"}
	if len(m.data) != 0 {
		s.NDMFamily = m.data[0]
	}
	_, parseErr := parseKernelNeighbor(m)
	s.ParseStages = DiagnosticStages(parseErr)
	if len(m.data) < 12 {
		s.ProductionStages = DiagnosticStages(at("kernel.bindings.neighbor.header", nil))
		return s
	}
	s.HeaderComplete = true
	index := int(int32(binary.NativeEndian.Uint32(m.data[4:8])))
	s.IndexPositive = index > 0
	s.State, s.Flags, s.Type = binary.NativeEndian.Uint16(m.data[8:10]), m.data[10], m.data[11]
	segment, selected := segments[index]
	s.Ingress = "foreign"
	if selected {
		s.Ingress = "selected"
		_, bookkeeping, err := decodeSegmentNeighbor(m, segment)
		s.Bookkeeping, s.SelectedStages = bookkeeping, DiagnosticStages(err)
	}
	// This mirrors the binder's choice of decoder, including its AF_BRIDGE
	// foreign bypass. Successful common parsing CANNOT hide a selected
	// segment's address/type/bookkeeping rejection.
	if selected || s.NDMFamily == 2 || s.NDMFamily == 10 {
		if s.NDMFamily != family {
			s.ProductionStages = DiagnosticStages(at("kernel.bindings.neighbor.dump-family", nil))
		} else if selected {
			s.ProductionStages = slices.Clone(s.SelectedStages)
		} else {
			_, bookkeeping, err := decodeForeignKernelNeighbor(m)
			s.ForeignBookkeeping, s.ProductionStages = bookkeeping, DiagnosticStages(err)
		}
	}
	a, err := attrs(m.data[12:])
	if err != nil {
		return s
	}
	s.AttributesDecoded = true
	for kind, raw := range a {
		s.Attributes = append(s.Attributes, nativeSelectedNeighborAttribute{kind, len(raw)})
	}
	slices.SortFunc(s.Attributes, func(a, b nativeSelectedNeighborAttribute) int { return int(a.Kind) - int(b.Kind) })
	if len(s.Attributes) > 16 {
		s.AttributesOmitted = len(s.Attributes) - 16
		s.Attributes = s.Attributes[:16]
	}
	_, s.DestinationPresent = a[1]
	s.DestinationBytes, s.LLAddressBytes = len(a[1]), len(a[2])
	mac := net.HardwareAddr(a[2]).String()
	s.LLAddressUnicast, s.IntentMACMatch = validMAC(mac), wanted[mac]
	switch {
	case a[2] == nil:
		s.LLAddressClass = "absent"
	case len(a[2]) == 0:
		s.LLAddressClass = "empty"
	case bytes.Equal(a[2], []byte{0, 0, 0, 0, 0, 0}):
		s.LLAddressClass = "all_zero"
	case bytes.Equal(a[2], []byte{255, 255, 255, 255, 255, 255}):
		s.LLAddressClass = "broadcast"
	case s.LLAddressUnicast:
		s.LLAddressClass = "unicast"
	case len(a[2]) == 6 && a[2][0]&1 != 0:
		s.LLAddressClass = "multicast"
	default:
		s.LLAddressClass = "invalid"
	}
	address, ok := netip.AddrFromSlice(a[1])
	s.AddressDecoded = ok
	switch {
	case !ok:
		s.AddressClass = "invalid"
	case address.Is4In6():
		s.AddressClass = "v4_mapped"
	case address.Is4() != (s.NDMFamily == 2):
		s.AddressClass = "family_mismatch"
	case address.IsUnspecified():
		s.AddressClass = "unspecified"
	case address.IsLoopback():
		s.AddressClass = "loopback"
	case address.IsMulticast():
		s.AddressClass = "multicast"
	default:
		s.AddressClass = "unicast"
	}
	return s
}

// Root-only actual complete dual-stack GET diagnostic:
// RAZVILKA_PHYSICAL_SCOPE_SELECTED_DIAGNOSTIC_NATIVE=1
// RAZVILKA_PHYSICAL_SCOPE_NATIVE=stock-nc1812
// RAZVILKA_PHYSICAL_SCOPE_SELECTED_FILE=<same absolute private Selection JSON>
// This never opens an Observer Review, alters production decoding, authorizes
// effects or grants, writes files, or loads modules. Root alone builds/runs it.
func TestPhysicalScopeNativeSelectedNeighborDiagnostic(t *testing.T) {
	if os.Getenv("RAZVILKA_PHYSICAL_SCOPE_SELECTED_DIAGNOSTIC_NATIVE") != "1" {
		t.Skip("Root-only selected-neighbor classified diagnostic")
	}
	if runtime.GOARCH != "arm64" || os.Getenv("RAZVILKA_PHYSICAL_SCOPE_NATIVE") != "stock-nc1812" {
		t.Fatal("selected diagnostic requires actual stock NC1812 on Linux ARM64")
	}
	selection, err := continuityNativePrivateSelection(os.Getenv("RAZVILKA_PHYSICAL_SCOPE_SELECTED_FILE"))
	if err == nil {
		selection, err = nativeSelectedContinuityIntent(selection)
	}
	if err != nil {
		t.Fatal("selected diagnostic private intent refused")
	}
	wanted, _ := projectionIntentMACs(selection.SelectedDevices)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	if deadline, ok := t.Deadline(); ok {
		bounded, finish := context.WithDeadline(ctx, deadline)
		defer finish()
		ctx = bounded
	}
	provider, err := netidentity.NewReviewedStockNC1812Provider(ctx)
	if err != nil {
		t.Fatalf("selected diagnostic provider refused: %v", DiagnosticStages(err))
	}
	type countedShape struct {
		Shape nativeSelectedNeighborShape `json:"shape"`
		Count int                         `json:"count"`
	}
	result := struct {
		ObservationOnly    bool           `json:"observation_only"`
		Capability         string         `json:"capability"`
		OriginalReview     bool           `json:"original_review"`
		CompleteDualStack  bool           `json:"complete_dual_stack"`
		TotalRows          int            `json:"total_rows"`
		SelectedRows       int            `json:"selected_rows"`
		ForeignRows        int            `json:"foreign_rows"`
		ForeignBookkeeping int            `json:"foreign_bookkeeping_rows"`
		ProductionRefusals int            `json:"production_decoder_refusals"`
		UnclassifiedRows   int            `json:"unclassified_refusals"`
		ClassifiedRefusals []countedShape `json:"classified_refusals"`
	}{ObservationOnly: true, Capability: "ungranted"}
	classes := map[string]int{}
	err = provider.WithCurrent(ctx, func(c context.Context, identity netidentity.Identity) error {
		if identity.Kind != netidentity.ReviewedSingleInitNet {
			return at("native.selected-diagnostic.identity", nil)
		}
		// Only production GET/NDM readers and assembler resolve the exact
		// configured segment. Neighbor rows stay private inside this callback.
		raw, err := provider.ReadReviewedStockInterfaces(c)
		if err != nil {
			return boundary("native.selected-diagnostic.ndm", err)
		}
		native, err := parseNDM(raw)
		if err != nil {
			return err
		}
		links, err := dump(c, 18, 0)
		if err != nil {
			return boundary("native.selected-diagnostic.links", err)
		}
		addresses, err := dump(c, 22, 0)
		if err != nil {
			return boundary("native.selected-diagnostic.addresses", err)
		}
		var routes []message
		for _, family := range []byte{2, 10} {
			frames, err := dump(c, 26, family)
			if err != nil {
				return boundary("native.selected-diagnostic.routes", err)
			}
			routes = append(routes, frames...)
		}
		segments, err := assembleSegments(selection, native, true, links, addresses, routes)
		if err != nil {
			return err
		}
		byIndex := map[int]Segment{}
		for _, segment := range segments {
			byIndex[segment.IfIndex] = segment
		}
		for _, family := range []byte{2, 10} {
			frames, err := dump(c, 30, family)
			if err != nil {
				return boundary("native.selected-diagnostic.neighbors", err)
			}
			for _, m := range frames {
				if err := c.Err(); err != nil {
					return err
				}
				result.TotalRows++
				if result.TotalRows > 8192 {
					return at("native.selected-diagnostic.row-limit", nil)
				}
				shape := nativeSelectedNeighborClass(family, m, byIndex, wanted)
				if shape.Ingress == "selected" {
					result.SelectedRows++
				} else if shape.Ingress == "foreign" {
					result.ForeignRows++
				}
				if shape.ForeignBookkeeping {
					result.ForeignBookkeeping++
				}
				if len(shape.ProductionStages) == 0 {
					continue
				}
				result.ProductionRefusals++
				key, err := json.Marshal(shape)
				if err != nil {
					return at("native.selected-diagnostic.class", nil)
				}
				if position, ok := classes[string(key)]; ok {
					result.ClassifiedRefusals[position].Count++
				} else if len(classes) < 8 {
					classes[string(key)] = len(result.ClassifiedRefusals)
					result.ClassifiedRefusals = append(result.ClassifiedRefusals, countedShape{shape, 1})
				} else {
					result.UnclassifiedRows++
				}
			}
		}
		result.CompleteDualStack = true
		return c.Err()
	})
	if err != nil {
		t.Fatalf("selected diagnostic actual read refused: %v", DiagnosticStages(err))
	}
	raw, err := json.Marshal(result)
	if err != nil || len(raw) > 32<<10 {
		t.Fatal("selected diagnostic output limit refused")
	}
	t.Log(string(raw))
}

func TestNativeSelectedDiagnosticRetainsSelectedDecodeFailureAndRedactsFacts(t *testing.T) {
	fixture, err := captureSelectedTest(context.Background(), selectedTestSelection(), selectedTestNeighbors())
	if err != nil {
		t.Fatal("fixture assembly refused")
	}
	byIndex := map[int]Segment{fixture.Segments[0].IfIndex: fixture.Segments[0]}
	wanted, _ := projectionIntentMACs(selectedTestSelection().SelectedDevices)
	foreignBroadcast := func(mac string) message {
		m := neighborFrame(30, "0.0.0.0", mac, 64)
		if mac == "" {
			m.data = append(m.data, attr(2, nil)...)
		}
		m.data[11] = 3
		m.data = append(m.data, attr(3, make([]byte, 16))...)
		m.data = append(m.data, attr(4, make([]byte, 4))...)
		return m
	}
	for name, candidate := range map[string]struct {
		row         message
		address     string
		mac         string
		ingress     string
		class       string
		llclass     string
		parseFailed bool
		bookkeeping bool
	}{
		"selected-multicast":    {neighborFrame(9, "224.0.0.1", "01:00:5e:00:00:01", 4), "224.0.0.1", "01:00:5e:00:00:01", "selected", "multicast", "multicast", false, false},
		"foreign-unspecified":   {neighborFrame(30, "0.0.0.0", projectionOtherMAC, 4), "0.0.0.0", projectionOtherMAC, "foreign", "unspecified", "unicast", true, false},
		"foreign-empty-MAC":     {foreignBroadcast(""), "0.0.0.0", "", "foreign", "unspecified", "empty", true, true},
		"foreign-zero-MAC":      {foreignBroadcast("00:00:00:00:00:00"), "0.0.0.0", "00:00:00:00:00:00", "foreign", "unspecified", "all_zero", true, true},
		"foreign-broadcast-MAC": {foreignBroadcast("ff:ff:ff:ff:ff:ff"), "0.0.0.0", "ff:ff:ff:ff:ff:ff", "foreign", "unspecified", "broadcast", true, false},
	} {
		t.Run(name, func(t *testing.T) {
			shape := nativeSelectedNeighborClass(2, candidate.row, byIndex, wanted)
			if shape.Ingress != candidate.ingress || shape.AddressClass != candidate.class || shape.LLAddressClass != candidate.llclass || (len(shape.ParseStages) != 0) != candidate.parseFailed || shape.ForeignBookkeeping != candidate.bookkeeping || slices.Contains(shape.ProductionStages, "kernel.bindings.neighbor.address") == candidate.bookkeeping {
				t.Fatal("diagnostic hid decoder refusal")
			}
			if candidate.ingress == "selected" && !slices.Contains(shape.SelectedStages, "kernel.bindings.neighbor.address") {
				t.Fatal("successful common parse hid selected segment rejection")
			}
			raw, err := json.Marshal(shape)
			if err != nil || bytes.Contains(raw, []byte(candidate.address)) || candidate.mac != "" && bytes.Contains(raw, []byte(candidate.mac)) || bytes.Contains(raw, []byte(fixture.Segments[0].Interface)) || bytes.Contains(raw, []byte(fixture.Devices[0].ID)) {
				t.Fatal("classified diagnostic exposed physical facts")
			}
		})
	}
}
