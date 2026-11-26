//go:build linux

package physicalscope

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"testing"
)

type nativeSelectedDiagnosticLink struct {
	Type  uint16
	Flags uint32
}

type nativeSelectedConflictInput struct {
	neighbor kernelNeighbor
	shape    nativeSelectedNeighborShape
}

type nativeSelectedConflictClass struct {
	Phase             string                       `json:"phase"`
	Family            byte                         `json:"address_family"`
	KeyScope          string                       `json:"key_scope"`
	EqualAddress      bool                         `json:"equal_address"`
	EqualMAC          bool                         `json:"equal_mac"`
	EqualIngress      bool                         `json:"equal_ingress"`
	OwnerCategory     string                       `json:"owner_category"`
	CandidateCategory string                       `json:"candidate_category"`
	OwnerLinkKnown    bool                         `json:"owner_link_known"`
	OwnerLinkType     uint16                       `json:"owner_link_type"`
	OwnerLinkFlags    uint32                       `json:"owner_link_flags"`
	Owner             *nativeSelectedNeighborShape `json:"owner_neighbor"`
	Candidate         nativeSelectedNeighborShape  `json:"candidate_neighbor"`
}

type nativeSelectedConflictCounter struct {
	Class nativeSelectedConflictClass `json:"class"`
	Count int                         `json:"count"`
}

type nativeSelectedConflictSummary struct {
	Total        int                             `json:"conflicting_pairs"`
	Unclassified int                             `json:"unclassified_pairs"`
	Classes      []nativeSelectedConflictCounter `json:"classified_pairs"`
}

// Diagnostic ONLY: reproduce the ownership scan phases and SAME address-key
// scoping. No actual address, MAC, index or intent string is stored in output.
// A conflict retains its first owner here; it never adopts a conflicting row.
func nativeSelectedConflictClasses(selection Selection, segments []Segment, neighbors, foreign []nativeSelectedConflictInput, routers map[string]bool, links map[int]nativeSelectedDiagnosticLink) (nativeSelectedConflictSummary, error) {
	wanted, err := projectionIntentMACs(selection.SelectedDevices)
	if err != nil || selection.SelectedDevices == nil {
		return nativeSelectedConflictSummary{}, ErrUnknown
	}
	excluded := map[string]bool{}
	for _, id := range selection.SelectedDevices.ExcludedDeviceIDs {
		for mac := range wanted {
			if physicalDeviceID(mac) == id {
				excluded[mac] = true
			}
		}
	}
	category := func(mac string) string {
		if excluded[mac] {
			return "excluded_intent"
		}
		if wanted[mac] {
			return "selected_intent"
		}
		if routers[mac] {
			return "router_negative"
		}
		return "unrelated"
	}
	type owner struct {
		address  netip.Addr
		index    int
		mac      string
		category string
		shape    *nativeSelectedNeighborShape
	}
	owners := map[string]owner{}
	result := nativeSelectedConflictSummary{}
	classes := map[string]int{}
	report := func(phase string, original, candidate owner) error {
		family, scope := byte(10), "global_key"
		if candidate.address.Is4() {
			family = 2
		}
		if candidate.address.IsLinkLocalUnicast() {
			scope = "linklocal_key"
		}
		link, known := links[original.index]
		c := nativeSelectedConflictClass{Phase: phase, Family: family, KeyScope: scope,
			EqualAddress: original.address == candidate.address, EqualMAC: original.mac == candidate.mac, EqualIngress: original.index == candidate.index,
			OwnerCategory: original.category, CandidateCategory: candidate.category, OwnerLinkKnown: known, OwnerLinkType: link.Type, OwnerLinkFlags: link.Flags, Owner: original.shape}
		if candidate.shape != nil {
			c.Candidate = *candidate.shape
		}
		key, err := json.Marshal(c)
		if err != nil {
			return ErrUnknown
		}
		result.Total++
		if position, exists := classes[string(key)]; exists {
			result.Classes[position].Count++
		} else if len(classes) < 8 {
			classes[string(key)] = len(result.Classes)
			result.Classes = append(result.Classes, nativeSelectedConflictCounter{c, 1})
		} else {
			result.Unclassified++
		}
		return nil
	}
	for _, segment := range segments {
		for _, raw := range segment.LinkAddresses {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil {
				return result, ErrUnknown
			}
			candidate := owner{prefix.Addr(), segment.IfIndex, segment.MAC, "bridge_local", nil}
			key := projectionAddressKey(candidate.index, candidate.address)
			if original, exists := owners[key]; exists && original.mac != candidate.mac {
				if err := report("bridge_seed", original, candidate); err != nil {
					return result, err
				}
			} else {
				owners[key] = candidate
			}
		}
	}
	for _, row := range neighbors {
		n := row.neighbor
		if !wanted[n.mac] && !routers[n.mac] {
			continue
		}
		shape := row.shape
		candidate := owner{n.address, n.index, n.mac, category(n.mac), &shape}
		key := projectionAddressKey(n.index, n.address)
		if original, exists := owners[key]; exists && original.mac != n.mac {
			if err := report("protected_row", original, candidate); err != nil {
				return result, err
			}
		} else {
			owners[key] = candidate
		}
	}
	for i, rows := range [][]nativeSelectedConflictInput{neighbors, foreign} {
		phase := []string{"selected_row", "foreign_row"}[i]
		for _, row := range rows {
			n := row.neighbor
			if i == 1 && routers[n.mac] {
				continue // production refuses this as ingress, not address conflict
			}
			if original, protected := owners[projectionAddressKey(n.index, n.address)]; protected && original.mac != n.mac {
				shape := row.shape
				if err := report(phase, original, owner{n.address, n.index, n.mac, category(n.mac), &shape}); err != nil {
					return result, err
				}
			}
		}
	}
	return result, nil
}

func TestNativeSelectedConflictDiagnosticKeepsGlobalAndScopesLinkLocal(t *testing.T) {
	fixture, err := captureSelectedTest(context.Background(), selectedTestSelection(), selectedTestNeighbors())
	if err != nil {
		t.Fatal("fixture refused")
	}
	selected := kernelNeighbor{index: 9, address: netip.MustParseAddr("192.0.2.20"), mac: projectionClientMAC}
	foreign := kernelNeighbor{index: 30, address: selected.address, mac: projectionOtherMAC}
	rows := []nativeSelectedConflictInput{{neighbor: selected}}
	others := []nativeSelectedConflictInput{{neighbor: foreign}}
	result, err := nativeSelectedConflictClasses(selectedTestSelection(), fixture.Segments, rows, others, nil, nil)
	if err != nil || result.Total != 1 || result.Classes[0].Class.Phase != "foreign_row" || result.Classes[0].Class.KeyScope != "global_key" || !result.Classes[0].Class.EqualAddress || result.Classes[0].Class.EqualMAC || result.Classes[0].Class.EqualIngress || result.Classes[0].Class.OwnerCategory != "selected_intent" {
		t.Fatal("global conflict classification was lost")
	}
	raw, err := json.Marshal(result)
	if err != nil || bytes.Contains(raw, []byte(selected.address.String())) || bytes.Contains(raw, []byte(selected.mac)) || bytes.Contains(raw, []byte(foreign.mac)) || bytes.Contains(raw, []byte(fixture.Segments[0].Interface)) {
		t.Fatal("conflict diagnostic exposed original physical values")
	}
	rows[0].neighbor.address = netip.MustParseAddr("fe80::20")
	others[0].neighbor.address = rows[0].neighbor.address
	result, err = nativeSelectedConflictClasses(selectedTestSelection(), fixture.Segments, rows, others, nil, nil)
	if err != nil || result.Total != 0 {
		t.Fatal("foreign scoped link-local became a global conflict")
	}
	others[0].neighbor.index = 9
	result, err = nativeSelectedConflictClasses(selectedTestSelection(), fixture.Segments, rows, others, nil, nil)
	if err != nil || result.Total != 1 || result.Classes[0].Class.KeyScope != "linklocal_key" || !result.Classes[0].Class.EqualIngress {
		t.Fatal("same-scope link-local conflict was lost")
	}
}
