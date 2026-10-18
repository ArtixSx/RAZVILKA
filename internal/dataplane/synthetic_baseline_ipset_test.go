package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

type syntheticIPSetModel struct {
	h           syntheticIPSetHeader
	values      []bool
	calls       int
	closeHeader bool
	failure     error
}

func (m *syntheticIPSetModel) header(context.Context, string) (syntheticIPSetHeader, error) {
	h := m.h
	if m.calls > 0 && m.closeHeader {
		h.revision++
	}
	return h, m.failure
}
func (m *syntheticIPSetModel) test(context.Context, string, netip.Addr, bool) (bool, error) {
	if m.failure != nil {
		return false, m.failure
	}
	n := m.calls
	m.calls++
	return m.values[n%len(m.values)], nil
}
func (*syntheticIPSetModel) Close() error { return nil }

func TestSyntheticIPSetComparisonRequiresBothExactMembershipKindsAndClosure(t *testing.T) {
	real, fake := netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("198.18.0.1")
	valid := syntheticIPSetHeader{name: "test", kind: "hash:net", protocol: 6, family: 2, revision: 2}
	for name, values := range map[string][]bool{"absent": {false, false, false, false}, "regular": {true, false, true, false}, "nomatch": {false, true, false, true}} {
		t.Run(name, func(t *testing.T) {
			m := &syntheticIPSetModel{h: valid, values: values}
			if err := syntheticIPSetCompare(context.Background(), m, "test", real, fake); err != nil || m.calls != 8 {
				t.Fatal("equal pair refused", err)
			}
		})
	}
	for name, change := range map[string]func(*syntheticIPSetModel){
		"different":        func(m *syntheticIPSetModel) { m.values = []bool{true, false, false, false} },
		"nomatch differs":  func(m *syntheticIPSetModel) { m.values = []bool{false, true, false, false} },
		"ambiguous":        func(m *syntheticIPSetModel) { m.values = []bool{true, true, true, true} },
		"membership drift": func(m *syntheticIPSetModel) { m.values = []bool{false, false, false, false, true, false, false, false} },
		"header drift":     func(m *syntheticIPSetModel) { m.closeHeader = true },
		"type":             func(m *syntheticIPSetModel) { m.h.kind = "hash:ip" },
		"family":           func(m *syntheticIPSetModel) { m.h.family = 10 },
		"name":             func(m *syntheticIPSetModel) { m.h.name = "foreign" },
		"revision":         func(m *syntheticIPSetModel) { m.h.revision = 99 },
		"protocol":         func(m *syntheticIPSetModel) { m.h.protocol = 99 },
		"kernel unknown":   func(m *syntheticIPSetModel) { m.failure = syntheticIPSetFailure("kernel-result") },
	} {
		t.Run(name, func(t *testing.T) {
			m := &syntheticIPSetModel{h: valid, values: []bool{false, false, false, false}}
			change(m)
			if err := syntheticIPSetCompare(context.Background(), m, "test", real, fake); !errors.Is(err, ErrSyntheticIPSet) {
				t.Fatal("unknown/different pair accepted", err)
			}
		})
	}
}

func TestSyntheticIPSetReaderCannotBeHydratedOrUseUnsafeNames(t *testing.T) {
	for _, name := range []string{"", "bad\x00name", "--help", "name with space", "01234567890123456789012345678901"} {
		// Leading dashes are safe netlink bytes rather than command options;
		// no shell/exec is involved. Every other malformed example must refuse.
		if name != "--help" && syntheticIPSetName(name) {
			t.Fatal("unsafe set name accepted")
		}
	}
	for _, r := range []*SyntheticBaselineIPSetReader{nil, {}} {
		if err := r.EquivalentDestinations(context.Background(), "test", netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("198.18.0.1")); !errors.Is(err, ErrSyntheticIPSet) {
			t.Fatal("hydrated reader accepted", err)
		}
	}
}
