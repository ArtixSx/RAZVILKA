package physicalscope

import (
	"net/netip"
	"testing"
)

func TestHomePrimaryUsesBothOriginalPacketCaptures(t *testing.T) {
	row := primaryIPv4Frame(9, "192.0.2.1/24", 0x80)
	p, m, ctx := packetTestScope(t, func(m *packetTestModel) { m.input.addresses[0] = row })
	address := netip.MustParseAddr("192.0.2.1")
	r, err := p.ReviewPrimaryIPv4(ctx, "Home", address)
	if err != nil || !r.MatchesBinding(p, "Home", address) {
		t.Fatalf("original Home primary: %v", DiagnosticStages(err))
	}
	copy := *r
	if copy.MatchesScope(p) || copy.CurrentRetained(ctx) == nil || r.MatchesBinding(p, "Guest", address) {
		t.Fatal("accepted a different owner or ingress")
	}
	m.intent.Revision++
	if r.Current(ctx) == nil || r.CurrentRetained(ctx) != nil {
		t.Fatal("intent change must close forward use and preserve original cleanup")
	}
	m.input.addresses[0] = primaryIPv4Cache(row, 0, ^uint32(0), 1, 1)
	if r.CurrentRetained(ctx) == nil {
		t.Fatal("expired address residence accepted")
	}
	m.input.addresses[0] = row
	if r.CurrentRetained(ctx) == nil {
		t.Fatal("lost primary revived")
	}
}

func TestHomePrimaryRejectsChangeBetweenAddressDumps(t *testing.T) {
	row := primaryIPv4Frame(9, "192.0.2.1/24", 0x80)
	p, m, ctx := packetTestScope(t, func(m *packetTestModel) { m.input.addresses[0] = row })
	last := m.captures + 2
	m.onCapture = func(n int) {
		if n == last {
			m.input.addresses[0] = primaryIPv4Cache(row, ^uint32(0), ^uint32(0), 2, 2)
		}
	}
	if _, err := p.ReviewPrimaryIPv4(ctx, "Home", netip.MustParseAddr("192.0.2.1")); err == nil {
		t.Fatal("two different address incarnations issued a single primary witness")
	}
}
