package physicalscope

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func primaryIPv4Frame(index int, prefix string, flags uint32) message {
	m := addressFrame(index, prefix)
	m.flags = 2
	m.data[2] = byte(flags)
	p := netip.MustParsePrefix(prefix)
	m.data = append(m.data, attr(2, p.Addr().AsSlice())...)
	m.data = append(m.data, attr(8, integer(flags))...)
	return primaryIPv4Cache(m, ^uint32(0), ^uint32(0), 1, 1)
}

func primaryIPv4WithoutAttr(m message, kind uint16) message {
	out := slices.Clone(m.data[:8])
	for raw := m.data[8:]; len(raw) > 0; {
		n := (int(binary.NativeEndian.Uint16(raw[:2])) + 3) &^ 3
		if binary.NativeEndian.Uint16(raw[2:4]) != kind {
			out = append(out, raw[:n]...)
		}
		raw = raw[n:]
	}
	m.data = out
	return m
}

func primaryIPv4Cache(m message, preferred, valid, created, updated uint32) message {
	raw := make([]byte, 16)
	for i, v := range []uint32{preferred, valid, created, updated} {
		binary.NativeEndian.PutUint32(raw[i*4:], v)
	}
	m = primaryIPv4WithoutAttr(m, 6)
	m.data = append(m.data, attr(6, raw)...)
	return m
}

func TestPhysicalPrimaryIPv4ActualFullFlagsAndWholeImage(t *testing.T) {
	address := netip.MustParseAddr("192.0.2.1")
	primary := primaryIPv4Cache(primaryIPv4Frame(9, "192.0.2.1/24", 0x80), ^uint32(0), ^uint32(0), 1, 1)
	foreignAlias := primaryIPv4Frame(20, "198.51.100.1/24", 0x1080)
	foreignPPP := primaryIPv4Frame(21, "203.0.113.1/32", 0x80)
	foreignPPP.data[12]++ // Typed foreign IFA_ADDRESS peer differs from IFA_LOCAL.
	if row, err := decodePrimaryIPv4Row(foreignAlias); err != nil || row.flags != 0x1080 {
		t.Fatal("full native vendor flag lost", row, err)
	}
	if row, err := selectPrimaryIPv4([]message{primary, foreignAlias, foreignPPP}, 9, "Home", address); err != nil || row.flags != 0x80 || row.index != 9 {
		t.Fatal("actual primary absent", row, err)
	}
	pointToPoint := primaryIPv4Frame(9, "192.0.2.1/24", 0x80)
	pointToPoint.data[12]++
	if _, err := selectPrimaryIPv4([]message{pointToPoint}, 9, "Home", address); err == nil {
		t.Fatal("point-to-point local candidate became LAN primary")
	}
	for _, flags := range []uint32{1, 0x81, 0x1080, 0x20, 0x40, 0x200, 0x40000000} {
		if _, err := selectPrimaryIPv4([]message{primaryIPv4Frame(9, "192.0.2.1/24", flags)}, 9, "Home", address); err == nil {
			t.Fatalf("secondary/alias/deprecated/unsupported full flags granted primary: %x", flags)
		}
	}
	for _, rows := range [][]message{
		nil,
		{foreignAlias},
		{primary, primary},
		{primary, primaryIPv4Frame(20, "192.0.2.1/24", 0x80)},
		{primaryIPv4Frame(20, "192.0.2.1/24", 0x80)},
		{primary, {kind: 20, flags: 2, data: []byte{2}}},
	} {
		if _, err := selectPrimaryIPv4(rows, 9, "Home", address); err == nil {
			t.Fatal("missing/duplicate/foreign malformed row accepted")
		}
	}
	if _, err := selectPrimaryIPv4([]message{primaryIPv4Cache(primaryIPv4Frame(9, "192.0.2.1/24", 0), 0, 1, 1, 1)}, 9, "Home", address); err == nil {
		t.Fatal("expired/deprecated residence accepted")
	}
}

func TestPhysicalPrimaryIPv4StrictProducerSchema(t *testing.T) {
	for name, mutate := range map[string]func(message) message{
		"wrong family":         func(m message) message { m.data[0] = 10; return m },
		"unknown header flag":  func(m message) message { m.flags |= 0x10; return m },
		"wrong kind":           func(m message) message { m.kind = 21; return m },
		"duplicate attr":       func(m message) message { m.data = append(m.data, attr(8, integer(0))...); return m },
		"unknown attr":         func(m message) message { m.data = append(m.data, attr(99, integer(0))...); return m },
		"nested attr":          func(m message) message { binary.NativeEndian.PutUint16(m.data[10:12], 0x8001); return m },
		"network endian attr":  func(m message) message { binary.NativeEndian.PutUint16(m.data[10:12], 0x4001); return m },
		"short full flags":     func(m message) message { m.data = m.data[:len(m.data)-4]; return m },
		"missing full flags":   func(m message) message { return primaryIPv4WithoutAttr(m, 8) },
		"missing cache":        func(m message) message { return primaryIPv4WithoutAttr(m, 6) },
		"header full mismatch": func(m message) message { m.data[2] = 1; return m },
		"invalid prefix":       func(m message) message { m.data[1] = 33; return m },
		"zero index":           func(m message) message { binary.NativeEndian.PutUint32(m.data[4:8], 0); return m },
		"bad label":            func(m message) message { m.data = append(m.data, attr(3, []byte("Home"))...); return m },
		"nonzero padding": func(m message) message {
			m.data = append(m.data, attr(3, []byte("Home\x00"))...)
			m.data[len(m.data)-1] = 1
			return m
		},
		"bad lifetime": func(m message) message { return primaryIPv4Cache(m, 3, 2, 1, 1) },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodePrimaryIPv4Row(mutate(primaryIPv4Frame(9, "192.0.2.1/24", 0x80))); err == nil {
				t.Fatal("malformed producer row accepted")
			}
		})
	}
}

func TestPhysicalPrimaryIPv4OriginalWitnessAndFreshAging(t *testing.T) {
	o, _, ctx := newModel(t)
	r, err := o.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	reads := 0
	read := func(context.Context) ([]message, error) {
		reads++
		return []message{primaryIPv4Cache(primaryIPv4Frame(9, "192.0.2.1/24", 0), uint32(100-reads), uint32(200-reads), 12, 13)}, nil
	}
	address := netip.MustParseAddr("192.0.2.1")
	p, err := o.reviewPrimaryIPv4(ctx, r, "Home", address, read)
	if err != nil || reads != 2 {
		t.Fatal("original complete bracket missing", err, reads)
	}
	copyFacts := r.Snapshot()
	copyFacts.Segments[0].IfIndex++
	copyFacts.Segments[0].LinkAddresses[0] = "192.0.2.2/24"
	if err := p.Current(ctx); err != nil || reads != 4 {
		t.Fatal("aging or detached snapshot changed original", err, reads)
	}
	copy := &PrimaryIPv4Review{state: p.state}
	if err := copy.Current(ctx); err == nil {
		t.Fatal("copied witness accepted")
	}
	for _, original := range []*Review{nil, {}, {state: r.state}} {
		if _, err := o.reviewPrimaryIPv4(ctx, original, "Home", address, read); err == nil {
			t.Fatal("DTO/copied review minted original witness")
		}
	}
	other, _, _ := newModel(t)
	if _, err := other.reviewPrimaryIPv4(ctx, r, "Home", address, read); err == nil {
		t.Fatal("other observer reissued same metadata")
	}
	if _, err := o.ReviewPrimaryIPv4(ctx, nil, "Home", address); err == nil {
		t.Fatal("public factory accepted metadata before native producer")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := p.Current(ctx); err == nil || reads != 4 {
		t.Fatal("closed original review revived witness", err, reads)
	}
}

func TestPhysicalPrimaryIPv4OriginalBookendsAndStickyRefusal(t *testing.T) {
	for _, kind := range []string{"secondary", "prefix", "timestamp", "second-pass", "identity", "fence", "selection", "closing-selection", "no-callback", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			o, m, ctx := newModel(t)
			r, err := o.Observe(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			active, reads := false, 0
			read := func(c context.Context) ([]message, error) {
				reads++
				row := primaryIPv4Cache(primaryIPv4Frame(9, "192.0.2.1/24", 0), 100, 200, 1, 1)
				if active {
					switch kind {
					case "secondary":
						row = primaryIPv4Frame(9, "192.0.2.1/24", 0x81)
					case "prefix":
						row.data[1] = 25
					case "timestamp":
						row = primaryIPv4Cache(primaryIPv4Frame(9, "192.0.2.1/24", 0), 100, 200, 1, 2)
					case "second-pass":
						if reads == 4 {
							row = primaryIPv4Frame(9, "192.0.2.1/24", 0x80)
						}
					case "identity":
						m.identity.Inode++
					case "fence":
						m.fence.changed = true
					case "cancel":
						<-c.Done()
					}
				}
				return []message{row}, nil
			}
			p, err := o.reviewPrimaryIPv4(ctx, r, "Home", netip.MustParseAddr("192.0.2.1"), read)
			if err != nil {
				t.Fatal(err)
			}
			active = true
			originalIdentity := m.identity
			if kind == "selection" {
				m.selection.Revision++
			}
			if kind == "closing-selection" {
				last := m.reads
				m.onSelection = func(n int) {
					if n == last+2 {
						m.selection.Revision++
					}
				}
			}
			originalCurrent := o.source.current
			if kind == "no-callback" {
				o.source.current = func(context.Context, func(context.Context, netidentity.Identity) error) error { return nil }
			}
			check := ctx
			if kind == "cancel" {
				var cancel context.CancelFunc
				check, cancel = context.WithTimeout(ctx, time.Millisecond)
				defer cancel()
			}
			if err := p.Current(check); err == nil {
				t.Fatal("changed/canceled primary evidence accepted")
			}
			active, m.fence.changed, m.identity, o.source.current = false, false, originalIdentity, originalCurrent
			m.selection.Revision, m.onSelection = 7, nil
			count := reads
			if err := p.Current(ctx); err == nil || reads != count {
				t.Fatal("restored tuple revived original witness", err, reads)
			}
		})
	}
}

func TestPhysicalPrimaryIPv4OriginalCloseJoinsNativeReaderModel(t *testing.T) {
	o, _, ctx := newModel(t)
	r, err := o.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	entered, finish := make(chan struct{}), make(chan struct{})
	block := false
	read := func(context.Context) ([]message, error) {
		if block {
			close(entered)
			<-finish
			block = false
		}
		return []message{primaryIPv4Frame(9, "192.0.2.1/24", 0x80)}, nil
	}
	p, err := o.reviewPrimaryIPv4(ctx, r, "Home", netip.MustParseAddr("192.0.2.1"), read)
	if err != nil {
		t.Fatal(err)
	}
	block = true
	used, closed := make(chan error, 1), make(chan error, 1)
	go func() { used <- p.Current(ctx) }()
	<-entered
	go func() { closed <- r.Close() }()
	select {
	case <-closed:
		t.Fatal("original Close released fence during actual read")
	default:
	}
	close(finish)
	if err := <-used; err != nil {
		t.Fatal(err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if err := p.Current(ctx); !errors.Is(err, ErrUnknown) {
		t.Fatal("closed original witness reused", err)
	}
}
