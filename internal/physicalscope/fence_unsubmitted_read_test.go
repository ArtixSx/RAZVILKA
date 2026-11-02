package physicalscope

import (
	"context"
	"errors"
	"testing"
)

type packetCancelBeforeCheckFence struct {
	*packetTestFence
	cancel context.CancelFunc
}

func (f *packetCancelBeforeCheckFence) check(c context.Context, t ipv4LANPacketTopology) (uint64, error) {
	if f.cancel != nil {
		f.cancel()
		f.cancel = nil
	}
	return f.packetTestFence.check(c, t)
}

func TestPacketUnsubmittedReadKeepsOnlyOriginalRetainedCleanup(t *testing.T) {
	p, m, parent := packetTestScope(t)
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	p.fence = &packetCancelBeforeCheckFence{packetTestFence: p.fence.(*packetTestFence), cancel: cancel}
	err := p.Current(ctx)
	if !errors.Is(err, context.Canceled) || !m.reader.ownsUnsubmittedRead(err) || !p.forwardBad || p.physicalBad {
		t.Fatal("unsubmitted read did not retain the exact cleanup-only owner", err)
	}
	if p.Current(parent) == nil {
		t.Fatal("expired forward review revived")
	}
	before := m.captures
	if err := p.RetainedCurrent(parent); err != nil {
		t.Fatal(err)
	}
	if m.captures != before+2 || m.opens != 1 {
		t.Fatal("cleanup skipped fresh captures or reopened collector")
	}
	// A subsequent real structural change is permanent even if restored later.
	m.id.BootID = "22345678-1234-1234-1234-123456789abc"
	if p.RetainedCurrent(parent) == nil || !p.physicalBad {
		t.Fatal("changed original identity accepted")
	}
	m.id = p.facts.Identity
	if p.RetainedCurrent(parent) == nil {
		t.Fatal("lost physical owner revived")
	}
}

func TestPacketUnsubmittedReadDoesNotHideLossOrAdoptOtherOwner(t *testing.T) {
	p, m, ctx := packetTestScope(t)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	_, original := m.reader.checkPacket(canceled, p.topology)
	var token *fenceUnsubmittedRead
	if !errors.As(original, &token) {
		t.Fatal("missing private refusal")
	}
	copy := *token
	other := &originalFenceCollector{}
	for name, err := range map[string]error{
		"plain cancellation":  context.Canceled,
		"joined source loss":  errors.Join(original, errors.New("lost source")),
		"joined cancellation": errors.Join(original, context.Canceled),
		"copied token":        &copy,
		"wrong boundary":      boundary("packet.identity.changed", original),
	} {
		t.Run(name, func(t *testing.T) {
			if m.reader.ownsUnsubmittedRead(err) {
				t.Fatal("non-original refusal accepted")
			}
		})
	}
	if other.ownsUnsubmittedRead(original) {
		t.Fatal("foreign collector adopted")
	}
	if !m.reader.ownsUnsubmittedRead(boundary("packet.capture", original)) {
		t.Fatal("original chain lost")
	}
}

func TestPacketUnsubmittedReadCannotRecoverClosedCollector(t *testing.T) {
	p, m, parent := packetTestScope(t)
	ctx, cancel := context.WithCancel(parent)
	p.fence = &packetCancelBeforeCheckFence{packetTestFence: p.fence.(*packetTestFence), cancel: cancel}
	if p.Current(ctx) == nil {
		t.Fatal("canceled forward read accepted")
	}
	m.reader.close()
	if p.RetainedCurrent(parent) == nil || !p.physicalBad {
		t.Fatal("closed original collector accepted")
	}
}
