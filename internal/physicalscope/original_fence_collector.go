package physicalscope

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"sync"
)

const (
	fenceReceiveBytes        = 1 << 20
	maxFenceDrainBytes       = 4 << 20
	maxFencePendingBytes     = 4 << 20
	maxFencePendingDatagrams = 8192
)

// Only the collector calls receive. empty means an actual nonblocking EAGAIN,
// never a timer, poll timeout or an empty userspace queue. wait must be bounded
// so stopping can join the reader without closing its descriptor underneath it.
type fenceCollectorSource struct {
	current func() error
	receive func([]byte) (n int, empty bool, err error)
	wait    func() error
}

type fenceCheckpoint struct {
	ctx      context.Context
	original Snapshot
	finite   *finiteIPv4FenceSnapshot
	packet   *ipv4LANPacketFenceSnapshot
	reply    chan fenceCheckpointReply
}

type fenceCheckpointReply struct {
	epoch uint64
	err   error
}

// This is a transport for one original fence, not an observation factory. Its
// lifetime is the Review's Close, independent of Observe's operation context.
// Before the first actual check, raw datagrams have finite byte/count bounds.
// Thereafter every frame is checked against the detached, immutable first
// purpose (full, finite or IPv4 LAN structure); no event is coalesced. Packet
// membership epochs are comparison metadata, never another scope authority.
type originalFenceCollector struct {
	source   fenceCollectorSource
	checks   chan fenceCheckpoint
	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once
	failure  error // Published by closing done; never read before that join.
}

var errFenceCollectorStopped = errors.New("original fence collector stopped")

func newOriginalFenceCollector(source fenceCollectorSource) *originalFenceCollector {
	r := &originalFenceCollector{
		source: source,
		checks: make(chan fenceCheckpoint),
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
	}
	go func() {
		r.failure = r.run()
		close(r.done)
	}()
	return r
}

func (r *originalFenceCollector) stopped() bool {
	select {
	case <-r.stop:
		return true
	default:
		return false
	}
}

func (r *originalFenceCollector) completedError() error {
	if r.failure != nil {
		return r.failure
	}
	return at("fence.check.closed", nil)
}

func (r *originalFenceCollector) check(ctx context.Context, snapshot Snapshot) error {
	return r.checkOriginal(ctx, snapshot, nil)
}

type finiteIPv4FenceSnapshot struct{ original Snapshot }

func (r *originalFenceCollector) checkFinite(ctx context.Context, snapshot Snapshot) error {
	return r.checkOriginal(ctx, snapshot, &finiteIPv4FenceSnapshot{original: cloneSnapshot(snapshot)})
}

func (r *originalFenceCollector) checkOriginal(ctx context.Context, snapshot Snapshot, finite *finiteIPv4FenceSnapshot) error {
	return r.checkRequest(ctx, fenceCheckpoint{original: cloneSnapshot(snapshot), finite: finite}).err
}

func (r *originalFenceCollector) checkPacket(ctx context.Context, topology ipv4LANPacketTopology) (uint64, error) {
	reply := r.checkRequest(ctx, fenceCheckpoint{packet: &ipv4LANPacketFenceSnapshot{original: clonePacketTopology(topology)}})
	return reply.epoch, reply.err
}

func (r *originalFenceCollector) checkRequest(ctx context.Context, req fenceCheckpoint) fenceCheckpointReply {
	fail := func(err error) fenceCheckpointReply { return fenceCheckpointReply{err: err} }
	if ctx == nil {
		return fail(at("fence.check.context", nil))
	}
	if err := ctx.Err(); err != nil {
		return fail(boundary("fence.check.context", err))
	}
	if r.stopped() {
		return fail(at("fence.check.closed", nil))
	}
	req.ctx, req.reply = ctx, make(chan fenceCheckpointReply, 1)
	select {
	case <-ctx.Done():
		return fail(boundary("fence.check.context", ctx.Err()))
	case <-r.stop:
		return fail(at("fence.check.closed", nil))
	case <-r.done:
		return fail(r.completedError())
	case r.checks <- req:
	}
	select {
	case reply := <-req.reply:
		return reply
	case <-ctx.Done():
		return fail(boundary("fence.check.context", ctx.Err()))
	case <-r.stop:
		return fail(at("fence.check.closed", nil))
	case <-r.done:
		return fail(r.completedError())
	}
}

func (r *originalFenceCollector) close() {
	r.stopOnce.Do(func() { close(r.stop) })
	<-r.done
}

type fenceCollectorState struct {
	reader          *originalFenceCollector
	original        Snapshot
	finite          *finiteIPv4FenceSnapshot
	packet          *ipv4LANPacketFenceSnapshot
	membershipEpoch uint64
	bound           bool
	pending         [][]byte
	bytes           int
}

func (r *originalFenceCollector) run() error {
	state := fenceCollectorState{reader: r}
	buf := make([]byte, fenceReceiveBytes)
	for {
		select {
		case <-r.stop:
			return nil
		case req := <-r.checks:
			err := state.checkpoint(req, buf)
			if err == errFenceCollectorStopped {
				return nil
			}
			req.reply <- fenceCheckpointReply{epoch: state.membershipEpoch, err: err}
			if err != nil {
				return err
			}
		default:
		}
		if err := state.drain(context.Background(), buf); err != nil {
			if err == errFenceCollectorStopped {
				return nil
			}
			return err
		}
		if r.stopped() {
			return nil
		}
		if err := r.source.wait(); err != nil {
			return err
		}
	}
}

func (s *fenceCollectorState) checkpoint(req fenceCheckpoint, buf []byte) error {
	if err := req.ctx.Err(); err != nil {
		return boundary("fence.drain.context", err)
	}
	if !s.bound {
		s.original, s.finite, s.packet, s.bound = req.original, req.finite, req.packet, true
		for _, raw := range s.pending {
			if s.reader.stopped() {
				return errFenceCollectorStopped
			}
			if err := req.ctx.Err(); err != nil {
				return boundary("fence.drain.context", err)
			}
			frames, err := messages(raw)
			if err != nil {
				return boundary("fence.datagram.decode", err)
			}
			if err := s.checkPurposeNotifications(frames); err != nil {
				return boundary("fence.notifications", err)
			}
		}
		s.pending, s.bytes = nil, 0
	} else if !reflect.DeepEqual(s.original, req.original) || !reflect.DeepEqual(s.finite, req.finite) || !reflect.DeepEqual(s.packet, req.packet) {
		return at("fence.check.baseline.changed", nil)
	}
	// Every request performs a NEW actual drain through EAGAIN, with descriptor
	// bookends. A prior background drain or empty pending slice cannot ACK it.
	return s.drain(req.ctx, buf)
}

func (s *fenceCollectorState) drain(ctx context.Context, buf []byte) error {
	total := 0
	for {
		if s.reader.stopped() {
			return errFenceCollectorStopped
		}
		if err := ctx.Err(); err != nil {
			return boundary("fence.drain.context", err)
		}
		if err := s.reader.source.current(); err != nil {
			return boundary("fence.check.descriptor", err)
		}
		n, empty, err := s.reader.source.receive(buf)
		if err != nil {
			return err
		}
		if empty {
			if n != 0 {
				return at("fence.receive.empty", nil)
			}
			if err := ctx.Err(); err != nil {
				return boundary("fence.drain.context", err)
			}
			if err := s.reader.source.current(); err != nil {
				return boundary("fence.drain.closing-descriptor", err)
			}
			if s.reader.stopped() {
				return errFenceCollectorStopped
			}
			if err := ctx.Err(); err != nil {
				return boundary("fence.drain.context", err)
			}
			return nil
		}
		if n <= 0 || n > len(buf) {
			return at("fence.receive.empty", nil)
		}
		total += n
		if total > maxFenceDrainBytes {
			return at("fence.receive.byte-limit", nil)
		}
		frames, err := messages(buf[:n])
		if err != nil {
			return boundary("fence.datagram.decode", err)
		}
		if s.bound {
			if err := s.checkPurposeNotifications(frames); err != nil {
				return boundary("fence.notifications", err)
			}
			continue
		}
		if s.bytes+n > maxFencePendingBytes {
			return at("fence.receive.pending-byte-limit", nil)
		}
		if len(s.pending) >= maxFencePendingDatagrams {
			return at("fence.receive.pending-count-limit", nil)
		}
		s.pending = append(s.pending, slices.Clone(buf[:n]))
		s.bytes += n
	}
}
