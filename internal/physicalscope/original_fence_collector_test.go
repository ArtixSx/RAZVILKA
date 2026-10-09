package physicalscope

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fenceTestDatagram struct {
	raw []byte
	err error
}

type fenceTestTransport struct {
	mu       sync.Mutex
	queue    []fenceTestDatagram
	reads    int
	empties  int
	idleRead int
	changed  chan struct{}
	wake     chan struct{}
	identity error
}

func newFenceTestTransport() *fenceTestTransport {
	return &fenceTestTransport{changed: make(chan struct{}, 1), wake: make(chan struct{}, 1)}
}
func (f *fenceTestTransport) signal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}
func (f *fenceTestTransport) push(datagrams ...fenceTestDatagram) {
	f.mu.Lock()
	f.queue = append(f.queue, datagrams...)
	f.mu.Unlock()
	f.signal(f.wake)
}
func (f *fenceTestTransport) source() fenceCollectorSource {
	return fenceCollectorSource{
		current: func() error {
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.identity
		},
		receive: func(buf []byte) (int, bool, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			defer f.signal(f.changed)
			if len(f.queue) == 0 {
				f.empties++
				f.idleRead = f.reads
				return 0, true, nil
			}
			d := f.queue[0]
			f.queue[0] = fenceTestDatagram{}
			f.queue = f.queue[1:]
			f.reads++
			if d.err != nil {
				return 0, false, d.err
			}
			if len(d.raw) > len(buf) {
				return 0, false, at("netlink.receive.truncated", nil)
			}
			return copy(buf, d.raw), false, nil
		},
		wait: func() error {
			select {
			case <-f.wake:
			case <-time.After(2 * time.Millisecond):
			}
			return nil
		},
	}
}
func (f *fenceTestTransport) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reads, f.empties
}
func waitFenceTest(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("bounded fence operation did not finish")
	}
}
func waitFenceTestCounts(t *testing.T, f *fenceTestTransport, reads, empties int) {
	t.Helper()
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	for {
		r, e := f.counts()
		if r >= reads && e >= empties {
			return
		}
		select {
		case <-f.changed:
		case <-timer.C:
			t.Fatal("original reader did not drain between checks")
		}
	}
}
func waitFenceTestDrained(t *testing.T, f *fenceTestTransport, reads int) {
	t.Helper()
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	for {
		f.mu.Lock()
		idleRead := f.idleRead
		f.mu.Unlock()
		if idleRead >= reads {
			return
		}
		select {
		case <-f.changed:
		case <-timer.C:
			t.Fatal("reader did not reach EAGAIN after the datagram")
		}
	}
}
func checkFenceTest(t *testing.T, r *originalFenceCollector, segments []Segment, devices []Device) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return r.check(ctx, segments, devices)
}
func assertFenceFailure(t *testing.T, err error, stage string) {
	t.Helper()
	if !errors.Is(err, ErrUnknown) || !strings.Contains(strings.Join(DiagnosticStages(err), ">"), stage) {
		t.Fatalf("missing closed refusal %s: %v", stage, DiagnosticStages(err))
	}
}

func TestOriginalFenceCollectorDrainsBetweenChecksWithoutRefreshing(t *testing.T) {
	f := newFenceTestTransport()
	r := newOriginalFenceCollector(f.source())
	t.Cleanup(r.close)
	segments := []Segment{{Interface: "Home", IfIndex: 9, Members: []Link{{Interface: "eth0", IfIndex: 4}}}}
	ctx, cancel := context.WithCancel(context.Background())
	if err := r.check(ctx, segments, nil); err != nil {
		t.Fatal(err)
	}
	cancel() // The operation context is not the retained reader's lifetime.
	unrelated := frame(linkFrame(20, "tun0", "tun", "", 0))
	// More than the startup count bound is accepted without another check:
	// each frame is consumed against the original baseline, never queued forever.
	for batch := 0; batch < 9; batch++ {
		packets := make([]fenceTestDatagram, 1024)
		for i := range packets {
			packets[i].raw = unrelated
		}
		f.push(packets...)
		waitFenceTestCounts(t, f, (batch+1)*1024, 0)
	}
	if err := checkFenceTest(t, r, segments, nil); err != nil {
		t.Fatal(err)
	}
	segments[0].Members[0].IfIndex = 40 // Cannot mutate the collector's first facts.
	deleted := linkFrame(4, "eth0", "", "02:00:00:00:00:02", 0)
	deleted.kind = 17
	f.push(fenceTestDatagram{raw: frame(deleted)})
	waitFenceTest(t, r.done)
	assertFenceFailure(t, checkFenceTest(t, r, segments, nil), "notifications.link.tracked-index")
}

func TestOriginalFenceCollectorKeepsStartupAndDeleteRecreate(t *testing.T) {
	for _, startup := range []bool{true, false} {
		t.Run(map[bool]string{true: "before-first-facts", false: "between-checks"}[startup], func(t *testing.T) {
			f := newFenceTestTransport()
			r := newOriginalFenceCollector(f.source())
			t.Cleanup(r.close)
			segments := []Segment{{Interface: "Home", IfIndex: 9}}
			if !startup {
				if err := checkFenceTest(t, r, segments, nil); err != nil {
					t.Fatal(err)
				}
			}
			original := linkFrame(9, "Home", "bridge", "02:00:00:00:00:01", 0)
			deleted := original
			deleted.kind = 17
			f.push(fenceTestDatagram{raw: frame(deleted)}, fenceTestDatagram{raw: frame(original)})
			if startup {
				waitFenceTestCounts(t, f, 2, 1)
			} else {
				waitFenceTest(t, r.done)
			}
			assertFenceFailure(t, checkFenceTest(t, r, segments, nil), "notifications.link.tracked-index")
			assertFenceFailure(t, checkFenceTest(t, r, segments, nil), "notifications.link.tracked-index")
		})
	}
}

func TestOriginalFenceCollectorStartupBounds(t *testing.T) {
	t.Run("bytes-across-empty-checkpoints", func(t *testing.T) {
		f := newFenceTestTransport()
		r := newOriginalFenceCollector(f.source())
		t.Cleanup(r.close)
		raw := frame(message{kind: 16, data: make([]byte, fenceReceiveBytes-16)})
		for i := 0; i < 4; i++ {
			f.push(fenceTestDatagram{raw: raw})
			waitFenceTestDrained(t, f, i+1)
		}
		f.push(fenceTestDatagram{raw: raw})
		waitFenceTest(t, r.done)
		assertFenceFailure(t, checkFenceTest(t, r, nil, nil), "fence.receive.pending-byte-limit")
	})
	t.Run("datagrams", func(t *testing.T) {
		f := newFenceTestTransport()
		packets := make([]fenceTestDatagram, maxFencePendingDatagrams+1)
		for i := range packets {
			packets[i].raw = frame(message{kind: 16})
		}
		f.push(packets...)
		r := newOriginalFenceCollector(f.source())
		t.Cleanup(r.close)
		waitFenceTest(t, r.done)
		assertFenceFailure(t, checkFenceTest(t, r, nil, nil), "fence.receive.pending-count-limit")
	})
}

func TestOriginalFenceCollectorLossTruncationUnknownAreSticky(t *testing.T) {
	privateCause := errors.New("private-device-address-and-path")
	for name, packet := range map[string]fenceTestDatagram{
		"loss":       {err: boundary("fence.receive.loss", privateCause)},
		"truncation": {err: boundary("fence.receive.read", at("netlink.receive.truncated", nil))},
		"unknown":    {raw: frame(message{kind: 4})},
		"malformed":  {raw: []byte{1, 2, 3}},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFenceTestTransport()
			r := newOriginalFenceCollector(f.source())
			t.Cleanup(r.close)
			if err := checkFenceTest(t, r, nil, nil); err != nil {
				t.Fatal(err)
			}
			f.push(packet)
			waitFenceTest(t, r.done)
			for i := 0; i < 2; i++ {
				err := checkFenceTest(t, r, nil, nil)
				if !errors.Is(err, ErrUnknown) || strings.Contains(err.Error(), privateCause.Error()) {
					t.Fatal("loss was refreshed or exposed private text")
				}
				if name == "loss" {
					assertFenceFailure(t, err, "fence.receive.loss")
					if !errors.Is(err, privateCause) {
						t.Fatal("original loss cause discarded")
					}
				}
			}
		})
	}
}

func TestOriginalFenceCheckpointRequiresFreshEAGAINAndDescriptorBookend(t *testing.T) {
	for _, closingChanged := range []bool{false, true} {
		t.Run(map[bool]string{false: "event-before-new-eagain", true: "closing-descriptor"}[closingChanged], func(t *testing.T) {
			reads, currents := 0, 0
			segments := []Segment{{Interface: "Home", IfIndex: 9}}
			selected := frame(addressFrame(9, "192.0.2.1/24"))
			r := &originalFenceCollector{stop: make(chan struct{}), source: fenceCollectorSource{
				current: func() error {
					currents++
					if closingChanged && currents == 2 {
						return at("fence.descriptor.cookie.changed", nil)
					}
					return nil
				},
				receive: func(buf []byte) (int, bool, error) {
					reads++
					if !closingChanged {
						return copy(buf, selected), false, nil
					}
					return 0, true, nil
				},
			}}
			state := fenceCollectorState{reader: r, bound: true, original: Snapshot{Segments: segments}}
			err := state.checkpoint(fenceCheckpoint{ctx: context.Background(), original: cloneSnapshot(state.original)}, make([]byte, fenceReceiveBytes))
			if reads != 1 || !errors.Is(err, ErrUnknown) {
				t.Fatal("checkpoint used an earlier empty userspace queue")
			}
			if closingChanged {
				assertFenceFailure(t, err, "fence.drain.closing-descriptor")
			} else {
				assertFenceFailure(t, err, "notifications.address.tracked")
			}
		})
	}
}

func TestOriginalFenceCollectorRejectsReplacementFacts(t *testing.T) {
	f := newFenceTestTransport()
	r := newOriginalFenceCollector(f.source())
	t.Cleanup(r.close)
	if err := checkFenceTest(t, r, []Segment{{Interface: "Home", IfIndex: 9}}, nil); err != nil {
		t.Fatal(err)
	}
	assertFenceFailure(t, checkFenceTest(t, r, []Segment{{Interface: "Home", IfIndex: 10}}, nil), "fence.check.baseline.changed")
	assertFenceFailure(t, checkFenceTest(t, r, []Segment{{Interface: "Home", IfIndex: 9}}, nil), "fence.check.baseline.changed")
}

func TestOriginalFenceCollectorCanceledQueuedCheckpointAndJoin(t *testing.T) {
	f := newFenceTestTransport()
	waiting, release := make(chan struct{}), make(chan struct{})
	source := f.source()
	var waitingOnce sync.Once
	source.wait = func() error { waitingOnce.Do(func() { close(waiting) }); <-release; return nil }
	r := newOriginalFenceCollector(source)
	waitFenceTest(t, waiting)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // An enqueued request can expire before the reader accepts it.
	reply := make(chan error, 1)
	sent := make(chan struct{})
	go func() {
		r.checks <- fenceCheckpoint{ctx: ctx, reply: reply}
		close(sent)
	}()
	close(release)
	waitFenceTest(t, sent)
	waitFenceTest(t, r.done)
	assertFenceFailure(t, checkFenceTest(t, r, nil, nil), "fence.drain.context")
	r.close()
}

func TestOriginalFenceCollectorCloseWaitsForReader(t *testing.T) {
	waiting, release := make(chan struct{}), make(chan struct{})
	f := newFenceTestTransport()
	source := f.source()
	source.wait = func() error { close(waiting); <-release; return nil }
	r := newOriginalFenceCollector(source)
	waitFenceTest(t, waiting)
	closed := make(chan struct{})
	go func() { r.close(); close(closed) }()
	waitFenceTest(t, r.stop)
	select {
	case <-closed:
		t.Fatal("Close returned while the original reader was still running")
	default:
	}
	reads, _ := f.counts()
	close(release)
	waitFenceTest(t, closed)
	if after, _ := f.counts(); after != reads {
		t.Fatal("reader accessed the descriptor after cancellation")
	}
	assertFenceFailure(t, checkFenceTest(t, r, nil, nil), "fence.check.closed")
	r.close()
}

func TestOriginalFenceCollectorConcurrentChecksCloseHaveOneReader(t *testing.T) {
	f := newFenceTestTransport()
	source := f.source()
	receive := source.receive
	var active atomic.Int32
	var concurrent atomic.Bool
	source.receive = func(buf []byte) (int, bool, error) {
		if active.Add(1) != 1 {
			concurrent.Store(true)
		}
		defer active.Add(-1)
		return receive(buf)
	}
	r := newOriginalFenceCollector(source)
	t.Cleanup(r.close)
	if err := checkFenceTest(t, r, nil, nil); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errorsFound := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			err := r.check(ctx, nil, nil)
			if err != nil && !errors.Is(err, ErrUnknown) {
				errorsFound <- err
			}
		})
	}
	for i := 0; i < 8; i++ {
		wg.Go(r.close)
	}
	finished := make(chan struct{})
	go func() { wg.Wait(); close(finished) }()
	waitFenceTest(t, finished)
	if concurrent.Load() || active.Load() != 0 || len(errorsFound) != 0 {
		t.Fatal("concurrent Check/Close did not retain a single joined reader")
	}
}

func TestOriginalFenceCollectorUnexpectedReaderExitAndDescriptorChangeAreTerminal(t *testing.T) {
	for _, change := range []bool{false, true} {
		t.Run(map[bool]string{false: "wait-error", true: "changed-before-receive"}[change], func(t *testing.T) {
			f := newFenceTestTransport()
			source := f.source()
			if change {
				f.identity = at("fence.descriptor.cookie.changed", nil)
			} else {
				source.wait = func() error { return at("fence.poll.read", nil) }
			}
			r := newOriginalFenceCollector(source)
			t.Cleanup(r.close)
			waitFenceTest(t, r.done)
			stage := "fence.poll.read"
			if change {
				stage = "fence.descriptor.cookie.changed"
				if reads, empties := f.counts(); reads != 0 || empties != 0 {
					t.Fatal("reader used a replaced descriptor")
				}
			}
			assertFenceFailure(t, checkFenceTest(t, r, nil, nil), stage)
			assertFenceFailure(t, checkFenceTest(t, r, nil, nil), stage)
		})
	}
}
