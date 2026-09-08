package systemprobe

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type fakeEpochSource struct {
	state      epochSnapshot
	err        error
	changed    bool
	drainErr   error
	reads      int
	closed     int
	during     []bool
	onSnapshot func(context.Context)
	onDrain    func(context.Context)
}

func (f *fakeEpochSource) Snapshot(ctx context.Context) (epochSnapshot, error) {
	f.reads++
	if f.onSnapshot != nil {
		f.onSnapshot(ctx)
	}
	return f.state, f.err
}
func (f *fakeEpochSource) Drain(ctx context.Context, _ map[uint32]bool) (bool, error) {
	if f.onDrain != nil {
		f.onDrain(ctx)
	}
	if len(f.during) > 0 {
		value := f.during[0]
		f.during = f.during[1:]
		return value, f.drainErr
	}
	changed := f.changed
	f.changed = false
	return changed, f.drainErr
}
func (f *fakeEpochSource) Close() { f.closed++ }

func fakeEpochSnapshot() epochSnapshot {
	return epochSnapshot{bootID: "boot-identity", wanInterface: "eth3", interfaces: map[uint32]bool{4: true}, parts: []string{"default=via-gateway-src-address", "addr=address-v4", "dns=digest"}}
}

func detectorForTest(source *fakeEpochSource) *epochDetector {
	return newEpochDetector(func(context.Context) (epochSource, error) { return source, nil }, bytes.NewReader([]byte("12345678")), time.Now)
}

func TestEpochFreshBypassesPassiveCacheAndTracksAllSnapshotParts(t *testing.T) {
	for _, changedPart := range []string{"source", "ipv6-default", "ipv6-address", "dns", "carrier"} {
		t.Run(changedPart, func(t *testing.T) {
			source := &fakeEpochSource{state: fakeEpochSnapshot()}
			d := detectorForTest(source)
			first, err := d.fresh(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if got := d.cached(); got != first || source.reads != 1 {
				t.Fatal("passive cache did not reuse the same epoch")
			}
			source.state.parts = append(source.state.parts, changedPart)
			second, err := d.fresh(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if second.ID == first.ID || !ValidWANProfileID(second.ID) || source.reads != 2 {
				t.Fatal("fresh observation did not change epoch immediately")
			}
			if d.cached() != second {
				t.Fatal("passive cache retained previous epoch")
			}
			if strings.Contains(second.ID, "gateway") || strings.Contains(second.ID, "address") {
				t.Fatal("private observation leaked")
			}
		})
	}
}

func TestEpochOrderIsStableButObservedABAInvalidates(t *testing.T) {
	source := &fakeEpochSource{state: fakeEpochSnapshot()}
	d := detectorForTest(source)
	first, _ := d.fresh(context.Background())
	source.state.parts[0], source.state.parts[1] = source.state.parts[1], source.state.parts[0]
	second, err := d.fresh(context.Background())
	if err != nil || first.ID != second.ID {
		t.Fatal("ordering changed epoch")
	}
	source.changed = true // link/default/DNS changed and returned to original state
	third, err := d.fresh(context.Background())
	if err != nil || third.ID == first.ID {
		t.Fatal("observed A-B-A reused proof epoch")
	}
}

func TestEpochUnknownAndRestartNeverReviveOldSession(t *testing.T) {
	for _, failure := range []string{"snapshot", "overflow", "missing-boot", "no-default"} {
		t.Run(failure, func(t *testing.T) {
			source := &fakeEpochSource{state: fakeEpochSnapshot()}
			d := detectorForTest(source)
			first, _ := d.fresh(context.Background())
			switch failure {
			case "snapshot":
				source.err = errors.New("private path")
			case "overflow":
				source.drainErr = errors.New("overflow")
			case "missing-boot":
				source.state.bootID = ""
			case "no-default":
				source.state.wanInterface = ""
			}
			unknown, err := d.fresh(context.Background())
			if !errors.Is(err, ErrNetworkUnavailable) || unknown.ID != "network-unknown" || source.closed != 1 || ValidWANProfileID(unknown.ID) {
				t.Fatal("observation failure was not fail-closed")
			}
			if d.cached() != unknown {
				t.Fatal("failure kept a known cached epoch")
			}
			source.err, source.drainErr = nil, nil
			source.state = fakeEpochSnapshot()
			again, err := d.fresh(context.Background())
			if err != nil || again.ID == first.ID {
				t.Fatal("A-unknown-A revived old proof")
			}
			other := newEpochDetector(func(context.Context) (epochSource, error) { return source, nil }, bytes.NewReader([]byte("87654321")), time.Now)
			restarted, err := other.fresh(context.Background())
			if err != nil || restarted.ID == first.ID {
				t.Fatal("restart reused old proof epoch")
			}
		})
	}
}

func TestEpochBoundedResnapshotAndCancellation(t *testing.T) {
	source := &fakeEpochSource{state: fakeEpochSnapshot(), during: []bool{false, true, false}}
	d := detectorForTest(source)
	if _, err := d.fresh(context.Background()); err != nil || source.reads != 2 {
		t.Fatal("change during snapshot was not resampled")
	}
	source.during = []bool{false, true, true}
	if _, err := d.fresh(context.Background()); !errors.Is(err, ErrNetworkUnavailable) {
		t.Fatal("unstable snapshot accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if result, err := d.fresh(ctx); err == nil || ValidWANProfileID(result.ID) {
		t.Fatal("cancelled observation accepted")
	}
	d.gate <- struct{}{}
	short, stop := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer stop()
	if _, err := d.fresh(short); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("busy observer ignored caller deadline")
	}
	<-d.gate
}

func TestValidWANProfileIDRejectsUnknownAndArbitraryLabels(t *testing.T) {
	for _, id := range []string{"", "network-unknown", "wan-a", "wan-123456789ABC", "wan-123456789abz", "wan-123456789abc\n"} {
		if ValidWANProfileID(id) {
			t.Errorf("accepted %q", id)
		}
	}
	if !ValidWANProfileID("wan-123456789abc") {
		t.Fatal("known token rejected")
	}
}

func TestEpochDNSConfigNeedsAnActualNameserver(t *testing.T) {
	for _, text := range []string{"", "# nameserver 127.0.0.1\n", "nameserver\n", "nameserver not-an-ip\n"} {
		if validEpochDNSConfig([]byte(text)) {
			t.Errorf("invalid DNS configuration accepted: %q", text)
		}
	}
	for _, text := range []string{"nameserver 127.0.0.1\noptions timeout:1 attempts:1 rotate\n", "nameserver fe80::1%eth3\n", "nameserver 1.1.1.1 # resolver\n"} {
		if !validEpochDNSConfig([]byte(text)) {
			t.Fatal("valid bounded DNS configuration rejected")
		}
	}
}

func TestEpochCallerCancellationDoesNotResetSharedObserver(t *testing.T) {
	for _, where := range []string{"before-admission", "during-drain", "during-snapshot"} {
		t.Run(where, func(t *testing.T) {
			source := &fakeEpochSource{state: fakeEpochSnapshot()}
			d := detectorForTest(source)
			first, err := d.fresh(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			hook := func(observation context.Context) {
				cancel()
				if observation.Err() != nil {
					t.Error("caller canceled shared observation")
				}
				if _, bounded := observation.Deadline(); !bounded {
					t.Error("shared observation is unbounded")
				}
			}
			switch where {
			case "before-admission":
				cancel()
			case "during-drain":
				source.onDrain = hook
			case "during-snapshot":
				source.onSnapshot = hook
			}
			result, err := d.fresh(ctx)
			if !errors.Is(err, context.Canceled) || ValidWANProfileID(result.ID) {
				t.Fatal("canceled caller received authority")
			}
			if source.closed != 0 || d.source != source || d.cached() != first {
				t.Fatal("caller cancellation reset the shared epoch")
			}
			source.onDrain, source.onSnapshot = nil, nil
			after, err := d.fresh(context.Background())
			if err != nil || after.ID != first.ID {
				t.Fatal("next request lost otherwise valid proofs")
			}
			if diagnostic := d.diagnostic(); diagnostic.CallerCancellations != 1 || diagnostic.Reason != "observer-start" {
				t.Fatalf("unsafe or missing cancellation diagnostic: %+v", diagnostic)
			}
		})
	}
}

func TestEpochCanceledObserverStillRecordsABA(t *testing.T) {
	source := &fakeEpochSource{state: fakeEpochSnapshot()}
	d := detectorForTest(source)
	first, err := d.fresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	source.changed = true
	source.onDrain = func(observation context.Context) {
		cancel()
		if observation.Err() != nil {
			t.Error("event drain was interrupted")
		}
	}
	result, err := d.fresh(ctx)
	if !errors.Is(err, context.Canceled) || ValidWANProfileID(result.ID) {
		t.Fatal("canceled caller received authority")
	}
	source.onDrain = nil
	after, err := d.fresh(context.Background())
	if err != nil || after.ID == first.ID || source.closed != 0 {
		t.Fatal("canceled request lost an observed ABA event")
	}
	if d.diagnostic().Reason != "observed-event" {
		t.Fatal("event reason was not retained")
	}
}

func TestEpochCallerDeadlineAndObservationTimeoutHaveDifferentAuthority(t *testing.T) {
	source := &fakeEpochSource{state: fakeEpochSnapshot()}
	d := detectorForTest(source)
	first, err := d.fresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	source.onSnapshot = func(observation context.Context) {
		<-ctx.Done()
		if observation.Err() != nil {
			t.Error("request deadline interrupted shared observation")
		}
	}
	if got, err := d.fresh(ctx); !errors.Is(err, context.DeadlineExceeded) || ValidWANProfileID(got.ID) {
		t.Fatal("expired caller received authority")
	}
	source.onSnapshot = nil
	if got, err := d.fresh(context.Background()); err != nil || got.ID != first.ID || source.closed != 0 {
		t.Fatal("caller deadline reset observer")
	}
	source.err = context.DeadlineExceeded // An actual bounded collection failed.
	if got, err := d.fresh(context.Background()); !errors.Is(err, context.DeadlineExceeded) || ValidWANProfileID(got.ID) || source.closed != 1 {
		t.Fatal("observation timeout retained authority")
	}
	source.err = nil
	if got, err := d.fresh(context.Background()); err != nil || got.ID == first.ID {
		t.Fatal("real observation timeout revived old proofs")
	}
}

func TestEpochReasonHasNoPrivateSnapshotValues(t *testing.T) {
	source := &fakeEpochSource{state: fakeEpochSnapshot()}
	d := detectorForTest(source)
	_, _ = d.fresh(context.Background())
	source.state.parts = append(source.state.parts, "dns=private-secret-host-token")
	_, err := d.fresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if d.diagnostic().Reason != "snapshot-dns" {
		t.Fatalf("unexpected safe diagnostic: %+v", d.diagnostic())
	}
	source.err = errors.New("private-secret-host-token")
	_, _ = d.fresh(context.Background())
	if d.diagnostic().Reason != "observation-failed-snapshot" {
		t.Fatal("error detail leaked or phase was lost")
	}
}
