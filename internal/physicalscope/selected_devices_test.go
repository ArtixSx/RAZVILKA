package physicalscope

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"
)

const (
	projectionClientMAC   = "02:00:00:00:00:03"
	projectionExcludedMAC = "02:00:00:00:00:06"
	projectionOtherMAC    = "02:00:00:00:00:07"
)

func selectedTestSelection() Selection {
	return Selection{Revision: 7, PolicyRevision: 3, SegmentIDs: []string{"Bridge0"}, SelectedDevices: &SelectedDeviceProjection{
		DeviceIDs: []string{physicalDeviceID(projectionClientMAC)}, ExcludedDeviceIDs: []string{physicalDeviceID(projectionExcludedMAC)},
	}}
}

func selectedTestNeighbors() map[byte][]message {
	router := neighborFrame(9, "fe80::5", "02:00:00:00:00:05", 2)
	router.data[10] = 128
	return map[byte][]message{
		2: {neighborFrame(9, "192.0.2.20", projectionClientMAC, 2), neighborFrame(9, "192.0.2.30", projectionExcludedMAC, 4), neighborFrame(9, "192.0.2.5", "02:00:00:00:00:05", 4)},
		10: {neighborFrame(9, "2001:db8::20", projectionClientMAC, 4), neighborFrame(9, "fe80::20", projectionClientMAC, 4),
			neighborFrame(9, "2001:db8::30", projectionExcludedMAC, 4), neighborFrame(9, "fe80::30", projectionExcludedMAC, 4), router},
	}
}

// The I/O is private fixture data; segment assembly, dual-stack decoding,
// binding, notification collector and original Review are production code.
func captureSelectedTest(ctx context.Context, selection Selection, frames map[byte][]message) (Snapshot, error) {
	native, err := parseNDM([]byte(ndmFixture()))
	if err != nil {
		return Snapshot{}, err
	}
	links, addresses, routes := kernelFixture()
	addresses = append(addresses, addressFrame(9, "2001:db8::1/64"))
	segments, err := assembleSegments(selection, native, true, links, addresses, routes)
	if err != nil {
		return Snapshot{}, err
	}
	devices, err := bindSelectedKernelNeighbors(ctx, selection, segments, frames)
	return Snapshot{Selection: selection, Segments: segments, Devices: devices}, err
}

type selectedCollectorTestFence struct{ reader *originalFenceCollector }

func (f *selectedCollectorTestFence) check(ctx context.Context, snapshot Snapshot) error {
	return f.reader.check(ctx, snapshot)
}
func (f *selectedCollectorTestFence) close() error { f.reader.close(); return nil }

func selectedTestReview(t *testing.T) (*Observer, *observerModel, *map[byte][]message, *fenceTestTransport, *Review, context.Context) {
	t.Helper()
	o, m, _ := newModel(t)
	m.selection = selectedTestSelection()
	frames := selectedTestNeighbors()
	transport := newFenceTestTransport()
	opens := 0
	o.source.open = func(context.Context) (lifecycleFence, error) {
		opens++
		if opens != 1 {
			t.Fatal("reopened original collector")
		}
		return &selectedCollectorTestFence{reader: newOriginalFenceCollector(transport.source())}, nil
	}
	o.source.capture = func(c context.Context, selection Selection) ([]Segment, []Device, error) {
		m.captures++
		if m.onCapture != nil {
			m.onCapture(m.captures)
		}
		snapshot, err := captureSelectedTest(c, selection, frames)
		return snapshot.Segments, snapshot.Devices, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	r, err := o.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	return o, m, &frames, transport, r, ctx
}

func TestSelectedDeviceProjectionCanonicalDetachedAndBounded(t *testing.T) {
	selection := selectedTestSelection()
	selection.SelectedDevices.DeviceIDs = []string{physicalDeviceID(projectionExcludedMAC), physicalDeviceID(projectionClientMAC)}
	canonical, err := canonicalSelection(selection)
	if err != nil || !slices.IsSorted(canonical.SelectedDevices.DeviceIDs) {
		t.Fatal("overlap between positive and excluded sets changed existing semantics", err)
	}
	selection.SelectedDevices.DeviceIDs[0] = "changed"
	if canonical.SelectedDevices.DeviceIDs[1] != physicalDeviceID(projectionExcludedMAC) {
		t.Fatal("selection adopted mutable input")
	}
	detached := cloneSnapshot(Snapshot{Selection: canonical})
	detached.Selection.SelectedDevices.ExcludedDeviceIDs[0] = "changed"
	if canonical.SelectedDevices.ExcludedDeviceIDs[0] != physicalDeviceID(projectionExcludedMAC) {
		t.Fatal("snapshot adopted mutable projection")
	}
	for name, p := range map[string]*SelectedDeviceProjection{
		"empty":              {},
		"IP-shaped":          {DeviceIDs: []string{"ip-192.0.2.20"}},
		"uppercase":          {DeviceIDs: []string{"mac-02-00-00-00-00-AA"}},
		"multicast":          {DeviceIDs: []string{"mac-01-00-00-00-00-03"}},
		"duplicate":          {DeviceIDs: []string{physicalDeviceID(projectionClientMAC), physicalDeviceID(projectionClientMAC)}},
		"oversized":          {DeviceIDs: make([]string, 129)},
		"excluded-malformed": {DeviceIDs: []string{physicalDeviceID(projectionClientMAC)}, ExcludedDeviceIDs: []string{"unknown"}},
		"excluded-oversized": {DeviceIDs: []string{physicalDeviceID(projectionClientMAC)}, ExcludedDeviceIDs: make([]string, 129)},
	} {
		t.Run(name, func(t *testing.T) {
			s := selectedTestSelection()
			s.SelectedDevices = p
			if _, err := canonicalSelection(s); !errors.Is(err, ErrUnknown) {
				t.Fatal("unsupported intent acquired projection", err)
			}
		})
	}
}

func TestSelectedDeviceProjectionCapturePreservesCohortAndInfrastructure(t *testing.T) {
	selection := selectedTestSelection()
	original, err := captureSelectedTest(context.Background(), selection, selectedTestNeighbors())
	if err != nil || len(original.Devices) != 2 || len(original.Segments[0].RouterNeighbors) != 2 {
		t.Fatal("selected or negative facts lost", err)
	}
	for _, d := range original.Devices {
		if len(d.Addresses) != 2 || len(d.LinkLocalAddresses) != 1 {
			t.Fatal("dual-stack cohort reduced to IP-only positive facts")
		}
	}
	for _, extras := range [][]message{
		{neighborFrame(9, "192.0.2.70", projectionOtherMAC, 2), neighborFrame(9, "2001:db8::70", projectionOtherMAC, 4)},
		{neighborFrame(9, "192.0.2.71", projectionOtherMAC, 4), neighborFrame(9, "2001:db8::71", projectionOtherMAC, 4), neighborFrame(9, "fe80::71", projectionOtherMAC, 4)},
		{neighborFrame(9, "192.0.2.70", "", 1), neighborFrame(9, "2001:db8::70", "", 32)},
		{neighborFrame(9, "198.51.100.70", projectionOtherMAC, 4)},
	} {
		frames := selectedTestNeighbors()
		for _, m := range extras {
			frames[m.data[0]] = append(frames[m.data[0]], m)
		}
		current, err := captureSelectedTest(context.Background(), selection, frames)
		if err != nil || !reflect.DeepEqual(original, current) {
			t.Fatal("ordinary unrelated churn changed frozen physical cohort", err)
		}
	}
	strict := selection
	strict.SelectedDevices = nil
	frames := selectedTestNeighbors()
	frames[2] = append(frames[2], neighborFrame(9, "192.0.2.70", projectionOtherMAC, 2))
	full, err := captureSelectedTest(context.Background(), strict, frames)
	if err != nil || len(full.Devices) != 3 {
		t.Fatal("nil projection stopped observing the complete segment", err)
	}
}

func TestSelectedDeviceProjectionCaptureNeverFiltersConflictsOrUnknowns(t *testing.T) {
	for name, change := range map[string]func(map[byte][]message){
		"selected-missing": func(f map[byte][]message) { f[2] = f[2][1:]; f[10] = f[10][2:] },
		"excluded-missing": func(f map[byte][]message) {
			f[2] = append(f[2][:1], f[2][2:]...)
			f[10] = append(f[10][:2], f[10][4:]...)
		},
		"selected-ingress": func(f map[byte][]message) {
			f[2] = append(f[2], neighborFrame(30, "192.0.2.21", projectionClientMAC, 2))
		},
		"excluded-ingress": func(f map[byte][]message) {
			f[2] = append(f[2], neighborFrame(30, "192.0.2.31", projectionExcludedMAC, 2))
		},
		"selected-IP-conflict": func(f map[byte][]message) { f[2] = append(f[2], neighborFrame(9, "192.0.2.20", projectionOtherMAC, 2)) },
		"excluded-IP-conflict-other-ingress": func(f map[byte][]message) {
			f[10] = append(f[10], neighborFrame(30, "2001:db8::30", projectionOtherMAC, 2))
		},
		"infrastructure-IP-conflict": func(f map[byte][]message) { f[2] = append(f[2], neighborFrame(30, "192.0.2.5", projectionOtherMAC, 2)) },
		"bridge-IP-conflict":         func(f map[byte][]message) { f[2] = append(f[2], neighborFrame(9, "192.0.2.1", projectionOtherMAC, 2)) },
		"selected-router-role":       func(f map[byte][]message) { f[10][0].data[10] = 128 },
		"excluded-router-role":       func(f map[byte][]message) { f[10][2].data[10] = 128 },
		"excluded-failed":            func(f map[byte][]message) { f[2][1] = neighborFrame(9, "192.0.2.30", projectionExcludedMAC, 32) },
		"malformed-unrelated":        func(f map[byte][]message) { f[2] = append(f[2], message{kind: 28, data: []byte{2}}) },
		"unrelated-duplicate-attribute": func(f map[byte][]message) {
			m := neighborFrame(9, "192.0.2.70", projectionOtherMAC, 4)
			m.data = append(m.data, attr(1, []byte{192, 0, 2, 70})...)
			f[2] = append(f[2], m)
		},
		"partial-family": func(f map[byte][]message) { delete(f, 10) },
	} {
		t.Run(name, func(t *testing.T) {
			frames := selectedTestNeighbors()
			change(frames)
			if _, err := captureSelectedTest(context.Background(), selectedTestSelection(), frames); !errors.Is(err, ErrUnknown) {
				t.Fatal("projection hid conflict/missing/unknown native evidence", err)
			}
		})
	}
}

func TestSelectedDeviceProjectionKeepsOneReviewAcrossUnrelatedChurn(t *testing.T) {
	o, _, frames, transport, review, ctx := selectedTestReview(t)
	original := review.Snapshot()
	for _, events := range [][]message{
		{neighborFrame(9, "192.0.2.70", projectionOtherMAC, 2), neighborFrame(9, "2001:db8::70", projectionOtherMAC, 4)},
		{neighborFrame(9, "192.0.2.71", projectionOtherMAC, 4), neighborFrame(9, "2001:db8::71", projectionOtherMAC, 8), neighborFrame(9, "fe80::71", projectionOtherMAC, 16)},
		{neighborFrame(9, "192.0.2.71", "", 1), neighborFrame(9, "2001:db8::71", "", 32)},
		{neighborFrame(9, "192.0.2.71", projectionOtherMAC, 4)},
	} {
		*frames = selectedTestNeighbors()
		for _, event := range events {
			(*frames)[event.data[0]] = append((*frames)[event.data[0]], event)
			transport.push(fenceTestDatagram{raw: frame(event)})
		}
		if err := o.Verify(ctx, review); err != nil {
			t.Fatal("unrelated churn revoked chosen PC", err)
		}
		if err := o.VerifyRetainedIncarnation(ctx, review); err != nil {
			t.Fatal("unrelated churn revoked retained cleanup", err)
		}
		if !reflect.DeepEqual(original, review.Snapshot()) {
			t.Fatal("Verify refreshed immutable facts")
		}
	}
	deleted := neighborFrame(9, "192.0.2.71", projectionOtherMAC, 4)
	deleted.kind = 29
	transport.push(fenceTestDatagram{raw: frame(deleted)})
	*frames = selectedTestNeighbors()
	if err := o.Verify(ctx, review); err != nil {
		t.Fatal("unrelated departure revoked chosen PC", err)
	}
	if !reflect.DeepEqual(original, review.Snapshot()) {
		t.Fatal("departure rebound original Review")
	}
}

func TestSelectedDeviceProjectionRelevantEventsPermanentlyRevokeBothPaths(t *testing.T) {
	router := neighborFrame(9, "2001:db8::70", projectionOtherMAC, 4)
	router.data[10] = 128
	deleted := neighborFrame(9, "192.0.2.20", projectionClientMAC, 4)
	deleted.kind = 29
	for name, event := range map[string]message{
		"selected-delete":            deleted,
		"selected-IP-conflict":       neighborFrame(9, "192.0.2.20", projectionOtherMAC, 4),
		"excluded-IP-conflict":       neighborFrame(9, "2001:db8::30", projectionOtherMAC, 4),
		"selected-new-address":       neighborFrame(9, "192.0.2.21", projectionClientMAC, 4),
		"excluded-new-address":       neighborFrame(9, "fe80::31", projectionExcludedMAC, 4),
		"selected-ingress":           neighborFrame(30, "192.0.2.20", projectionClientMAC, 4),
		"excluded-ingress":           neighborFrame(30, "192.0.2.31", projectionExcludedMAC, 4),
		"selected-incomplete":        neighborFrame(9, "192.0.2.20", "", 1),
		"excluded-failed":            neighborFrame(9, "192.0.2.30", "", 32),
		"new-router-role":            router,
		"infrastructure-new-address": neighborFrame(9, "192.0.2.15", "02:00:00:00:00:05", 4),
		"bridge-link":                linkFrame(9, "Home", "bridge", "02:00:00:00:00:01", 0),
		"bridge-address":             addressFrame(9, "2001:db8::1/64"),
		"bridge-route":               routeFrame(9),
		"malformed-unrelated":        {kind: 28, data: []byte{2}},
		"unknown":                    {kind: 4},
	} {
		t.Run(name, func(t *testing.T) {
			o, _, _, transport, review, ctx := selectedTestReview(t)
			transport.push(fenceTestDatagram{raw: frame(event)})
			if o.Verify(ctx, review) == nil || !review.state.physicalInvalid {
				t.Fatal("relevant/unknown event did not permanently refuse")
			}
			if o.Verify(ctx, review) == nil || o.VerifyRetainedIncarnation(ctx, review) == nil {
				t.Fatal("unchanged dump revived failed original collector")
			}
		})
	}
}

func TestSelectedDeviceProjectionRetainsOriginalCleanupAfterSelectionRevocation(t *testing.T) {
	o, m, frames, transport, review, ctx := selectedTestReview(t)
	original := review.Snapshot()
	m.selection.SelectedDevices = &SelectedDeviceProjection{DeviceIDs: []string{physicalDeviceID(projectionOtherMAC)}}
	m.selection.PolicyRevision++
	if o.Verify(ctx, review) == nil || review.state.physicalInvalid {
		t.Fatal("selection-only revocation lost separate boundary")
	}
	o.selection = func(context.Context) (Selection, error) {
		t.Fatal("cleanup reread current intent")
		return Selection{}, nil
	}
	third := neighborFrame(9, "192.0.2.70", projectionOtherMAC, 4)
	(*frames)[2] = append((*frames)[2], third)
	transport.push(fenceTestDatagram{raw: frame(third)})
	if err := o.VerifyRetainedIncarnation(ctx, review); err != nil {
		t.Fatal("cleanup did not retain original cohort", err)
	}
	if !reflect.DeepEqual(original, review.Snapshot()) || o.Verify(ctx, review) == nil {
		t.Fatal("cleanup refreshed facts or forward admission")
	}
	transport.push(fenceTestDatagram{raw: frame(neighborFrame(9, "192.0.2.30", projectionOtherMAC, 4))})
	if o.VerifyRetainedIncarnation(ctx, review) == nil || !review.state.physicalInvalid {
		t.Fatal("original negative conflict waived after selection change")
	}
}

func TestSelectedDeviceProjectionNilNotificationsRemainStrict(t *testing.T) {
	snapshot, err := captureSelectedTest(context.Background(), selectedTestSelection(), selectedTestNeighbors())
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Selection.SelectedDevices = nil
	for _, event := range []message{neighborFrame(9, "192.0.2.70", projectionOtherMAC, 4), neighborFrame(9, "192.0.2.70", "", 1), neighborFrame(9, "2001:db8::70", "", 32)} {
		if checkSnapshotNotifications([]message{event}, snapshot) == nil {
			t.Fatal("nil/lan_except boundary acquired projection waiver")
		}
	}
}

func TestSelectedDeviceProjectionCaptureDriftCannotBeRestored(t *testing.T) {
	for name, change := range map[string]func(map[byte][]message){
		"selected-address": func(f map[byte][]message) { f[2][0] = neighborFrame(9, "192.0.2.21", projectionClientMAC, 4) },
		"excluded-address": func(f map[byte][]message) { f[10][2] = neighborFrame(9, "2001:db8::31", projectionExcludedMAC, 4) },
		"excluded-missing": func(f map[byte][]message) {
			f[2] = append(f[2][:1], f[2][2:]...)
			f[10] = append(f[10][:2], f[10][4:]...)
		},
		"IPv4-client-IPv6-router": func(f map[byte][]message) {
			f[10] = f[10][2:]
			n := neighborFrame(9, "fe80::21", projectionClientMAC, 4)
			n.data[10] = 128
			f[10] = append(f[10], n)
		},
	} {
		for _, retained := range []bool{false, true} {
			t.Run(name+map[bool]string{false: "/forward", true: "/retained"}[retained], func(t *testing.T) {
				o, _, frames, _, review, ctx := selectedTestReview(t)
				change(*frames)
				var err error
				if retained {
					err = o.VerifyRetainedIncarnation(ctx, review)
				} else {
					err = o.Verify(ctx, review)
				}
				if !errors.Is(err, ErrUnknown) || !review.state.physicalInvalid {
					t.Fatal("cohort dump drift did not stick", err)
				}
				*frames = selectedTestNeighbors()
				if o.VerifyRetainedIncarnation(ctx, review) == nil || o.Verify(ctx, review) == nil {
					t.Fatal("restoration refreshed original cohort")
				}
			})
		}
	}
}

func TestSelectedDeviceProjectionUnrelatedChurnBetweenCapturePasses(t *testing.T) {
	o, m, frames, transport, review, ctx := selectedTestReview(t)
	original := review.Snapshot()
	nextPass := m.captures + 2
	m.onCapture = func(pass int) {
		if pass == nextPass {
			extra := neighborFrame(9, "2001:db8::70", projectionOtherMAC, 4)
			(*frames)[10] = append((*frames)[10], extra)
			transport.push(fenceTestDatagram{raw: frame(extra)})
		}
	}
	if err := o.Verify(ctx, review); err != nil {
		t.Fatal("capture passes still compared entire unrelated client table", err)
	}
	if !reflect.DeepEqual(original, review.Snapshot()) {
		t.Fatal("capture adopted second-pass unrelated facts")
	}
}

func TestSelectedDeviceProjectionCollectorRetainsFullDetachedSnapshot(t *testing.T) {
	snapshot, err := captureSelectedTest(context.Background(), selectedTestSelection(), selectedTestNeighbors())
	if err != nil {
		t.Fatal(err)
	}
	snapshot.ReviewID = "original-review"
	for name, change := range map[string]func(*Snapshot){
		"review":             func(s *Snapshot) { s.ReviewID = "replacement-review" },
		"identity":           func(s *Snapshot) { s.Identity.Inode++ },
		"selection-revision": func(s *Snapshot) { s.Selection.PolicyRevision++ },
		"projection":         func(s *Snapshot) { s.Selection.SelectedDevices = nil },
		"negative-set":       func(s *Snapshot) { s.Selection.SelectedDevices.ExcludedDeviceIDs = nil },
	} {
		t.Run(name, func(t *testing.T) {
			transport := newFenceTestTransport()
			collector := newOriginalFenceCollector(transport.source())
			t.Cleanup(collector.close)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := collector.check(ctx, snapshot); err != nil {
				t.Fatal(err)
			}
			changed := cloneSnapshot(snapshot)
			change(&changed)
			assertFenceFailure(t, collector.check(ctx, changed), "fence.check.baseline.changed")
			assertFenceFailure(t, collector.check(ctx, snapshot), "fence.check.baseline.changed")
		})
	}
	transport := newFenceTestTransport()
	collector := newOriginalFenceCollector(transport.source())
	t.Cleanup(collector.close)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	mutable := cloneSnapshot(snapshot)
	if err := collector.check(ctx, mutable); err != nil {
		t.Fatal(err)
	}
	mutable.Selection.SelectedDevices.DeviceIDs[0] = physicalDeviceID(projectionOtherMAC)
	mutable.Devices[0].Addresses[0] = "192.0.2.99"
	transport.push(fenceTestDatagram{raw: frame(neighborFrame(9, "192.0.2.20", projectionClientMAC, 4))})
	if err := collector.check(ctx, snapshot); err != nil {
		t.Fatal("mutable DTO changed collector's retained original", err)
	}
}

func TestSelectedDeviceProjectionCollectorLossAndBoundsStillPermanent(t *testing.T) {
	for name, packet := range map[string]fenceTestDatagram{
		"loss":       {err: at("fence.receive.loss", nil)},
		"truncation": {raw: make([]byte, fenceReceiveBytes+1)},
		"malformed":  {raw: []byte{1, 2, 3}},
	} {
		t.Run(name, func(t *testing.T) {
			o, _, _, transport, review, ctx := selectedTestReview(t)
			transport.push(packet)
			if o.Verify(ctx, review) == nil || !review.state.physicalInvalid {
				t.Fatal("projection muted original transport uncertainty")
			}
			if o.VerifyRetainedIncarnation(ctx, review) == nil {
				t.Fatal("uncertainty granted retained cleanup")
			}
		})
	}
	// A stream of individually irrelevant neighbors is still bounded before
	// the first snapshot has been attached; projection cannot coalesce loss.
	transport := newFenceTestTransport()
	packets := make([]fenceTestDatagram, maxFencePendingDatagrams+1)
	for i := range packets {
		packets[i].raw = frame(neighborFrame(9, "192.0.2.70", projectionOtherMAC, 4))
	}
	transport.push(packets...)
	collector := newOriginalFenceCollector(transport.source())
	t.Cleanup(collector.close)
	waitFenceTest(t, collector.done)
	snapshot, err := captureSelectedTest(context.Background(), selectedTestSelection(), selectedTestNeighbors())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	assertFenceFailure(t, collector.check(ctx, snapshot), "fence.receive.pending-count-limit")
}
