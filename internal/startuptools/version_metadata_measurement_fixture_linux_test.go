//go:build linux && (amd64 || arm64) && razvilka_native_fixture

package startuptools

import "testing"

func TestNativeVersionMeasurementSurvivesOriginalClose(t *testing.T) {
	l := unitLease(t)
	r := l.review
	noteVersionMetadataAttempt(r)
	noteVersionChildStart(r, 0)
	m := NativeFixtureMeasureVersions(l)
	noteVersionMetadataAttempt(r)
	noteVersionMetadataAttempt(r)
	noteVersionChildStart(r, 1)
	noteVersionChildStart(r, 2)
	if err := l.Close(); err != nil || l.review != nil {
		t.Fatal("original Close did not release review", err)
	}
	if NativeFixtureVersionMetadataCount(l) != 0 || NativeFixtureMeasureVersions(l) != nil {
		t.Fatal("closed Lease supplied a new measurement")
	}
	other := unitLease(t)
	for range 7 {
		noteVersionMetadataAttempt(other.review)
		noteVersionChildStart(other.review, 0)
	}
	metadata, children, err := m.Delta()
	if err != nil || metadata != 2 || children != [3]uint64{0, 1, 1} {
		t.Fatal("original generation lost or replaced", metadata, children, err)
	}
}

func TestNativeVersionMeasurementRejectsMissingOrRegression(t *testing.T) {
	if _, _, err := (*NativeFixtureVersionMeasurement)(nil).Delta(); err == nil {
		t.Fatal("missing measurement accepted")
	}
	for index, name := range []string{"metadata", "iptables", "ip6tables", "ip"} {
		t.Run(name, func(t *testing.T) {
			l := unitLease(t)
			noteVersionMetadataAttempt(l.review)
			for i := range 3 {
				noteVersionChildStart(l.review, i)
			}
			m := NativeFixtureMeasureVersions(l)
			if index == 0 {
				m.counts.metadata.Store(0)
			} else {
				m.counts.children[index-1].Store(0)
			}
			if _, _, err := m.Delta(); err == nil {
				t.Fatal("regressed measurement accepted")
			}
		})
	}
}
