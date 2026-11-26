package dataplane

import (
	"path/filepath"
	"testing"
)

// Structural coordinate regression only. Real CheckCurrent still requires the
// original registry, provider, held tools and actual DNS owner on every use.
func TestMihomoSameBootSourceCoordinatesDistinguishDNSFromConfiguration(t *testing.T) {
	root := filepath.Join(t.TempDir(), "dataplane")
	m := New(root)
	r := &RuntimeInactivitySourceReview{manager: m, root: root, settings: filepath.Join(t.TempDir(), "dns", "state.json")}
	r.self = r
	i := &mihomoSameBootInputs{statePath: root, configPath: filepath.Join(t.TempDir(), "config.json")}
	o := &mihomoSameBootCleanup{inputs: i, read: &mihomoColdReadRunner{original: r}}
	if !o.sourceCoordinatesCurrent() {
		t.Fatal("DNS settings mistaken for configuration input")
	}
	r.root = filepath.Join(root, "foreign")
	if o.sourceCoordinatesCurrent() {
		t.Fatal("foreign source root accepted")
	}
	r.root = root
	m.StateRoot = filepath.Join(root, "foreign")
	if o.sourceCoordinatesCurrent() {
		t.Fatal("changed manager root accepted")
	}
	m.StateRoot = root
	copied := *r
	o.read.original = &copied
	if o.sourceCoordinatesCurrent() {
		t.Fatal("copied original source accepted")
	}
	o.read.original = nil
	if o.sourceCoordinatesCurrent() {
		t.Fatal("missing source accepted")
	}
}
