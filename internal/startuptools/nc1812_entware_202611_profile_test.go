package startuptools

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestNC1812Entware202611FixedPackageClosure(t *testing.T) {
	p := nc1812Entware202611Profile()
	images := map[string]string{p.main: p.mainSHA}
	if len(p.pins) != 11 || len(p.extensionExpectations) != 30 {
		t.Fatal("incomplete fixed package closure")
	}
	for path, hashes := range p.pins {
		if len(hashes) != 1 {
			t.Fatal("alternative package bytes", path)
		}
		images[path] = hashes[0]
	}
	links := 0
	for name, e := range p.extensionExpectations {
		if e.link != "" {
			links++
			if name != "libxt_NOTRACK.so" && name != "libxt_state.so" {
				t.Fatal("unexpected package alias")
			}
		}
		if old, exists := images[e.target]; exists && old != e.sha256 {
			t.Fatal("conflicting image pins")
		}
		images[e.target] = e.sha256
	}
	if links != 2 || len(images) != 40 {
		t.Fatal("wrong unique image count")
	}
	var manifest strings.Builder
	for _, path := range sortedKeys(images) {
		raw, err := hex.DecodeString(images[path])
		if err != nil || len(raw) != sha256.Size {
			t.Fatal("invalid pin")
		}
		fmt.Fprintf(&manifest, "%s %s\n", path, images[path])
	}
	// Independently computed from the reviewed package manifest, not the
	// constructors: SHA256(sorted canonical path + space + hash + newline).
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(manifest.String()))); got != "ba2e2a3d66e3a6471bdf6cc100d42f25a6280c747255fb1d0eee44be42a11fdf" {
		t.Fatal("package source pins drifted", got)
	}
	if p.extensionExpectations["libxt_NOTRACK.so"].link != "libxt_CT.so" || p.extensionExpectations["libxt_state.so"].link != "libxt_conntrack.so" || p.extensionExpectations["libxt_DHCPMAC.so"].sha256 == p.extensionExpectations["libxt_dhcpmac.so"].sha256 {
		t.Fatal("literal aliases or case-sensitive package members changed")
	}
}

func TestNC1812Entware202611ProfileFamilyAndOldFacts(t *testing.T) {
	base := nc1812Entware202611Profile()
	old := stockProfile()
	if base.arch != old.arch || base.version != old.version || !base.stock || base.aliases != old.aliases || base.main != old.main || base.loader != old.loader || base.extension != old.extension || !reflect.DeepEqual(base.environment(), old.environment()) {
		t.Fatal("fixed vendor paths/environment changed")
	}
	for path, oldHashes := range old.pins {
		for _, hash := range oldHashes {
			if len(base.pins[path]) != 1 || base.pins[path][0] == hash {
				t.Fatal("old backend package bytes admitted in new closure", path)
			}
		}
	}
	seen := map[string]bool{}
	for _, p := range []profile{base, nc1812Entware202611PolicyProfile(), nc1812Entware202611WGProfile("wireguard"), nc1812Entware202611WGProfile("amneziawg"), nc1812Entware202611ManagedListProfile()} {
		if !strings.HasPrefix(p.id, "stock-nc1812-entware-202611-") || seen[p.id] || p.classicSaveABI || staticVersionProfile(p) {
			t.Fatal("new profile identity/ABI/fact changed", p.id)
		}
		seen[p.id] = true
		if !reflect.DeepEqual(p.pins, base.pins) || !reflect.DeepEqual(p.extensionExpectations, base.extensionExpectations) {
			t.Fatal("derived closure differs")
		}
		if p.id != base.id && (p.ipAlias != "/opt/sbin/ip" || p.ipMain != "/opt/libexec/ip-full" || p.ipSHA != "2a83e9832ad7a3f96f6bcd25e7f90afb80a1a7ee4b680f1a3687e29848c5c2d3" || p.ipVersion != "ip utility, iproute2-ss4.4.0-11-entware\n") {
			t.Fatal("fixed IP contract changed")
		}
		if p.wgEngine != "" {
			if p.wgAliases != [2]string{"/opt/bin/wg", "/opt/sbin/awg"} {
				t.Fatal("WG discovery introduced")
			}
			if _, err := wgRequiredEntry(p.wgEngine); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := wgRequiredEntry(nc1812Entware202611WGProfile("unknown").wgEngine); err == nil {
		t.Fatal("unknown engine admitted")
	}
	for _, p := range []profile{old, stockPolicyProfile(), wgProfile(true, "wireguard"), managedListProfile(), ubuntuProfile()} {
		if p.extensionExpectations != nil || !staticVersionProfile(p) {
			t.Fatal("old profile behavior changed", p.id)
		}
	}
	if old.mainSHA != "966a3efa461f9f42a9f48dfb8c0bc8b5ef858aac1130adf5f84e3724b3ec2acf" || stockPolicyProfile().ipSHA != "cce8d3fafdf0c1393878adb53e596c16788b37f8ecdd0d0ac25c4a751b0b7b88" {
		t.Fatal("old pins changed")
	}
	// Even old byte pins cannot extend the old static fact to a new closure.
	old.extensionExpectations = map[string]extensionExpectation{}
	if staticVersionProfile(old) {
		t.Fatal("empty explicit closure admitted static fact")
	}
}

func TestNC1812Entware202611IndependentAndClonedData(t *testing.T) {
	first := nc1812Entware202611ManagedListProfile()
	before := nc1812Entware202611ManagedListProfile()
	cloned := cloneVersionProfile(first)
	if !reflect.DeepEqual(first, cloned) {
		t.Fatal("clone changed profile")
	}
	cloned.extensionExpectations["libxt_CT.so"] = extensionExpectation{}
	cloned.pins["/opt/lib/libiptext.so"][0] = "changed"
	cloned.libraries[0] = "/changed"
	if !reflect.DeepEqual(first, before) {
		t.Fatal("clone mutation reached source")
	}
	delete(first.extensionExpectations, "libxt_CT.so")
	first.pins["/opt/lib/libiptext.so"][0] = "changed"
	if !reflect.DeepEqual(before, nc1812Entware202611ManagedListProfile()) {
		t.Fatal("constructor shares mutable package data")
	}
}
