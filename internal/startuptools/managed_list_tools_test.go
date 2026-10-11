package startuptools

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestManagedListFixedProfileRetainsOriginalPolicyDeployment(t *testing.T) {
	p := managedListProfile()
	policy := stockPolicyProfile()
	if p.wgEngine != managedListWGProfile || p.wgAliases != [2]string{"/opt/bin/wg", "/opt/sbin/awg"} {
		t.Fatal("managed list changed fixed native aliases")
	}
	p.id, p.wgEngine, p.wgAliases = policy.id, policy.wgEngine, policy.wgAliases
	if !reflect.DeepEqual(p, policy) {
		t.Fatal("managed WG capture replaced policy/IP/xtables deployment")
	}
	for _, test := range []struct {
		mode string
		want int
	}{{"wireguard", 0}, {"amneziawg", 1}, {managedListWGProfile, -1}} {
		if got, err := wgRequiredEntry(test.mode); err != nil || got != test.want {
			t.Fatal("required primary changed", test.mode, got, err)
		}
	}
	if _, err := wgRequiredEntry("from-PATH"); err == nil {
		t.Fatal("unknown capture profile admitted")
	}
}

// Portable descriptor/absence model only. The production Linux factory still
// owns protected ELF/dependencies, actual version execution and Provider proof.
// No fixture bytes are executed or offered as native network/tool evidence.
func managedListDescriptorFixture(t *testing.T, present [2]bool) *Lease {
	t.Helper()
	l := unitLease(t)
	p := managedListProfile()
	dir := t.TempDir()
	// Join descriptor Close before TempDir cleanup on Windows.
	t.Cleanup(func() { _ = l.Close() })
	p.wgAliases = [2]string{filepath.Join(dir, "wg"), filepath.Join(dir, "awg")}
	l.profile, l.review.profile = p, p
	l.review.absent = map[string]bool{}
	l.review.ipEntry = &heldImage{path: p.ipAlias}
	for i, path := range p.wgAliases {
		if !present[i] {
			l.review.absent[path] = true
			continue
		}
		if err := os.WriteFile(path, []byte("private descriptor comparison model only"), 0600); err != nil {
			t.Fatal(err)
		}
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			file.Close()
			t.Fatal(err)
		}
		image := &heldImage{path: path, file: file, info: info}
		l.review.wgEntry[i], l.review.images[path] = image, image
	}
	return l
}

func TestManagedListMissingPrimaryAndSecondaryRefuseOnlyTheirEngine(t *testing.T) {
	for _, present := range [][2]bool{{false, false}, {true, false}, {false, true}, {true, true}} {
		l := managedListDescriptorFixture(t, present)
		if _, err := l.InventoryTools(); err != nil {
			t.Fatal("WG absence removed same-lease inventory descriptor", present, err)
		}
		if _, _, err := l.PolicyRuntimeTools(); err != nil {
			t.Fatal("WG absence removed same-lease policy descriptor", present, err)
		}
		for i, engine := range []string{"wireguard", "amneziawg"} {
			tools, err := l.WGCommandTools(engine)
			if !present[i] {
				if !errors.Is(err, ErrUnknown) {
					t.Fatal("missing primary issued engine descriptor", present, engine, err)
				}
				continue
			}
			if err != nil {
				t.Fatal("held primary refused due only to missing secondary", present, engine, err)
			}
			if tools.Runner.(*wgRunner).lease != l || tools.ReviewSHA256 != l.digest || tools.Provider != l.provider {
				t.Fatal("engine descriptor escaped original shared lease")
			}
			for j, value := range []string{tools.WG, tools.AWG} {
				if present[j] && value != l.profile.wgAliases[j] || !present[j] && value != "" {
					t.Fatal("missing tool acquired fallback alias", present, engine, value)
				}
			}
		}
	}
}

func TestManagedListNewAbsentPathOccupantRevokesOtherEngineDescriptor(t *testing.T) {
	for _, missing := range []int{0, 1} {
		present := [2]bool{true, true}
		present[missing] = false
		l := managedListDescriptorFixture(t, present)
		engine := []string{"wireguard", "amneziawg"}[1-missing]
		if _, err := l.WGCommandTools(engine); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(l.profile.wgAliases[missing], []byte("new unreviewed occupant"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := l.review.wgAbsencesCurrent(context.Background()); !errors.Is(err, ErrUnknown) {
			t.Fatal("new absent-path occupant preserved closure", missing, err)
		}
		for _, selected := range []string{"wireguard", "amneziawg"} {
			if _, err := l.WGCommandTools(selected); !errors.Is(err, ErrUnknown) {
				t.Fatal("changed absent slot issued an engine descriptor", missing, selected, err)
			}
		}
	}
}

func TestManagedListUnissuedAbsenceAndForeignProfileRefuse(t *testing.T) {
	l := managedListDescriptorFixture(t, [2]bool{true, false})
	delete(l.review.absent, l.profile.wgAliases[1])
	if _, err := l.WGCommandTools("wireguard"); !errors.Is(err, ErrUnknown) {
		t.Fatal("missing secondary without original absence issued descriptor", err)
	}
	l.review.absent[l.profile.wgAliases[1]] = true
	l.review.profile.wgAliases[1] = filepath.Join(t.TempDir(), "another-awg")
	if _, err := l.WGCommandTools("wireguard"); !errors.Is(err, ErrUnknown) {
		t.Fatal("foreign capture profile issued descriptor", err)
	}
}
