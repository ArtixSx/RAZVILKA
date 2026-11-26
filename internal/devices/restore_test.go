package devices

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

func TestRegistryCloseRefusesCorruptCacheAndCancelledSession(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.json")
	m := loadRegistry(t, path)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if s, err := m.BeginRestore(ctx); !errors.Is(err, restorejournal.ErrAborted) {
		if s != nil {
			s.Close()
		}
		t.Fatal("cancelled session accepted")
	}
	s, err := m.BeginRestore(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Noncooperating external writer. Close must fence the old cache on a
	// failed reload, not allow it to overwrite the unknown file afterwards.
	if err := os.WriteFile(path, []byte("corrupt-external-file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); !errors.Is(err, restorejournal.ErrRecovery) {
		t.Fatal("bad reload accepted")
	}
	if !m.writeUncertain {
		t.Fatal("cache not fenced")
	}
	if err := m.MergeMetadata(nil); !errors.Is(err, restorejournal.ErrRecovery) {
		t.Fatal("uncertain cache wrote")
	}
	if _, err := m.ListWithStatus(context.Background()); !errors.Is(err, restorejournal.ErrRecovery) {
		t.Fatal("uncertain state hidden on empty discovery")
	}
	data, _ := os.ReadFile(path)
	if string(data) != "corrupt-external-file" {
		t.Fatal("unknown file overwritten")
	}
}

func loadRegistry(t *testing.T, path string) *Manager {
	t.Helper()
	m, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	m.Runner = nil
	m.ARPPaths = nil
	m.LeasePaths = nil
	return m
}
func seedRegistry(t *testing.T, path string) *Manager {
	t.Helper()
	m := loadRegistry(t, path)
	if err := m.MergeMetadata([]Device{{ID: "test-device", Name: "Before", IPs: []string{"192.168.1.5"}}}); err != nil {
		t.Fatal(err)
	}
	return m
}
func TestDeviceStaleWritersAndUndo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	first := seedRegistry(t, path)
	stale := loadRegistry(t, path)
	old := cloneDevices(stale.devices)
	if _, err := first.Update("test-device", "Later", "Group"); err != nil {
		t.Fatal(err)
	}
	for _, write := range []func() error{
		func() error { _, err := stale.Update("test-device", "Stale", ""); return err },
		func() error { return stale.MergeMetadata([]Device{{ID: "other-device"}}) },
		func() error { return stale.ReplaceAll(nil) },
	} {
		if err := write(); !errors.Is(err, restorejournal.ErrConflict) {
			t.Fatalf("stale write: %v", err)
		}
		if !reflect.DeepEqual(old, stale.devices) {
			t.Fatal("failed write changed cache")
		}
	}
	if s, err := stale.BeginRestore(context.Background()); !errors.Is(err, restorejournal.ErrConflict) {
		if s != nil {
			s.Close()
		}
		t.Fatal("stale restore")
	}
	undo, err := first.MergeMetadataWithRollback([]Device{{ID: "test-device", Name: "Imported"}})
	if err != nil {
		t.Fatal(err)
	}
	other := loadRegistry(t, path)
	if _, err := other.Update("test-device", "Third", ""); err != nil {
		t.Fatal(err)
	}
	if err := undo(); !errors.Is(err, restorejournal.ErrConflict) {
		t.Fatal("undo overwrote external change")
	}
	if loadRegistry(t, path).devices["test-device"].Name != "Third" {
		t.Fatal("new name lost")
	}
}
func TestDevicesRestoreKeepsDiscoveryOnlyOnRollback(t *testing.T) {
	ctx := context.Background()
	for _, rollback := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "devices.json")
		m := seedRegistry(t, path)
		live := m.devices["test-device"]
		live.Discovered = true
		live.State = "reachable"
		live.LastSeenAt = "2026-08-31T12:00:00Z"
		m.devices[live.ID] = live
		old := cloneDevices(m.devices)
		other := loadRegistry(t, path)
		s, err := m.BeginRestore(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if second, err := m.BeginRestore(ctx); !errors.Is(err, restorejournal.ErrBusy) {
			if second != nil {
				second.Close()
			}
			t.Fatal("second restore")
		}
		if _, err := other.Update("test-device", "Third", ""); !errors.Is(err, restorejournal.ErrBusy) {
			t.Fatal("writer bypassed lease")
		}
		before, _ := s.Read(ctx)
		after, err := s.MergeImage(ctx, []Device{{ID: "test-device", Name: "Imported", IPs: []string{"192.168.1.6"}}, {ID: "new-device", Name: "New"}})
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := os.ReadFile(path)
		if !bytes.Equal(raw, before.Data) {
			t.Fatal("builder wrote")
		}
		if err := s.CompareAndSwap(ctx, before, after); err != nil {
			t.Fatal(err)
		}
		if rollback {
			if err := s.CompareAndSwap(ctx, after, before); err != nil {
				t.Fatal(err)
			}
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Read(ctx); !errors.Is(err, restorejournal.ErrUnavailable) {
			t.Fatal("closed session read")
		}
		got := m.devices["test-device"]
		if rollback {
			if !reflect.DeepEqual(old, m.devices) {
				t.Fatal("rollback lost discovery evidence")
			}
		} else if got.Discovered || got.LastSeenAt != "" || got.State != "offline" || got.Name != "Imported" || len(got.IPs) != 2 || len(m.devices) != 2 {
			t.Fatal("commit falsely claims live state or lost metadata")
		}
		if _, err := m.Update("test-device", "Next", ""); err != nil {
			t.Fatal(err)
		}
	}
}
func TestDeviceDiscoveryFailureIsReportedAndRetried(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	m := loadRegistry(t, path)
	m.IPCommand = "ip"
	m.Runner = fakeRunner{output: "192.168.1.25 dev br0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n"}
	target, err := OpenRestoreTarget(path)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := m.ListWithStatus(context.Background())
	if !errors.Is(err, restorejournal.ErrBusy) || len(rows) != 1 || !rows[0].Discovered {
		t.Fatal("failure hidden or observations lost")
	}
	if len(m.Known()) != 0 {
		t.Fatal("unpersisted observation became confirmed metadata")
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	rows, err = m.ListWithStatus(context.Background())
	if err != nil || len(rows) != 1 || len(m.Known()) != 1 || len(loadRegistry(t, path).Known()) != 1 {
		t.Fatal("discovery not retried")
	}
}
func TestDeviceDiscoveryCapacityDoesNotDesyncCache(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	m := loadRegistry(t, path)
	for i := 0; i < maxDevices; i++ {
		id := deviceID("", strings.Repeat("a", i+1))
		m.devices[id] = Device{ID: id, IPs: []string{"192.168.1.5"}}
	}
	if err := m.saveLocked(); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	old := cloneDevices(m.devices)
	m.IPCommand = "ip"
	m.Runner = fakeRunner{output: "192.168.1.25 dev br0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n"}
	if _, err := m.ListWithStatus(context.Background()); err == nil {
		t.Fatal("capacity overflow hidden")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) || !reflect.DeepEqual(old, m.devices) {
		t.Fatal("overflow changed registry")
	}
}
func TestDeviceTargetValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	_ = loadRegistry(t, path)
	target, err := OpenRestoreTarget(path)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	ctx := context.Background()
	before, _ := target.Read(ctx)
	for _, data := range []string{"", "null", "{", `{"schema":99}`, `{"schema":1,"devices":{"?":{}}}`, `{"schema":1,"devices":{"test-device":{"name":"bad\nname"}}}`, strings.Repeat(" ", restorejournal.MaxImageBytes+1)} {
		if err := target.CompareAndSwap(ctx, before, restorejournal.Image{Exists: true, Data: []byte(data)}); !errors.Is(err, restorejournal.ErrInvalid) {
			t.Fatal("invalid image accepted")
		}
	}
	if err := target.CompareAndSwap(ctx, before, restorejournal.Image{}); !errors.Is(err, restorejournal.ErrInvalid) {
		t.Fatal("deletion accepted")
	}
	after, _ := target.Read(ctx)
	if !bytes.Equal(before.Data, after.Data) {
		t.Fatal("invalid write")
	}
}

type failingPersist struct {
	image   restorejournal.Image
	replace bool
}

func (f *failingPersist) Read(context.Context) (restorejournal.Image, error) { return f.image, nil }
func (f *failingPersist) CompareAndSwap(_ context.Context, _, after restorejournal.Image) error {
	if f.replace {
		f.image = after
	}
	return restorejournal.ErrRecovery
}
func TestDeviceAmbiguousWriteFencesCache(t *testing.T) {
	for _, replace := range []bool{false, true} {
		m := seedRegistry(t, filepath.Join(t.TempDir(), "devices.json"))
		before := append([]byte(nil), m.diskImage.Data...)
		f := &failingPersist{image: m.diskImage, replace: replace}
		err := m.persistLocked(f, append(append([]byte(nil), before...), '\n'))
		if replace {
			if !errors.Is(err, restorejournal.ErrRecovery) || !m.writeUncertain {
				t.Fatal("ambiguous result accepted")
			}
			if _, err := m.Update("test-device", "Next", ""); !errors.Is(err, restorejournal.ErrRecovery) {
				t.Fatal("uncertain cache wrote")
			}
			if s, err := m.BeginRestore(context.Background()); !errors.Is(err, restorejournal.ErrRecovery) {
				if s != nil {
					s.Close()
				}
				t.Fatal("uncertain restore")
			}
		} else if !errors.Is(err, restorejournal.ErrAborted) || m.writeUncertain {
			t.Fatal("unchanged result misclassified")
		}
		if !bytes.Equal(before, m.diskImage.Data) {
			t.Fatal("expected snapshot changed")
		}
	}
}
