package devices

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestImportDevicesGuardedRollback(t *testing.T) {
	for _, change := range []string{"none", "edit", "discovery", "write-failure"} {
		t.Run(change, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "devices.json")
			m, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := m.MergeMetadata([]Device{{ID: "test-device", Name: "Before", IPs: []string{"192.168.1.5"}}}); err != nil {
				t.Fatal(err)
			}
			// The undo must not sanitize the captured in-memory discovery state.
			device := m.devices["test-device"]
			device.Discovered, device.State, device.LastSeenAt = true, "reachable", "2026-08-31T12:00:00Z"
			m.devices[device.ID] = device
			before := cloneDevices(m.devices)
			undo, err := m.MergeMetadataWithRollback([]Device{{ID: "test-device", Name: "Imported"}})
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "edit":
				_, err = m.Update("test-device", "Later", "New group")
			case "discovery":
				device := m.devices["test-device"]
				device.IPs = append(device.IPs, "192.168.1.6")
				m.devices[device.ID] = device
			case "write-failure":
				m.Path = filepath.Join(path, "impossible.json")
			}
			if err != nil {
				t.Fatal(err)
			}
			current := cloneDevices(m.devices)
			err = undo()
			if change != "none" {
				if err == nil || !reflect.DeepEqual(current, m.devices) {
					t.Fatal("undo clobbered later device state or lost memory on I/O error")
				}
				if change != "write-failure" {
					return
				}
				m.Path = path
				if err := undo(); err != nil {
					t.Fatal(err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, m.devices) {
				t.Fatal("undo did not restore exact device memory")
			}
			if err := undo(); err != nil {
				t.Fatal(err)
			}
			reloaded, err := Load(path)
			if err != nil || reloaded.devices["test-device"].Name != "Before" {
				t.Fatal("device metadata rollback not persisted")
			}
		})
	}
}
