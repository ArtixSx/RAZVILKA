package config

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"
)

func TestServiceRuntimeCommitReturnsItsExactDetachedCASImage(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		t.Run(map[bool]string{false: "caller-mutation", true: "next-writer"}[foreign], func(t *testing.T) {
			store, err := Load(filepath.Join(t.TempDir(), "config.json"))
			if err != nil {
				t.Fatal(err)
			}
			if err = store.SetSafeMode(false); err != nil {
				t.Fatal(err)
			}
			if err = store.UpdateService("telegram", ServiceState{Enabled: true, Route: "direct", Sources: []string{"192.168.1.40/32"}}); err != nil {
				t.Fatal(err)
			}
			if err = store.ApplyDraft(); err != nil {
				t.Fatal(err)
			}
			before := store.Get()
			image, undo, err := store.CommitServiceRuntimeWithImage(true, map[string]string{"telegram": "direct"}, before.Revision)
			if err != nil || undo == nil || image.Revision != before.Revision+1 || image.AppliedRevision != image.Revision || !image.ServiceControl.Stopped || !reflect.DeepEqual(image, store.Get()) {
				t.Fatal("not own exact committed image", err)
			}
			if foreign {
				if err = store.UpdateService("telegram", ServiceState{Enabled: false, Route: "direct"}); err != nil {
					t.Fatal(err)
				}
				if image.Revision != before.Revision+1 || !image.Services["telegram"].Enabled {
					t.Fatal("later writer changed captured image")
				}
				if err = undo(); !errors.Is(err, ErrRevisionChanged) {
					t.Fatal("undo overwrote next writer", err)
				}
			} else {
				image.Services["telegram"] = ServiceState{Route: "changed"}
				image.ServiceControl.SuspendedRoutes["telegram"] = "changed"
				state := image.ServiceControl.SuspendedServices["telegram"]
				state.Sources[0] = "192.168.1.99/32"
				if err = undo(); err != nil || !reflect.DeepEqual(store.Get(), before) {
					t.Fatal("returned image aliases rollback comparison", err)
				}
			}
		})
	}
}
