package nativeenrollment

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func marker(id string) []byte {
	b, _ := json.Marshal(map[string]any{"schema": 1, "directory": "attempt-" + strings.Repeat(id, 32), "created_at": "2026-09-01T00:00:00Z", "fresh": false})
	return b
}
func openTest(t *testing.T) *Target {
	t.Helper()
	root := t.TempDir()
	os.Chmod(root, 0o700)
	target, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { target.Close() })
	return target
}
func put(t *testing.T, target *Target, d Document) {
	t.Helper()
	before, err := target.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := target.Save(context.Background(), before, d); err != nil {
		t.Fatal(err)
	}
}
func snap(t *testing.T, d Document) Snapshot {
	t.Helper()
	s, err := SnapshotOf(d)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func TestNativeMergeRetainsUnknownPendingAndAllOriginalBytes(t *testing.T) {
	target := openTest(t)
	d := Document{Schema: 1}
	d.Set("current.json", marker("a"))
	d.Set("pending.json", marker("b"))
	d.Set("attempt-"+strings.Repeat("b", 32)+"/private-key.bin", []byte{0, 1, 0, 255})
	d.Set("attempt-"+strings.Repeat("b", 32)+"/response.private.json", []byte("partial raw response"))
	put(t, target, d)
	before, _ := target.Read(context.Background())
	old := Document{Schema: 1}
	old.Set("current.json", marker("a"))
	if _, err := target.MergeImage(context.Background(), snap(t, old)); !errors.Is(err, ErrConflict) {
		t.Fatal("old image removed pending", err)
	}
	after, _ := target.Read(context.Background())
	if !bytes.Equal(before.Data, after.Data) {
		t.Fatal("refusal modified state")
	}
	merged, err := target.MergeImage(context.Background(), snap(t, d))
	if err != nil || !bytes.Equal(merged.Data, before.Data) {
		t.Fatal("identical image lost binary checkpoint", err)
	}
}
func TestNativeImportPendingWithSavedRegistrationIsStillPending(t *testing.T) {
	target := openTest(t)
	d := Document{Schema: 1}
	d.Set("pending.json", marker("a"))
	d.Set("attempt-"+strings.Repeat("a", 32)+"/registration.private.json", []byte("inert registration"))
	merged, err := target.MergeImage(context.Background(), snap(t, d))
	if err != nil {
		t.Fatal(err)
	}
	result, err := Decode(merged)
	if err != nil || !result.Has("pending.json") {
		t.Fatal("incoming registration wrongly certified request completed")
	}
}
func TestNativeStateBoundsAndPathConfinement(t *testing.T) {
	for _, name := range []string{"../pending.json", "/pending.json", "attempt-" + strings.Repeat("a", 32) + "/../../outside", "attempt-" + strings.Repeat("a", 32) + "/provider/other", "pending.json/child"} {
		d := Document{Schema: 1}
		d.Set(name, []byte("x"))
		if _, err := Encode(d); err == nil {
			t.Fatal("invalid destination accepted")
		}
	}
	d := Document{Schema: 1}
	d.Set("attempt-"+strings.Repeat("a", 32)+"/private-key.bin", make([]byte, 33))
	if _, err := Encode(d); err == nil {
		t.Fatal("oversize key accepted")
	}
	target := openTest(t)
	if _, err := Open(target.path); err == nil {
		t.Fatal("second writer acquired canonical lease")
	}
	if _, err := os.Stat(filepath.Join(target.path, FileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("opening empty target created state")
	}
}
