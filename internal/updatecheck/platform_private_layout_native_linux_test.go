//go:build linux

package updatecheck

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestNativePrivateLayoutDoesNotTrustOrChangeForeignSharedVar(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("real foreign owner fixture requires root")
	}
	base := t.TempDir()
	shared := filepath.Join(base, "var")
	private := filepath.Join(base, "razvilka/state/self-update")
	for _, path := range []string{shared, private} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	marker := filepath.Join(shared, "other-app.conf")
	if err := os.WriteFile(marker, []byte("foreign preserved\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(shared, 1001, -1); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(shared)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkOwnedAncestors(private, base); err != nil {
		t.Fatal("foreign shared var blocked the independent private subtree", err)
	}
	if checkOwnedAncestors(filepath.Join(shared, "self-update"), base) == nil {
		t.Fatal("foreign-owned ancestor was trusted")
	}
	after, err := os.Lstat(shared)
	if err != nil || !reflect.DeepEqual(before.Sys(), after.Sys()) || before.Mode() != after.Mode() {
		t.Fatal("checking private ownership changed shared Entware metadata", err)
	}
	if data, err := os.ReadFile(marker); err != nil || string(data) != "foreign preserved\n" {
		t.Fatal("checking private ownership changed foreign bytes", err)
	}
}
