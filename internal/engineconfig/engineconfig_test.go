package engineconfig

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStageReadValidateDiscard(t *testing.T) {
	tmp := t.TempDir()
	m := New(filepath.Join(tmp, "stage"), filepath.Join(tmp, "backup"))
	got, err := m.Stage("nfqws2", "main", "NFQWS_ARGS=\"--foo\"\n")
	if err != nil {
		t.Fatal(err)
	}
	if got.Source != "staged" {
		t.Fatalf("source=%s", got.Source)
	}
	read, err := m.Read("nfqws2", "main")
	if err != nil {
		t.Fatal(err)
	}
	if read.Content == "" || read.Source != "staged" {
		t.Fatalf("unexpected read: %+v", read)
	}
	v := m.Validate("nfqws2", "main")
	if !v.OK {
		t.Fatalf("validation failed: %+v", v)
	}
	if err := m.Discard("nfqws2", "main"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(tmp, "stage", "nfqws2", "main.draft")); !os.IsNotExist(err) {
		t.Fatalf("draft still exists: %v", err)
	}
}

func TestSensitiveConfigIsNotReturned(t *testing.T) {
	tmp := t.TempDir()
	m := New(filepath.Join(tmp, "stage"), filepath.Join(tmp, "backup"))
	got, err := m.Stage("warp-wg", "main", "[Interface]\nPrivateKey = secret\n")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Sensitive || got.Content != "" {
		t.Fatalf("secret leaked: %+v", got)
	}
	read, err := m.Read("warp-wg", "main")
	if err != nil {
		t.Fatal(err)
	}
	if read.Content != "" || !read.Sensitive {
		t.Fatalf("secret leaked on read: %+v", read)
	}
	v := m.Validate("warp-wg", "main")
	if !v.OK {
		t.Fatalf("ini validation failed: %+v", v)
	}
}
