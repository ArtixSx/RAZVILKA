package engineconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
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

func TestConcurrentStageIsAtomic(t *testing.T) {
	tmp := t.TempDir()
	m := New(filepath.Join(tmp, "stage"), filepath.Join(tmp, "backup"))

	const writers = 32
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := m.Stage("nfqws2", "user-list", fmt.Sprintf("service-%02d.example\n", i))
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	read, err := m.Read("nfqws2", "user-list")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(read.Content, "service-") || !strings.HasSuffix(read.Content, ".example\n") {
		t.Fatalf("partial staged content: %q", read.Content)
	}
	entries, err := os.ReadDir(filepath.Join(tmp, "stage", "nfqws2"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "user-list.draft" {
		t.Fatalf("temporary staging files leaked: %+v", entries)
	}
}

func TestRunNativeTimeout(t *testing.T) {
	t.Setenv("RAZVILKA_VALIDATOR_HELPER", "1")
	v := runNative(
		Validation{OK: true, EngineID: "test", FileID: "main"},
		25*time.Millisecond,
		os.Args[0],
		"-test.run=TestNativeValidatorHelper",
	)
	if v.OK || !v.Native || !strings.Contains(v.Output, "timed out") {
		t.Fatalf("unexpected timeout result: %+v", v)
	}
}

func TestNativeValidatorHelper(t *testing.T) {
	if os.Getenv("RAZVILKA_VALIDATOR_HELPER") != "1" {
		return
	}
	time.Sleep(2 * time.Second)
	os.Exit(0)
}
