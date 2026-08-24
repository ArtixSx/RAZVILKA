package engineconfig

import (
	"encoding/json"
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

func TestUsqueKeeneticSessionIsThePrimaryEditableProfile(t *testing.T) {
	for _, spec := range Specs() {
		if spec.ID != "usque" {
			continue
		}
		if len(spec.Files) != 1 || len(spec.Files[0].Paths) == 0 || spec.Files[0].Paths[0] != "/opt/etc/usque/session.conf" || spec.Files[0].Syntax != "json" {
			t.Fatalf("unexpected usque profile specification: %#v", spec.Files)
		}
		return
	}
	t.Fatal("usque engine config specification is missing")
}

func TestGuidedJSONUpdatesNamedBlocksInsideArrays(t *testing.T) {
	input := []byte(`{"log":{"level":"warn"},"inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":1080}],"outbounds":[{"type":"vless","server":"old.example","server_port":443}]}`)
	fields := guidedFields("sing-box", "main")
	updated, err := encodeGuided("json", input, fields, map[string]string{
		"log.level": "info", "inbounds.0.listen_port": "2080", "outbounds.0.server": "new.example", "outbounds.0.server_port": "8443",
	})
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(updated, &document); err != nil {
		t.Fatal(err)
	}
	if got := jsonScalar(getJSONPath(document, "inbounds.0.listen_port")); got != "2080" {
		t.Fatalf("listen_port=%q, document=%s", got, updated)
	}
	if got := jsonScalar(getJSONPath(document, "outbounds.0.server")); got != "new.example" {
		t.Fatalf("server=%q", got)
	}
}

func TestGuidedJSONDoesNotCreateAbsentOptionalEmptyBlock(t *testing.T) {
	updated, err := encodeGuided("json", []byte(`{"log":{"level":"warn"}}`), guidedFields("xray", "main"), map[string]string{"inbounds.0.listen": ""})
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	_ = json.Unmarshal(updated, &document)
	if _, exists := document["inbounds"]; exists {
		t.Fatalf("empty optional block was created: %s", updated)
	}
}

func TestNFQWSGuidedArgumentsRejectShellExecution(t *testing.T) {
	field := GuidedField{ID: "NFQWS_ARGS", Type: "arguments"}
	for _, value := range []string{"--filter-tcp=443; reboot", "$(touch /tmp/pwned)", "`id`", "--foo | sh"} {
		if err := validateGuidedValue(field, value); err == nil {
			t.Fatalf("unsafe arguments accepted: %q", value)
		}
	}
	if err := validateGuidedValue(field, "--filter-tcp=443 --dpi-desync=fake,split2 --new"); err != nil {
		t.Fatalf("valid strategy rejected: %v", err)
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
