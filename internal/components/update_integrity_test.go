package components

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type preciseUpdateRunner struct {
	calls         []string
	before, after string
	changed       bool
	failed        string
}

func (r *preciseUpdateRunner) Run(_ context.Context, _ string, args ...string) ([]byte, error) {
	c := strings.Join(args, " ")
	r.calls = append(r.calls, c)
	if c == r.failed {
		return nil, errors.New("test-read-failure")
	}
	switch c {
	case "list-installed":
		v := r.before
		if r.changed {
			v = r.after
		}
		return []byte("sing-box-go - " + v + " - test\n"), nil
	case "list":
		return []byte("sing-box-go - 1.14.1 - test\n"), nil
	case "upgrade sing-box-go":
		r.changed = true
		return []byte("ok"), nil
	}
	return nil, errors.New("unreviewed operation")
}
func TestNamedUpgradeMustAdvanceBeforeReceipt(t *testing.T) {
	for _, version := range []string{"1.14.1", "1.13.3", "1.12.0"} {
		t.Run(version, func(t *testing.T) {
			r := &preciseUpdateRunner{before: "1.13.3", after: version}
			m := &Manager{Opkg: "opkg", RepoDir: t.TempDir(), StateDir: t.TempDir(), Runner: r}
			result, err := m.Apply(context.Background(), "sing-box")
			if (err == nil) != (version == "1.14.1") || result.OK != (version == "1.14.1") {
				t.Fatal(result, err)
			}
			for _, c := range r.calls {
				if c == "upgrade" || strings.HasPrefix(c, "install") {
					t.Fatal(c)
				}
			}
			_, stat := os.Stat(filepath.Join(m.StateDir, "receipts/sing-box.json"))
			if (stat == nil) != (version == "1.14.1") {
				t.Fatal(stat)
			}
		})
	}
}
func TestPartialInventoryNeverInventsMissingOrNewerVersion(t *testing.T) {
	for _, failed := range []string{"list-installed", "list"} {
		r := &preciseUpdateRunner{before: "1.13.3", failed: failed}
		m := &Manager{Opkg: "opkg", Runner: r}
		if v, e := m.List(context.Background(), false); e == nil || len(v) != 0 {
			t.Fatal(failed, v, e)
		}
	}
}
func TestChecksumRejectsDuplicateEvenEqual(t *testing.T) {
	a := strings.Repeat("a", 64)
	b := strings.Repeat("b", 64)
	for _, raw := range []string{a + " file\n" + a + " file", a + " file\n" + b + " file", a + " extra file", "bad file", a + " other"} {
		if _, e := checksumForAsset([]byte(raw), "file"); e == nil {
			t.Fatal(raw)
		}
	}
	if s, e := checksumForAsset([]byte(a+" *file"), "file"); e != nil || s != a {
		t.Fatal(s, e)
	}
}
func TestRepositoryReadCannotClobberExternalDefinition(t *testing.T) {
	m := &Manager{RepoDir: t.TempDir()}
	f := filepath.Join(m.RepoDir, "nfqws2.conf")
	original := []byte("src/gz mine https://example.org/other\n")
	os.WriteFile(f, original, 0600)
	spec, _ := lookup("nfqws2")
	if m.ensureRepository(spec) == nil {
		t.Fatal("overwrote foreign file")
	}
	after, _ := os.ReadFile(f)
	if string(after) != string(original) {
		t.Fatal("clobbered")
	}
}

func TestParentInstallReusesIntegrityVerifiedDependencyWithoutDownload(t *testing.T) {
	bin := t.TempDir()
	target := filepath.Join(bin, "wgcf")
	data := []byte("fixture bytes never executed")
	if err := os.WriteFile(target, data, 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeExternalReceipt(target, "2.2.0", data); err != nil {
		t.Fatal(err)
	}
	r := &fakeRunner{output: map[string]string{"install": "ok"}}
	m := &Manager{Opkg: "opkg", RepoDir: t.TempDir(), StateDir: t.TempDir(), BinDir: bin, Runner: r}
	result, err := m.Apply(context.Background(), "warp-wg")
	if err != nil || !result.OK {
		t.Fatal(result, err)
	}
	for _, args := range r.calls {
		if len(args) > 2 && args[2] != "wireguard-tools" {
			t.Fatal("unexpected dependency upgrade", args)
		}
	}
	after, _ := os.ReadFile(target)
	if string(after) != string(data) {
		t.Fatal("existing dependency replaced")
	}
}
