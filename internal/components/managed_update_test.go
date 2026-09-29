package components

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// managedRunner simulates opkg for the nfqws2 package: download, upgrade
// (which migrates the configuration, as a CONFIG_VERSION bump would) and a
// forced reinstall of a cached file.
type managedRunner struct {
	installed, available string
	conf                 string
	calls                []string
}

func (r *managedRunner) Run(_ context.Context, _ string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, strings.Join(args, " "))
	switch {
	case len(args) == 1 && args[0] == "list-installed":
		return []byte("nfqws2-keenetic - " + r.installed + " - x\n"), nil
	case len(args) == 1 && args[0] == "list":
		return []byte("nfqws2-keenetic - " + r.available + " - x\n"), nil
	case len(args) == 1 && args[0] == "update":
		return []byte("ok"), nil
	case len(args) == 2 && args[0] == "upgrade":
		r.installed = r.available
		return []byte("upgraded"), os.WriteFile(r.conf, []byte("DEFAULT CONFIG\n"), 0o600)
	case len(args) == 4 && args[0] == "install" && args[1] == "--force-downgrade":
		base := filepath.Base(args[3])
		r.installed = strings.Split(base, "_")[1]
		return []byte("reinstalled"), nil
	}
	return nil, errors.New("unexpected opkg call " + strings.Join(args, " "))
}

func (r *managedRunner) RunIn(_ context.Context, dir, _ string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, "in:"+strings.Join(args, " "))
	if len(args) == 2 && args[0] == "download" {
		return []byte("downloaded"), os.WriteFile(filepath.Join(dir, args[1]+"_"+r.available+"_all.ipk"), []byte("ipk"), 0o600)
	}
	return nil, errors.New("unexpected download")
}

func managedFixture(t *testing.T) (*Manager, *managedRunner, string) {
	t.Helper()
	root := t.TempDir()
	conf := filepath.Join(root, "nfqws2.conf")
	if err := os.WriteFile(conf, []byte("USER STRATEGIES\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	info := filepath.Join(root, "info")
	if err := os.MkdirAll(info, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(info, "nfqws2-keenetic.conffiles"), []byte(conf+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := &managedRunner{installed: "1.3.1", available: "1.3.1", conf: conf}
	m := &Manager{Opkg: "opkg", Runner: r, RepoDir: filepath.Join(root, "repo"), StateDir: filepath.Join(root, "state"), InfoDir: info, Client: offlineReleases()}
	if _, err := m.List(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	return m, r, conf
}

func TestRollbackPackageCachedOnlyForOfferedInstalledVersion(t *testing.T) {
	m, r, _ := managedFixture(t)
	path, err := m.CacheRollbackPackage(context.Background(), "nfqws2")
	if err != nil || !strings.HasSuffix(path, "nfqws2-keenetic_1.3.1_all.ipk") {
		t.Fatalf("cache=%q err=%v", path, err)
	}
	downloads := 0
	for _, call := range r.calls {
		if strings.HasPrefix(call, "in:download") {
			downloads++
		}
	}
	if _, err := m.CacheRollbackPackage(context.Background(), "nfqws2"); err != nil || downloads != 1 {
		t.Fatalf("cached copy downloaded again: %v", err)
	}
	views, _ := m.List(context.Background(), false)
	if v := componentView(t, views, "nfqws2"); !v.ManagedUpdate || !v.RollbackReady {
		t.Fatalf("view does not report rollback readiness: %+v", v)
	}
	r.available = "1.3.2"
	m.lastAvailable = nil
	if _, err := m.List(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if _, err := m.CacheRollbackPackage(context.Background(), "sing-box"); err == nil {
		t.Fatal("unmanaged component cached")
	}
}

func TestManagedUpdateRequiresRollbackCopy(t *testing.T) {
	m, r, _ := managedFixture(t)
	r.available = "1.3.2"
	if _, err := m.List(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ManagedUpdate(context.Background(), "nfqws2", func(context.Context) error { return nil }); !errors.Is(err, ErrRollbackPackageMissing) {
		t.Fatalf("update without rollback copy: %v", err)
	}
	for _, call := range r.calls {
		if strings.HasPrefix(call, "upgrade") {
			t.Fatal("package upgraded without a rollback copy")
		}
	}
}

func TestManagedUpdateKeepsCheckedUpgrade(t *testing.T) {
	m, r, _ := managedFixture(t)
	if _, err := m.CacheRollbackPackage(context.Background(), "nfqws2"); err != nil {
		t.Fatal(err)
	}
	r.available = "1.3.2"
	if _, err := m.List(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	checks := 0
	result, err := m.ManagedUpdate(context.Background(), "nfqws2", func(context.Context) error { checks++; return nil })
	if err != nil || !result.OK || r.installed != "1.3.2" || checks != 1 {
		t.Fatalf("checked update not kept: %+v %v installed=%s checks=%d", result, err, r.installed, checks)
	}
	if m.rollbackPackage(Spec{Package: "nfqws2-keenetic"}, "1.3.2") == "" {
		t.Fatal("new version not cached for the next rollback")
	}
}

// Regression for the package's configuration migration: a failed check
// restores the user's configuration and the previous version.
func TestManagedUpdateRollsBackConfigurationAndVersion(t *testing.T) {
	m, r, conf := managedFixture(t)
	if _, err := m.CacheRollbackPackage(context.Background(), "nfqws2"); err != nil {
		t.Fatal(err)
	}
	r.available = "1.3.2"
	if _, err := m.List(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	checks := 0
	_, err := m.ManagedUpdate(context.Background(), "nfqws2", func(context.Context) error {
		checks++
		data, _ := os.ReadFile(conf)
		if string(data) != "USER STRATEGIES\n" {
			return errors.New("package replaced the configuration")
		}
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "rolled back to 1.3.1") {
		t.Fatalf("failed check not rolled back: %v", err)
	}
	data, _ := os.ReadFile(conf)
	if r.installed != "1.3.1" || string(data) != "USER STRATEGIES\n" || checks != 2 {
		t.Fatalf("installed=%s conf=%q checks=%d", r.installed, data, checks)
	}
	found := false
	for _, call := range r.calls {
		if strings.HasPrefix(call, "install --force-downgrade --force-reinstall ") && strings.HasSuffix(call, "nfqws2-keenetic_1.3.1_all.ipk") {
			found = true
		}
	}
	if !found {
		t.Fatalf("previous version not reinstalled: %v", r.calls)
	}
}
