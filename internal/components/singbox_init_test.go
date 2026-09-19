package components

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Captured from Entware sing-box-go 1.13.3-2. Keep this independent of the
// production matcher so an accidental matcher change cannot change the fixture.
const singBoxInitFixture = `#!/bin/sh

ENABLED=yes
PROCS=sing-box
ARGS="run -D /opt/var/lib/$PROCS -C /opt/etc/$PROCS"
PREARGS=""
DESC=$PROCS
PATH=/opt/sbin:/opt/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

. /opt/etc/init.d/rc.func
`

type singBoxPackageRunner struct {
	initDir   string
	installed string
	calls     []string
	unpack    func() error
	fail      bool
}

func (r *singBoxPackageRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	if name != "opkg" {
		return nil, errors.New("attempted to execute an init script or process command")
	}
	command := strings.Join(args, " ")
	r.calls = append(r.calls, command)
	switch command {
	case "list-installed":
		if r.installed == "" {
			return nil, nil
		}
		return []byte("sing-box-go - " + r.installed + " - fixture\n"), nil
	case "list":
		return []byte("sing-box-go - 1.14.0-2 - fixture\n"), nil
	case "install sing-box-go", "upgrade sing-box-go":
		if r.unpack != nil {
			if err := r.unpack(); err != nil {
				return nil, err
			}
		} else if err := os.WriteFile(filepath.Join(r.initDir, singBoxInitName), []byte(singBoxInitFixture), 0755); err != nil {
			return nil, err
		}
		r.installed = "1.14.0-2"
		if r.fail {
			return nil, errors.New("interrupted after unpacking")
		}
		return []byte("fixture installed"), nil
	default:
		return nil, errors.New("unexpected package operation")
	}
}

func singBoxManagerFixture(t *testing.T) (*Manager, *singBoxPackageRunner) {
	t.Helper()
	dir := t.TempDir()
	r := &singBoxPackageRunner{initDir: dir}
	return &Manager{Opkg: "opkg", Runner: r, InitDir: dir, StateDir: t.TempDir()}, r
}

func TestSingBoxFreshAndUpgradeDisableOnlyPackageAutostart(t *testing.T) {
	for _, previous := range []string{"", "yes", "no"} {
		t.Run("previous="+previous, func(t *testing.T) {
			m, r := singBoxManagerFixture(t)
			if previous != "" {
				r.installed = "1.13.3-2"
				if err := os.WriteFile(filepath.Join(m.InitDir, singBoxInitName), []byte(strings.Replace(singBoxInitFixture, "ENABLED=yes", "ENABLED="+previous, 1)), 0755); err != nil {
					t.Fatal(err)
				}
			}
			foreign := filepath.Join(m.InitDir, "S99unrelated")
			if err := os.WriteFile(foreign, []byte("unrelated process and config"), 0755); err != nil {
				t.Fatal(err)
			}
			result, err := m.Apply(context.Background(), "sing-box")
			if err != nil || !result.OK {
				t.Fatal(result, err)
			}
			got, err := os.ReadFile(filepath.Join(m.InitDir, singBoxInitName))
			want := strings.Replace(singBoxInitFixture, "ENABLED=yes", "ENABLED=no", 1)
			if err != nil || string(got) != want {
				t.Fatal("package autostart not disabled", err)
			}
			if data, err := os.ReadFile(foreign); err != nil || string(data) != "unrelated process and config" {
				t.Fatal("unrelated file changed", err)
			}
			if _, err := os.Stat(filepath.Join(m.StateDir, "receipts", "sing-box.json")); err != nil {
				t.Fatal("verified receipt missing", err)
			}
			if runtime.GOOS != "windows" {
				info, _ := os.Stat(filepath.Join(m.InitDir, singBoxInitName))
				if info.Mode().Perm() != 0755 {
					t.Fatal("package init permissions changed")
				}
			}
			for _, call := range r.calls {
				if call != "list-installed" && call != "install sing-box-go" && call != "upgrade sing-box-go" {
					t.Fatalf("process/config side effect: %s", call)
				}
			}
		})
	}
}

func TestSingBoxPartialPackageFailureStillDisablesAutostart(t *testing.T) {
	m, r := singBoxManagerFixture(t)
	r.fail = true
	result, err := m.Apply(context.Background(), "sing-box")
	if err == nil || result.OK || !strings.Contains(err.Error(), "interrupted after unpacking") {
		t.Fatal(result, err)
	}
	data, err := os.ReadFile(filepath.Join(m.InitDir, singBoxInitName))
	if err != nil || !strings.Contains(string(data), "ENABLED=no") {
		t.Fatal("failed operation left autostart enabled", err)
	}
	if _, err := os.Stat(filepath.Join(m.StateDir, "receipts", "sing-box.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed package operation gained receipt", err)
	}
}

func TestSingBoxRefusesForeignInitBeforePackageMutation(t *testing.T) {
	for _, scenario := range []string{"custom", "orphan", "alternative", "symlink", "directory"} {
		t.Run(scenario, func(t *testing.T) {
			m, r := singBoxManagerFixture(t)
			r.installed = "1.13.3-2"
			path := filepath.Join(m.InitDir, singBoxInitName)
			var before []byte
			switch scenario {
			case "custom":
				before = []byte(singBoxInitFixture + "echo custom command\n")
			case "orphan":
				r.installed = ""
				before = []byte(singBoxInitFixture)
			case "alternative":
				path = filepath.Join(m.InitDir, "S51sing-box")
				before = []byte("foreign init")
			case "directory":
				if err := os.Mkdir(path, 0755); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				target := filepath.Join(t.TempDir(), "foreign")
				if err := os.WriteFile(target, []byte(singBoxInitFixture), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
			}
			if before != nil {
				if err := os.WriteFile(path, before, 0755); err != nil {
					t.Fatal(err)
				}
			}
			result, err := m.Apply(context.Background(), "sing-box")
			if err == nil || result.OK {
				t.Fatal("foreign init accepted", result, err)
			}
			if len(r.calls) != 1 || r.calls[0] != "list-installed" {
				t.Fatal("opkg mutated before ownership was checked", r.calls)
			}
			if before != nil {
				data, _ := os.ReadFile(path)
				if string(data) != string(before) {
					t.Fatal("foreign init overwritten")
				}
			}
		})
	}
}

func TestSingBoxInitVerificationFailureHasNoSuccessReceipt(t *testing.T) {
	for _, scenario := range []string{"missing", "custom", "directory"} {
		t.Run(scenario, func(t *testing.T) {
			m, r := singBoxManagerFixture(t)
			path := filepath.Join(m.InitDir, singBoxInitName)
			r.unpack = func() error {
				switch scenario {
				case "missing":
					return nil
				case "custom":
					return os.WriteFile(path, []byte(singBoxInitFixture+"ENABLED=yes\n"), 0755)
				default:
					return os.Mkdir(path, 0755)
				}
			}
			result, err := m.Apply(context.Background(), "sing-box")
			if err == nil || result.OK || !strings.Contains(err.Error(), "autostart could not be disabled") {
				t.Fatal("unverified package treated as success", result, err)
			}
			if _, err := os.Stat(filepath.Join(m.StateDir, "receipts", "sing-box.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("unsafe package received success receipt", err)
			}
		})
	}
}

func TestSingBoxPlanExplainsAutostartAndBlocksCustomScript(t *testing.T) {
	m, r := singBoxManagerFixture(t)
	plan, err := m.Plan(context.Background(), "sing-box", "install", false)
	if err != nil || !plan.Ready || !strings.Contains(plan.Steps[5].Summary, "автозапуск") {
		t.Fatal(plan, err)
	}
	if _, err := os.Stat(filepath.Join(m.InitDir, singBoxInitName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("plan wrote an init script", err)
	}
	r.installed = "1.13.3-2"
	if err := os.WriteFile(filepath.Join(m.InitDir, singBoxInitName), []byte("custom"), 0755); err != nil {
		t.Fatal(err)
	}
	plan, err = m.Plan(context.Background(), "sing-box", "update", false)
	if err != nil || plan.Ready {
		t.Fatal(plan, err)
	}
	found := false
	for _, issue := range plan.Blockers {
		found = found || issue.Code == "PACKAGE_AUTOSTART_CONFLICT"
	}
	if !found {
		t.Fatal("missing actionable ownership blocker", plan)
	}
}
