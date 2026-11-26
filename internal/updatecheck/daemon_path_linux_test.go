//go:build linux

package updatecheck

import (
	"os"
	"path/filepath"
	"testing"
)

func daemonPathFixture(t *testing.T) (string, string, string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("native root-owned daemon alias fixture requires root")
	}
	base := t.TempDir()
	alias := filepath.Join(base, "sbin/start-stop-daemon")
	target := filepath.Join(base, "bin/busybox")
	for _, p := range []string{filepath.Dir(alias), filepath.Dir(target)} {
		if err := os.MkdirAll(p, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(target, []byte("owned applet fixture"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, alias); err != nil {
		t.Fatal(err)
	}
	return base, alias, target
}

func TestNativeEntwareDaemonAliasReviewKeepsGenericGuardClosed(t *testing.T) {
	base, alias, target := daemonPathFixture(t)
	if checkOwnedAncestors(alias, base) == nil {
		t.Fatal("generic symlink guard was weakened")
	}
	check, err := reviewOwnedDaemonPath(alias, target, base)
	if err != nil || check == nil || check() != nil {
		t.Fatal("exact owned Entware alias refused", err)
	}
	raw, err := os.Readlink(alias)
	if err != nil || raw != target {
		t.Fatal("review modified alias")
	}
}

func TestNativeEntwareDaemonAliasReviewRefusesUnownedOrUnexpectedLayout(t *testing.T) {
	for _, mode := range []string{"wrong-target", "relative-target", "target-parent", "alias-parent", "target-owner", "alias-owner", "target-writable", "target-noexec", "target-chain", "target-directory", "missing-target"} {
		t.Run(mode, func(t *testing.T) {
			base, alias, target := daemonPathFixture(t)
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			switch mode {
			case "wrong-target":
				must(os.Remove(alias))
				must(os.Symlink(filepath.Join(base, "foreign"), alias))
			case "relative-target":
				must(os.Remove(alias))
				must(os.Symlink("../bin/busybox", alias))
			case "target-parent":
				must(os.Chmod(filepath.Dir(target), 0777))
			case "alias-parent":
				must(os.Chmod(filepath.Dir(alias), 0777))
			case "target-owner":
				must(os.Chown(target, 1001, -1))
			case "alias-owner":
				must(os.Lchown(alias, 1001, -1))
			case "target-writable":
				must(os.Chmod(target, 0777))
			case "target-noexec":
				must(os.Chmod(target, 0644))
			case "target-chain":
				must(os.Rename(target, target+".real"))
				must(os.Symlink(target+".real", target))
			case "target-directory":
				must(os.Remove(target))
				must(os.Mkdir(target, 0755))
			case "missing-target":
				must(os.Remove(target))
			}
			if _, err := reviewOwnedDaemonPath(alias, target, base); err == nil {
				t.Fatal("unexpected daemon layout admitted")
			}
		})
	}
}

func TestNativeEntwareDaemonAliasReviewRejectsChangedIdentity(t *testing.T) {
	for _, mode := range []string{"alias", "target", "target-mode", "target-owner", "alias-owner"} {
		t.Run(mode, func(t *testing.T) {
			base, alias, target := daemonPathFixture(t)
			check, err := reviewOwnedDaemonPath(alias, target, base)
			if err != nil {
				t.Fatal(err)
			}
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			switch mode {
			case "alias":
				must(os.Rename(alias, alias+".old"))
				must(os.Symlink(target, alias))
			case "target":
				must(os.Rename(target, target+".old"))
				must(os.WriteFile(target, []byte("replacement"), 0755))
			case "target-mode":
				must(os.Chmod(target, 0777))
			case "target-owner":
				must(os.Chown(target, 1001, -1))
			case "alias-owner":
				must(os.Lchown(alias, 1001, -1))
			}
			if check() == nil {
				t.Fatal("changed daemon owner retained permission")
			}
		})
	}
}

func TestNativeRegularEntwareDaemonRemainsSupported(t *testing.T) {
	base, alias, target := daemonPathFixture(t)
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(alias, []byte("standalone daemon"), 0755); err != nil {
		t.Fatal(err)
	}
	check, err := reviewOwnedDaemonPath(alias, target, base)
	if err != nil {
		t.Fatal(err)
	}
	if check == nil || check() != nil {
		t.Fatal("owned regular daemon refused")
	}
}
