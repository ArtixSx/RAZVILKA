//go:build linux && (amd64 || arm64) && razvilka_native_fixture

package startuptools

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// Same isolated /opt and protected scratch contract as the loader fixture.
// These synthetic ARM64 ELF files are inspected, never executed.
func nc1812ExtensionFixture(t *testing.T) *heldReview {
	t.Helper()
	r := cpuidCaptureFixture(t, "arm64")
	r.profile.id = "test-explicit-package-extension-closure"
	dir := r.profile.extension
	raw, err := os.ReadFile(filepath.Join(dir, "module.so"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "other.so"), raw, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("module.so", filepath.Join(dir, "alias.so")); err != nil {
		t.Fatal(err)
	}
	hash := fmt.Sprintf("%x", sha256.Sum256(raw))
	r.profile.extensionExpectations = map[string]extensionExpectation{
		"module.so": {target: filepath.Join(dir, "module.so"), sha256: hash},
		"other.so":  {target: filepath.Join(dir, "other.so"), sha256: hash},
		"alias.so":  {target: filepath.Join(dir, "module.so"), sha256: hash, link: "module.so"},
	}
	return r
}

func TestNC1812Entware202611NativeCaptureDigestAndClosing(t *testing.T) {
	r := nc1812ExtensionFixture(t)
	ctx := context.Background()
	if err := r.capture(ctx); err != nil {
		t.Fatal("complete capture", err)
	}
	if err := r.unchanged(ctx); err != nil {
		t.Fatal("complete closing", err)
	}
	if _, err := r.versionExtensionPath(); err != nil {
		t.Fatal(err)
	}
	before, err := r.digest()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(r.profile.extension, "module.so")
	original := r.images[path].hash
	r.images[path].hash[0] ^= 1
	after, err := r.digest()
	r.images[path].hash = original
	if err != nil || before == after {
		t.Fatal("module bytes not digest-bound", err)
	}
	n := r.nodes[filepath.Join(r.profile.extension, "alias.so")]
	changed := n
	changed.link = "other.so"
	r.nodes[n.path] = changed
	after, err = r.digest()
	r.nodes[n.path] = n
	if err != nil || before == after {
		t.Fatal("literal alias not digest-bound", err)
	}
	// The retained profile snapshot must not alias the constructor's map.
	r.profile.extensionExpectations["module.so"] = extensionExpectation{}
	if _, err := r.versionExtensionPath(); err == nil {
		t.Fatal("changed expectation preserved retained profile")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := r.unchanged(canceled); err == nil {
		t.Fatal("canceled closing accepted")
	}
}

func TestNC1812Entware202611NativePackageRefusals(t *testing.T) {
	for _, cut := range []string{"missing", "extra", "case", "bytes", "rawlink", "target", "regular-to-link", "link-to-regular", "empty-map", "wrong-pin", "directory-alias", "uid1001"} {
		t.Run(cut, func(t *testing.T) {
			r := nc1812ExtensionFixture(t)
			dir := r.profile.extension
			module, alias := filepath.Join(dir, "module.so"), filepath.Join(dir, "alias.so")
			raw, err := os.ReadFile(module)
			if err != nil {
				t.Fatal(err)
			}
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			switch cut {
			case "missing":
				must(os.Remove(filepath.Join(dir, "other.so")))
			case "extra":
				must(os.WriteFile(filepath.Join(dir, "extra.so"), raw, 0700))
			case "case":
				must(os.Rename(filepath.Join(dir, "other.so"), filepath.Join(dir, "Other.so")))
			case "bytes":
				must(os.WriteFile(module, append(raw, 0), 0700))
			case "rawlink":
				must(os.Remove(alias))
				must(os.Symlink("./module.so", alias))
			case "target":
				must(os.Remove(alias))
				must(os.Symlink("other.so", alias))
			case "regular-to-link":
				must(os.Remove(module))
				must(os.Symlink("other.so", module))
			case "link-to-regular":
				must(os.Remove(alias))
				must(os.WriteFile(alias, raw, 0700))
			case "empty-map":
				r.profile.extensionExpectations = map[string]extensionExpectation{}
			case "wrong-pin":
				e := r.profile.extensionExpectations["module.so"]
				e.sha256 = stockProfile().mainSHA
				r.profile.extensionExpectations["module.so"] = e
			case "directory-alias":
				must(os.Symlink(dir, dir+"-alias"))
				r.profile.extension = dir + "-alias"
			case "uid1001":
				must(os.Chown(dir, 1001, 1001))
			}
			if err := r.capture(context.Background()); err == nil {
				t.Fatal("package drift admitted")
			}
		})
	}
}

func TestNC1812Entware202611NativeFreshClosingRefusesDrift(t *testing.T) {
	for _, cut := range []string{"extra", "missing", "bytes", "link", "same-bytes-replacement"} {
		t.Run(cut, func(t *testing.T) {
			r := nc1812ExtensionFixture(t)
			ctx := context.Background()
			if err := r.capture(ctx); err != nil {
				t.Fatal(err)
			}
			if err := r.unchanged(ctx); err != nil {
				t.Fatal(err)
			}
			module := filepath.Join(r.profile.extension, "module.so")
			raw, err := os.ReadFile(module)
			if err != nil {
				t.Fatal(err)
			}
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			switch cut {
			case "extra":
				must(os.WriteFile(filepath.Join(r.profile.extension, "extra.so"), raw, 0700))
			case "missing":
				must(os.Remove(filepath.Join(r.profile.extension, "other.so")))
			case "bytes":
				must(os.WriteFile(module, append(raw, 0), 0700))
			case "link":
				alias := filepath.Join(r.profile.extension, "alias.so")
				must(os.Remove(alias))
				must(os.Symlink("other.so", alias))
			case "same-bytes-replacement":
				temp := filepath.Join(r.profile.libraries[0], "replacement")
				must(os.WriteFile(temp, raw, 0700))
				must(os.Rename(temp, module))
			}
			if err := r.unchanged(ctx); err == nil {
				t.Fatal("fresh closing accepted filesystem drift")
			}
		})
	}
}

func TestNC1812Entware202611NativeNilExpectationKeepsOldScan(t *testing.T) {
	r := nc1812ExtensionFixture(t)
	r.profile.extensionExpectations = nil
	raw, err := os.ReadFile(filepath.Join(r.profile.extension, "module.so"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.profile.extension, "extra.so"), raw, 0700); err != nil {
		t.Fatal(err)
	}
	if err := r.capture(context.Background()); err != nil {
		t.Fatal("legacy generic extension scan changed", err)
	}
	if err := r.unchanged(context.Background()); err != nil {
		t.Fatal(err)
	}
}
