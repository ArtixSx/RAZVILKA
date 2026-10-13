package projectmeta

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	markdownLinkPattern  = regexp.MustCompile(`\[[^\]]+\]\(([^)]+)\)`)
	versionPattern       = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)
	projectModulePattern = regexp.MustCompile(`(?m)^[\t ]*module[\t ]+(github\.com/ArtixSx/razvilka|"github\.com/ArtixSx/razvilka")[\t ]*(//[^\r\n]*)?\r?$`)
)

// VERSION identifies the source release. CI appends its own build metadata,
// so an embedded +build suffix belongs to build provenance, not this file.
func validCanonicalVersion(version string) bool {
	if !versionPattern.MatchString(version) {
		return false
	}
	_, prerelease, present := strings.Cut(version, "-")
	if present {
		for _, id := range strings.Split(prerelease, ".") {
			if len(id) > 1 && id[0] == '0' && strings.Trim(id, "0123456789") == "" {
				return false
			}
		}
	}
	return true
}

func TestCanonicalVersionAcceptsStableAndPrerelease(t *testing.T) {
	for _, version := range []string{"0.0.0", "1.2.3", "0.18.2-dev", "0.18.2-rc.1", "1.0.0-alpha.beta", "1.0.0-0.3.7", "1.0.0-alpha-1", "1.0.0-01a"} {
		if !validCanonicalVersion(version) {
			t.Errorf("valid source version rejected: %q", version)
		}
	}
	for _, version := range []string{"", "v1.2.3", "1.2", "01.2.3", "1.02.3", "1.2.03", "1.2.3-", "1.2.3-rc..1", "1.2.3-rc.01", "1.2.3-01", "1.2.3-rc_1", "1.2.3\n", "1.2.3+build"} {
		if validCanonicalVersion(version) {
			t.Errorf("invalid canonical source version accepted: %q", version)
		}
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatalf("locate project metadata working directory: %v", err)
	}
	root, err := findRepositoryRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// Go runs package tests in their source directory. Unlike runtime.Caller,
// this path still identifies the actual checkout when built with -trimpath.
// Stop at the nearest module so a foreign checkout cannot borrow our parent.
func findRepositoryRoot(directory string) (string, error) {
	for directory = filepath.Clean(directory); ; directory = filepath.Dir(directory) {
		data, err := os.ReadFile(filepath.Join(directory, "go.mod"))
		if err == nil {
			if !projectModulePattern.Match(data) {
				return "", fmt.Errorf("nearest go.mod at %s is not the RAZVILKA module", directory)
			}
			return directory, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("read project module marker: %w", err)
		}
		if filepath.Dir(directory) == directory {
			return "", fmt.Errorf("cannot locate RAZVILKA go.mod from the test working directory")
		}
	}
}

func TestRepositoryRootUsesNearestExactModule(t *testing.T) {
	for _, module := range []string{"module github.com/ArtixSx/razvilka\n", "module \"github.com/ArtixSx/razvilka\" // source checkout\r\n"} {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte(module), 0600); err != nil {
			t.Fatal(err)
		}
		packageDirectory := filepath.Join(root, "internal", "projectmeta")
		if err := os.MkdirAll(packageDirectory, 0700); err != nil {
			t.Fatal(err)
		}
		for _, start := range []string{root, packageDirectory} {
			found, err := findRepositoryRoot(start)
			if err != nil || found != root {
				t.Fatalf("actual module root not found: %s, %v", found, err)
			}
		}
		// A similarly named nested module must refuse instead of selecting
		// the valid parent and silently checking another checkout's files.
		if err := os.WriteFile(filepath.Join(packageDirectory, "go.mod"), []byte("module github.com/ArtixSx/razvilka-other\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if found, err := findRepositoryRoot(packageDirectory); err == nil || found != "" {
			t.Fatal("foreign module borrowed the parent's source checks")
		}
	}
}

func readFile(t *testing.T, root, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(data)
}

func TestCanonicalVersionIsConsistent(t *testing.T) {
	root := repositoryRoot(t)
	version := strings.TrimSpace(readFile(t, root, "VERSION"))
	if !validCanonicalVersion(version) {
		t.Fatalf("VERSION = %q, want a semantic source version such as 1.0.0, 0.18.2-dev or 0.18.2-rc.1", version)
	}

	checks := map[string]string{
		"internal/app/app.go":         `Version     = "` + version + `"`,
		"cmd/razvilka/web/index.html": `id="version">v` + version + `<`,
		"build.sh":                    `VERSION_FILE="$ROOT/VERSION"`,
		".github/workflows/ci.yml":    `BASE_VERSION="$(tr -d '\r\n' < VERSION)"`,
	}
	for name, required := range checks {
		if body := readFile(t, root, name); !strings.Contains(body, required) {
			t.Errorf("%s does not derive or mirror VERSION; missing %q", name, required)
		}
	}
	if body := readFile(t, root, "cmd/razvilka/web/index.html"); !strings.Contains(body, `app.js?v=`+version+`"`) || !strings.Contains(body, `id="footerVersion">v`+version+`<`) {
		t.Errorf("web asset cache key or footer fallback does not match full VERSION %q", version)
	}
	releaseWorkflow := readFile(t, root, ".github/workflows/release.yml")
	for _, required := range []string{
		`SOURCE_VERSION="$(tr -d '\r\n' < VERSION)"`,
		`"${SOURCE_VERSION%-dev}"`,
		`VERSION README.md`,
		`RELEASE_OPTIONS+=(--prerelease --latest=false)`,
		`RELEASE_OPTIONS=(--verify-tag)`,
	} {
		if !strings.Contains(releaseWorkflow, required) {
			t.Errorf("release workflow is missing canonical version guard %q", required)
		}
	}
	if body := readFile(t, root, "internal/sources/sources.go"); strings.Contains(body, "RAZVILKA/0.2.0") {
		t.Error("Source Hub still uses the historical 0.2.0 user agent")
	}
}

func TestCurrentDocumentationLocalLinksExist(t *testing.T) {
	root := repositoryRoot(t)
	current := []string{
		"README.md",
		"README_EN.md",
		"SECURITY.md",
		"docs/CURRENT_STATUS_RU.md",
		"docs/ROADMAP.md",
		"docs/README.md",
		"docs/FILES_RU.md",
		"CONTRIBUTING.md",
		"docs/VERSIONING_RU.md",
	}
	for _, name := range current {
		body := readFile(t, root, name)
		for _, match := range markdownLinkPattern.FindAllStringSubmatch(body, -1) {
			target := strings.TrimSpace(match[1])
			if fields := strings.Fields(target); len(fields) > 0 {
				target = strings.Trim(fields[0], "<>")
			}
			if target == "" || strings.HasPrefix(target, "#") || strings.HasPrefix(target, "/") ||
				strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") || strings.HasPrefix(target, "mailto:") {
				continue
			}
			target = strings.SplitN(target, "#", 2)[0]
			decoded, err := url.PathUnescape(target)
			if err != nil {
				t.Errorf("%s has invalid escaped link %q: %v", name, target, err)
				continue
			}
			resolved := filepath.Clean(filepath.Join(root, filepath.Dir(filepath.FromSlash(name)), filepath.FromSlash(decoded)))
			if _, err := os.Stat(resolved); err != nil {
				t.Errorf("%s links to missing local target %q", name, target)
			}
		}
	}
}
