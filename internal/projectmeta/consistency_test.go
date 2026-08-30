package projectmeta

import (
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

var (
	markdownLinkPattern = regexp.MustCompile(`\[[^\]]+\]\(([^)]+)\)`)
	versionPattern      = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+-dev$`)
)

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate project metadata test")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
}

func readFile(t *testing.T, root, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(data)
}

func TestCanonicalDevelopmentVersionIsConsistent(t *testing.T) {
	root := repositoryRoot(t)
	version := strings.TrimSpace(readFile(t, root, "VERSION"))
	if !versionPattern.MatchString(version) {
		t.Fatalf("VERSION = %q, want a development semantic version such as 0.18.1-dev", version)
	}
	assetVersion := strings.TrimSuffix(version, "-dev")

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
	if body := readFile(t, root, "cmd/razvilka/web/index.html"); !strings.Contains(body, `app.js?v=`+assetVersion) {
		t.Errorf("web asset cache key does not match VERSION base %q", assetVersion)
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
		"docs/ROADMAP_2026-08-30_RU.md",
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
