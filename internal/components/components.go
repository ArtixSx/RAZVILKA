package components

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

type Spec struct {
	SchemaVersion int            `json:"schema_version"`
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	Category      string         `json:"category"`
	Package       string         `json:"package,omitempty"`
	Provider      string         `json:"provider"`
	Repository    string         `json:"repository,omitempty"`
	Binary        string         `json:"-"`
	Archive       string         `json:"-"`
	Description   string         `json:"description"`
	Recommended   bool           `json:"recommended"`
	Removable     bool           `json:"removable"`
	Capabilities  []string       `json:"capabilities,omitempty"`
	Dependencies  []string       `json:"dependencies,omitempty"`
	Claims        []Claim        `json:"claims,omitempty"`
	Budget        ResourceBudget `json:"resource_budget"`
}

type View struct {
	Spec
	InstalledVersion string `json:"installed_version,omitempty"`
	AvailableVersion string `json:"available_version,omitempty"`
	Installed        bool   `json:"installed"`
	Available        bool   `json:"available"`
	UpdateAvailable  bool   `json:"update_available"`
	State            string `json:"state"`
	CanInstall       bool   `json:"can_install"`
	CanUpdate        bool   `json:"can_update"`
	CanRemove        bool   `json:"can_remove"`
	Configured       bool   `json:"configured"`
	Running          bool   `json:"running"`
	ExternalOwner    bool   `json:"external_owner"`
}

type Result struct {
	OK        bool   `json:"ok"`
	Component string `json:"component"`
	Action    string `json:"action"`
	Output    string `json:"output"`
}

type BatchResult struct {
	OK      bool     `json:"ok"`
	Results []Result `json:"results"`
	Errors  []string `json:"errors,omitempty"`
}

type Runner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

type Manager struct {
	Opkg     string
	RepoDir  string
	BinDir   string
	StateDir string
	Arch     string
	Client   *http.Client
	Timeout  time.Duration
	Runner   Runner
	external map[string]releaseInfo
	mu       sync.Mutex
}

func New() *Manager {
	return &Manager{Opkg: findOpkg(), RepoDir: "/opt/etc/opkg", BinDir: "/opt/bin", StateDir: "/opt/var/lib/razvilka/components", Arch: runtime.GOARCH, Client: releaseHTTPClient(), Timeout: 90 * time.Second, Runner: execRunner{}, external: map[string]releaseInfo{}}
}

func Specs() []Spec {
	specs := []Spec{
		{SchemaVersion: 1, ID: "nfqws2", Name: "NFQWS2", Category: "local-dpi", Package: "nfqws2-keenetic", Provider: "opkg", Repository: "https://nfqws.github.io/nfqws2-keenetic/all", Description: "Локальный DPI-desync через NFQUEUE", Recommended: true, Removable: true, Capabilities: []string{"tcp", "udp", "quic", "strategy-lab"}, Claims: []Claim{{Kind: "nfqueue", Value: "managed"}}, Budget: ResourceBudget{RAMMiB: 24, FlashMiB: 18, CPUClass: "medium"}},
		{SchemaVersion: 1, ID: "usque", Name: "WARP · MASQUE", Category: "tunnel", Package: "usque-keenetic", Provider: "opkg", Repository: "https://side-effect-tm.github.io/usque-keenetic/all", Description: "Cloudflare WARP через MASQUE по TCP/443", Recommended: true, Removable: true, Capabilities: []string{"masque", "http2", "tun", "split-routing"}, Dependencies: []string{"sing-box"}, Claims: []Claim{{Kind: "tun", Value: "managed"}, {Kind: "policy-table", Value: "managed"}}, Budget: ResourceBudget{RAMMiB: 32, FlashMiB: 20, CPUClass: "medium"}},
		{SchemaVersion: 1, ID: "sing-box", Name: "Sing-box", Category: "proxy", Package: "sing-box-go", Provider: "opkg", Description: "VLESS, Reality, Hysteria2, TUIC и Shadowsocks", Removable: true, Capabilities: []string{"vless", "reality", "hysteria2", "tuic", "shadowsocks", "tun"}, Claims: []Claim{{Kind: "tun", Value: "managed"}, {Kind: "listen-port", Value: "profile"}}, Budget: ResourceBudget{RAMMiB: 64, FlashMiB: 32, CPUClass: "medium"}},
		{SchemaVersion: 1, ID: "xray", Name: "Xray", Category: "proxy", Package: "xray", Provider: "opkg", Description: "Xray и VLESS-транспорты", Removable: true, Capabilities: []string{"vless", "reality", "proxy"}, Claims: []Claim{{Kind: "listen-port", Value: "profile"}}, Budget: ResourceBudget{RAMMiB: 64, FlashMiB: 38, CPUClass: "medium"}},
		{SchemaVersion: 1, ID: "warp-wg", Name: "WARP · WireGuard", Category: "tunnel", Package: "wireguard-tools", Provider: "opkg", Description: "WireGuard-инструменты для WARP-профиля", Removable: true, Capabilities: []string{"wireguard", "tun", "split-routing"}, Dependencies: []string{"wgcf"}, Claims: []Claim{{Kind: "interface", Value: "managed"}, {Kind: "policy-table", Value: "managed"}}, Budget: ResourceBudget{RAMMiB: 12, FlashMiB: 8, CPUClass: "light"}},
		{SchemaVersion: 1, ID: "wgcf", Name: "WARP Generator", Category: "tool", Provider: "github-release", Repository: "https://github.com/ViRb3/wgcf", Binary: "wgcf", Archive: "binary", Description: "Регистрация и генерация профиля WARP", Removable: true, Capabilities: []string{"warp-registration", "wireguard-profile"}, Budget: ResourceBudget{RAMMiB: 8, FlashMiB: 12, CPUClass: "light"}},
		{SchemaVersion: 1, ID: "amneziawg", Name: "AmneziaWG", Category: "tunnel", Provider: "platform", Repository: "https://github.com/amnezia-vpn/amneziawg-openwrt", Description: "Требует совместимый модуль ядра или userspace runtime", Capabilities: []string{"amneziawg", "tun", "split-routing"}, Claims: []Claim{{Kind: "interface", Value: "managed"}, {Kind: "policy-table", Value: "managed"}}, Budget: ResourceBudget{RAMMiB: 24, FlashMiB: 16, CPUClass: "medium"}},
	}
	return normalizeManifest(specs)
}

func (m *Manager) InstallRecommended(ctx context.Context) BatchResult {
	report := BatchResult{OK: true, Results: []Result{}, Errors: []string{}}
	for _, spec := range Specs() {
		if !spec.Recommended {
			continue
		}
		result, err := m.Apply(ctx, spec.ID)
		if err != nil {
			report.OK = false
			report.Errors = append(report.Errors, fmt.Sprintf("%s: %v", spec.ID, err))
			result.Component = spec.ID
			if result.Action == "" {
				result.Action = "install"
			}
		}
		report.Results = append(report.Results, result)
	}
	return report
}

func (m *Manager) List(ctx context.Context, refresh bool) ([]View, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if refresh && m.Opkg != "" {
		if err := m.ensureRepositories(); err != nil {
			return nil, err
		}
		if _, err := m.run(ctx, "update"); err != nil {
			return nil, fmt.Errorf("opkg update: %w", err)
		}
	}
	installed, available := map[string]string{}, map[string]string{}
	if m.Opkg != "" {
		installedOut, installedErr := m.run(ctx, "list-installed")
		availableOut, availableErr := m.run(ctx, "list")
		if installedErr != nil && availableErr != nil {
			return nil, fmt.Errorf("read opkg catalog: %v; %v", installedErr, availableErr)
		}
		installed = parsePackageVersions(string(installedOut))
		available = parsePackageVersions(string(availableOut))
	}
	views := make([]View, 0, len(Specs()))
	for _, spec := range Specs() {
		if spec.Provider == "github-release" {
			view, err := m.externalView(ctx, spec, refresh)
			if err != nil {
				view.State = "check-failed"
			}
			view.CanInstall = !view.Installed && view.Available
			view.CanUpdate = view.UpdateAvailable
			view.CanRemove = view.Installed && spec.Removable
			views = append(views, view)
			continue
		}
		if spec.Provider != "opkg" || spec.Package == "" {
			state := "provider-required"
			if spec.Provider == "external" {
				state = "external"
			}
			views = append(views, View{Spec: spec, State: state})
			continue
		}
		iv, av := installed[spec.Package], available[spec.Package]
		v := View{Spec: spec, InstalledVersion: iv, AvailableVersion: av, Installed: iv != "", Available: av != ""}
		switch {
		case v.Installed && v.Available && compareVersions(iv, av) < 0:
			v.State, v.UpdateAvailable = "update", true
		case v.Installed:
			v.State = "installed"
		case v.Available:
			v.State = "available"
		default:
			v.State = "unavailable"
		}
		v.CanInstall = !v.Installed && v.Available
		v.CanUpdate = v.UpdateAvailable
		v.CanRemove = v.Installed && spec.Removable
		views = append(views, v)
	}
	return views, nil
}

func (m *Manager) Apply(ctx context.Context, id string) (Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.applyLocked(ctx, id, map[string]bool{})
}

func (m *Manager) applyLocked(ctx context.Context, id string, visiting map[string]bool) (Result, error) {
	spec, ok := lookup(id)
	if !ok {
		return Result{}, fmt.Errorf("unknown component %q", id)
	}
	if visiting[id] {
		return Result{}, fmt.Errorf("component dependency cycle at %s", id)
	}
	visiting[id] = true
	defer delete(visiting, id)
	for _, dependency := range spec.Dependencies {
		if _, err := m.applyLocked(ctx, dependency, visiting); err != nil {
			return Result{Component: id, Action: "install"}, fmt.Errorf("install dependency %s: %w", dependency, err)
		}
	}
	if spec.Provider == "github-release" {
		return m.installExternal(ctx, spec)
	}
	if spec.Provider != "opkg" || spec.Package == "" {
		return Result{}, fmt.Errorf("component %s requires the %s installer, which is not enabled yet", id, spec.Provider)
	}
	if m.Opkg == "" {
		return Result{}, errors.New("opkg is not available")
	}
	if err := m.prepareReceiptDir(); err != nil {
		return Result{}, err
	}
	before, err := m.installedPackageVersions(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("read installed packages before component operation: %w", err)
	}
	beforeVersion := before[spec.Package]
	action := "install"
	if beforeVersion != "" {
		action = "update"
	}
	if err := m.ensureRepository(spec); err != nil {
		return Result{}, err
	}
	if spec.Repository != "" {
		if _, err := m.run(ctx, "update"); err != nil {
			return Result{}, fmt.Errorf("opkg update after repository setup: %w", err)
		}
	}
	out, err := m.run(ctx, "install", spec.Package)
	text := strings.TrimSpace(string(out))
	if len(text) > 8192 {
		text = text[len(text)-8192:]
	}
	if err != nil {
		return Result{Component: id, Action: action, Output: text}, fmt.Errorf("opkg install %s: %w", spec.Package, err)
	}
	after, verifyErr := m.installedPackageVersions(ctx)
	if verifyErr != nil {
		return Result{Component: id, Action: action, Output: text}, fmt.Errorf("verify installed component: %w", verifyErr)
	}
	afterVersion := after[spec.Package]
	if afterVersion == "" {
		if beforeVersion == "" {
			_, _ = m.run(ctx, "remove", spec.Package)
		}
		return Result{Component: id, Action: action, Output: text}, fmt.Errorf("opkg reported success but %s is not installed", spec.Package)
	}
	receipt := lifecycleReceipt{SchemaVersion: 1, Component: id, Package: spec.Package, Provider: spec.Provider, Action: action, BeforeVersion: beforeVersion, AfterVersion: afterVersion, CompletedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if err := m.writeLifecycleReceipt(receipt); err != nil {
		return Result{Component: id, Action: action, Output: text}, fmt.Errorf("write component receipt: %w", err)
	}
	return Result{OK: true, Component: id, Action: action, Output: text + fmt.Sprintf("\nverified installed version: %s", afterVersion)}, nil
}

func (m *Manager) ensureRepositories() error {
	for _, spec := range Specs() {
		if err := m.ensureRepository(spec); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) ensureRepository(spec Spec) error {
	if spec.Provider != "opkg" || spec.Repository == "" {
		return nil
	}
	dir := m.RepoDir
	if dir == "" {
		dir = "/opt/etc/opkg"
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create opkg repository directory: %w", err)
	}
	declared, err := repositoryDeclared(dir, spec.Package, spec.Repository)
	if err != nil {
		return fmt.Errorf("inspect opkg repositories: %w", err)
	}
	if declared {
		return nil
	}
	path := filepath.Join(dir, spec.ID+".conf")
	content := []byte(fmt.Sprintf("src/gz %s %s\n", spec.Package, spec.Repository))
	if existing, err := os.ReadFile(path); err == nil && string(existing) == string(content) {
		return nil
	}
	tmp, err := os.CreateTemp(dir, ".razvilka-repo-*")
	if err != nil {
		return fmt.Errorf("create opkg repository draft: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("commit opkg repository: %w", err)
	}
	return nil
}

func repositoryDeclared(dir, packageName, repository string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".conf") {
			continue
		}
		file, err := os.Open(filepath.Join(dir, entry.Name()))
		if err != nil {
			return false, err
		}
		data, readErr := io.ReadAll(io.LimitReader(file, 64<<10))
		closeErr := file.Close()
		if readErr != nil {
			return false, readErr
		}
		if closeErr != nil {
			return false, closeErr
		}
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) >= 3 && (fields[0] == "src" || fields[0] == "src/gz") && fields[1] == packageName && fields[2] == repository {
				return true, nil
			}
		}
	}
	return false, nil
}

func (m *Manager) run(parent context.Context, args ...string) ([]byte, error) {
	timeout := m.Timeout
	if timeout <= 0 {
		timeout = 90 * time.Second
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	out, err := m.Runner.Run(ctx, m.Opkg, args...)
	if ctx.Err() == context.DeadlineExceeded {
		return out, fmt.Errorf("timed out after %s", timeout)
	}
	return out, err
}

func findOpkg() string {
	for _, path := range []string{"/opt/bin/opkg", "/opt/sbin/opkg", "opkg"} {
		if strings.Contains(path, "/") {
			if _, err := exec.LookPath(path); err == nil {
				return path
			}
			continue
		}
		if found, err := exec.LookPath(path); err == nil {
			return found
		}
	}
	return ""
}

func lookup(id string) (Spec, bool) {
	for _, spec := range Specs() {
		if spec.ID == id {
			return spec, true
		}
	}
	return Spec{}, false
}

func unavailableViews() []View {
	views := make([]View, 0, len(Specs()))
	for _, spec := range Specs() {
		views = append(views, View{Spec: spec, State: "unavailable"})
	}
	return views
}

func parsePackageVersions(output string) map[string]string {
	result := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), " - ", 3)
		if len(parts) >= 2 && parts[0] != "" && parts[1] != "" {
			if old := result[parts[0]]; old == "" || compareVersions(old, parts[1]) < 0 {
				result[parts[0]] = parts[1]
			}
		}
	}
	return result
}

var versionPart = regexp.MustCompile(`[0-9]+|[A-Za-z]+`)

func compareVersions(a, b string) int {
	aa, bb := versionPart.FindAllString(a, -1), versionPart.FindAllString(b, -1)
	n := len(aa)
	if len(bb) > n {
		n = len(bb)
	}
	for i := 0; i < n; i++ {
		if i >= len(aa) {
			return -1
		}
		if i >= len(bb) {
			return 1
		}
		if aa[i] == bb[i] {
			continue
		}
		var ai, bi int
		_, ae := fmt.Sscanf(aa[i], "%d", &ai)
		_, be := fmt.Sscanf(bb[i], "%d", &bi)
		if ae == nil && be == nil {
			if ai < bi {
				return -1
			}
			return 1
		}
		if aa[i] < bb[i] {
			return -1
		}
		return 1
	}
	return 0
}

func Sort(views []View) {
	sort.Slice(views, func(i, j int) bool { return views[i].Name < views[j].Name })
}
