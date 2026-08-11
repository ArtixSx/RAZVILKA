package engine

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultCommandTimeout = 2 * time.Second
	maxCommandOutput      = 4096
)

// Capabilities describe what an adapter can safely reason about today.
// Lifecycle means a fixed, known service script exposes lifecycle actions; it
// does not mean the unauthenticated Web UI is allowed to invoke them.
type Capabilities struct {
	Config         bool `json:"config"`
	Validate       bool `json:"validate"`
	NativeValidate bool `json:"native_validate"`
	Lifecycle      bool `json:"lifecycle"`
	IsolatedProbe  bool `json:"isolated_probe"`
	Telemetry      bool `json:"telemetry"`
}

// Spec is the fixed engine registry. Paths and process names are code-owned so
// browser input can never turn discovery into arbitrary command execution.
type Spec struct {
	ID               string
	Name             string
	Kind             string
	Description      string
	Package          string
	BinaryCandidates []string
	InitScripts      []string
	ConfigPaths      []string
	ProcessNames     []string
	Capabilities     Capabilities
}

type Status struct {
	ID               string       `json:"id"`
	Name             string       `json:"name"`
	Installed        bool         `json:"installed"`
	Running          bool         `json:"running"`
	Kind             string       `json:"kind"`
	Description      string       `json:"description"`
	Package          string       `json:"package,omitempty"`
	PackageInstalled bool         `json:"package_installed"`
	Binary           string       `json:"binary,omitempty"`
	Version          string       `json:"version,omitempty"`
	VersionSource    string       `json:"version_source,omitempty"`
	InitScript       string       `json:"init_script,omitempty"`
	ConfigPaths      []string     `json:"config_paths,omitempty"`
	DetectedConfigs  []string     `json:"detected_configs,omitempty"`
	Capabilities     Capabilities `json:"capabilities"`
	ControlEnabled   bool         `json:"control_enabled"`
	Evidence         []string     `json:"evidence,omitempty"`
}

type Detector struct {
	CommandTimeout time.Duration
}

var registry = []Spec{
	{
		ID: "nfqws2", Name: "NFQWS2", Kind: "dpi",
		Description: "Локальный DPI bypass · без внешнего сервера",
		Package:     "nfqws2-keenetic",
		BinaryCandidates: []string{
			"/opt/usr/bin/nfqws2", "/opt/bin/nfqws2", "/usr/bin/nfqws2", "nfqws2",
		},
		InitScripts:  []string{"/opt/etc/init.d/S51nfqws2"},
		ConfigPaths:  []string{"/opt/etc/nfqws2/nfqws2.conf"},
		ProcessNames: []string{"nfqws2", "nfqws"},
		Capabilities: Capabilities{Config: true, Validate: true, Lifecycle: true},
	},
	{
		ID: "usque", Name: "WARP · MASQUE", Kind: "masque",
		Description:      "Cloudflare WARP через MASQUE / CONNECT-IP",
		BinaryCandidates: []string{"/opt/usr/bin/usque", "/opt/bin/usque", "/usr/bin/usque", "usque"},
		InitScripts:      []string{"/opt/etc/init.d/S51usque"},
		ConfigPaths:      []string{"/opt/etc/usque/usque.conf"},
		ProcessNames:     []string{"usque"},
		Capabilities:     Capabilities{Config: true, Validate: true},
	},
	{
		ID: "warp-wg", Name: "WARP · WireGuard", Kind: "warp",
		Description:  "Резервный WARP транспорт через WireGuard профиль",
		ConfigPaths:  []string{"/opt/etc/razvilka/warp/wgcf-profile.conf", "/opt/etc/wireguard/warp.conf"},
		ProcessNames: []string{"wg"},
		Capabilities: Capabilities{Config: true, Validate: true},
	},
	{
		ID: "sing-box", Name: "Sing-box", Kind: "proxy",
		Description:      "VLESS / Reality / Hysteria2 / TUIC / Shadowsocks",
		BinaryCandidates: []string{"/opt/bin/sing-box", "/opt/usr/bin/sing-box", "/usr/bin/sing-box", "sing-box"},
		InitScripts:      []string{"/opt/etc/init.d/S99sing-box", "/opt/etc/init.d/S51sing-box"},
		ConfigPaths:      []string{"/opt/etc/sing-box/config.json", "/opt/etc/singbox/config.json", "/opt/etc/sing-box.json"},
		ProcessNames:     []string{"sing-box"},
		Capabilities:     Capabilities{Config: true, Validate: true, NativeValidate: true},
	},
	{
		ID: "xray", Name: "Xray", Kind: "proxy",
		Description:      "Дополнительные Xray транспорты",
		BinaryCandidates: []string{"/opt/bin/xray", "/opt/usr/bin/xray", "/usr/bin/xray", "xray"},
		InitScripts:      []string{"/opt/etc/init.d/S99xray", "/opt/etc/init.d/S51xray"},
		ConfigPaths:      []string{"/opt/etc/xray/config.json", "/opt/etc/xray.json"},
		ProcessNames:     []string{"xray"},
		Capabilities:     Capabilities{Config: true, Validate: true, NativeValidate: true},
	},
	{
		ID: "amneziawg", Name: "AmneziaWG", Kind: "vpn",
		Description:      "Опциональный AmneziaWG туннель",
		BinaryCandidates: []string{"/opt/bin/awg", "/opt/usr/bin/awg", "/usr/bin/awg", "awg"},
		ConfigPaths:      []string{"/opt/etc/amnezia/amneziawg.conf", "/opt/etc/wireguard/awg.conf"},
		ProcessNames:     []string{"awg"},
		Capabilities:     Capabilities{Config: true, Validate: true},
	},
}

// Registry returns a defensive copy of the fixed engine registry.
func Registry() []Spec {
	out := make([]Spec, len(registry))
	copy(out, registry)
	return out
}

func (d Detector) All() []Status {
	out := make([]Status, 0, len(registry))
	for _, spec := range registry {
		out = append(out, d.detect(spec))
	}
	return out
}

func (d Detector) detect(spec Spec) Status {
	timeout := d.CommandTimeout
	if timeout <= 0 {
		timeout = defaultCommandTimeout
	}

	binary := findBinary(spec.BinaryCandidates)
	initScript := firstExisting(spec.InitScripts)
	detectedConfigs := existingFiles(spec.ConfigPaths)

	packageVersion, packageInstalled := "", false
	if spec.Package != "" {
		packageVersion, packageInstalled = installedPackageVersion(spec.Package, timeout)
	}

	installed := binary != "" || initScript != "" || len(detectedConfigs) > 0 || packageInstalled
	running := processRunning(spec.ProcessNames, timeout)
	if !running && initScript != "" {
		running = initReportsRunning(initScript, timeout)
	}

	version, versionSource := packageVersion, ""
	if packageVersion != "" {
		versionSource = "opkg"
	}

	evidence := make([]string, 0, 4+len(detectedConfigs))
	if packageInstalled {
		item := "package:" + spec.Package
		if packageVersion != "" {
			item += "@" + packageVersion
		}
		evidence = append(evidence, item)
	}
	if binary != "" {
		evidence = append(evidence, "binary:"+binary)
	}
	if initScript != "" {
		evidence = append(evidence, "init:"+initScript)
	}
	for _, p := range detectedConfigs {
		evidence = append(evidence, "config:"+p)
	}

	return Status{
		ID: spec.ID, Name: spec.Name, Installed: installed, Running: running,
		Kind: spec.Kind, Description: spec.Description,
		Package: spec.Package, PackageInstalled: packageInstalled,
		Binary: binary, Version: version, VersionSource: versionSource,
		InitScript: initScript, ConfigPaths: append([]string(nil), spec.ConfigPaths...),
		DetectedConfigs: detectedConfigs, Capabilities: spec.Capabilities,
		// Active lifecycle mutation remains auth-gated; discovery is read-only.
		ControlEnabled: false,
		Evidence:       evidence,
	}
}

func findBinary(candidates []string) string {
	for _, candidate := range candidates {
		if strings.ContainsRune(candidate, os.PathSeparator) {
			if fi, err := os.Stat(candidate); err == nil && !fi.IsDir() {
				return candidate
			}
			continue
		}
		if p, err := exec.LookPath(candidate); err == nil {
			return p
		}
	}
	return ""
}

func firstExisting(paths []string) string {
	for _, p := range paths {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	return ""
}

func existingFiles(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			out = append(out, p)
		}
	}
	return out
}

func installedPackageVersion(pkg string, timeout time.Duration) (string, bool) {
	opkg := findBinary([]string{"/opt/bin/opkg", "/opt/sbin/opkg", "opkg"})
	if opkg == "" {
		return "", false
	}
	out, err := runBounded(timeout, opkg, "status", pkg)
	version, installed := parseOpkgStatus(out)
	if err != nil && !installed {
		return "", false
	}
	return version, installed
}

func parseOpkgStatus(out string) (version string, installed bool) {
	statusSeen := false
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		switch strings.ToLower(key) {
		case "version":
			version = value
		case "status":
			statusSeen = true
			fields := strings.Fields(strings.ToLower(value))
			installed = len(fields) > 0 && fields[len(fields)-1] == "installed"
		}
	}
	// Some opkg builds omit Status in `opkg status` but only print a package
	// stanza for installed packages. A non-empty Version is strong evidence.
	if !statusSeen && version != "" {
		installed = true
	}
	return version, installed
}

func processRunning(names []string, timeout time.Duration) bool {
	if len(names) == 0 {
		return false
	}
	out, err := runBounded(timeout, "ps", "w")
	if err != nil && strings.TrimSpace(out) == "" {
		out, _ = runBounded(timeout, "ps")
	}
	return psOutputHasProcess(out, names)
}

func psOutputHasProcess(out string, names []string) bool {
	wanted := make(map[string]struct{}, len(names))
	for _, name := range names {
		wanted[strings.ToLower(filepath.Base(strings.TrimSpace(name)))] = struct{}{}
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || strings.EqualFold(fields[0], "PID") {
			continue
		}
		// BusyBox `ps w` on Keenetic and common GNU `ps w` layouts both put
		// COMMAND at field 5. Only inspect the executable token, never args.
		commandIndex := 4
		if len(fields) <= commandIndex {
			commandIndex = len(fields) - 1
		}
		base := strings.ToLower(filepath.Base(strings.Trim(fields[commandIndex], "[]")))
		if _, ok := wanted[base]; ok {
			return true
		}
	}
	return false
}

func initReportsRunning(path string, timeout time.Duration) bool {
	out, _ := runBounded(timeout, path, "status")
	return statusOutputRunning(out)
}

func statusOutputRunning(out string) bool {
	s := strings.ToLower(strings.TrimSpace(out))
	if s == "" {
		return false
	}
	for _, negative := range []string{"not running", "not started", "stopped", "inactive", "dead"} {
		if strings.Contains(s, negative) {
			return false
		}
	}
	for _, positive := range []string{"is running", "running", "started", "active", "alive"} {
		if strings.Contains(s, positive) {
			return true
		}
	}
	return false
}

type cappedBuffer struct {
	buf bytes.Buffer
	max int
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	original := len(p)
	if b.buf.Len() < b.max {
		remain := b.max - b.buf.Len()
		if len(p) > remain {
			p = p[:remain]
		}
		_, _ = b.buf.Write(p)
	}
	return original, nil
}

func (b *cappedBuffer) String() string { return b.buf.String() }

func runBounded(timeout time.Duration, bin string, args ...string) (string, error) {
	if timeout <= 0 {
		timeout = defaultCommandTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	var out cappedBuffer
	out.max = maxCommandOutput
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return strings.TrimSpace(out.String()), err
}
