package enginelab

import (
	"encoding/json"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/engine"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/systemprobe"
)

type Check struct {
	ID     string `json:"id"`
	Status string `json:"status"` // pass, warn, fail, not-ready
	Detail string `json:"detail"`
}

type Resource struct {
	Kind     string `json:"kind"` // port, interface, nfqueue
	Value    string `json:"value"`
	EngineID string `json:"engine_id"`
	Source   string `json:"source"`
}

type Conflict struct {
	Kind      string   `json:"kind"`
	Value     string   `json:"value"`
	Engines   []string `json:"engines"`
	SystemUse string   `json:"system_use,omitempty"`
	Blocking  bool     `json:"blocking"`
}

type EngineReport struct {
	engine.Status
	Compatibility string     `json:"compatibility"`
	SchemaLevel   string     `json:"schema_level"`
	VersionNumber string     `json:"version_number,omitempty"`
	Checks        []Check    `json:"checks"`
	Resources     []Resource `json:"resources"`
	ProbeMode     string     `json:"probe_mode"`
}

type Report struct {
	GeneratedAt string                 `json:"generated_at"`
	System      systemprobe.Snapshot   `json:"system"`
	Engines     []EngineReport         `json:"engines"`
	Conflicts   []Conflict             `json:"conflicts"`
	Ready       bool                   `json:"ready_for_isolated_probes"`
	Gate        map[string]interface{} `json:"gate"`
}

type Manager struct {
	Configs        *engineconfig.Manager
	Statuses       func() []engine.Status
	System         func() systemprobe.Snapshot
	ListeningPorts func() map[string]string
}

type capabilitySpec struct {
	Schema    string
	ProbeMode string
	NeedsTUN  bool
	NeedsNFQ  bool
	NeedsIP   bool
}

var capabilities = map[string]capabilitySpec{
	"nfqws2":   {Schema: "native-shell", ProbeMode: "wan-bound-unconfirmed", NeedsNFQ: true, NeedsIP: true},
	"z2k":      {Schema: "external-read-only", ProbeMode: "external-nfqueue-owner", NeedsNFQ: true, NeedsIP: true},
	"usque":    {Schema: "native-json", ProbeMode: "local-socks", NeedsIP: true},
	"warp-wg":  {Schema: "wireguard-ini", ProbeMode: "source-address-bound", NeedsTUN: true, NeedsIP: true},
	"sing-box": {Schema: "native-json", ProbeMode: "local-socks-or-tun", NeedsIP: true},
	"xray":     {Schema: "native-json", ProbeMode: "local-socks", NeedsIP: true},
	"amneziawg": {Schema: "wireguard-ini", ProbeMode: "source-address-bound", NeedsTUN: true,
		NeedsIP: true},
}

var (
	semverPattern  = regexp.MustCompile(`(?i)(?:v|version\s*)?(\d+)\.(\d+)(?:\.(\d+))?`)
	portPattern    = regexp.MustCompile(`(?i)(?:listen[_-]?port|socks[_-]?port|http[_-]?port|local[_-]?port)\s*[:=]\s*["']?(\d{1,5})`)
	queuePattern   = regexp.MustCompile(`(?i)(?:queue[_-]?(?:num|number)|nfqueue)\s*[:=]\s*["']?(\d{1,5})`)
	interfaceRegex = regexp.MustCompile(`(?i)(?:interface[_-]?name|interface|device|tun[_-]?name)\s*[:=]\s*["']?([a-zA-Z0-9_.-]{1,32})`)
)

func New(configs *engineconfig.Manager) *Manager {
	return &Manager{
		Configs:        configs,
		Statuses:       func() []engine.Status { return (engine.Detector{}).All() },
		System:         systemprobe.Probe,
		ListeningPorts: listeningPorts,
	}
}

func (m *Manager) Inspect() Report {
	system := m.System()
	listening := m.ListeningPorts()
	report := Report{GeneratedAt: time.Now().UTC().Format(time.RFC3339), System: system, Gate: map[string]interface{}{}, Ready: false}
	allResources := []Resource{}
	z2kRunning := false
	nfqws2Installed := false
	for _, status := range m.Statuses() {
		if status.ID == "z2k" {
			z2kRunning = status.Running
			report.Gate["external_nfqws2_owner"] = map[string]interface{}{
				"detected": status.Installed, "running": status.Running,
				"managed_by": "external", "action": "stop or remove the external owner before NFQWS2 activation",
			}
			continue
		}
		if status.ID == "nfqws2" && status.Installed {
			nfqws2Installed = true
		}
		spec := capabilities[status.ID]
		item := EngineReport{Status: status, SchemaLevel: spec.Schema, ProbeMode: spec.ProbeMode, Checks: []Check{}, Resources: []Resource{}}
		item.VersionNumber, item.Compatibility = versionCompatibility(status)
		installedStatus := "not-ready"
		if status.Installed {
			installedStatus = "pass"
		}
		item.Checks = append(item.Checks, Check{ID: "installed", Status: installedStatus, Detail: installedDetail(status)})
		configuredStatus := "not-ready"
		if status.Configured {
			configuredStatus = "pass"
		}
		item.Checks = append(item.Checks, Check{ID: "configured", Status: configuredStatus, Detail: configuredDetail(status)})
		runningStatus := "not-ready"
		if status.Running {
			runningStatus = "pass"
		}
		item.Checks = append(item.Checks, Check{ID: "running", Status: runningStatus, Detail: runningDetail(status)})
		itemReady := status.RuntimeReady && status.Running
		if status.Installed {
			item.Checks = append(item.Checks, requirementChecks(system, spec)...)
			resources, validation := m.inspectConfig(status.ID)
			if status.External {
				resources = declaredResources(status)
				validation = Check{ID: "external-owner", Status: "pass", Detail: "обнаружен внешний владелец; RAZVILKA не изменяет его конфиг и firewall"}
			}
			item.Resources = resources
			item.Checks = append(item.Checks, validation)
			allResources = append(allResources, resources...)
		}
		for _, check := range item.Checks {
			if check.Status == "fail" {
				itemReady = false
			}
		}
		if itemReady {
			report.Ready = true
		}
		report.Engines = append(report.Engines, item)
	}
	report.Conflicts = resourceConflicts(allResources, listening)
	if z2kRunning {
		detail := "активный внешний владелец NFQUEUE (z2k/Zapret2)"
		if !nfqws2Installed {
			detail += "; установка NFQWS2 заблокирована до освобождения ownership"
		}
		report.Conflicts = append(report.Conflicts, Conflict{Kind: "nfqueue", Value: "external-owner", Engines: []string{"nfqws2"}, SystemUse: detail, Blocking: true})
	}
	for _, conflict := range report.Conflicts {
		if conflict.Blocking {
			report.Ready = false
		}
	}
	report.Gate["active_writes"] = false
	report.Gate["mode"] = "read-only-preflight"
	report.Gate["note"] = "Engine Lab inventories capabilities and conflicts but does not change firewall, routes, DNS or running processes."
	return report
}

func declaredResources(status engine.Status) []Resource {
	out := []Resource{}
	for _, value := range status.Ownership.Ports {
		out = append(out, Resource{Kind: "port", Value: value, EngineID: status.ID, Source: "declared-external"})
	}
	for _, value := range status.Ownership.Interfaces {
		out = append(out, Resource{Kind: "interface", Value: value, EngineID: status.ID, Source: "declared-external"})
	}
	for _, value := range status.Ownership.NFQueues {
		out = append(out, Resource{Kind: "nfqueue", Value: value, EngineID: status.ID, Source: "declared-external"})
	}
	return out
}

func versionCompatibility(status engine.Status) (string, string) {
	if !status.Installed {
		return "", "not-installed"
	}
	match := semverPattern.FindStringSubmatch(status.Version)
	if len(match) == 0 {
		return "", "unknown-requires-native-validation"
	}
	patch := "0"
	if match[3] != "" {
		patch = match[3]
	}
	return match[1] + "." + match[2] + "." + patch, "native-validation-required"
}

func requirementChecks(system systemprobe.Snapshot, spec capabilitySpec) []Check {
	out := []Check{}
	if spec.NeedsIP {
		out = append(out, Check{ID: "ip-command", Status: passFail(system.IPCommand), Detail: boolDetail(system.IPCommand, "ip command is available", "ip command is required")})
	}
	if spec.NeedsTUN {
		out = append(out, Check{ID: "tun", Status: passFail(system.TUN), Detail: boolDetail(system.TUN, "/dev/net/tun is available", "/dev/net/tun is unavailable")})
	}
	if spec.NeedsNFQ {
		out = append(out,
			Check{ID: "nfqueue", Status: passFail(system.NFQueue), Detail: boolDetail(system.NFQueue, "NFQUEUE kernel support detected", "NFQUEUE kernel support is missing")},
			Check{ID: "firewall", Status: passFail(system.IPTables || system.NFTables), Detail: boolDetail(system.IPTables || system.NFTables, "iptables or nft is available", "iptables/nft is required")},
		)
	}
	return out
}

func (m *Manager) inspectConfig(engineID string) ([]Resource, Check) {
	if m.Configs == nil {
		return []Resource{}, Check{ID: "config", Status: "warn", Detail: "configuration manager is unavailable"}
	}
	content, err := m.Configs.ReadExpert(engineID, "main")
	if err != nil || content.Source == "missing" || content.Content == "" {
		return []Resource{}, Check{ID: "config", Status: "not-ready", Detail: "main configuration is missing"}
	}
	resources := extractResources(engineID, content.Content, content.Source)
	validation := m.Configs.Validate(engineID, "main")
	status := "pass"
	if !validation.OK {
		status = "fail"
	} else if !validation.Native {
		status = "warn"
	}
	detail := validation.Output
	if validation.OK && !validation.Native {
		detail = "basic validation passed; native validator was not available"
	}
	return resources, Check{ID: "config-validation", Status: status, Detail: detail}
}

func extractResources(engineID, content, source string) []Resource {
	seen := map[string]bool{}
	out := []Resource{}
	add := func(kind, value string) {
		key := kind + ":" + value
		if value == "" || seen[key] {
			return
		}
		seen[key] = true
		out = append(out, Resource{Kind: kind, Value: value, EngineID: engineID, Source: source})
	}
	for _, match := range portPattern.FindAllStringSubmatch(content, -1) {
		if port, _ := strconv.Atoi(match[1]); port > 0 && port <= 65535 {
			add("port", strconv.Itoa(port))
		}
	}
	for _, match := range queuePattern.FindAllStringSubmatch(content, -1) {
		add("nfqueue", match[1])
	}
	for _, match := range interfaceRegex.FindAllStringSubmatch(content, -1) {
		if !isGenericValue(match[1]) {
			add("interface", match[1])
		}
	}
	// JSON-aware extraction avoids missing common sing-box inbound fields when
	// their formatting does not match the line-oriented expressions above.
	var document map[string]interface{}
	if json.Unmarshal([]byte(content), &document) == nil {
		if inbounds, ok := document["inbounds"].([]interface{}); ok {
			for _, raw := range inbounds {
				inbound, _ := raw.(map[string]interface{})
				value, ok := number(inbound["listen_port"])
				if !ok {
					value, ok = number(inbound["port"])
				}
				if ok {
					add("port", value)
				}
				if value, ok := inbound["interface_name"].(string); ok {
					add("interface", value)
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Kind+out[i].Value < out[j].Kind+out[j].Value })
	return out
}

func resourceConflicts(resources []Resource, listening map[string]string) []Conflict {
	owners := map[string]map[string]bool{}
	for _, resource := range resources {
		key := resource.Kind + ":" + resource.Value
		if owners[key] == nil {
			owners[key] = map[string]bool{}
		}
		owners[key][resource.EngineID] = true
	}
	out := []Conflict{}
	for key, engineSet := range owners {
		kind, value, _ := strings.Cut(key, ":")
		engines := mapKeys(engineSet)
		systemUse := ""
		if kind == "port" {
			systemUse = listening[value]
		}
		if len(engines) > 1 || systemUse != "" {
			out = append(out, Conflict{Kind: kind, Value: value, Engines: engines, SystemUse: systemUse, Blocking: true})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Kind+out[i].Value < out[j].Kind+out[j].Value })
	return out
}

func listeningPorts() map[string]string {
	commands := [][]string{{"ss", "-lntu"}, {"netstat", "-lntu"}, {"/opt/bin/netstat", "-lntu"}}
	for _, command := range commands {
		if strings.Contains(command[0], "/") {
			if info, err := os.Stat(command[0]); err != nil || !info.Mode().IsRegular() {
				continue
			}
		} else if _, err := exec.LookPath(command[0]); err != nil {
			continue
		}
		output, err := exec.Command(command[0], command[1:]...).Output()
		if err != nil {
			continue
		}
		return parseListeningPorts(string(output))
	}
	return map[string]string{}
}

func parseListeningPorts(output string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		for _, field := range fields {
			field = strings.Trim(field, "[]")
			index := strings.LastIndexByte(field, ':')
			if index < 0 {
				continue
			}
			port := strings.TrimSpace(field[index+1:])
			if value, err := strconv.Atoi(port); err == nil && value > 0 && value <= 65535 {
				out[port] = shortLine(line)
				break
			}
		}
	}
	return out
}

func installedDetail(status engine.Status) string {
	if !status.Installed {
		return "engine is not installed"
	}
	if status.BinaryPath != "" {
		return status.BinaryPath
	}
	return "runtime binary detected"
}

func configuredDetail(status engine.Status) string {
	if status.Configured {
		return "live configuration/profile detected"
	}
	return "live configuration/profile is missing"
}

func runningDetail(status engine.Status) string {
	if status.Running {
		return "active process or tunnel interface detected"
	}
	return "engine is not active"
}

func passFail(value bool) string {
	if value {
		return "pass"
	}
	return "fail"
}

func boolDetail(value bool, yes, no string) string {
	if value {
		return yes
	}
	return no
}

func number(value interface{}) (string, bool) {
	switch typed := value.(type) {
	case float64:
		if typed > 0 && typed <= 65535 && typed == float64(int(typed)) {
			return strconv.Itoa(int(typed)), true
		}
	case json.Number:
		parsed, err := typed.Int64()
		return strconv.FormatInt(parsed, 10), err == nil && parsed > 0 && parsed <= 65535
	}
	return "", false
}

func mapKeys(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func isGenericValue(value string) bool {
	return value == "auto" || value == "dynamic" || value == "config" || value == "on" || value == "off"
}

func shortLine(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 180 {
		value = value[:180]
	}
	return value
}
