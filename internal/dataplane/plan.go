package dataplane

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/engine"
	"github.com/ArtixSx/razvilka/internal/evidence"
)

const SchemaVersion = 1

type Route struct {
	ServiceID    string   `json:"service_id"`
	ServiceName  string   `json:"service_name"`
	Selected     string   `json:"selected_route"`
	Resolved     string   `json:"resolved_route"`
	Domains      []string `json:"domains,omitempty"`
	CIDRs        []string `json:"cidrs,omitempty"`
	SourceRefs   []string `json:"source_refs,omitempty"`
	Sources      []string `json:"sources,omitempty"`
	ProbeURL     string   `json:"probe_url,omitempty"`
	AppliedRoute string   `json:"applied_route,omitempty"`
}

type Engine struct {
	ID          string `json:"id"`
	Installed   bool   `json:"installed"`
	Configured  bool   `json:"configured"`
	Running     bool   `json:"running"`
	Activatable bool   `json:"activatable"`
	Version     string `json:"version,omitempty"`
}

type HostState struct {
	IPCommand        bool   `json:"ip_command"`
	TUN              bool   `json:"tun"`
	SingBox          bool   `json:"sing_box"`
	IPTables         bool   `json:"iptables"`
	IP6Tables        bool   `json:"ip6tables"`
	NFQueueTarget    bool   `json:"nfqueue_target"`
	NFQWS2Config     bool   `json:"nfqws2_config"`
	NFQWS2ConfigPath string `json:"nfqws2_config_path,omitempty"`
	NFQWS2Init       bool   `json:"nfqws2_init"`
	NFQWS2InitPath   string `json:"nfqws2_init_path,omitempty"`
	OffloadState     string `json:"offload_state"`
	Z2KInstalled     bool   `json:"z2k_installed"`
	Z2KRunning       bool   `json:"z2k_running"`
	Z2KVersion       string `json:"z2k_version,omitempty"`
}

type ResourceConflict struct {
	Kind      string   `json:"kind"`
	Value     string   `json:"value"`
	Engines   []string `json:"engines"`
	SystemUse string   `json:"system_use,omitempty"`
}

type Input struct {
	Revision           uint64             `json:"revision"`
	SafeMode           bool               `json:"safe_mode"`
	Routes             []Route            `json:"routes"`
	Engines            []Engine           `json:"engines"`
	EngineConfigDrafts []string           `json:"engine_config_drafts,omitempty"`
	ResourceConflicts  []ResourceConflict `json:"resource_conflicts,omitempty"`
	Host               HostState          `json:"host"`
}

type Action struct {
	Order   int    `json:"order"`
	Phase   string `json:"phase"`
	Adapter string `json:"adapter"`
	Kind    string `json:"kind"`
	Target  string `json:"target"`
	Summary string `json:"summary"`
	Owned   bool   `json:"razvilka_owned"`
}

type Blocker struct {
	Code       string `json:"code"`
	Adapter    string `json:"adapter,omitempty"`
	Message    string `json:"message"`
	Resolution string `json:"resolution,omitempty"`
}

type Warning struct {
	Code    string `json:"code"`
	Adapter string `json:"adapter,omitempty"`
	Message string `json:"message"`
}

type RouteEvidence struct {
	ServiceID string         `json:"service_id"`
	Route     string         `json:"route"`
	Required  evidence.Level `json:"required_evidence"`
	Observed  evidence.Level `json:"observed_evidence"`
	Source    string         `json:"source,omitempty"`
	Note      string         `json:"note,omitempty"`
}

type Plan struct {
	SchemaVersion     int                `json:"schema_version"`
	PlanID            string             `json:"plan_id"`
	Digest            string             `json:"digest"`
	Revision          uint64             `json:"revision"`
	CreatedAt         string             `json:"created_at"`
	SafeMode          bool               `json:"safe_mode"`
	Ready             bool               `json:"ready"`
	Noop              bool               `json:"noop"`
	RouteCount        int                `json:"route_count"`
	EngineDrafts      []string           `json:"engine_config_drafts,omitempty"`
	ResourceConflicts []ResourceConflict `json:"resource_conflicts,omitempty"`
	Adapters          []string           `json:"adapters"`
	Routes            []Route            `json:"routes"`
	Actions           []Action           `json:"actions"`
	Blockers          []Blocker          `json:"blockers"`
	Warnings          []Warning          `json:"warnings"`
	RequiredEvidence  evidence.Level     `json:"required_evidence"`
	ObservedEvidence  evidence.Level     `json:"observed_evidence"`
	EvidenceNote      string             `json:"evidence_note"`
	RouteEvidence     []RouteEvidence    `json:"route_evidence"`
	Host              HostState          `json:"host"`
	Protocol          []string           `json:"protocol"`
	State             string             `json:"state"`
	Note              string             `json:"note"`
}

// DiscoverHost is read-only. It only inventories binaries, the NFQUEUE kernel
// target and the canonical nfqws2-keenetic paths used on Entware.
func DiscoverHost() HostState {
	host := HostState{
		IPCommand:    lookupAny("/opt/sbin/ip", "/opt/bin/ip", "ip"),
		TUN:          regularFile("/dev/net/tun"),
		SingBox:      lookupAny("/opt/bin/sing-box", "/opt/usr/bin/sing-box", "sing-box"),
		IPTables:     lookupAny("/opt/sbin/iptables", "/opt/bin/iptables", "iptables"),
		IP6Tables:    lookupAny("/opt/sbin/ip6tables", "/opt/bin/ip6tables", "ip6tables"),
		OffloadState: "unknown",
	}
	for _, path := range []string{"/opt/etc/nfqws2/nfqws2.conf", "/etc/nfqws2/nfqws2.conf"} {
		if regularFile(path) {
			host.NFQWS2Config = true
			host.NFQWS2ConfigPath = path
			break
		}
	}
	for _, path := range []string{"/opt/etc/init.d/S51nfqws2", "/etc/init.d/nfqws2-keenetic"} {
		if regularFile(path) {
			host.NFQWS2Init = true
			host.NFQWS2InitPath = path
			break
		}
	}
	if regularFile("/opt/zapret2/config") && regularFile("/opt/zapret2/nfq2/nfqws2") {
		host.Z2KInstalled = true
		if data, err := os.ReadFile("/opt/zapret2/.z2k-installed-tag"); err == nil {
			host.Z2KVersion = strings.TrimSpace(string(data))
		}
		for _, status := range (engine.Detector{}).Inventory() {
			if status.ID == "z2k" {
				host.Z2KRunning = status.Running
				break
			}
		}
	}
	if data, err := os.ReadFile("/proc/net/ip_tables_targets"); err == nil {
		for _, target := range strings.Fields(string(data)) {
			if target == "NFQUEUE" {
				host.NFQueueTarget = true
				break
			}
		}
	}
	return host
}

func Build(input Input) (Plan, error) {
	return BuildAt(input, time.Now().UTC())
}

func BuildAt(input Input, now time.Time) (Plan, error) {
	if now.IsZero() {
		return Plan{}, errors.New("plan time is required")
	}
	canonicalize(&input)
	encoded, err := json.Marshal(input)
	if err != nil {
		return Plan{}, fmt.Errorf("encode dataplane input: %w", err)
	}
	sum := sha256.Sum256(encoded)
	digest := hex.EncodeToString(sum[:])
	plan := Plan{
		SchemaVersion:     SchemaVersion,
		PlanID:            "dp-" + digest[:16],
		Digest:            digest,
		Revision:          input.Revision,
		CreatedAt:         now.Format(time.RFC3339),
		SafeMode:          input.SafeMode,
		RouteCount:        len(input.Routes),
		EngineDrafts:      input.EngineConfigDrafts,
		ResourceConflicts: input.ResourceConflicts,
		Routes:            input.Routes,
		RequiredEvidence:  evidence.None,
		ObservedEvidence:  evidence.None,
		EvidenceNote:      "План описывает намерение и сам по себе не подтверждает доступ. Уровень повышается только после health-check уже активированного маршрута.",
		Host:              input.Host,
		Protocol:          []string{"plan", "snapshot", "stage", "validate", "activate", "health", "commit-or-rollback"},
		State:             "planned",
		Note:              "План ничего не изменяет сам по себе. Live Apply разрешается только после проверки установленного обхода, ownership, snapshot, native validation, health и готовности rollback.",
	}
	if len(input.Routes) > 0 {
		plan.RequiredEvidence = evidence.Service
		for _, route := range input.Routes {
			plan.RouteEvidence = append(plan.RouteEvidence, RouteEvidence{ServiceID: route.ServiceID, Route: route.Resolved, Required: evidence.Service, Observed: evidence.None, Note: "Ожидается изолированный health-check уже активированного маршрута."})
		}
	}

	engineByID := make(map[string]Engine, len(input.Engines))
	for _, item := range input.Engines {
		engineByID[item.ID] = item
	}
	adapterSet := map[string]bool{}
	for _, route := range input.Routes {
		adapter := adapterID(route.Resolved)
		if adapter == "" {
			plan.Blockers = append(plan.Blockers, Blocker{Code: "UNKNOWN_ROUTE", Message: fmt.Sprintf("Маршрут %q для %s не поддерживается", route.Resolved, route.ServiceName), Resolution: "Выберите AUTO, direct или зарегистрированный обход."})
			continue
		}
		if adapter != "direct" {
			adapterSet[adapter] = true
		}
	}
	for adapter := range adapterSet {
		plan.Adapters = append(plan.Adapters, adapter)
	}
	sort.Strings(plan.Adapters)
	for _, conflict := range input.ResourceConflicts {
		adapter := ""
		for _, engineID := range conflict.Engines {
			if adapterSet[engineID] {
				adapter = engineID
				break
			}
		}
		if adapter == "" {
			continue
		}
		code := "RESOURCE_CONFLICT"
		switch conflict.Kind {
		case "port":
			code = "PORT_CONFLICT"
		case "interface":
			code = "INTERFACE_CONFLICT"
		case "nfqueue":
			code = "NFQUEUE_CONFLICT"
		case "dns":
			code = "DNS_CONFLICT"
		}
		message := fmt.Sprintf("Ресурс %s %s уже занят", conflict.Kind, conflict.Value)
		if len(conflict.Engines) > 1 {
			message = fmt.Sprintf("Ресурс %s %s одновременно заявлен обходами %s", conflict.Kind, conflict.Value, strings.Join(conflict.Engines, ", "))
		} else if conflict.SystemUse != "" {
			message += ": " + conflict.SystemUse
		}
		resolution := "Освободите ресурс или измените порт, интерфейс либо NFQUEUE в настройках конфликтующего обхода, затем обновите план."
		if conflict.Kind == "dns" {
			resolution = "Выберите безопасный режим интеграции с системным DNS (forwarder или upstream) и подтвердите ownership порта 53 перед применением."
		}
		plan.Blockers = append(plan.Blockers, Blocker{Code: code, Adapter: adapter, Message: message, Resolution: resolution})
	}
	for _, draft := range input.EngineConfigDrafts {
		engineID := strings.SplitN(draft, "/", 2)[0]
		if !adapterSet[engineID] {
			plan.Blockers = append(plan.Blockers, Blocker{
				Code:       "ENGINE_DRAFT_UNUSED",
				Adapter:    engineID,
				Message:    fmt.Sprintf("Черновик %s не связан ни с одним включённым сервисом", draft),
				Resolution: "Назначьте хотя бы один сервис этому обходу и повторите Apply либо отмените черновик в настройках обхода.",
			})
		}
	}
	plan.Noop = len(plan.Adapters) == 0 && len(plan.Blockers) == 0
	if plan.Noop {
		plan.Ready = true
		plan.State = "ready"
		plan.Note = "Все включённые сервисы используют direct: изменений firewall, DNS или маршрутов не требуется."
		return plan, nil
	}

	order := 1
	addAction := func(phase, adapter, kind, target, summary string, owned bool) {
		plan.Actions = append(plan.Actions, Action{Order: order, Phase: phase, Adapter: adapter, Kind: kind, Target: target, Summary: summary, Owned: owned})
		order++
	}
	addAction("snapshot", "manager", "journal", "/opt/var/lib/razvilka/dataplane", "Зафиксировать revision, digest и снимок только объектов RAZVILKA.", true)
	for _, adapter := range plan.Adapters {
		addAdapterActions(&plan, adapter, &order)
		engineState, exists := engineByID[adapter]
		if adapter == "xray" {
			engineState, exists = engineByID["xray"]
		}
		if !exists || !engineState.Installed {
			plan.Blockers = append(plan.Blockers, Blocker{Code: "ENGINE_NOT_INSTALLED", Adapter: adapter, Message: fmt.Sprintf("Обход %s не установлен", adapter), Resolution: "Установите компонент в разделе «Обходы», затем обновите план."})
		}
		if exists && engineState.Installed && !engineState.Configured {
			plan.Blockers = append(plan.Blockers, Blocker{Code: "ENGINE_NOT_CONFIGURED", Adapter: adapter, Message: fmt.Sprintf("Обход %s не настроен", adapter), Resolution: "Создайте или импортируйте конфигурацию и выполните native validation."})
		}
		switch adapter {
		case "nfqws2":
			addNFQWS2Preflight(&plan, input.Host)
			for _, route := range input.Routes {
				if adapterID(route.Resolved) == adapter && len(route.Sources) > 0 {
					plan.Blockers = append(plan.Blockers, Blocker{Code: "DEVICE_SCOPE_UNSUPPORTED", Adapter: adapter, Message: "NFQWS2 пока не может доказуемо ограничить обход выбранными устройствами", Resolution: "Очистите область устройств или выберите туннельный маршрут с policy routing."})
					break
				}
			}
		case "usque":
			addProxyTunnelPreflight(&plan, adapter, input.Host)
			plan.Warnings = append(plan.Warnings, Warning{Code: "USERSPACE_MEMORY", Adapter: adapter, Message: "SOCKS/MASQUE работает в userspace; перед автозапуском нужен контроль RAM и изолированный health probe."})
		case "warp-wg", "amneziawg":
			if !input.Host.IPCommand {
				plan.Blockers = append(plan.Blockers, Blocker{Code: "IP_COMMAND_MISSING", Adapter: adapter, Message: "Команда ip не найдена", Resolution: "Установите ip-full/iproute2 через Entware."})
			}
			plan.Warnings = append(plan.Warnings, Warning{Code: "ENDPOINT_BOOTSTRAP", Adapter: adapter, Message: "До активации нужен отдельный маршрут к endpoint, иначе возможен self-tunnel loop."})
		case "sing-box", "xray":
			addProxyTunnelPreflight(&plan, adapter, input.Host)
			plan.Warnings = append(plan.Warnings, Warning{Code: "PROXY_LOOP_GUARD", Adapter: adapter, Message: "До активации требуется исключить endpoint узла и управляющий трафик из проксирования."})
		}
		for _, route := range input.Routes {
			if adapterID(route.Resolved) == adapter && len(route.Sources) > 0 && adapter != "nfqws2" {
				plan.Warnings = append(plan.Warnings, Warning{Code: "DEVICE_SCOPE_KERNEL_PROBE", Adapter: adapter, Message: "Для ограниченного устройства Apply подтверждает from/to маршрут ядра; HTTP-probe с адреса LAN-клиента выполняется отдельно в аппаратных тестах."})
				break
			}
		}
		if !exists || !engineState.Activatable {
			plan.Blockers = append(plan.Blockers, Blocker{Code: "ADAPTER_ACTIVATION_PENDING", Adapter: adapter, Message: fmt.Sprintf("Для %s ещё нет транзакционного runtime-адаптера", adapter), Resolution: "Используйте обход только после появления snapshot/activate/health/rollback реализации для этой платформы."})
		}
	}
	addAction("commit", "manager", "state", "/opt/etc/razvilka/config.json", "Зафиксировать applied revision только после успешного health; иначе выполнить rollback.", true)
	if input.SafeMode {
		plan.Blockers = append(plan.Blockers, Blocker{Code: "SAFE_MODE", Message: "Safe Mode запрещает изменения firewall, DNS, TUN и policy routing", Resolution: "Проверьте план, backup и hardware preflight, затем явно разрешите Active Apply в настройках."})
	}
	plan.Blockers = uniqueBlockers(plan.Blockers)
	plan.Warnings = uniqueWarnings(plan.Warnings)
	plan.Ready = len(plan.Blockers) == 0
	if !plan.Ready {
		plan.State = "blocked"
	}
	return plan, nil
}

func addAdapterActions(plan *Plan, adapter string, order *int) {
	appendAction := func(phase, kind, target, summary string, owned bool) {
		plan.Actions = append(plan.Actions, Action{Order: *order, Phase: phase, Adapter: adapter, Kind: kind, Target: target, Summary: summary, Owned: owned})
		*order++
	}
	switch adapter {
	case "nfqws2":
		appendAction("stage", "lists", "/opt/var/lib/razvilka/dataplane/nfqws2", "Сгенерировать нормализованные domain/CIDR-листы в изолированной staging-папке.", true)
		appendAction("validate", "native", "nfqws2 + iptables", "Проверить синтаксис, NFQUEUE, WAN binding, IPv4/IPv6 и offload без записи правил.", true)
		appendAction("activate", "netfilter", "RAZVILKA-owned chain/set", "Подключить собственную цепочку атомарно, не удаляя чужие правила.", true)
	case "usque":
		appendAction("stage", "candidate", "/opt/var/lib/razvilka/dataplane/usque", "Запустить candidate SOCKS/TUN рядом с рабочим профилем.", true)
		appendAction("validate", "route", "MASQUE endpoint", "Закрепить bootstrap route и подтвердить handshake/egress.", true)
		appendAction("activate", "policy-route", "RAZVILKA-owned table", "Подключить только выбранные сервисные сети.", true)
	case "warp-wg", "amneziawg":
		appendAction("stage", "candidate", "/opt/var/lib/razvilka/dataplane/"+adapter, "Создать отдельный candidate interface без замены live-профиля.", true)
		appendAction("validate", "handshake", adapter+" endpoint", "Проверить handshake, egress и сервисные probes.", true)
		appendAction("activate", "policy-route", "RAZVILKA-owned table", "Переключить сервисные правила на подтверждённый interface.", true)
	case "sing-box", "xray":
		appendAction("stage", "candidate", "/opt/var/lib/razvilka/dataplane/"+adapter, "Сгенерировать candidate-конфиг со стабильными node ID.", true)
		appendAction("validate", "native", adapter+" check", "Выполнить native config check и локальный proxy probe.", true)
		appendAction("activate", "policy-route", "RAZVILKA-owned table", "Подключить service policy после защиты от self-proxy loop.", true)
	}
	appendAction("health", "probe", adapter, "Проверить выбранные сервисы через изолированный маршрут и сохранить evidence.", true)
}

func addNFQWS2Preflight(plan *Plan, host HostState) {
	if host.Z2KRunning {
		version := host.Z2KVersion
		if version == "" {
			version = "установленная версия"
		}
		plan.Blockers = append(plan.Blockers, Blocker{Code: "EXTERNAL_NFQUEUE_OWNER", Adapter: "nfqws2", Message: fmt.Sprintf("z2k %s уже управляет Zapret2/NFQUEUE", version), Resolution: "Не запускайте второй NFQWS2. Оставьте z2k активным как внешний обход либо явно остановите его перед передачей управления RAZVILKA."})
	}
	if !host.IPCommand {
		plan.Blockers = append(plan.Blockers, Blocker{Code: "IP_COMMAND_MISSING", Adapter: "nfqws2", Message: "Команда ip не найдена", Resolution: "Установите ip-full/iproute2 через Entware."})
	}
	if !host.IPTables {
		plan.Blockers = append(plan.Blockers, Blocker{Code: "IPTABLES_MISSING", Adapter: "nfqws2", Message: "iptables не найден", Resolution: "Установите Entware iptables и модуль Netfilter в KeeneticOS."})
	}
	if !host.NFQueueTarget {
		plan.Blockers = append(plan.Blockers, Blocker{Code: "NFQUEUE_MISSING", Adapter: "nfqws2", Message: "Ядро не сообщает target NFQUEUE", Resolution: "Установите модули Netfilter и перезапустите роутер перед повторным preflight."})
	}
	if !host.NFQWS2Config {
		plan.Blockers = append(plan.Blockers, Blocker{Code: "NFQWS2_CONFIG_MISSING", Adapter: "nfqws2", Message: "Конфигурация nfqws2-keenetic не найдена", Resolution: "Установите или обновите компонент nfqws2-keenetic."})
	}
	if !host.NFQWS2Init {
		plan.Blockers = append(plan.Blockers, Blocker{Code: "NFQWS2_INIT_MISSING", Adapter: "nfqws2", Message: "Init-скрипт nfqws2-keenetic не найден", Resolution: "Переустановите пакет nfqws2-keenetic и проверьте /opt/etc/init.d/S51nfqws2."})
	}
	if !host.IP6Tables {
		plan.Warnings = append(plan.Warnings, Warning{Code: "IPV6_NOT_READY", Adapter: "nfqws2", Message: "ip6tables не найден: IPv6 нельзя считать покрытым."})
	}
	if host.OffloadState == "unknown" || host.OffloadState == "enabled" {
		plan.Warnings = append(plan.Warnings, Warning{Code: "OFFLOAD_UNCONFIRMED", Adapter: "nfqws2", Message: "Состояние аппаратного ускорения не подтверждено; оно может обходить netfilter."})
	}
}

func addProxyTunnelPreflight(plan *Plan, adapter string, host HostState) {
	if !host.IPCommand {
		plan.Blockers = append(plan.Blockers, Blocker{Code: "IP_COMMAND_MISSING", Adapter: adapter, Message: "Команда ip не найдена", Resolution: "Установите ip-full/iproute2 через Entware."})
	}
	if !host.TUN {
		plan.Blockers = append(plan.Blockers, Blocker{Code: "TUN_MISSING", Adapter: adapter, Message: "Устройство /dev/net/tun недоступно", Resolution: "Установите компонент TUN в KeeneticOS и перезапустите роутер."})
	}
	if !host.SingBox {
		plan.Blockers = append(plan.Blockers, Blocker{Code: "TUN_SIDECAR_MISSING", Adapter: adapter, Message: "Для изолированного TUN-sidecar нужен sing-box", Resolution: "Установите компонент sing-box-go в разделе «Обходы»."})
	}
}

func adapterID(route string) string {
	route = strings.ToLower(strings.TrimSpace(route))
	switch {
	case route == "direct":
		return "direct"
	case route == "nfqws2":
		return "nfqws2"
	case route == "usque" || strings.HasPrefix(route, "usque:"):
		return "usque"
	case route == "warp-wg" || strings.HasPrefix(route, "warp-wg:"):
		return "warp-wg"
	case route == "amneziawg" || strings.HasPrefix(route, "amneziawg:"):
		return "amneziawg"
	case route == "xray" || strings.HasPrefix(route, "xray:"):
		return "xray"
	case route == "sing-box" || strings.HasPrefix(route, "sing-box:"):
		return "sing-box"
	default:
		return ""
	}
}

// AdapterID returns the runtime adapter represented by a public route value.
// Profile suffixes such as sing-box:home map to their base adapter.
func AdapterID(route string) string { return adapterID(route) }

func canonicalize(input *Input) {
	input.EngineConfigDrafts = sortedUnique(input.EngineConfigDrafts)
	for i := range input.ResourceConflicts {
		input.ResourceConflicts[i].Engines = sortedUnique(input.ResourceConflicts[i].Engines)
	}
	for i := range input.Routes {
		route := &input.Routes[i]
		route.Domains = sortedUnique(route.Domains)
		route.CIDRs = sortedUnique(route.CIDRs)
		route.SourceRefs = sortedUnique(route.SourceRefs)
		route.Sources = sortedUnique(route.Sources)
	}
	sort.Slice(input.Routes, func(i, j int) bool { return input.Routes[i].ServiceID < input.Routes[j].ServiceID })
	sort.Slice(input.Engines, func(i, j int) bool { return input.Engines[i].ID < input.Engines[j].ID })
	sort.Slice(input.ResourceConflicts, func(i, j int) bool {
		return input.ResourceConflicts[i].Kind+"\x00"+input.ResourceConflicts[i].Value < input.ResourceConflicts[j].Kind+"\x00"+input.ResourceConflicts[j].Value
	})
}

func sortedUnique(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func uniqueBlockers(values []Blocker) []Blocker {
	seen := map[string]bool{}
	out := make([]Blocker, 0, len(values))
	for _, value := range values {
		key := value.Code + "\x00" + value.Adapter + "\x00" + value.Message
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Adapter == out[j].Adapter {
			return out[i].Code < out[j].Code
		}
		return out[i].Adapter < out[j].Adapter
	})
	return out
}

func uniqueWarnings(values []Warning) []Warning {
	seen := map[string]bool{}
	out := make([]Warning, 0, len(values))
	for _, value := range values {
		key := value.Code + "\x00" + value.Adapter
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Adapter == out[j].Adapter {
			return out[i].Code < out[j].Code
		}
		return out[i].Adapter < out[j].Adapter
	})
	return out
}

func lookupAny(paths ...string) bool {
	for _, path := range paths {
		if strings.ContainsAny(path, `/\\`) {
			if regularFile(path) {
				return true
			}
			continue
		}
		if _, err := exec.LookPath(path); err == nil {
			return true
		}
	}
	return false
}

func regularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
