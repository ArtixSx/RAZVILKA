package usquediag

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"time"
)

type Command struct {
	Name string
	Args []string
	Env  []string
}

type Runner interface {
	Run(context.Context, Command) ([]byte, error)
}

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type Check struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Status  string `json:"status"`
	Message string `json:"message"`
	Action  string `json:"action,omitempty"`
}

type SafeConfig struct {
	Interface string `json:"interface,omitempty"`
	Address   string `json:"address,omitempty"`
	Mask      string `json:"mask,omitempty"`
	SNI       string `json:"sni,omitempty"`
	Transport string `json:"transport"`
	Version   string `json:"version,omitempty"`
}

type Endpoints struct {
	IPv4   string `json:"ipv4,omitempty"`
	IPv6   string `json:"ipv6,omitempty"`
	H2IPv4 string `json:"http2_ipv4,omitempty"`
	H2IPv6 string `json:"http2_ipv6,omitempty"`
}

type EndpointRoute struct {
	Family         string `json:"family"`
	Endpoint       string `json:"endpoint"`
	Interface      string `json:"interface,omitempty"`
	Available      bool   `json:"available"`
	Expected       bool   `json:"expected"`
	DependencyLoop bool   `json:"dependency_loop,omitempty"`
}

type VersionInfo struct {
	Package string `json:"package,omitempty"`
	Core    string `json:"core,omitempty"`
	Config  string `json:"config,omitempty"`
	Source  string `json:"source,omitempty"`
}

type EnvironmentInfo struct {
	Architecture string `json:"architecture"`
	Binary       string `json:"binary,omitempty"`
	Init         string `json:"init,omitempty"`
	RouteTool    string `json:"route_tool,omitempty"`
	NDMCMode     string `json:"ndmc_mode"`
}

type RuntimeOwnership struct {
	Interface        string `json:"interface,omitempty"`
	ClaimedBy        string `json:"claimed_by,omitempty"`
	ServiceRunning   bool   `json:"service_running"`
	InterfacePresent bool   `json:"interface_present"`
	RuntimeOwner     string `json:"runtime_owner"`
}

type SafeFileMetadata struct {
	Name       string `json:"name"`
	Present    bool   `json:"present"`
	Mode       string `json:"mode,omitempty"`
	OwnerUID   string `json:"owner_uid,omitempty"`
	Size       int64  `json:"size,omitempty"`
	ModifiedAt string `json:"modified_at,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
}

type CanaryEvidence struct {
	CheckedAt       string   `json:"checked_at,omitempty"`
	Transport       string   `json:"transport,omitempty"`
	Warp            string   `json:"warp,omitempty"`
	Colo            string   `json:"colo,omitempty"`
	Loc             string   `json:"loc,omitempty"`
	EgressIP        string   `json:"egress_ip,omitempty"`
	ConfirmedRoutes []string `json:"confirmed_routes,omitempty"`
}

type RepairPreview struct {
	Status            string   `json:"status"`
	Needed            bool     `json:"needed"`
	Eligible          bool     `json:"eligible"`
	Summary           string   `json:"summary"`
	NDMCInvocations   int      `json:"ndmc_invocations"`
	ScopedInvocations int      `json:"scoped_invocations"`
	GlobalLibraryPath bool     `json:"global_library_path"`
	Steps             []string `json:"steps,omitempty"`
	Blockers          []string `json:"blockers,omitempty"`
}

type Report struct {
	OK              bool                        `json:"ok"`
	State           string                      `json:"state"`
	Readiness       string                      `json:"readiness"`
	CheckedAt       string                      `json:"checked_at"`
	Config          SafeConfig                  `json:"config"`
	Versions        VersionInfo                 `json:"versions"`
	Environment     EnvironmentInfo             `json:"environment"`
	Ownership       RuntimeOwnership            `json:"ownership"`
	Files           map[string]SafeFileMetadata `json:"files,omitempty"`
	LastBackup      SafeFileMetadata            `json:"last_backup"`
	Endpoints       Endpoints                   `json:"endpoints"`
	EndpointRoute   string                      `json:"endpoint_route_interface,omitempty"`
	EndpointRoutes  []EndpointRoute             `json:"endpoint_routes,omitempty"`
	Evidence        CanaryEvidence              `json:"canary_evidence"`
	NDMCRepair      RepairPreview               `json:"ndmc_repair_preview"`
	Checks          []Check                     `json:"checks"`
	Recommendations []string                    `json:"recommendations,omitempty"`
	Note            string                      `json:"note"`
}

type Manager struct {
	Runner                  Runner
	HTTP                    HTTPDoer
	BinaryCandidates        []string
	Architecture            string
	FeedPatterns            []string
	PackageStatusCandidates []string
	BackupPatterns          []string
	ConfigPath              string
	SessionPath             string
	InitPath                string
	NDMCPath                string
	IPCandidates            []string
	RegistrationURL         string
	EvidencePath            string
}

func New() *Manager {
	return &Manager{
		Runner: execRunner{}, HTTP: &http.Client{Timeout: 12 * time.Second},
		BinaryCandidates:        []string{"/opt/usr/bin/usque", "/opt/bin/usque"},
		Architecture:            runtime.GOARCH,
		FeedPatterns:            []string{"/opt/etc/opkg.conf", "/opt/etc/opkg/*.conf"},
		PackageStatusCandidates: []string{"/opt/lib/opkg/status", "/opt/var/lib/opkg/status"},
		BackupPatterns:          []string{"/opt/var/lib/razvilka/backups/usque/*", "/opt/etc/usque/*.bak", "/opt/etc/usque/backup-*/*"},
		ConfigPath:              "/opt/etc/usque/usque.conf", SessionPath: "/opt/etc/usque/session.conf",
		InitPath: "/opt/etc/init.d/S51usque", NDMCPath: "/bin/ndmc",
		IPCandidates:    []string{"/opt/sbin/ip", "/opt/bin/ip", "ip"},
		RegistrationURL: "https://api.cloudflareclient.com/v0a4471/reg",
		EvidencePath:    "/opt/var/lib/razvilka/dataplane/usque/evidence.json",
	}
}

func (m *Manager) Check(ctx context.Context) Report {
	report := Report{CheckedAt: time.Now().UTC().Format(time.RFC3339), Note: "Проверка ничего не устанавливает, не меняет DNS, маршруты, конфигурацию или сессию USQUE."}
	add := func(id, label, status, message, action string) {
		report.Checks = append(report.Checks, Check{ID: id, Label: label, Status: status, Message: message, Action: action})
		if action != "" && (status == "warning" || status == "fail") {
			report.Recommendations = append(report.Recommendations, action)
		}
	}
	architecture := strings.ToLower(strings.TrimSpace(m.Architecture))
	if architecture == "" {
		architecture = runtime.GOARCH
	}
	if architecture == "arm64" || architecture == "mips" || architecture == "mipsle" {
		add("architecture", "Архитектура", "pass", architecture+" поддерживается официальным пакетом usque-keenetic.", "")
	} else {
		add("architecture", "Архитектура", "fail", architecture+" не входит в официальный набор Keenetic-пакетов USQUE.", "Не устанавливайте пакет другой архитектуры; используйте совместимую сборку или другой обход.")
	}
	report.Environment.Architecture = architecture

	feedCount, feedFiles := feedDeclarations(m.FeedPatterns)
	switch {
	case feedCount == 1:
		add("feed", "Репозиторий пакета", "pass", fmt.Sprintf("Найдена одна декларация usque-keenetic (%d файл).", feedFiles), "")
	case feedCount > 1:
		add("feed", "Репозиторий пакета", "warning", fmt.Sprintf("Найдено деклараций usque-keenetic: %d.", feedCount), "Оставьте одну строку feed; дубликаты мешают понимать источник обновления пакета.")
	default:
		add("feed", "Репозиторий пакета", "warning", "Репозиторий usque-keenetic не найден в конфигурации opkg.", "Добавьте официальный feed перед установкой или обновлением пакета.")
	}

	binaryPath := firstFile(m.BinaryCandidates)
	if binaryPath == "" {
		add("binary", "Пакет USQUE", "fail", "Исполняемый файл USQUE не найден.", "Установите usque-keenetic во вкладке «Обходы».")
	} else {
		report.Environment.Binary = binaryPath
		add("binary", "Пакет USQUE", "pass", "USQUE найден: "+filepath.Base(binaryPath)+".", "")
	}
	report.Versions.Package, report.Versions.Core, report.Versions.Source = readInstalledVersions(m.PackageStatusCandidates)
	if report.Versions.Package != "" {
		message := "Установлен пакет usque-keenetic " + report.Versions.Package + "."
		if report.Versions.Core == "" {
			message += " Версия ядра отдельно не опубликована метаданными пакета."
		}
		add("version", "Версии USQUE", "pass", message, "")
	} else {
		add("version", "Версии USQUE", "warning", "Версия пакета не найдена в локальной базе opkg; запуск бинарника ради определения версии не выполнялся.", "Обновите локальные метаданные opkg или переустановите пакет из проверенного feed.")
	}

	config, configErr := readSafeConfig(m.ConfigPath)
	report.Config = config
	report.Versions.Config = config.Version
	report.Files = map[string]SafeFileMetadata{
		"config":  inspectFile(m.ConfigPath),
		"session": inspectFile(m.SessionPath),
		"binary":  inspectFile(binaryPath),
		"init":    inspectFile(m.InitPath),
	}
	report.LastBackup = latestFileMetadata(m.BackupPatterns)
	if configErr != nil {
		add("config", "Настройки USQUE", "fail", "Файл usque.conf отсутствует или не читается.", "Переустановите только конфигурацию пакета либо восстановите её из резервной копии.")
		add("interface-config", "Интерфейс USQUE", "skipped", "IFACE нельзя проверить, пока usque.conf отсутствует или не читается.", "")
	} else if config.Interface == "" {
		add("config", "Настройки USQUE", "pass", fmt.Sprintf("Транспорт %s, SNI %s.", config.Transport, fallback(config.SNI, "по умолчанию")), "")
		add("interface-config", "Интерфейс USQUE", "fail", "В usque.conf не задан обязательный IFACE, поэтому состояние TUN проверить нельзя.", "Укажите интерфейс пакета USQUE либо восстановите последнюю рабочую конфигурацию.")
	} else {
		add("config", "Настройки USQUE", "pass", fmt.Sprintf("Интерфейс %s, транспорт %s, SNI %s.", fallback(config.Interface, "не задан"), config.Transport, fallback(config.SNI, "по умолчанию")), "")
		add("interface-config", "Интерфейс USQUE", "pass", "Для диагностики выбран интерфейс "+config.Interface+".", "")
	}

	endpoints, secretsOK, modeOK, sessionErr := readSafeSession(m.SessionPath)
	report.Endpoints = endpoints
	if sessionErr != nil {
		add("session", "Сессия Cloudflare", "fail", "session.conf отсутствует, повреждён или не является JSON.", "Не удаляйте старую сессию. Сначала создайте backup, затем используйте мастер восстановления USQUE.")
	} else if !secretsOK {
		add("session", "Сессия Cloudflare", "fail", "В сессии отсутствуют обязательные поля регистрации; их значения не выводились.", "Восстановите последнюю рабочую сессию или создайте отдельного кандидата после backup.")
	} else if !modeOK {
		add("session", "Сессия Cloudflare", "warning", "Сессия читается, но права файла шире рекомендуемых 0600.", "Ограничьте права session.conf до 0600.")
	} else {
		add("session", "Сессия Cloudflare", "pass", "Обязательные поля присутствуют, секретные значения скрыты.", "")
	}

	runner := m.Runner
	if runner == nil {
		runner = execRunner{}
	}
	serviceRunning := false
	if regularFile(m.InitPath) {
		report.Environment.Init = m.InitPath
		out, err := runner.Run(ctx, Command{Name: m.InitPath, Args: []string{"status"}})
		if err == nil && strings.Contains(strings.ToLower(string(out)), "running") {
			serviceRunning = true
			add("service", "Служба USQUE", "pass", "Пакетная служба запущена.", "")
		} else {
			add("service", "Служба USQUE", "warning", "Пакетная служба не запущена или не подтвердила статус.", "Не запускайте её параллельно с кандидатом RAZVILKA; сначала проверьте владельца runtime.")
		}
	} else {
		add("service-init", "Запуск USQUE", "fail", "Ожидаемый init-скрипт S51usque не найден; состояние службы не проверялось.", "Переустановите пакет usque-keenetic или восстановите его init-скрипт из проверенной резервной копии.")
	}

	addTunnelSkipped := func(reason string) {
		for _, item := range []struct{ id, label string }{
			{"tun-ipv4", "TUN IPv4"}, {"tun-ipv6", "TUN IPv6"},
			{"endpoint-route-ipv4", "MASQUE IPv4"}, {"endpoint-route-ipv6", "MASQUE IPv6"},
		} {
			add(item.id, item.label, "skipped", reason, "")
		}
	}
	interfacePresent := false
	ipCommand := firstCommand(m.IPCandidates)
	if ipCommand != "" {
		report.Environment.RouteTool = ipCommand
	}
	if configErr != nil {
		addTunnelSkipped("Проверка пропущена: сначала нужен читаемый usque.conf с интерфейсом IFACE.")
	} else if config.Interface == "" {
		addTunnelSkipped("Проверка пропущена: в usque.conf не задан интерфейс IFACE.")
	} else {
		if ip := ipCommand; ip != "" {
			for _, family := range []struct{ name, flag string }{{"IPv4", "-4"}, {"IPv6", "-6"}} {
				out, err := runner.Run(ctx, Command{Name: ip, Args: []string{family.flag, "addr", "show", "dev", config.Interface}})
				if err == nil && strings.Contains(string(out), config.Interface) {
					interfacePresent = true
					add("tun-"+strings.ToLower(family.name), "TUN "+family.name, "pass", "Интерфейс "+config.Interface+" имеет "+family.name+" состояние.", "")
				} else {
					add("tun-"+strings.ToLower(family.name), "TUN "+family.name, "warning", family.name+" на интерфейсе "+config.Interface+" сейчас не подтверждён.", "Проверьте семейство адресов отдельно; отсутствие IPv6 не должно скрывать рабочий IPv4.")
				}
			}
			for _, route := range []struct{ family, endpoint string }{{"IPv4", firstNonEmpty(endpoints.IPv4, endpoints.H2IPv4)}, {"IPv6", firstNonEmpty(endpoints.IPv6, endpoints.H2IPv6)}} {
				if route.endpoint == "" {
					add("endpoint-route-"+strings.ToLower(route.family), "MASQUE "+route.family, "warning", "В сессии нет публичного endpoint "+route.family+".", "Используйте доступное семейство; не считайте отсутствие IPv6 отказом IPv4.")
					continue
				}
				args := []string{"route", "get", route.endpoint}
				if route.family == "IPv6" {
					args = append([]string{"-6"}, args...)
				}
				out, err := runner.Run(ctx, Command{Name: ip, Args: args})
				item := EndpointRoute{Family: route.family, Endpoint: route.endpoint, Available: err == nil}
				if err == nil {
					item.Interface = routeInterface(string(out))
					item.DependencyLoop = item.Interface != "" && item.Interface == config.Interface
					item.Expected = !item.DependencyLoop
					if route.family == "IPv4" {
						report.EndpointRoute = item.Interface
					}
					if item.DependencyLoop {
						add("endpoint-route-"+strings.ToLower(route.family), "MASQUE "+route.family, "fail", "Endpoint Cloudflare направлен обратно в "+config.Interface+"; это routing loop.", "Верните маршрут endpoint во внешний WAN. Не запускайте USQUE до устранения петли.")
					} else {
						add("endpoint-route-"+strings.ToLower(route.family), "MASQUE "+route.family, "pass", "Endpoint доступен через "+fallback(item.Interface, "определённый системой маршрут")+" вне собственного TUN.", "")
					}
				} else {
					add("endpoint-route-"+strings.ToLower(route.family), "MASQUE "+route.family, "warning", "Маршрут до endpoint не определён.", "Проверьте WAN и исключите routing loop до повторного запуска.")
				}
				report.EndpointRoutes = append(report.EndpointRoutes, item)
			}
		} else {
			addTunnelSkipped("Проверка пропущена: утилита ip не найдена, поэтому состояние интерфейса и маршрутов неизвестно.")
		}
	}
	report.Ownership = RuntimeOwnership{
		Interface: config.Interface, ClaimedBy: "usque.conf", ServiceRunning: serviceRunning,
		InterfacePresent: interfacePresent, RuntimeOwner: "not-confirmed",
	}
	if config.Interface == "" {
		report.Ownership.ClaimedBy = ""
	}
	if serviceRunning && interfacePresent {
		report.Ownership.RuntimeOwner = "consistent-with-usque-init"
	}

	if evidence, err := readCanaryEvidence(m.EvidencePath); err == nil {
		report.Evidence = evidence
		warpOK := evidence.Warp == "on" || evidence.Warp == "plus"
		if warpOK {
			message := "Последний изолированный кандидат подтвердил warp=" + evidence.Warp + "."
			if evidence.Colo != "" || evidence.Loc != "" {
				message += " POP " + fallback(evidence.Colo, "неизвестен") + ", локация " + fallback(evidence.Loc, "неизвестна") + "."
			}
			add("warp-evidence", "Технический WARP", "pass", message, "")
		} else {
			add("warp-evidence", "Технический WARP", "warning", "Последний кандидат не подтвердил warp=on.", "Повторите изолированную проверку профиля; рабочий маршрут не меняйте.")
		}
		if len(evidence.ConfirmedRoutes) > 0 {
			add("service-evidence", "Проверка сервиса", "pass", "После WARP отдельно ответили: "+strings.Join(evidence.ConfirmedRoutes, ", ")+".", "")
		} else {
			add("service-evidence", "Проверка сервиса", "warning", "WARP и доступность выбранного сервиса ещё не подтверждены вместе.", "Назначьте USQUE одному сервису и выполните применение с canary.")
		}
	} else {
		add("warp-evidence", "Технический WARP", "warning", "Нет сохранённого результата изолированного canary.", "Назначьте USQUE выбранному сервису и выполните безопасное применение; текущий маршрут не будет заменён при ошибке.")
	}

	if regularFile(m.NDMCPath) {
		_, normalErr := runner.Run(ctx, Command{Name: m.NDMCPath, Args: []string{"-c", "show version"}})
		_, cleanErr := runner.Run(ctx, Command{Name: m.NDMCPath, Args: []string{"-c", "show version"}, Env: []string{"LD_LIBRARY_PATH=/lib:/usr/lib"}})
		switch {
		case normalErr == nil:
			report.Environment.NDMCMode = "current-environment"
			add("ndmc", "Связь с Keenetic", "pass", "ndmc работает в текущем окружении.", "")
		case cleanErr == nil:
			report.Environment.NDMCMode = "system-libraries-only"
			add("ndmc", "Связь с Keenetic", "warning", "ndmc работает только с системными библиотеками.", "Нужен точечный backup и patch вызовов ndmc в S51usque; глобальный LD_LIBRARY_PATH не меняйте.")
		default:
			report.Environment.NDMCMode = "unavailable"
			add("ndmc", "Связь с Keenetic", "fail", "ndmc не отвечает и с изолированным путём системных библиотек.", "Сначала восстановите связь Entware с Keenetic; не перерегистрируйте USQUE.")
		}
	} else {
		report.Environment.NDMCMode = "not-found"
	}
	report.NDMCRepair = previewNDMCRepair(m.InitPath, report.Environment.NDMCMode)
	switch report.NDMCRepair.Status {
	case "needed":
		add("ndmc-init", "Безопасный вызов ndmc", "warning", report.NDMCRepair.Summary, "Просмотрите план ремонта; автоматическое изменение init-скрипта пока не выполняется.")
	case "blocked":
		add("ndmc-init", "Безопасный вызов ndmc", "warning", report.NDMCRepair.Summary, "Устраните блокирующие причины до ремонта init-скрипта.")
	default:
		add("ndmc-init", "Безопасный вызов ndmc", "pass", report.NDMCRepair.Summary, "")
	}

	if m.HTTP != nil && m.RegistrationURL != "" {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, m.RegistrationURL, nil)
		resp, err := m.HTTP.Do(req)
		if err != nil {
			add("cloudflare-api", "Cloudflare API", "warning", "TLS/HTTPS до API регистрации не подтверждён.", "Проверьте время, CA, DNS и bootstrap NFQWS2 до создания новой сессии.")
		} else {
			_ = resp.Body.Close()
			status := "pass"
			if resp.StatusCode >= 500 {
				status = "warning"
			}
			add("cloudflare-api", "Cloudflare API", status, fmt.Sprintf("Получен HTTP %d; TLS-соединение установлено.", resp.StatusCode), "Повторите позже, если Cloudflare возвращает 5xx.")
		}
	}

	hasFail, hasWarning, hasSkipped := false, false, false
	for _, check := range report.Checks {
		hasFail = hasFail || check.Status == "fail"
		hasWarning = hasWarning || check.Status == "warning"
		hasSkipped = hasSkipped || check.Status == "skipped"
	}
	report.OK = !hasFail
	switch {
	case hasFail:
		report.State = "problem"
		report.Readiness = "BLOCKED"
	case hasSkipped:
		report.State = "attention"
		report.Readiness = "UNKNOWN"
	case hasWarning:
		report.State = "attention"
		report.Readiness = "DEGRADED"
	default:
		report.State = "ready"
		report.Readiness = "READY"
	}
	return report
}

func previewNDMCRepair(initPath, ndmcMode string) RepairPreview {
	preview := RepairPreview{
		Status:  "blocked",
		Summary: "Ремонт ndmc недоступен: init-скрипт USQUE не найден или не читается.",
		Steps: []string{
			"Создать закрытую резервную копию init-скрипта.",
			"Изменить только строки вызова /bin/ndmc, не задавая глобальный LD_LIBRARY_PATH.",
			"Проверить синтаксис, ndmc в чистом окружении и запуск USQUE.",
			"При любой ошибке атомарно вернуть резервную копию.",
		},
	}
	b, err := os.ReadFile(initPath)
	if err != nil || len(b) == 0 || len(b) > 1<<20 {
		preview.Blockers = []string{"init-скрипт отсутствует, пуст или превышает безопасный размер"}
		return preview
	}
	for _, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "export LD_LIBRARY_PATH=") || strings.HasPrefix(line, "LD_LIBRARY_PATH=") && !strings.Contains(line, "ndmc") {
			preview.GlobalLibraryPath = true
		}
		if !strings.Contains(line, "ndmc") || strings.HasPrefix(line, "#") {
			continue
		}
		preview.NDMCInvocations++
		if strings.Contains(line, "LD_LIBRARY_PATH=/lib:/usr/lib") {
			preview.ScopedInvocations++
		}
	}
	if preview.GlobalLibraryPath {
		preview.Blockers = append(preview.Blockers, "init-скрипт содержит глобальное изменение LD_LIBRARY_PATH")
	}
	if preview.NDMCInvocations == 0 {
		preview.Blockers = append(preview.Blockers, "в init-скрипте не найдены вызовы ndmc")
	}
	if ndmcMode == "unavailable" || ndmcMode == "not-found" {
		preview.Blockers = append(preview.Blockers, "ndmc не прошёл read-only проверку")
	}
	if len(preview.Blockers) > 0 {
		preview.Summary = "Точечный ремонт ndmc заблокирован до устранения обнаруженных условий."
		return preview
	}
	preview.Eligible = true
	if preview.ScopedInvocations == preview.NDMCInvocations {
		preview.Status = "protected"
		preview.Summary = fmt.Sprintf("Все вызовы ndmc (%d) уже используют системные библиотеки только для своей команды; ремонт не нужен.", preview.NDMCInvocations)
		return preview
	}
	if ndmcMode == "system-libraries-only" {
		preview.Status = "needed"
		preview.Needed = true
		preview.Summary = fmt.Sprintf("Из %d вызовов ndmc безопасное окружение задано для %d; доступен только точечный ремонт с backup и rollback.", preview.NDMCInvocations, preview.ScopedInvocations)
		return preview
	}
	preview.Status = "not-needed"
	preview.Summary = "ndmc работает в текущем окружении; init-скрипт менять не требуется."
	return preview
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, command Command) ([]byte, error) {
	cmd := exec.CommandContext(ctx, command.Name, command.Args...)
	if len(command.Env) > 0 {
		cmd.Env = append(os.Environ(), command.Env...)
	}
	return cmd.CombinedOutput()
}

var safeName = regexp.MustCompile(`^[A-Za-z0-9_.:-]+$`)

func readSafeConfig(path string) (SafeConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return SafeConfig{Transport: "QUIC"}, err
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), "=", 2)
		if len(parts) != 2 {
			continue
		}
		value := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
		if safeName.MatchString(value) {
			values[parts[0]] = value
		}
	}
	transport := "QUIC"
	if values["HTTP2_ENABLE"] == "1" {
		transport = "HTTP/2"
	}
	return SafeConfig{Interface: values["IFACE"], Address: values["IFACE_IP"], Mask: values["IFACE_MASK"], SNI: values["SNI"], Transport: transport, Version: values["CONFIG_VERSION"]}, nil
}

func readSafeSession(path string) (Endpoints, bool, bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Endpoints{}, false, false, err
	}
	var values map[string]json.RawMessage
	if err := json.Unmarshal(b, &values); err != nil {
		return Endpoints{}, false, false, err
	}
	rawString := func(key string) string {
		var value string
		if json.Unmarshal(values[key], &value) != nil {
			return ""
		}
		return value
	}
	stringValue := func(key string) string {
		value := rawString(key)
		if !safeName.MatchString(value) {
			return ""
		}
		return value
	}
	endpoints := Endpoints{IPv4: stringValue("endpoint_v4"), IPv6: stringValue("endpoint_v6"), H2IPv4: stringValue("endpoint_h2_v4"), H2IPv6: stringValue("endpoint_h2_v6")}
	required := []string{"private_key", "endpoint_pub_key", "id", "access_token"}
	valid := true
	for _, key := range required {
		if len(values[key]) == 0 || rawString(key) == "" {
			valid = false
		}
	}
	info, err := os.Stat(path)
	return endpoints, valid, err == nil && info.Mode().Perm()&0o077 == 0, nil
}

func readCanaryEvidence(path string) (CanaryEvidence, error) {
	if strings.TrimSpace(path) == "" {
		return CanaryEvidence{}, os.ErrNotExist
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return CanaryEvidence{}, err
	}
	if len(b) > 64*1024 {
		return CanaryEvidence{}, fmt.Errorf("USQUE canary evidence is too large")
	}
	var evidence CanaryEvidence
	if err := json.Unmarshal(b, &evidence); err != nil {
		return CanaryEvidence{}, err
	}
	evidence.Warp = strings.ToLower(strings.TrimSpace(evidence.Warp))
	if evidence.Warp != "on" && evidence.Warp != "plus" && evidence.Warp != "off" {
		evidence.Warp = "unknown"
	}
	if !regexp.MustCompile(`^[A-Z0-9]{3}$`).MatchString(evidence.Colo) {
		evidence.Colo = ""
	}
	if !regexp.MustCompile(`^[A-Z]{2}$`).MatchString(evidence.Loc) {
		evidence.Loc = ""
	}
	if net.ParseIP(evidence.EgressIP) == nil {
		evidence.EgressIP = ""
	}
	if _, err := time.Parse(time.RFC3339, evidence.CheckedAt); err != nil {
		evidence.CheckedAt = ""
	}
	confirmed := make([]string, 0, len(evidence.ConfirmedRoutes))
	for _, name := range evidence.ConfirmedRoutes {
		name = strings.TrimSpace(name)
		if len(name) > 0 && len(name) <= 80 && !strings.ContainsAny(name, "\r\n\t") {
			confirmed = append(confirmed, name)
		}
	}
	evidence.ConfirmedRoutes = confirmed
	return evidence, nil
}

var safeVersion = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~:-]{0,79}$`)

func readInstalledVersions(paths []string) (packageVersion, coreVersion, source string) {
	for _, path := range paths {
		b, err := os.ReadFile(path)
		if err != nil || len(b) > 4*1024*1024 {
			continue
		}
		versions := map[string]string{}
		for _, stanza := range strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n\n") {
			fields := map[string]string{}
			for _, line := range strings.Split(stanza, "\n") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					fields[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
				}
			}
			name, version := fields["Package"], fields["Version"]
			if safeName.MatchString(name) && safeVersion.MatchString(version) {
				versions[name] = version
			}
		}
		packageVersion = versions["usque-keenetic"]
		coreVersion = firstNonEmpty(versions["usque"], versions["usque-core"])
		if packageVersion != "" || coreVersion != "" {
			return packageVersion, coreVersion, path
		}
	}
	return "", "", ""
}

const maximumDiagnosticDigestSize = 32 * 1024 * 1024

func inspectFile(path string) SafeFileMetadata {
	metadata := SafeFileMetadata{Name: filepath.Base(path)}
	if strings.TrimSpace(path) == "" {
		metadata.Name = ""
		return metadata
	}
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return metadata
	}
	metadata.Present = true
	metadata.Mode = fmt.Sprintf("%04o", info.Mode().Perm())
	metadata.Size = info.Size()
	metadata.ModifiedAt = info.ModTime().UTC().Format(time.RFC3339)
	metadata.OwnerUID = ownerUID(info)
	if info.Size() > maximumDiagnosticDigestSize {
		return metadata
	}
	file, err := os.Open(path)
	if err != nil {
		return metadata
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, maximumDiagnosticDigestSize+1)); err == nil {
		metadata.SHA256 = fmt.Sprintf("%x", hash.Sum(nil))
	}
	return metadata
}

func ownerUID(info os.FileInfo) string {
	value := reflect.ValueOf(info.Sys())
	if !value.IsValid() {
		return ""
	}
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return ""
		}
		value = value.Elem()
	}
	if value.Kind() != reflect.Struct {
		return ""
	}
	field := value.FieldByName("Uid")
	if !field.IsValid() {
		return ""
	}
	switch field.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return fmt.Sprint(field.Uint())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return fmt.Sprint(field.Int())
	default:
		return ""
	}
}

func latestFileMetadata(patterns []string) SafeFileMetadata {
	var latest SafeFileMetadata
	var latestTime time.Time
	seen := map[string]bool{}
	for _, pattern := range patterns {
		matches := []string{pattern}
		if strings.ContainsAny(pattern, "*?[") {
			matches, _ = filepath.Glob(pattern)
		}
		for _, path := range matches {
			if seen[path] {
				continue
			}
			seen[path] = true
			info, err := os.Stat(path)
			if err != nil || info.IsDir() || !info.ModTime().After(latestTime) {
				continue
			}
			latestTime = info.ModTime()
			latest = inspectFile(path)
		}
	}
	return latest
}

func firstFile(paths []string) string {
	for _, path := range paths {
		if regularFile(path) {
			return path
		}
	}
	return ""
}

func feedDeclarations(patterns []string) (declarations, files int) {
	seen := map[string]bool{}
	for _, pattern := range patterns {
		matches := []string{pattern}
		if strings.ContainsAny(pattern, "*?[") {
			matches, _ = filepath.Glob(pattern)
		}
		for _, path := range matches {
			if seen[path] {
				continue
			}
			seen[path] = true
			b, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			files++
			for _, line := range strings.Split(string(b), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "src/gz usque-keenetic ") && strings.Contains(line, "side-effect-tm.github.io/usque-keenetic/") {
					declarations++
				}
			}
		}
	}
	return declarations, files
}

func firstCommand(paths []string) string {
	for _, path := range paths {
		if strings.ContainsAny(path, `/\\`) {
			if regularFile(path) {
				return path
			}
		} else if found, err := exec.LookPath(path); err == nil {
			return found
		}
	}
	return ""
}

func regularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func routeInterface(output string) string {
	fields := strings.Fields(output)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "dev" && safeName.MatchString(fields[i+1]) {
			return fields[i+1]
		}
	}
	return ""
}

func fallback(value, other string) string {
	if value == "" {
		return other
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
