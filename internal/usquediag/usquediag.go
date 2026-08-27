package usquediag

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
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

type Report struct {
	OK              bool       `json:"ok"`
	State           string     `json:"state"`
	CheckedAt       string     `json:"checked_at"`
	Config          SafeConfig `json:"config"`
	Endpoints       Endpoints  `json:"endpoints"`
	EndpointRoute   string     `json:"endpoint_route_interface,omitempty"`
	Checks          []Check    `json:"checks"`
	Recommendations []string   `json:"recommendations,omitempty"`
	Note            string     `json:"note"`
}

type Manager struct {
	Runner           Runner
	HTTP             HTTPDoer
	BinaryCandidates []string
	Architecture     string
	FeedPatterns     []string
	ConfigPath       string
	SessionPath      string
	InitPath         string
	NDMCPath         string
	IPCandidates     []string
	RegistrationURL  string
}

func New() *Manager {
	return &Manager{
		Runner: execRunner{}, HTTP: &http.Client{Timeout: 12 * time.Second},
		BinaryCandidates: []string{"/opt/usr/bin/usque", "/opt/bin/usque"},
		Architecture:     runtime.GOARCH,
		FeedPatterns:     []string{"/opt/etc/opkg.conf", "/opt/etc/opkg/*.conf"},
		ConfigPath:       "/opt/etc/usque/usque.conf", SessionPath: "/opt/etc/usque/session.conf",
		InitPath: "/opt/etc/init.d/S51usque", NDMCPath: "/bin/ndmc",
		IPCandidates:    []string{"/opt/sbin/ip", "/opt/bin/ip", "ip"},
		RegistrationURL: "https://api.cloudflareclient.com/v0a4471/reg",
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

	feedCount, feedFiles := feedDeclarations(m.FeedPatterns)
	switch {
	case feedCount == 1:
		add("feed", "Репозиторий пакета", "pass", fmt.Sprintf("Найдена одна декларация usque-keenetic (%d файл).", feedFiles), "")
	case feedCount > 1:
		add("feed", "Репозиторий пакета", "warning", fmt.Sprintf("Найдено деклараций usque-keenetic: %d.", feedCount), "Оставьте одну строку feed; дубликаты мешают понимать источник обновления пакета.")
	default:
		add("feed", "Репозиторий пакета", "warning", "Репозиторий usque-keenetic не найден в конфигурации opkg.", "Добавьте официальный feed перед установкой или обновлением пакета.")
	}

	if path := firstFile(m.BinaryCandidates); path == "" {
		add("binary", "Пакет USQUE", "fail", "Исполняемый файл USQUE не найден.", "Установите usque-keenetic во вкладке «Обходы».")
	} else {
		add("binary", "Пакет USQUE", "pass", "USQUE найден: "+filepath.Base(path)+".", "")
	}

	config, configErr := readSafeConfig(m.ConfigPath)
	report.Config = config
	if configErr != nil {
		add("config", "Настройки USQUE", "fail", "Файл usque.conf отсутствует или не читается.", "Переустановите только конфигурацию пакета либо восстановите её из резервной копии.")
	} else {
		add("config", "Настройки USQUE", "pass", fmt.Sprintf("Интерфейс %s, транспорт %s, SNI %s.", fallback(config.Interface, "не задан"), config.Transport, fallback(config.SNI, "по умолчанию")), "")
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
	if regularFile(m.InitPath) {
		out, err := runner.Run(ctx, Command{Name: m.InitPath, Args: []string{"status"}})
		if err == nil && strings.Contains(strings.ToLower(string(out)), "running") {
			add("service", "Служба USQUE", "pass", "Пакетная служба запущена.", "")
		} else {
			add("service", "Служба USQUE", "warning", "Пакетная служба не запущена или не подтвердила статус.", "Не запускайте её параллельно с кандидатом RAZVILKA; сначала проверьте владельца runtime.")
		}
	}

	if config.Interface != "" {
		if ip := firstCommand(m.IPCandidates); ip != "" {
			out, err := runner.Run(ctx, Command{Name: ip, Args: []string{"-4", "addr", "show", "dev", config.Interface}})
			if err == nil && strings.Contains(string(out), config.Interface) {
				add("tun", "Интерфейс TUN", "pass", "Интерфейс "+config.Interface+" существует.", "")
			} else {
				add("tun", "Интерфейс TUN", "warning", "Интерфейс "+config.Interface+" сейчас не найден.", "Проверьте службу и ndmc; зависший OpkgTun удаляйте только после snapshot.")
			}
			endpoint := firstNonEmpty(endpoints.IPv4, endpoints.H2IPv4)
			if endpoint != "" {
				out, err := runner.Run(ctx, Command{Name: ip, Args: []string{"route", "get", endpoint}})
				if err == nil {
					report.EndpointRoute = routeInterface(string(out))
					add("endpoint-route", "Маршрут к MASQUE", "pass", "Публичный endpoint доступен через "+fallback(report.EndpointRoute, "определённый системой маршрут")+".", "")
				} else {
					add("endpoint-route", "Маршрут к MASQUE", "warning", "Маршрут до публичного endpoint не определён.", "Проверьте WAN и исключите routing loop до повторного запуска.")
				}
			}
		}
	}

	if regularFile(m.NDMCPath) {
		_, normalErr := runner.Run(ctx, Command{Name: m.NDMCPath, Args: []string{"-c", "show version"}})
		_, cleanErr := runner.Run(ctx, Command{Name: m.NDMCPath, Args: []string{"-c", "show version"}, Env: []string{"LD_LIBRARY_PATH=/lib:/usr/lib"}})
		switch {
		case normalErr == nil:
			add("ndmc", "Связь с Keenetic", "pass", "ndmc работает в текущем окружении.", "")
		case cleanErr == nil:
			add("ndmc", "Связь с Keenetic", "warning", "ndmc работает только с системными библиотеками.", "Нужен точечный backup и patch вызовов ndmc в S51usque; глобальный LD_LIBRARY_PATH не меняйте.")
		default:
			add("ndmc", "Связь с Keenetic", "fail", "ndmc не отвечает и с изолированным путём системных библиотек.", "Сначала восстановите связь Entware с Keenetic; не перерегистрируйте USQUE.")
		}
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

	hasFail, hasWarning := false, false
	for _, check := range report.Checks {
		hasFail = hasFail || check.Status == "fail"
		hasWarning = hasWarning || check.Status == "warning"
	}
	report.OK = !hasFail
	switch {
	case hasFail:
		report.State = "problem"
	case hasWarning:
		report.State = "attention"
	default:
		report.State = "ready"
	}
	return report
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
