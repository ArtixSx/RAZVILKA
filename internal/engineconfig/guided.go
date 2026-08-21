package engineconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"unicode"
)

type GuidedOption struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

type GuidedField struct {
	ID          string         `json:"id"`
	Label       string         `json:"label"`
	Group       string         `json:"group"`
	Type        string         `json:"type"`
	Description string         `json:"description,omitempty"`
	Placeholder string         `json:"placeholder,omitempty"`
	Options     []GuidedOption `json:"options,omitempty"`
	Required    bool           `json:"required,omitempty"`
	Min         int            `json:"min,omitempty"`
	Max         int            `json:"max,omitempty"`
	Default     string         `json:"default,omitempty"`
}

type GuidedView struct {
	EngineID  string            `json:"engine_id"`
	FileID    string            `json:"file_id"`
	Format    string            `json:"format"`
	Source    string            `json:"source"`
	Supported bool              `json:"supported"`
	Message   string            `json:"message,omitempty"`
	Fields    []GuidedField     `json:"fields"`
	Values    map[string]string `json:"values"`
}

func (m *Manager) Guided(engineID, fileID string) (GuidedView, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, file, err := lookup(engineID, fileID)
	if err != nil {
		return GuidedView{}, err
	}
	fields := guidedFields(engineID, fileID)
	view := GuidedView{EngineID: engineID, FileID: fileID, Format: file.Syntax, Supported: len(fields) > 0, Fields: fields, Values: map[string]string{}}
	for _, field := range fields {
		view.Values[field.ID] = field.Default
	}
	if len(fields) == 0 {
		view.Message = "Для этого файла простой редактор не требуется: используйте список или экспертный режим."
		return view, nil
	}
	b, source, err := m.rawLocked(engineID, fileID)
	if errors.Is(err, os.ErrNotExist) {
		view.Source = "missing"
		return view, nil
	}
	if err != nil {
		return GuidedView{}, err
	}
	view.Source = source
	values, err := decodeGuided(file.Syntax, b, fields)
	if err != nil {
		return GuidedView{}, err
	}
	for _, field := range fields {
		if values[field.ID] == "" && field.Default != "" {
			values[field.ID] = field.Default
		}
	}
	view.Values = values
	return view, nil
}

func (m *Manager) StageGuided(engineID, fileID string, values map[string]string) (Content, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, file, err := lookup(engineID, fileID)
	if err != nil {
		return Content{}, err
	}
	fields := guidedFields(engineID, fileID)
	if len(fields) == 0 {
		return Content{}, errors.New("guided editor is not available for this file")
	}
	known := make(map[string]GuidedField, len(fields))
	for _, field := range fields {
		known[field.ID] = field
	}
	for id, value := range values {
		field, ok := known[id]
		if !ok {
			return Content{}, fmt.Errorf("unknown guided field %q", id)
		}
		if err := validateGuidedValue(field, value); err != nil {
			return Content{}, fmt.Errorf("%s: %w", field.Label, err)
		}
	}
	b, _, err := m.rawLocked(engineID, fileID)
	if errors.Is(err, os.ErrNotExist) {
		switch file.Syntax {
		case "json":
			b = []byte("{}\n")
		case "ini":
			b = []byte("[Interface]\n\n[Peer]\n")
		default:
			b = nil
		}
	} else if err != nil {
		return Content{}, err
	}
	updated, err := encodeGuided(file.Syntax, b, fields, values)
	if err != nil {
		return Content{}, err
	}
	if len(updated) > maxConfigBytes {
		return Content{}, errors.New("config is too large")
	}
	path := m.stagePath(engineID, fileID)
	if err := os.MkdirAll(filepathDir(path), 0o700); err != nil {
		return Content{}, err
	}
	if err := writeAtomic(path, updated, 0o600); err != nil {
		return Content{}, err
	}
	livePath := choosePath(file.Paths)
	return Content{EngineID: engineID, FileID: fileID, Path: livePath, Source: "staged", SHA256: sum(updated), Sensitive: file.Sensitive}, nil
}

func (m *Manager) rawLocked(engineID, fileID string) ([]byte, string, error) {
	_, file, err := lookup(engineID, fileID)
	if err != nil {
		return nil, "", err
	}
	path := choosePath(file.Paths)
	source := "live"
	if staged := m.stagePath(engineID, fileID); fileExists(staged) {
		path, source = staged, "staged"
	}
	if !fileExists(path) {
		return nil, "missing", os.ErrNotExist
	}
	b, err := readLimited(path)
	return b, source, err
}

func guidedFields(engineID, fileID string) []GuidedField {
	if fileID != "main" {
		return nil
	}
	switch engineID {
	case "nfqws2":
		return []GuidedField{
			{ID: "NFQWS_EXTRA_ARGS", Label: "Режим обработки", Group: "Основное", Type: "select", Required: true, Default: "$MODE_AUTO", Options: []GuidedOption{{"$MODE_AUTO", "Авто — обучаемый список"}, {"$MODE_LIST", "Только user.list"}, {"$MODE_ALL", "Весь трафик кроме исключений"}}},
			{ID: "ISP_INTERFACE", Label: "WAN-интерфейс", Group: "Основное", Type: "interfaces", Description: "Обычно определяется установщиком; можно указать несколько через пробел."},
			{ID: "IPV6_ENABLED", Label: "Обрабатывать IPv6", Group: "Сеть", Type: "toggle", Default: "1", Options: []GuidedOption{{"1", "Включено"}, {"0", "Выключено"}}},
			{ID: "TCP_PORTS", Label: "TCP-порты", Group: "Сеть", Type: "ports", Default: "80,443", Placeholder: "80,443,2053"},
			{ID: "UDP_PORTS", Label: "UDP-порты", Group: "Сеть", Type: "ports", Default: "443", Placeholder: "443,3478:3481"},
			{ID: "POLICY_NAME", Label: "Политика Keenetic", Group: "Маршрутизация", Type: "identifier", Default: "nfqws", Placeholder: "nfqws"},
			{ID: "POLICY_EXCLUDE", Label: "Политика-исключение", Group: "Маршрутизация", Type: "toggle", Default: "0", Options: []GuidedOption{{"1", "Да"}, {"0", "Нет"}}},
			{ID: "NFQWS_BASE_ARGS", Label: "Базовые аргументы", Group: "Стратегии", Type: "arguments", Description: "Общие безопасные аргументы nfqws2. Командные подстановки запрещены."},
			{ID: "NFQWS_ARGS", Label: "HTTPS / TCP стратегия", Group: "Стратегии", Type: "arguments", Placeholder: "--filter-tcp=443 --dpi-desync=fake,split2"},
			{ID: "NFQWS_ARGS_QUIC", Label: "QUIC стратегия", Group: "Стратегии", Type: "arguments", Placeholder: "--filter-udp=443 --dpi-desync=fake"},
			{ID: "NFQWS_ARGS_UDP", Label: "Прочий UDP", Group: "Стратегии", Type: "arguments"},
			{ID: "NFQWS_ARGS_IPSET", Label: "IP/CIDR стратегия", Group: "Стратегии", Type: "arguments"},
			{ID: "NFQWS_ARGS_CUSTOM", Label: "Дополнительные стратегии", Group: "Стратегии", Type: "arguments", Description: "Несколько стратегий можно разделить флагом --new."},
			{ID: "NFQUEUE_NUM", Label: "Номер NFQUEUE", Group: "Дополнительно", Type: "number", Default: "300", Min: 1, Max: 65535},
			{ID: "LOG_LEVEL", Label: "Отладочный лог", Group: "Дополнительно", Type: "toggle", Default: "0", Options: []GuidedOption{{"1", "Включён"}, {"0", "Выключен"}}},
		}
	case "usque":
		return []GuidedField{
			{ID: "endpoint_v4", Label: "MASQUE endpoint IPv4", Group: "QUIC / HTTP3", Type: "ip"},
			{ID: "endpoint_v6", Label: "MASQUE endpoint IPv6", Group: "QUIC / HTTP3", Type: "ip"},
			{ID: "endpoint_h2_v4", Label: "HTTP/2 endpoint IPv4", Group: "TCP fallback", Type: "ip", Default: "162.159.198.2", Placeholder: "162.159.198.2"},
			{ID: "endpoint_h2_v6", Label: "HTTP/2 endpoint IPv6", Group: "TCP fallback", Type: "ip"},
			{ID: "ipv4", Label: "Адрес внутри WARP IPv4", Group: "Назначенные адреса", Type: "ip"},
			{ID: "ipv6", Label: "Адрес внутри WARP IPv6", Group: "Назначенные адреса", Type: "ip"},
		}
	case "warp-wg":
		return wireGuardFields(false)
	case "amneziawg":
		return wireGuardFields(true)
	case "sing-box":
		return []GuidedField{
			{ID: "log.level", Label: "Уровень логов", Group: "Диагностика", Type: "select", Default: "warn", Options: []GuidedOption{{"warn", "Предупреждения"}, {"info", "Информация"}, {"debug", "Отладка"}, {"error", "Только ошибки"}}},
			{ID: "log.timestamp", Label: "Время в логах", Group: "Диагностика", Type: "boolean", Default: "true"},
			{ID: "route.auto_detect_interface", Label: "Определять интерфейс автоматически", Group: "Маршрутизация", Type: "boolean", Default: "true"},
			{ID: "inbounds.0.tag", Label: "Имя первого входа", Group: "Первый inbound", Type: "identifier", Placeholder: "socks-in"},
			{ID: "inbounds.0.listen", Label: "Адрес прослушивания", Group: "Первый inbound", Placeholder: "127.0.0.1", Description: "Для локального proxy используйте loopback, а не 0.0.0.0."},
			{ID: "inbounds.0.listen_port", Label: "Порт", Group: "Первый inbound", Type: "number", Min: 1, Max: 65535},
			{ID: "outbounds.0.tag", Label: "Имя первого выхода", Group: "Первый outbound", Type: "identifier", Placeholder: "proxy-out"},
			{ID: "outbounds.0.server", Label: "Сервер", Group: "Первый outbound", Placeholder: "example.com"},
			{ID: "outbounds.0.server_port", Label: "Порт сервера", Group: "Первый outbound", Type: "number", Min: 1, Max: 65535},
		}
	case "xray":
		return []GuidedField{
			{ID: "log.loglevel", Label: "Уровень логов", Group: "Диагностика", Type: "select", Default: "warning", Options: []GuidedOption{{"warning", "Предупреждения"}, {"info", "Информация"}, {"debug", "Отладка"}, {"error", "Только ошибки"}, {"none", "Выключены"}}},
			{ID: "inbounds.0.tag", Label: "Имя первого входа", Group: "Первый inbound", Type: "identifier", Placeholder: "socks-in"},
			{ID: "inbounds.0.listen", Label: "Адрес прослушивания", Group: "Первый inbound", Placeholder: "127.0.0.1"},
			{ID: "inbounds.0.port", Label: "Порт", Group: "Первый inbound", Type: "number", Min: 1, Max: 65535},
			{ID: "outbounds.0.tag", Label: "Имя первого выхода", Group: "Первый outbound", Type: "identifier", Placeholder: "proxy-out"},
			{ID: "outbounds.0.settings.vnext.0.address", Label: "VLESS-сервер", Group: "VLESS / Reality", Placeholder: "example.com"},
			{ID: "outbounds.0.settings.vnext.0.port", Label: "Порт VLESS", Group: "VLESS / Reality", Type: "number", Min: 1, Max: 65535},
			{ID: "outbounds.0.streamSettings.network", Label: "Транспорт", Group: "VLESS / Reality", Placeholder: "tcp"},
			{ID: "outbounds.0.streamSettings.security", Label: "Защита", Group: "VLESS / Reality", Placeholder: "reality"},
		}
	}
	return nil
}

func wireGuardFields(amnezia bool) []GuidedField {
	fields := []GuidedField{
		{ID: "Interface.Address", Label: "Адреса интерфейса", Group: "Интерфейс", Type: "cidrs", Placeholder: "172.16.0.2/32, 2606:4700::/128"},
		{ID: "Interface.DNS", Label: "DNS", Group: "Интерфейс", Type: "ips", Placeholder: "1.1.1.1, 1.0.0.1"},
		{ID: "Interface.MTU", Label: "MTU", Group: "Интерфейс", Type: "number", Default: "1280", Min: 576, Max: 9000},
		{ID: "Peer.Endpoint", Label: "Endpoint", Group: "Пир", Type: "endpoint", Placeholder: "engage.cloudflareclient.com:2408"},
		{ID: "Peer.AllowedIPs", Label: "Разрешённые сети", Group: "Пир", Type: "cidrs", Default: "0.0.0.0/0, ::/0", Placeholder: "0.0.0.0/0, ::/0"},
		{ID: "Peer.PersistentKeepalive", Label: "Keepalive, сек.", Group: "Пир", Type: "number", Default: "25", Min: 0, Max: 65535},
	}
	if amnezia {
		fields = append(fields,
			GuidedField{ID: "Interface.Jc", Label: "Jc", Group: "AmneziaWG", Type: "number", Min: 0, Max: 128},
			GuidedField{ID: "Interface.Jmin", Label: "Jmin", Group: "AmneziaWG", Type: "number", Min: 0, Max: 65535},
			GuidedField{ID: "Interface.Jmax", Label: "Jmax", Group: "AmneziaWG", Type: "number", Min: 0, Max: 65535},
			GuidedField{ID: "Interface.S1", Label: "S1", Group: "AmneziaWG", Type: "number", Min: 0, Max: 2147483647},
			GuidedField{ID: "Interface.S2", Label: "S2", Group: "AmneziaWG", Type: "number", Min: 0, Max: 2147483647},
			GuidedField{ID: "Interface.H1", Label: "H1", Group: "AmneziaWG", Type: "number", Min: 0, Max: 2147483647},
			GuidedField{ID: "Interface.H2", Label: "H2", Group: "AmneziaWG", Type: "number", Min: 0, Max: 2147483647},
			GuidedField{ID: "Interface.H3", Label: "H3", Group: "AmneziaWG", Type: "number", Min: 0, Max: 2147483647},
			GuidedField{ID: "Interface.H4", Label: "H4", Group: "AmneziaWG", Type: "number", Min: 0, Max: 2147483647},
		)
	}
	return fields
}

func decodeGuided(format string, b []byte, fields []GuidedField) (map[string]string, error) {
	values := make(map[string]string, len(fields))
	switch format {
	case "shell":
		parsed := parseShellAssignments(string(b))
		for _, field := range fields {
			values[field.ID] = parsed[field.ID]
		}
	case "json":
		var doc map[string]any
		if err := json.Unmarshal(b, &doc); err != nil {
			return nil, fmt.Errorf("invalid JSON: %w", err)
		}
		for _, field := range fields {
			values[field.ID] = jsonScalar(getJSONPath(doc, field.ID))
		}
	case "ini":
		parsed := parseINI(string(b))
		for _, field := range fields {
			values[field.ID] = parsed[field.ID]
		}
	default:
		return nil, fmt.Errorf("unsupported guided format %q", format)
	}
	return values, nil
}

func encodeGuided(format string, b []byte, fields []GuidedField, values map[string]string) ([]byte, error) {
	switch format {
	case "shell":
		return []byte(updateShellAssignments(string(b), values)), nil
	case "json":
		var doc map[string]any
		if len(strings.TrimSpace(string(b))) == 0 {
			doc = map[string]any{}
		} else if err := json.Unmarshal(b, &doc); err != nil {
			return nil, err
		}
		fieldMap := make(map[string]GuidedField, len(fields))
		for _, field := range fields {
			fieldMap[field.ID] = field
		}
		for id, value := range values {
			if value == "" && getJSONPath(doc, id) == nil {
				continue
			}
			setJSONPath(doc, id, jsonValue(fieldMap[id], value))
		}
		return json.MarshalIndent(doc, "", "  ")
	case "ini":
		return []byte(updateINI(string(b), values)), nil
	default:
		return nil, fmt.Errorf("unsupported guided format %q", format)
	}
}

func validateGuidedValue(field GuidedField, value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		if field.Required {
			return errors.New("обязательное поле")
		}
		return nil
	}
	if len(value) > 4096 || strings.ContainsAny(value, "\r\n\x00") {
		return errors.New("недопустимые символы")
	}
	if len(field.Options) > 0 {
		for _, option := range field.Options {
			if value == option.Value {
				return nil
			}
		}
		return errors.New("неизвестное значение")
	}
	switch field.Type {
	case "number":
		n, err := strconv.Atoi(value)
		if err != nil {
			return errors.New("нужно целое число")
		}
		if field.Min != 0 && n < field.Min {
			return fmt.Errorf("минимум %d", field.Min)
		}
		if field.Max != 0 && n > field.Max {
			return fmt.Errorf("максимум %d", field.Max)
		}
	case "boolean":
		if value != "true" && value != "false" {
			return errors.New("нужно true или false")
		}
	case "ip":
		if net.ParseIP(value) == nil {
			return errors.New("неверный IP-адрес")
		}
	case "ips":
		for _, item := range splitCSV(value) {
			if net.ParseIP(item) == nil {
				return fmt.Errorf("неверный IP %q", item)
			}
		}
	case "cidrs":
		for _, item := range splitCSV(value) {
			if _, _, err := net.ParseCIDR(item); err != nil {
				return fmt.Errorf("неверная сеть %q", item)
			}
		}
	case "ports":
		for _, r := range value {
			if !unicode.IsDigit(r) && r != ',' && r != ':' && r != '-' {
				return errors.New("разрешены цифры, запятые и диапазоны")
			}
		}
	case "interfaces":
		for _, r := range value {
			if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !strings.ContainsRune("._- ", r) {
				return errors.New("неверное имя интерфейса")
			}
		}
	case "identifier":
		for _, r := range value {
			if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !strings.ContainsRune("._-", r) {
				return errors.New("разрешены буквы, цифры, точка, _ и -")
			}
		}
	case "endpoint":
		if _, _, err := net.SplitHostPort(value); err != nil {
			return errors.New("ожидается адрес:порт; IPv6 укажите в [скобках]")
		}
	case "arguments":
		if strings.ContainsAny(value, "`;&|<>\r\n") || strings.Contains(value, "$(") || strings.Contains(value, "${") {
			return errors.New("командные подстановки и shell-операторы запрещены; используйте экспертный режим")
		}
	default:
		if strings.ContainsAny(value, "`$;&|<>") {
			return errors.New("небезопасные символы")
		}
	}
	return nil
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseShellAssignments(content string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		trimmed = strings.TrimPrefix(trimmed, "export ")
		key, value, ok := strings.Cut(trimmed, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		out[key] = unquoteSimple(strings.TrimSpace(value))
	}
	return out
}

func updateShellAssignments(content string, values map[string]string) string {
	lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	seen := map[string]bool{}
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		candidate := strings.TrimPrefix(trimmed, "export ")
		key, _, ok := strings.Cut(candidate, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value, wanted := values[key]
		if !wanted {
			continue
		}
		prefix := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
		lines[i] = prefix + key + "=" + shellValue(value)
		seen[key] = true
	}
	for key, value := range values {
		if !seen[key] {
			lines = append(lines, key+"="+shellValue(value))
		}
	}
	return strings.TrimRight(strings.Join(lines, "\n"), "\n") + "\n"
}

func shellValue(value string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(value, `\`, `\\`), `"`, `\"`) + `"`
}
func unquoteSimple(value string) string {
	if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
		value = value[1 : len(value)-1]
	}
	return strings.ReplaceAll(strings.ReplaceAll(value, `\"`, `"`), `\\`, `\`)
}

func parseINI(content string) map[string]string {
	out := map[string]string{}
	section := ""
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if ok && section != "" {
			out[section+"."+strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	return out
}

func updateINI(content string, values map[string]string) string {
	lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	section := ""
	seen := map[string]bool{}
	sectionLast := map[string]int{}
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = strings.TrimSpace(trimmed[1 : len(trimmed)-1])
			sectionLast[section] = i
			continue
		}
		if section == "" {
			continue
		}
		key, _, ok := strings.Cut(trimmed, "=")
		if !ok {
			continue
		}
		full := section + "." + strings.TrimSpace(key)
		if value, ok := values[full]; ok {
			lines[i] = strings.TrimSpace(key) + " = " + value
			seen[full] = true
		}
		sectionLast[section] = i
	}
	for full, value := range values {
		if seen[full] {
			continue
		}
		sectionName, key, ok := strings.Cut(full, ".")
		if !ok {
			continue
		}
		insert := -1
		for i, line := range lines {
			if strings.TrimSpace(line) == "["+sectionName+"]" {
				insert = i + 1
				for insert < len(lines) && !(strings.HasPrefix(strings.TrimSpace(lines[insert]), "[") && strings.HasSuffix(strings.TrimSpace(lines[insert]), "]")) {
					insert++
				}
				break
			}
		}
		entry := key + " = " + value
		if insert < 0 {
			lines = append(lines, "["+sectionName+"]", entry)
		} else {
			lines = append(lines[:insert], append([]string{entry}, lines[insert:]...)...)
		}
	}
	return strings.TrimRight(strings.Join(lines, "\n"), "\n") + "\n"
}

func getJSONPath(doc map[string]any, path string) any {
	parts := strings.Split(path, ".")
	var current any = doc
	for _, part := range parts {
		switch value := current.(type) {
		case map[string]any:
			current = value[part]
		case []any:
			index, err := strconv.Atoi(part)
			if err != nil || index < 0 || index >= len(value) {
				return nil
			}
			current = value[index]
		default:
			return nil
		}
	}
	return current
}
func setJSONPath(doc map[string]any, path string, value any) {
	_ = setJSONValue(doc, strings.Split(path, "."), value)
}
func setJSONValue(current any, parts []string, value any) any {
	if len(parts) == 0 {
		return value
	}
	part := parts[0]
	if index, err := strconv.Atoi(part); err == nil {
		array, _ := current.([]any)
		for len(array) <= index {
			array = append(array, nil)
		}
		array[index] = setJSONValue(array[index], parts[1:], value)
		return array
	}
	object, _ := current.(map[string]any)
	if object == nil {
		object = map[string]any{}
	}
	object[part] = setJSONValue(object[part], parts[1:], value)
	return object
}
func jsonScalar(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case bool:
		return strconv.FormatBool(v)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case json.Number:
		return string(v)
	default:
		return ""
	}
}
func jsonValue(field GuidedField, value string) any {
	switch field.Type {
	case "boolean":
		return value == "true"
	case "number":
		n, _ := strconv.Atoi(value)
		return n
	default:
		return value
	}
}

// filepathDir is kept tiny so guided staging shares the same transaction rules as the expert editor.
func filepathDir(path string) string {
	index := strings.LastIndexAny(path, `/\\`)
	if index < 0 {
		return "."
	}
	return path[:index]
}
