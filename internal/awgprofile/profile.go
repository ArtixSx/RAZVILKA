// Package awgprofile validates local client profiles. It never executes hooks,
// registers remote accounts, loads modules, or changes routing.
package awgprofile

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const MaxBytes = 256 << 10
const MaxLineBytes = 16 << 10

type Issue struct {
	Code    string `json:"code"`
	Field   string `json:"field,omitempty"`
	Message string `json:"message"`
}

func (e Issue) Error() string                   { return e.Code + ": " + e.Message }
func invalid(code, field, message string) error { return Issue{code, field, message} }

type Preview struct {
	SHA256              string   `json:"sha256"`
	Version             string   `json:"version"`
	MinimumMajor        int      `json:"minimum_major"`
	MinimumMinor        int      `json:"minimum_minor"`
	RequiredFeatures    []string `json:"required_features"`
	Endpoint            string   `json:"endpoint"`
	AddressCount        int      `json:"address_count"`
	AllowedIPCount      int      `json:"allowed_ip_count"`
	HasIPv6             bool     `json:"has_ipv6"`
	HasHeaderProtection bool     `json:"has_header_protection"`
	RandomTrailers      bool     `json:"random_trailers"`
	DisableCookies      bool     `json:"disable_cookies"`
	MTU                 int      `json:"mtu"`
	Warnings            []Issue  `json:"warnings"`
	Verification        string   `json:"verification"`
}

// Profile's secret-bearing fields are private. JSON, fmt and errors contain
// only Preview. Config is an explicit secret export to an authenticated caller.
type Profile struct {
	preview Preview
	config  string
}

func (p Profile) Public() Preview {
	b, _ := json.Marshal(p.preview)
	var v Preview
	_ = json.Unmarshal(b, &v)
	return v
}
func (p Profile) Config() string               { return p.config }
func (p Profile) MarshalJSON() ([]byte, error) { return json.Marshal(p.preview) }
func (p Profile) String() string               { return "[private AWG client profile]" }
func (p Profile) GoString() string             { return p.String() }
func (p Profile) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, p.String()) }

var interfaceOrder = []string{"PrivateKey", "Address", "DNS", "MTU", "ListenPort", "Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5", "HeaderProtectionKey", "ContentPaddingAddition", "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime", "KeepaliveTimeout", "MaxHandshakeAttempts", "RandomTrailers", "DisableCookies", "Table"}
var peerOrder = []string{"PublicKey", "PresharedKey", "Endpoint", "AllowedIPs", "PersistentKeepalive"}
var timingFields = []string{"ContentPaddingAddition", "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime", "KeepaliveTimeout", "MaxHandshakeAttempts"}

func Parse(text string) (Profile, error) {
	if len(text) == 0 || len(text) > MaxBytes || !utf8.ValidString(text) || strings.ContainsRune(text, 0) {
		return Profile{}, invalid("AWG_INPUT_INVALID", "", "Нужен текстовый профиль до 256 КиБ без NUL.")
	}
	text = strings.TrimPrefix(text, "\ufeff")
	values := map[string]map[string]string{"Interface": {}, "Peer": {}}
	seenSections := map[string]bool{}
	section := ""
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		if len(line) > MaxLineBytes {
			return Profile{}, invalid("AWG_LINE_TOO_LARGE", "", "Строка профиля превышает безопасный предел.")
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if line != "[Interface]" && line != "[Peer]" {
				return Profile{}, invalid("AWG_SECTION_UNSUPPORTED", "", "Поддерживается один клиентский Interface и один Peer.")
			}
			section = strings.Trim(line, "[]")
			if seenSections[section] {
				return Profile{}, invalid("AWG_SECTION_DUPLICATE", section, "Повторная секция или несколько peers пока не поддерживаются.")
			}
			seenSections[section] = true
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if !ok || section == "" || value == "" {
			return Profile{}, invalid("AWG_LINE_INVALID", "", "Неверная или пустая строка параметра.")
		}
		lower := strings.ToLower(key)
		if strings.Contains(lower, "postup") || strings.Contains(lower, "preup") || strings.Contains(lower, "predown") || strings.Contains(lower, "postdown") || lower == "saveconfig" {
			return Profile{}, invalid("AWG_HOOK_FORBIDDEN", "", "Команды и SaveConfig из импортируемого профиля запрещены.")
		}
		order := interfaceOrder
		if section == "Peer" {
			order = peerOrder
		}
		if !contains(order, key) {
			return Profile{}, invalid("AWG_FIELD_UNSUPPORTED", "", "Неизвестный параметр или неверный регистр; значение не отброшено молча.")
		}
		if _, ok := values[section][key]; ok {
			return Profile{}, invalid("AWG_FIELD_DUPLICATE", key, "Повторный параметр не допускается.")
		}
		values[section][key] = value
	}
	i, p := values["Interface"], values["Peer"]
	for _, name := range []string{"PrivateKey", "Address"} {
		if i[name] == "" {
			return Profile{}, invalid("AWG_REQUIRED", name, "Отсутствует обязательный параметр интерфейса.")
		}
	}
	for _, name := range []string{"PublicKey", "Endpoint", "AllowedIPs"} {
		if p[name] == "" {
			return Profile{}, invalid("AWG_REQUIRED", name, "Отсутствует обязательный параметр peer.")
		}
	}
	for _, v := range []struct{ k, v string }{{"PrivateKey", i["PrivateKey"]}, {"PublicKey", p["PublicKey"]}, {"PresharedKey", p["PresharedKey"]}, {"HeaderProtectionKey", i["HeaderProtectionKey"]}} {
		if v.v != "" && !validKey(v.v) {
			return Profile{}, invalid("AWG_KEY_INVALID", v.k, "Ключ должен быть ненулевым каноническим base64 из 32 байт.")
		}
	}
	view := Preview{Version: "wg", RequiredFeatures: []string{}, Warnings: []Issue{}, Verification: "syntax-only", MTU: 1280}
	for _, v := range []struct{ k, v string }{{"Address", i["Address"]}, {"AllowedIPs", p["AllowedIPs"]}} {
		parts := strings.Split(v.v, ",")
		if len(parts) > 256 {
			return Profile{}, invalid("AWG_PREFIX_LIMIT", v.k, "Слишком много адресов или сетей.")
		}
		for _, part := range parts {
			prefix, err := netip.ParsePrefix(strings.TrimSpace(part))
			if err != nil || prefix.Addr().IsMulticast() || prefix.Addr().IsLoopback() {
				return Profile{}, invalid("AWG_PREFIX_INVALID", v.k, "Неверный адрес или сеть.")
			}
			if v.k == "Address" && (!prefix.Addr().IsGlobalUnicast() || prefix.Addr().IsUnspecified()) {
				return Profile{}, invalid("AWG_ADDRESS_INVALID", v.k, "Неверный адрес туннеля.")
			}
			view.HasIPv6 = view.HasIPv6 || prefix.Addr().Is6()
		}
		if v.k == "Address" {
			view.AddressCount = len(parts)
		} else {
			view.AllowedIPCount = len(parts)
		}
	}
	host, port, err := net.SplitHostPort(p["Endpoint"])
	if err != nil || !validHost(host) {
		return Profile{}, invalid("AWG_ENDPOINT_INVALID", "Endpoint", "Нужен публичный адрес или DNS-имя и UDP-порт; IPv6 — в скобках.")
	}
	if n, err := number(port, 65535); err != nil || n == 0 {
		return Profile{}, invalid("AWG_PORT_INVALID", "Endpoint", "Порт должен быть от 1 до 65535.")
	}
	view.Endpoint = p["Endpoint"]
	for _, s := range []struct {
		k, v string
		max  uint64
	}{{"MTU", i["MTU"], 9000}, {"ListenPort", i["ListenPort"], 65535}, {"PersistentKeepalive", p["PersistentKeepalive"], 65535}} {
		if s.v != "" {
			n, e := number(s.v, s.max)
			if e != nil || s.k == "MTU" && n < 576 {
				return Profile{}, invalid("AWG_NUMBER_INVALID", s.k, "Значение вне допустимого числового диапазона.")
			}
			if s.k == "MTU" {
				view.MTU = int(n)
			}
		}
	}
	if i["DNS"] != "" {
		for _, s := range strings.Split(i["DNS"], ",") {
			if _, err := netip.ParseAddr(strings.TrimSpace(s)); err != nil {
				return Profile{}, invalid("AWG_DNS_INVALID", "DNS", "Нужны IP-адреса DNS; глобальные настройки DNS не импортируются.")
			}
		}
		view.Warnings = append(view.Warnings, Issue{"DNS_NOT_APPLIED", "DNS", "DNS сохранён как данные профиля. Системный DNS не меняется автоматически."})
	}
	if i["Table"] != "" && i["Table"] != "off" {
		view.Warnings = append(view.Warnings, Issue{"TABLE_OWNED_BY_RAZVILKA", "Table", "Маршруты создаёт RAZVILKA только для выбранных сервисов и устройств."})
	}
	i["Table"] = "off"
	major, minor, features, e := validateObfuscation(i)
	if e != nil {
		return Profile{}, e
	}
	view.MinimumMajor, view.MinimumMinor, view.RequiredFeatures = major, minor, features
	if major > 0 {
		view.Version = fmt.Sprintf("awg%d.%d", major, minor)
	}
	view.HasHeaderProtection = i["HeaderProtectionKey"] != ""
	view.RandomTrailers = i["RandomTrailers"] == "on"
	view.DisableCookies = i["DisableCookies"] == "on"
	if major >= 3 {
		view.Warnings = append(view.Warnings, Issue{"SERVER_COMPATIBILITY_REQUIRED", "", "Параметры 3.x должны соответствовать удалённому серверу. Импорт не доказывает поддержку peer."})
	}
	if view.HasHeaderProtection {
		for n := 1; n <= 4; n++ {
			k := fmt.Sprintf("H%d", n)
			if i[k] != "" && i[k] != strconv.Itoa(n) {
				view.Warnings = append(view.Warnings, Issue{"HP_HEADER_HINT", k, "При Header Protection документация рекомендует стандартные H1–H4. Значение из файла сохранено."})
			}
		}
	}
	if view.RandomTrailers && (i["S1"] != i["S2"] || i["S1"] != i["S3"] || i["S1"] != i["S4"]) {
		view.Warnings = append(view.Warnings, Issue{"TRAILER_PADDING_HINT", "S1-S4", "Для RandomTrailers рекомендуются одинаковые S1–S4. Сверьте параметры сервера."})
	}
	if view.DisableCookies {
		view.Warnings = append(view.Warnings, Issue{"COOKIES_SECURITY_TRADEOFF", "DisableCookies", "Изменяется поведение защиты handshake от нагрузки. Флаг не включается проектом автоматически."})
	}
	var b strings.Builder
	for _, s := range []struct {
		section string
		order   []string
	}{{"Interface", interfaceOrder}, {"Peer", peerOrder}} {
		b.WriteString("[" + s.section + "]\n")
		for _, k := range s.order {
			if value := values[s.section][k]; value != "" {
				b.WriteString(k + " = " + value + "\n")
			}
		}
		b.WriteByte('\n')
	}
	config := b.String()
	sum := sha256.Sum256([]byte(config))
	view.SHA256 = hex.EncodeToString(sum[:])
	return Profile{view, config}, nil
}
func contains(items []string, x string) bool {
	for _, s := range items {
		if s == x {
			return true
		}
	}
	return false
}
func validKey(s string) bool {
	b, e := base64.StdEncoding.Strict().DecodeString(s)
	if e != nil || len(b) != 32 || base64.StdEncoding.EncodeToString(b) != s {
		return false
	}
	for _, v := range b {
		if v != 0 {
			return true
		}
	}
	return false
}
func validHost(h string) bool {
	if a, e := netip.ParseAddr(h); e == nil {
		return a.Zone() == "" && a.IsGlobalUnicast() && !a.IsPrivate() && !a.IsLoopback() && !a.IsLinkLocalUnicast()
	}
	if len(h) > 253 || !strings.Contains(h, ".") || strings.HasSuffix(strings.ToLower(h), ".local") {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if len(label) < 1 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
func number(s string, max uint64) (uint64, error) {
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("not decimal")
		}
	}
	n, e := strconv.ParseUint(s, 10, 64)
	if e != nil || n > max {
		return 0, fmt.Errorf("out of range")
	}
	return n, nil
}
func numrange(s string, max uint64) (uint64, uint64, error) {
	a, b, ok := strings.Cut(s, "-")
	if !ok {
		b = a
	}
	lo, e := number(a, max)
	if e != nil {
		return 0, 0, e
	}
	hi, e := number(b, max)
	if e != nil || lo > hi {
		return 0, 0, fmt.Errorf("invalid range")
	}
	return lo, hi, nil
}
func validateObfuscation(i map[string]string) (int, int, []string, error) {
	major, minor := 0, 0
	features := map[string]bool{}
	require := func(a, b int, f string) {
		features[f] = true
		if a > major || a == major && b > minor {
			major, minor = a, b
		}
	}
	vals := map[string]uint64{}
	for _, k := range []string{"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4"} {
		if i[k] == "" {
			continue
		}
		n, e := number(i[k], 65535)
		if e != nil {
			return 0, 0, nil, invalid("AWG_NUMBER_INVALID", k, "Параметр должен быть целым uint16.")
		}
		vals[k] = n
		require(1, 0, "junk-padding")
		if k == "S3" || k == "S4" {
			require(2, 0, "padding-v2")
		}
	}
	if vals["Jc"] > 128 {
		return 0, 0, nil, invalid("AWG_RESOURCE_LIMIT", "Jc", "Локальный бюджет RAZVILKA: не больше 128 junk-пакетов.")
	}
	if vals["Jmin"] > vals["Jmax"] || vals["Jc"] > 0 && (vals["Jmin"] == 0 || vals["Jmax"] == 0) {
		return 0, 0, nil, invalid("AWG_JUNK_RANGE", "Jmin/Jmax", "Нужно Jmin <= Jmax, а при Jc > 0 — положительные границы.")
	}
	var ranges [][2]uint64
	for n := 1; n <= 4; n++ {
		k := fmt.Sprintf("H%d", n)
		value := i[k]
		if value == "" {
			value = strconv.Itoa(n)
		}
		lo, hi, e := numrange(value, 1<<32-1)
		if e != nil {
			return 0, 0, nil, invalid("AWG_RANGE_INVALID", k, "Нужен uint32 или возрастающий диапазон uint32.")
		}
		for _, r := range ranges {
			if lo <= r[1] && hi >= r[0] {
				return 0, 0, nil, invalid("AWG_HEADER_OVERLAP", k, "Диапазоны H1–H4 не должны пересекаться.")
			}
		}
		ranges = append(ranges, [2]uint64{lo, hi})
		if i[k] != "" {
			require(1, 0, "headers")
		}
		if strings.Contains(i[k], "-") {
			require(2, 0, "header-ranges")
		}
	}
	for n := 1; n <= 5; n++ {
		k := fmt.Sprintf("I%d", n)
		if i[k] != "" {
			if e := validateCPS(i[k]); e != nil {
				return 0, 0, nil, invalid("AWG_CPS_INVALID", k, "Неверный CPS: проверьте теги, положительные длины и локальный лимит 4096 байт на пакет.")
			}
			require(1, 5, "cps")
		}
	}
	for _, k := range timingFields {
		if i[k] != "" {
			if _, _, e := numrange(i[k], 65535); e != nil {
				return 0, 0, nil, invalid("AWG_RANGE_INVALID", k, "Нужен uint16 или возрастающий диапазон uint16.")
			}
			require(3, 0, "timing-padding-v3")
		}
	}
	if i["HeaderProtectionKey"] != "" {
		for _, k := range []string{"S1", "S2", "S3", "S4"} {
			if vals[k] < 12 {
				return 0, 0, nil, invalid("AWG_HP_PADDING", k, "HeaderProtectionKey требует явно заданных S1–S4 не меньше 12 байт.")
			}
		}
		require(3, 0, "header-protection")
	}
	for _, k := range []string{"RandomTrailers", "DisableCookies"} {
		if i[k] != "" {
			switch strings.ToLower(i[k]) {
			case "on", "true", "1":
				i[k] = "on"
			case "off", "false", "0":
				i[k] = "off"
			default:
				return 0, 0, nil, invalid("AWG_BOOL_INVALID", k, "Нужно on/off; булевы значения при импорте нормализуются.")
			}
			require(3, 1, "flags-v31")
		}
	}
	fs := []string{}
	for f := range features {
		fs = append(fs, f)
	}
	sort.Strings(fs)
	return major, minor, fs, nil
}

// ValidateField validates a public guided-editor value without parsing secrets.
// Cross-field constraints remain mandatory when validating the complete draft.
func ValidateField(kind, value string) error {
	if value == "" {
		return nil
	}
	switch kind {
	case "range32":
		_, _, err := numrange(value, 1<<32-1)
		return err
	case "range16":
		_, _, err := numrange(value, 65535)
		return err
	case "cps":
		return validateCPS(value)
	}
	return fmt.Errorf("unsupported field kind")
}
