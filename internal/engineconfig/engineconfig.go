package engineconfig

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/engine"
)

const maxConfigBytes = 2 << 20

type FileSpec struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Kind        string   `json:"kind"`
	Syntax      string   `json:"syntax"`
	Paths       []string `json:"-"`
	Sensitive   bool     `json:"sensitive"`
	Description string   `json:"description,omitempty"`
}

type EngineSpec struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Files       []FileSpec `json:"-"`
}

type FileView struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Syntax      string `json:"syntax"`
	Path        string `json:"path"`
	Exists      bool   `json:"exists"`
	Size        int64  `json:"size"`
	ModifiedAt  string `json:"modified_at,omitempty"`
	Sensitive   bool   `json:"sensitive"`
	Staged      bool   `json:"staged"`
	StagedAt    string `json:"staged_at,omitempty"`
	SHA256      string `json:"sha256,omitempty"`
	Description string `json:"description,omitempty"`
}

type EngineView struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Installed   bool       `json:"installed"`
	Running     bool       `json:"running"`
	Kind        string     `json:"kind"`
	Files       []FileView `json:"files"`
	CanValidate bool       `json:"can_validate"`
	CanRestart  bool       `json:"can_restart"`
}

type Content struct {
	EngineID  string `json:"engine_id"`
	FileID    string `json:"file_id"`
	Path      string `json:"path"`
	Source    string `json:"source"` // live, staged, missing, redacted
	Content   string `json:"content,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
	Sensitive bool   `json:"sensitive"`
}

type Validation struct {
	OK        bool   `json:"ok"`
	EngineID  string `json:"engine_id"`
	FileID    string `json:"file_id"`
	Validator string `json:"validator"`
	Native    bool   `json:"native"`
	Output    string `json:"output"`
}

type StageItem struct {
	EngineID string `json:"engine_id"`
	FileID   string `json:"file_id"`
	Content  string `json:"content"`
}

type Manager struct {
	StageRoot     string
	BackupRoot    string
	NativeTimeout time.Duration
	mu            sync.RWMutex
}

func New(stageRoot, backupRoot string) *Manager {
	return &Manager{StageRoot: stageRoot, BackupRoot: backupRoot, NativeTimeout: 10 * time.Second}
}

func Specs() []EngineSpec {
	return []EngineSpec{
		{
			ID: "nfqws2", Name: "NFQWS2", Description: "Локальный обход DPI через NFQUEUE / zapret2",
			Files: []FileSpec{
				{ID: "main", Name: "Основной конфиг", Kind: "config", Syntax: "shell", Paths: []string{"/opt/etc/nfqws2/nfqws2.conf"}, Description: "NFQWS_ARGS, интерфейс, порты, политика и режимы"},
				{ID: "user-list", Name: "user.list", Kind: "domains", Syntax: "list", Paths: []string{"/opt/etc/nfqws2/lists/user.list"}, Description: "Пользовательский список доменов"},
				{ID: "auto-list", Name: "auto.list", Kind: "domains", Syntax: "list", Paths: []string{"/opt/etc/nfqws2/lists/auto.list"}, Description: "Автоматически накопленный список"},
				{ID: "exclude-list", Name: "exclude.list", Kind: "domains", Syntax: "list", Paths: []string{"/opt/etc/nfqws2/lists/exclude.list"}, Description: "Исключения доменов"},
				{ID: "ipset-list", Name: "ipset.list", Kind: "cidrs", Syntax: "cidr-list", Paths: []string{"/opt/etc/nfqws2/lists/ipset.list"}, Description: "IP/CIDR список"},
				{ID: "ipset-exclude", Name: "ipset_exclude.list", Kind: "cidrs", Syntax: "cidr-list", Paths: []string{"/opt/etc/nfqws2/lists/ipset_exclude.list"}, Description: "IP/CIDR исключения"},
			},
		},
		{
			ID: "usque", Name: "WARP · MASQUE", Description: "Cloudflare WARP через usque / MASQUE",
			Files: []FileSpec{{ID: "main", Name: "session.conf", Kind: "secret-config", Syntax: "json", Paths: []string{"/opt/etc/usque/session.conf", "/opt/etc/usque/config.json", "/opt/var/lib/usque/config.json"}, Sensitive: true, Description: "JSON-сессия usque/usque-keenetic: регистрация MASQUE, публичные endpoints и назначенные адреса; приватные поля скрыты в простом режиме"}},
		},
		{
			ID: "warp-wg", Name: "WARP · WireGuard", Description: "WARP WireGuard профиль",
			Files: []FileSpec{{ID: "main", Name: "WARP WireGuard", Kind: "secret-config", Syntax: "ini", Paths: []string{"/opt/etc/razvilka/warp/wgcf-profile.conf", "/opt/etc/wireguard/warp.conf"}, Sensitive: true, Description: "Содержит приватный ключ; чтение из UI скрыто до появления авторизации"}},
		},
		{
			ID: "sing-box", Name: "Sing-box", Description: "VLESS / Reality / Hysteria2 / TUIC / Shadowsocks",
			Files: []FileSpec{{ID: "main", Name: "config.json", Kind: "secret-config", Syntax: "json", Paths: []string{"/opt/etc/sing-box/config.json", "/opt/etc/singbox/config.json", "/opt/etc/sing-box.json"}, Sensitive: true, Description: "Основной JSON-конфиг sing-box; может содержать UUID, пароли и ключи"}},
		},
		{
			ID: "xray", Name: "Xray", Description: "Дополнительное Xray-ядро и транспорты",
			Files: []FileSpec{{ID: "main", Name: "config.json", Kind: "secret-config", Syntax: "json", Paths: []string{"/opt/etc/xray/config.json", "/opt/etc/xray.json"}, Sensitive: true, Description: "Основной JSON-конфиг Xray; может содержать UUID, пароли и ключи"}},
		},
		{
			ID: "amneziawg", Name: "AmneziaWG", Description: "Устойчивый к DPI туннель на основе WireGuard",
			Files: []FileSpec{{ID: "main", Name: "AmneziaWG", Kind: "secret-config", Syntax: "ini", Paths: []string{"/opt/etc/amnezia/amneziawg.conf", "/opt/etc/wireguard/awg.conf"}, Sensitive: true, Description: "Содержит ключи; чтение из UI скрыто до появления авторизации"}},
		},
	}
}

func (m *Manager) List() []EngineView {
	m.mu.RLock()
	defer m.mu.RUnlock()
	statuses := map[string]engine.Status{}
	for _, st := range (engine.Detector{}).All() {
		statuses[st.ID] = st
	}
	out := make([]EngineView, 0, len(Specs()))
	for _, spec := range Specs() {
		st := statuses[spec.ID]
		view := EngineView{ID: spec.ID, Name: spec.Name, Description: spec.Description, Installed: st.Installed, Running: st.Running, Kind: st.Kind, CanValidate: true, CanRestart: false}
		for _, f := range spec.Files {
			view.Files = append(view.Files, m.fileView(spec.ID, f))
		}
		out = append(out, view)
	}
	return out
}

func (m *Manager) Read(engineID, fileID string) (Content, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.readLocked(engineID, fileID, false)
}

func (m *Manager) ReadExpert(engineID, fileID string) (Content, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.readLocked(engineID, fileID, true)
}

func (m *Manager) readLocked(engineID, fileID string, revealSensitive bool) (Content, error) {
	_, f, err := lookup(engineID, fileID)
	if err != nil {
		return Content{}, err
	}
	livePath := choosePath(f.Paths)
	staged := m.stagePath(engineID, fileID)
	if f.Sensitive && !revealSensitive {
		src := "missing"
		if fileExists(staged) {
			src = "staged"
		} else if fileExists(livePath) {
			src = "redacted"
		}
		return Content{EngineID: engineID, FileID: fileID, Path: livePath, Source: src, Sensitive: true}, nil
	}
	path, src := livePath, "live"
	if fileExists(staged) {
		path, src = staged, "staged"
	} else if !fileExists(livePath) {
		return Content{EngineID: engineID, FileID: fileID, Path: livePath, Source: "missing"}, nil
	}
	b, err := readLimited(path)
	if err != nil {
		return Content{}, err
	}
	return Content{EngineID: engineID, FileID: fileID, Path: livePath, Source: src, Content: string(b), SHA256: sum(b), Sensitive: f.Sensitive}, nil
}

func (m *Manager) Stage(engineID, fileID, content string) (Content, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, f, err := lookup(engineID, fileID)
	if err != nil {
		return Content{}, err
	}
	if len(content) > maxConfigBytes {
		return Content{}, fmt.Errorf("config too large: %d bytes", len(content))
	}
	if strings.IndexByte(content, 0) >= 0 {
		return Content{}, errors.New("NUL byte is not allowed")
	}
	path := m.stagePath(engineID, fileID)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return Content{}, err
	}
	if err := writeAtomic(path, []byte(content), 0o600); err != nil {
		return Content{}, err
	}
	livePath := choosePath(f.Paths)
	if f.Sensitive {
		return Content{EngineID: engineID, FileID: fileID, Path: livePath, Source: "staged", Sensitive: true, SHA256: sum([]byte(content))}, nil
	}
	return Content{EngineID: engineID, FileID: fileID, Path: livePath, Source: "staged", Content: content, Sensitive: false, SHA256: sum([]byte(content))}, nil
}

// PublicFile reports whether a file is explicitly classified as non-secret.
// Portable profiles are restricted to this allowlist.
func PublicFile(engineID, fileID string) bool {
	_, file, err := lookup(engineID, fileID)
	return err == nil && !file.Sensitive
}

// ValidateContent performs the portable, non-mutating validation used by
// profile preview. Native validators run only after a draft exists.
func ValidateContent(engineID, fileID, content string) Validation {
	_, file, err := lookup(engineID, fileID)
	if err != nil {
		return Validation{OK: false, EngineID: engineID, FileID: fileID, Output: err.Error()}
	}
	result := Validation{OK: true, EngineID: engineID, FileID: fileID, Validator: file.Syntax, Output: "portable validation passed"}
	if file.Sensitive {
		result.OK = false
		result.Output = "sensitive engine files are not accepted in portable profiles"
		return result
	}
	if len(content) > maxConfigBytes || strings.IndexByte(content, 0) >= 0 {
		result.OK = false
		result.Output = "file is too large or contains NUL"
		return result
	}
	return validateBytes(result, file.Syntax, []byte(content))
}

// ValidatePrivateContent accepts known sensitive file slots for an already
// authenticated and decrypted private backup. It still applies the same size,
// NUL and syntax checks and never runs or writes the configuration.
func ValidatePrivateContent(engineID, fileID, content string) Validation {
	_, file, err := lookup(engineID, fileID)
	if err != nil {
		return Validation{OK: false, EngineID: engineID, FileID: fileID, Output: err.Error()}
	}
	result := Validation{OK: true, EngineID: engineID, FileID: fileID, Validator: file.Syntax, Output: "encrypted private backup validation passed"}
	if len(content) > maxConfigBytes || strings.IndexByte(content, 0) >= 0 {
		result.OK = false
		result.Output = "file is too large or contains NUL"
		return result
	}
	return validateBytes(result, file.Syntax, []byte(content))
}

// StagePublic validates every item before writing and rolls already-written
// draft files back if an I/O error occurs. It never touches live configs.
func (m *Manager) StagePublic(items []StageItem) ([]Content, error) {
	return m.stageValidated(items, ValidateContent)
}

// StagePrivate is the encrypted-backup counterpart of StagePublic. Sensitive
// files are allowed only because the caller has already authenticated,
// decrypted and previewed the AEAD envelope. Writes remain draft-only and are
// rolled back as one local transaction on any error.
func (m *Manager) StagePrivate(items []StageItem) ([]Content, error) {
	return m.stageValidated(items, ValidatePrivateContent)
}

func (m *Manager) stageValidated(items []StageItem, validate func(string, string, string) Validation) ([]Content, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	type prior struct {
		path    string
		existed bool
		content []byte
	}
	seen := map[string]bool{}
	previous := make([]prior, 0, len(items))
	for _, item := range items {
		key := item.EngineID + "/" + item.FileID
		if seen[key] {
			return nil, fmt.Errorf("duplicate engine draft %q", key)
		}
		seen[key] = true
		validation := validate(item.EngineID, item.FileID, item.Content)
		if !validation.OK {
			return nil, fmt.Errorf("%s: %s", key, validation.Output)
		}
		path := m.stagePath(item.EngineID, item.FileID)
		old, err := os.ReadFile(path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		previous = append(previous, prior{path: path, existed: err == nil, content: old})
	}
	restore := func(written int) {
		for i := written - 1; i >= 0; i-- {
			if previous[i].existed {
				_ = writeAtomic(previous[i].path, previous[i].content, 0o600)
			} else {
				_ = os.Remove(previous[i].path)
			}
		}
	}
	out := make([]Content, 0, len(items))
	for i, item := range items {
		path := m.stagePath(item.EngineID, item.FileID)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			restore(i)
			return nil, err
		}
		if err := writeAtomic(path, []byte(item.Content), 0o600); err != nil {
			restore(i)
			return nil, err
		}
		_, file, _ := lookup(item.EngineID, item.FileID)
		out = append(out, Content{EngineID: item.EngineID, FileID: item.FileID, Path: choosePath(file.Paths), Source: "staged", Content: item.Content, SHA256: sum([]byte(item.Content))})
	}
	return out, nil
}

func (m *Manager) Discard(engineID, fileID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, _, err := lookup(engineID, fileID); err != nil {
		return err
	}
	err := os.Remove(m.stagePath(engineID, fileID))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (m *Manager) Validate(engineID, fileID string) Validation {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.validateLocked(engineID, fileID)
}

func (m *Manager) validateLocked(engineID, fileID string) Validation {
	_, f, err := lookup(engineID, fileID)
	if err != nil {
		return Validation{OK: false, EngineID: engineID, FileID: fileID, Output: err.Error()}
	}
	staged := m.stagePath(engineID, fileID)
	live := choosePath(f.Paths)
	path := live
	if fileExists(staged) {
		path = staged
	}
	if !fileExists(path) {
		return Validation{OK: false, EngineID: engineID, FileID: fileID, Validator: f.Syntax, Output: "file is missing; import or create a draft first"}
	}
	b, err := readLimited(path)
	if err != nil {
		return Validation{OK: false, EngineID: engineID, FileID: fileID, Validator: f.Syntax, Output: err.Error()}
	}
	v := validateBytes(Validation{OK: true, EngineID: engineID, FileID: fileID, Validator: f.Syntax, Output: "basic validation passed"}, f.Syntax, b)
	if !v.OK {
		return v
	}
	switch f.Syntax {
	case "json":
		if engineID == "sing-box" {
			if bin := findBin([]string{"/opt/bin/sing-box", "/opt/usr/bin/sing-box", "sing-box"}); bin != "" {
				return runNative(v, m.nativeTimeout(), bin, "check", "-c", path)
			}
		}
		if engineID == "xray" {
			if bin := findBin([]string{"/opt/bin/xray", "/opt/usr/bin/xray", "xray"}); bin != "" {
				// Modern Xray supports `run -test -config`; if an older build rejects it, JSON validation still reports separately in output.
				return runNative(v, m.nativeTimeout(), bin, "run", "-test", "-config", path)
			}
		}
	case "shell":
		// Keenetic's system /bin/sh is not a full POSIX shell and rejects -n.
		// Prefer Entware's BusyBox shell when it is installed under /opt.
		if sh := findBin([]string{"/opt/bin/sh", "/bin/sh", "sh"}); sh != "" {
			return runNative(v, m.nativeTimeout(), sh, "-n", path)
		}
	}
	return v
}

func validateBytes(v Validation, syntax string, data []byte) Validation {
	switch syntax {
	case "json":
		if !json.Valid(data) {
			v.OK = false
			v.Output = "invalid JSON"
		}
	case "shell":
		if len(bytes.TrimSpace(data)) == 0 {
			v.OK = false
			v.Output = "shell config is empty"
		}
	case "cidr-list":
		if err := validateCIDRList(string(data)); err != nil {
			v.OK = false
			v.Output = err.Error()
		}
	case "list":
		if err := validateTextList(string(data)); err != nil {
			v.OK = false
			v.Output = err.Error()
		}
	case "ini":
		if !bytes.Contains(data, []byte("[Interface]")) {
			v.OK = false
			v.Output = "missing [Interface] section"
		}
	}
	return v
}

func (m *Manager) Apply(engineID, fileID string, safeMode bool) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, f, err := lookup(engineID, fileID)
	if err != nil {
		return "", err
	}
	if safeMode {
		return "", errors.New("Safe Mode blocks writes to engine configs; draft is preserved")
	}
	validation := m.validateLocked(engineID, fileID)
	if !validation.OK {
		return "", fmt.Errorf("validation failed: %s", validation.Output)
	}
	staged := m.stagePath(engineID, fileID)
	if !fileExists(staged) {
		return "", errors.New("no staged config to apply")
	}
	dst := choosePath(f.Paths)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return "", err
	}
	if fileExists(dst) {
		if err := os.MkdirAll(m.BackupRoot, 0o700); err != nil {
			return "", err
		}
		backup := filepath.Join(m.BackupRoot, fmt.Sprintf("%s-%s-%s.bak", safeName(engineID), safeName(fileID), time.Now().UTC().Format("20060102T150405.000000000Z")))
		b, err := readLimited(dst)
		if err != nil {
			return "", err
		}
		if err := writeAtomic(backup, b, 0o600); err != nil {
			return "", err
		}
	}
	b, err := readLimited(staged)
	if err != nil {
		return "", err
	}
	mode := os.FileMode(0o600)
	if !f.Sensitive {
		if fi, err := os.Stat(dst); err == nil {
			mode = fi.Mode().Perm()
		}
	}
	if err := writeAtomic(dst, b, mode); err != nil {
		return "", err
	}
	_ = os.Remove(staged)
	return dst, nil
}

func (m *Manager) fileView(engineID string, f FileSpec) FileView {
	path := choosePath(f.Paths)
	v := FileView{ID: f.ID, Name: f.Name, Kind: f.Kind, Syntax: f.Syntax, Path: path, Sensitive: f.Sensitive, Description: f.Description}
	if fi, err := os.Stat(path); err == nil && !fi.IsDir() {
		v.Exists = true
		v.Size = fi.Size()
		v.ModifiedAt = fi.ModTime().UTC().Format(time.RFC3339)
		if !f.Sensitive && fi.Size() <= maxConfigBytes {
			if b, err := readLimited(path); err == nil {
				v.SHA256 = sum(b)
			}
		}
	}
	stage := m.stagePath(engineID, f.ID)
	if fi, err := os.Stat(stage); err == nil && !fi.IsDir() {
		v.Staged = true
		v.StagedAt = fi.ModTime().UTC().Format(time.RFC3339)
	}
	return v
}

func lookup(engineID, fileID string) (EngineSpec, FileSpec, error) {
	for _, e := range Specs() {
		if e.ID != engineID {
			continue
		}
		for _, f := range e.Files {
			if f.ID == fileID {
				return e, f, nil
			}
		}
		return EngineSpec{}, FileSpec{}, fmt.Errorf("unknown file %q for engine %q", fileID, engineID)
	}
	return EngineSpec{}, FileSpec{}, fmt.Errorf("unknown engine %q", engineID)
}

func choosePath(paths []string) string {
	for _, p := range paths {
		if fileExists(p) {
			return p
		}
	}
	if len(paths) > 0 {
		return paths[0]
	}
	return ""
}
func (m *Manager) stagePath(engineID, fileID string) string {
	return filepath.Join(m.StageRoot, safeName(engineID), safeName(fileID)+".draft")
}
func safeName(v string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, v)
}
func fileExists(path string) bool { fi, err := os.Stat(path); return err == nil && !fi.IsDir() }

func writeAtomic(path string, content []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create transaction for %s: %w", path, err)
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()
	if err := tmp.Chmod(mode); err != nil {
		return fmt.Errorf("protect transaction for %s: %w", path, err)
	}
	if _, err := tmp.Write(content); err != nil {
		return fmt.Errorf("write transaction for %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync transaction for %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close transaction for %s: %w", path, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("commit transaction for %s: %w", path, err)
	}
	return nil
}

func readLimited(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Size() > maxConfigBytes {
		return nil, fmt.Errorf("file too large: %d bytes", fi.Size())
	}
	return os.ReadFile(path)
}
func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func findBin(candidates []string) string {
	for _, p := range candidates {
		if strings.ContainsRune(p, os.PathSeparator) {
			if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
				return p
			}
			continue
		}
		if got, err := exec.LookPath(p); err == nil {
			return got
		}
	}
	return ""
}
func (m *Manager) nativeTimeout() time.Duration {
	if m.NativeTimeout <= 0 {
		return 10 * time.Second
	}
	return m.NativeTimeout
}

func runNative(v Validation, timeout time.Duration, bin string, args ...string) Validation {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, args...).CombinedOutput()
	v.Native = true
	if ctx.Err() == context.DeadlineExceeded {
		v.OK = false
		v.Output = fmt.Sprintf("native validator timed out after %s", timeout)
		return v
	}
	text := strings.TrimSpace(string(out))
	if text == "" {
		text = "native validator passed"
	}
	if len(text) > 4096 {
		text = text[:4096] + "…"
	}
	v.Output = text
	v.OK = err == nil
	return v
}
func validateTextList(s string) error {
	n := 0
	for i, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		n++
		if strings.ContainsAny(line, " \t") {
			return fmt.Errorf("line %d contains whitespace", i+1)
		}
		if len(line) > 512 {
			return fmt.Errorf("line %d is too long", i+1)
		}
	}
	if n == 0 {
		return errors.New("list has no data entries")
	}
	return nil
}
func validateCIDRList(s string) error {
	n := 0
	for i, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		n++
		if net.ParseIP(line) != nil {
			continue
		}
		if _, _, err := net.ParseCIDR(line); err != nil {
			return fmt.Errorf("line %d is not IP/CIDR: %s", i+1, line)
		}
	}
	if n == 0 {
		return errors.New("CIDR list has no data entries")
	}
	return nil
}
func SortViews(v []EngineView) { sort.Slice(v, func(i, j int) bool { return v[i].Name < v[j].Name }) }
