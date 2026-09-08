package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const minimumTokenLength = 32
const (
	minimumPasswordLength = 10
	passwordIterations    = 210000
	sessionLifetime       = 12 * time.Hour
	sessionCookie         = "razvilka_session"
	defaultLoginWindow    = 10 * time.Minute
	defaultLoginLockout   = time.Minute
	defaultLoginMax       = 5
)

var ErrLoginRateLimited = errors.New("too many login attempts")

// Gate protects API operations that change router state. Read-only endpoints
// remain accessible on the LAN so the dashboard can load before authentication.
type Gate struct {
	tokenHash      [sha256.Size]byte
	tokenPath      string
	credentialPath string
	mu             sync.RWMutex
	credential     *credentialRecord
	sessions       map[[sha256.Size]byte]sessionRecord
	loginAttempts  map[string]loginAttempt
	now            func() time.Time
	loginWindow    time.Duration
	loginLockout   time.Duration
	loginMax       int
}

type sessionRecord struct {
	ID         string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastSeenAt time.Time
	RemoteIP   string
	UserAgent  string
}

type SessionInfo struct {
	ID         string `json:"id"`
	CreatedAt  string `json:"created_at"`
	ExpiresAt  string `json:"expires_at"`
	LastSeenAt string `json:"last_seen_at"`
	RemoteIP   string `json:"remote_ip,omitempty"`
	UserAgent  string `json:"user_agent,omitempty"`
	Current    bool   `json:"current"`
}

type loginAttempt struct {
	Failures    int
	FirstAt     time.Time
	LockedUntil time.Time
}

type credentialRecord struct {
	SchemaVersion int    `json:"schema_version"`
	Username      string `json:"username"`
	Salt          string `json:"salt"`
	Iterations    int    `json:"iterations"`
	PasswordHash  string `json:"password_hash"`
}

func NewGate(token string) (*Gate, error) {
	token = strings.TrimSpace(token)
	if len(token) < minimumTokenLength {
		return nil, fmt.Errorf("admin token must contain at least %d characters", minimumTokenLength)
	}
	return &Gate{
		tokenHash: sha256.Sum256([]byte(token)), sessions: map[[sha256.Size]byte]sessionRecord{}, loginAttempts: map[string]loginAttempt{},
		now: time.Now, loginWindow: defaultLoginWindow, loginLockout: defaultLoginLockout, loginMax: defaultLoginMax,
	}, nil
}

func (g *Gate) ConfigureCredentials(path string) error {
	if g == nil || strings.TrimSpace(path) == "" {
		return errors.New("credential path is empty")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.credentialPath = path
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		g.credential = nil
		return nil
	}
	if err != nil {
		return fmt.Errorf("read credentials: %w", err)
	}
	var record credentialRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return fmt.Errorf("decode credentials: %w", err)
	}
	if err := validateCredentialRecord(record); err != nil {
		return err
	}
	g.credential = &record
	return nil
}

func (g *Gate) SetupRequired() bool {
	if g == nil {
		return false
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.credential == nil
}

func (g *Gate) Username() string {
	if g == nil {
		return ""
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.credential == nil {
		return ""
	}
	return g.credential.Username
}

func (g *Gate) Setup(username, password string, requests ...*http.Request) (string, error) {
	username = strings.TrimSpace(username)
	if len(username) < 3 || len(username) > 64 {
		return "", errors.New("username must contain 3 to 64 characters")
	}
	if strings.ContainsAny(username, "\r\n\t") {
		return "", errors.New("username contains invalid characters")
	}
	if len(password) < minimumPasswordLength || len(password) > 256 {
		return "", fmt.Errorf("password must contain %d to 256 characters", minimumPasswordLength)
	}
	salt := make([]byte, 24)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	record := credentialRecord{SchemaVersion: 1, Username: username, Salt: base64.RawStdEncoding.EncodeToString(salt), Iterations: passwordIterations}
	record.PasswordHash = base64.RawStdEncoding.EncodeToString(pbkdf2SHA256([]byte(password), salt, record.Iterations, 32))

	g.mu.Lock()
	defer g.mu.Unlock()
	if g.credential != nil {
		return "", errors.New("administrator account is already configured")
	}
	if err := writeCredential(g.credentialPath, record); err != nil {
		return "", err
	}
	g.credential = &record
	return g.newSessionLocked(firstRequest(requests))
}

func (g *Gate) Login(username, password string, requests ...*http.Request) (string, error) {
	if g == nil {
		return "", errors.New("authentication is disabled")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	request := firstRequest(requests)
	key := requestIP(request)
	now := g.now()
	if attempt := g.loginAttempts[key]; now.Before(attempt.LockedUntil) {
		return "", ErrLoginRateLimited
	}
	if g.credential == nil {
		return "", errors.New("administrator account is not configured")
	}
	record := *g.credential
	salt, _ := base64.RawStdEncoding.DecodeString(record.Salt)
	want, _ := base64.RawStdEncoding.DecodeString(record.PasswordHash)
	got := pbkdf2SHA256([]byte(password), salt, record.Iterations, len(want))
	userOK := subtle.ConstantTimeCompare([]byte(username), []byte(record.Username)) == 1
	passOK := subtle.ConstantTimeCompare(got, want) == 1
	if !userOK || !passOK {
		g.recordLoginFailureLocked(key, now)
		return "", errors.New("invalid username or password")
	}
	delete(g.loginAttempts, key)
	return g.newSessionLocked(request)
}

func (g *Gate) ChangePassword(current, replacement string, request *http.Request) (string, error) {
	if len(replacement) < minimumPasswordLength || len(replacement) > 256 {
		return "", fmt.Errorf("password must contain %d to 256 characters", minimumPasswordLength)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.credential == nil {
		return "", errors.New("administrator account is not configured")
	}
	record := *g.credential
	salt, _ := base64.RawStdEncoding.DecodeString(record.Salt)
	want, _ := base64.RawStdEncoding.DecodeString(record.PasswordHash)
	got := pbkdf2SHA256([]byte(current), salt, record.Iterations, len(want))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return "", errors.New("current password is invalid")
	}
	newSalt := make([]byte, 24)
	if _, err := rand.Read(newSalt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	record.Salt = base64.RawStdEncoding.EncodeToString(newSalt)
	record.Iterations = passwordIterations
	record.PasswordHash = base64.RawStdEncoding.EncodeToString(pbkdf2SHA256([]byte(replacement), newSalt, record.Iterations, 32))
	if err := writeCredential(g.credentialPath, record); err != nil {
		return "", err
	}
	g.credential = &record
	g.sessions = map[[sha256.Size]byte]sessionRecord{}
	return g.newSessionLocked(request)
}

// RecoverPassword accepts only the recovery bearer key, not an existing UI
// session. It resets the local UI account and revokes every previous session.
func (g *Gate) RecoverPassword(username, replacement string, request *http.Request) (string, error) {
	if !g.RecoveryAuthenticated(request) {
		return "", errors.New("recovery key is invalid")
	}
	username = strings.TrimSpace(username)
	if len(username) < 3 || len(username) > 64 || strings.ContainsAny(username, "\r\n\t") {
		return "", errors.New("username must contain 3 to 64 valid characters")
	}
	if len(replacement) < minimumPasswordLength || len(replacement) > 256 {
		return "", fmt.Errorf("password must contain %d to 256 characters", minimumPasswordLength)
	}
	newSalt := make([]byte, 24)
	if _, err := rand.Read(newSalt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	record := credentialRecord{
		SchemaVersion: 1, Username: username, Salt: base64.RawStdEncoding.EncodeToString(newSalt),
		Iterations: passwordIterations,
	}
	record.PasswordHash = base64.RawStdEncoding.EncodeToString(pbkdf2SHA256([]byte(replacement), newSalt, record.Iterations, 32))
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.credential == nil {
		return "", errors.New("administrator account is not configured")
	}
	if err := writeCredential(g.credentialPath, record); err != nil {
		return "", err
	}
	g.credential = &record
	g.sessions = map[[sha256.Size]byte]sessionRecord{}
	return g.newSessionLocked(request)
}

// RotateRecoveryToken reveals a new recovery key once after verifying the
// current UI password. Existing browser sessions stay valid; the old key is
// invalid immediately.
func (g *Gate) RotateRecoveryToken(current string) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.credential == nil {
		return "", errors.New("administrator account is not configured")
	}
	if strings.TrimSpace(g.tokenPath) == "" {
		return "", errors.New("recovery token path is unavailable")
	}
	record := *g.credential
	salt, _ := base64.RawStdEncoding.DecodeString(record.Salt)
	want, _ := base64.RawStdEncoding.DecodeString(record.PasswordHash)
	got := pbkdf2SHA256([]byte(current), salt, record.Iterations, len(want))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return "", errors.New("current password is invalid")
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate recovery key: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(random)
	if err := writeTokenAtomic(g.tokenPath, token); err != nil {
		return "", err
	}
	g.tokenHash = sha256.Sum256([]byte(token))
	return token, nil
}

func (g *Gate) Sessions(request *http.Request) []SessionInfo {
	if g == nil {
		return []SessionInfo{}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	current := g.sessionHash(request)
	out := make([]SessionInfo, 0, len(g.sessions))
	for hash, session := range g.sessions {
		if now.After(session.ExpiresAt) {
			delete(g.sessions, hash)
			continue
		}
		out = append(out, sessionInfo(session, hash == current))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	return out
}

func (g *Gate) RevokeSession(id string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	for hash, session := range g.sessions {
		if session.ID == id {
			delete(g.sessions, hash)
			return true
		}
	}
	return false
}

func (g *Gate) RevokeOtherSessions(request *http.Request) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	current := g.sessionHash(request)
	removed := 0
	for hash := range g.sessions {
		if hash != current {
			delete(g.sessions, hash)
			removed++
		}
	}
	return removed
}

func (g *Gate) Logout(r *http.Request) {
	if g == nil {
		return
	}
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return
	}
	hash := sha256.Sum256([]byte(cookie.Value))
	g.mu.Lock()
	delete(g.sessions, hash)
	g.mu.Unlock()
}

func SetSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil, MaxAge: int(sessionLifetime.Seconds())})
}

func ClearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil, MaxAge: -1})
}

// LoadOrCreateToken loads a stable local administrator token, or creates a
// cryptographically random one on first start. The token file is intentionally
// readable only by its owner.
func LoadOrCreateToken(path string) (gate *Gate, token string, created bool, err error) {
	if strings.TrimSpace(path) == "" {
		return nil, "", false, errors.New("admin token path is empty")
	}

	data, readErr := readTokenFile(path)
	if readErr == nil {
		token = strings.TrimSpace(string(data))
		gate, err = NewGate(token)
		if gate != nil {
			gate.tokenPath = path
		}
		return gate, token, false, err
	}
	if !errors.Is(readErr, fs.ErrNotExist) {
		return nil, "", false, fmt.Errorf("read admin token: %w", readErr)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, "", false, fmt.Errorf("create admin token directory: %w", err)
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return nil, "", false, fmt.Errorf("generate admin token: %w", err)
	}
	token = base64.RawURLEncoding.EncodeToString(random)

	f, createErr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(createErr, fs.ErrExist) {
		data, err = readTokenFile(path)
		if err != nil {
			return nil, "", false, fmt.Errorf("read concurrently created admin token: %w", err)
		}
		token = strings.TrimSpace(string(data))
		gate, err = NewGate(token)
		if gate != nil {
			gate.tokenPath = path
		}
		return gate, token, false, err
	}
	if createErr != nil {
		return nil, "", false, fmt.Errorf("create admin token: %w", createErr)
	}
	if _, err = f.WriteString(token + "\n"); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(path)
		return nil, "", false, fmt.Errorf("persist admin token: %w", err)
	}

	gate, err = NewGate(token)
	if gate != nil {
		gate.tokenPath = path
	}
	return gate, token, true, err
}
func readTokenFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("admin token must be a regular file, not a symlink")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, fmt.Errorf("protect admin token: %w", err)
	}
	return os.ReadFile(path)
}

func (g *Gate) Authenticated(r *http.Request) bool {
	if g == nil {
		return false
	}
	if g.RecoveryAuthenticated(r) {
		return true
	}
	cookie, err := r.Cookie(sessionCookie)
	if err != nil || cookie.Value == "" {
		return false
	}
	hash := sha256.Sum256([]byte(cookie.Value))
	now := g.now()
	g.mu.Lock()
	session, ok := g.sessions[hash]
	if ok && now.After(session.ExpiresAt) {
		delete(g.sessions, hash)
		ok = false
	} else if ok {
		session.LastSeenAt = now
		g.sessions[hash] = session
	}
	g.mu.Unlock()
	return ok
}

func (g *Gate) RecoveryAuthenticated(r *http.Request) bool {
	if g == nil || r == nil {
		return false
	}
	const prefix = "Bearer "
	header := r.Header.Get("Authorization")
	if strings.HasPrefix(header, prefix) {
		token := strings.TrimSpace(strings.TrimPrefix(header, prefix))
		provided := sha256.Sum256([]byte(token))
		g.mu.RLock()
		valid := subtle.ConstantTimeCompare(g.tokenHash[:], provided[:]) == 1
		g.mu.RUnlock()
		return valid
	}
	return false
}

func (g *Gate) Middleware(next http.Handler) http.Handler {
	if g == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		mutation := isMutation(r)
		if mutation && !sameOrigin(r) {
			http.Error(w, "request origin is not allowed", http.StatusForbidden)
			return
		}
		if mutation && !isJSON(r) {
			http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
			return
		}
		if publicAPI(r.URL.Path, r.Method) {
			next.ServeHTTP(w, r)
			return
		}
		// Before first-run setup, read-only diagnostics remain visible. Once an
		// account exists, the control API requires a session for reads and writes.
		if !mutation && g.SetupRequired() {
			next.ServeHTTP(w, r)
			return
		}
		if !g.Authenticated(r) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="RAZVILKA"`)
			http.Error(w, "administrator login is required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func publicAPI(path, method string) bool {
	if path == "/api/v1/status" && method == http.MethodGet {
		return true
	}
	if path == "/api/v1/auth/status" && method == http.MethodGet {
		return true
	}
	return path == "/api/v1/auth/login" && method == http.MethodPost
}

func validateCredentialRecord(record credentialRecord) error {
	if record.SchemaVersion != 1 || len(record.Username) < 3 || record.Iterations < 100000 {
		return errors.New("invalid administrator credential record")
	}
	if _, err := base64.RawStdEncoding.DecodeString(record.Salt); err != nil {
		return errors.New("invalid credential salt")
	}
	hash, err := base64.RawStdEncoding.DecodeString(record.PasswordHash)
	if err != nil || len(hash) != 32 {
		return errors.New("invalid credential hash")
	}
	return nil
}

func writeCredential(path string, record credentialRecord) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("credential path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create credential directory: %w", err)
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".credentials.tmp-*")
	if err != nil {
		return fmt.Errorf("create credential transaction: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = tmp.Close(); _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("commit credentials: %w", err)
	}
	return nil
}

func writeTokenAtomic(path, token string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("recovery token path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return errors.New("recovery token must be a regular file")
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".admin-token.tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = tmp.Close(); _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := tmp.WriteString(token + "\n"); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("commit recovery token: %w", err)
	}
	return nil
}

func (g *Gate) newSessionLocked(request *http.Request) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate session: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(token))
	now := g.now()
	g.sessions[hash] = sessionRecord{ID: fmt.Sprintf("%x", hash[:8]), CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(sessionLifetime), RemoteIP: requestIP(request), UserAgent: boundedUserAgent(request)}
	return token, nil
}

func (g *Gate) recordLoginFailureLocked(key string, now time.Time) {
	attempt := g.loginAttempts[key]
	if attempt.FirstAt.IsZero() || now.Sub(attempt.FirstAt) > g.loginWindow {
		attempt = loginAttempt{FirstAt: now}
	}
	attempt.Failures++
	if attempt.Failures >= g.loginMax {
		attempt.LockedUntil = now.Add(g.loginLockout)
	}
	g.loginAttempts[key] = attempt
}

func (g *Gate) sessionHash(request *http.Request) [sha256.Size]byte {
	if request == nil {
		return [sha256.Size]byte{}
	}
	cookie, err := request.Cookie(sessionCookie)
	if err != nil {
		return [sha256.Size]byte{}
	}
	return sha256.Sum256([]byte(cookie.Value))
}

func sessionInfo(session sessionRecord, current bool) SessionInfo {
	return SessionInfo{ID: session.ID, CreatedAt: session.CreatedAt.UTC().Format(time.RFC3339), ExpiresAt: session.ExpiresAt.UTC().Format(time.RFC3339), LastSeenAt: session.LastSeenAt.UTC().Format(time.RFC3339), RemoteIP: session.RemoteIP, UserAgent: session.UserAgent, Current: current}
}

func firstRequest(requests []*http.Request) *http.Request {
	if len(requests) > 0 {
		return requests[0]
	}
	return nil
}

func requestIP(request *http.Request) string {
	if request == nil {
		return "local"
	}
	host := request.RemoteAddr
	if address, err := netip.ParseAddrPort(host); err == nil {
		return address.Addr().String()
	}
	if address, err := netip.ParseAddr(host); err == nil {
		return address.String()
	}
	return "unknown"
}

func boundedUserAgent(request *http.Request) string {
	if request == nil {
		return ""
	}
	value := strings.TrimSpace(request.UserAgent())
	if len(value) > 160 {
		value = value[:160]
	}
	return value
}

func pbkdf2SHA256(password, salt []byte, iterations, keyLen int) []byte {
	if iterations < 1 || keyLen < 1 {
		return nil
	}
	result := make([]byte, 0, keyLen)
	var counter [4]byte
	for block := uint32(1); len(result) < keyLen; block++ {
		binary.BigEndian.PutUint32(counter[:], block)
		mac := hmac.New(sha256.New, password)
		_, _ = mac.Write(salt)
		_, _ = mac.Write(counter[:])
		u := mac.Sum(nil)
		t := append([]byte(nil), u...)
		for i := 1; i < iterations; i++ {
			mac = hmac.New(sha256.New, password)
			_, _ = mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		result = append(result, t...)
	}
	return result[:keyLen]
}

func isMutation(r *http.Request) bool {
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func isJSON(r *http.Request) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && mediaType == "application/json"
}

func sameOrigin(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		// Non-browser clients do not normally send Origin and still need a usable
		// authenticated API. Browser requests are checked whenever Origin exists.
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return false
	}
	expectedScheme := "http"
	if r.TLS != nil {
		expectedScheme = "https"
	}
	return strings.EqualFold(u.Scheme, expectedScheme) && strings.EqualFold(u.Host, r.Host)
}
