package security

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const minimumTokenLength = 32

// Gate protects API operations that change router state. Read-only endpoints
// remain accessible on the LAN so the dashboard can load before authentication.
type Gate struct {
	tokenHash [sha256.Size]byte
}

func NewGate(token string) (*Gate, error) {
	token = strings.TrimSpace(token)
	if len(token) < minimumTokenLength {
		return nil, fmt.Errorf("admin token must contain at least %d characters", minimumTokenLength)
	}
	return &Gate{tokenHash: sha256.Sum256([]byte(token))}, nil
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
	const prefix = "Bearer "
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	token := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	provided := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(g.tokenHash[:], provided[:]) == 1
}

func (g *Gate) Middleware(next http.Handler) http.Handler {
	if g == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isMutation(r) || !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		if !sameOrigin(r) {
			http.Error(w, "request origin is not allowed", http.StatusForbidden)
			return
		}
		if !isJSON(r) {
			http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
			return
		}
		if !g.Authenticated(r) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="RAZVILKA"`)
			http.Error(w, "administrator token is required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
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
