package security

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// "Remember this device" keeps a session for 30 days and across restarts of
// the panel (updates, maintenance, router reboots). Only the SHA-256 of the
// session token is stored on the router; the token itself exists only in the
// browser cookie. Revocation, logout and password changes rewrite the file.
const (
	rememberedSessionLifetime = 30 * 24 * time.Hour
	maxRememberedSessions     = 16
	rememberedSchema          = 1
)

type rememberedDocument struct {
	Schema   int                 `json:"schema"`
	Sessions []rememberedSession `json:"sessions"`
}

type rememberedSession struct {
	Hash       string    `json:"hash"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
	RemoteIP   string    `json:"remote_ip,omitempty"`
	UserAgent  string    `json:"user_agent,omitempty"`
}

// ConfigureRememberedSessions loads remembered sessions from path and keeps
// them there. A missing file starts empty. An unreadable or invalid file is
// not loaded (the caller only logs it) and is replaced on the next change.
func (g *Gate) ConfigureRememberedSessions(path string) error {
	if g == nil || strings.TrimSpace(path) == "" {
		return errors.New("remembered session path is empty")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sessionsPath = path
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read remembered sessions: %w", err)
	}
	var doc rememberedDocument
	if json.Unmarshal(data, &doc) != nil || doc.Schema != rememberedSchema || len(doc.Sessions) > maxRememberedSessions {
		return errors.New("remembered sessions file is invalid")
	}
	now := g.now()
	for _, s := range doc.Sessions {
		raw, err := hex.DecodeString(s.Hash)
		if err != nil || len(raw) != sha256.Size || !now.Before(s.ExpiresAt) || s.ExpiresAt.Sub(s.CreatedAt) > rememberedSessionLifetime {
			continue
		}
		var hash [sha256.Size]byte
		copy(hash[:], raw)
		g.sessions[hash] = sessionRecord{ID: fmt.Sprintf("%x", hash[:8]), CreatedAt: s.CreatedAt, ExpiresAt: s.ExpiresAt, LastSeenAt: s.LastSeenAt,
			RemoteIP: boundedText(s.RemoteIP, 64), UserAgent: boundedText(s.UserAgent, 160), Remembered: true}
	}
	return nil
}

// persistRememberedLocked rewrites the file with the current unexpired
// remembered sessions. Without a configured path it does nothing.
func (g *Gate) persistRememberedLocked() error {
	if g.sessionsPath == "" {
		return nil
	}
	now := g.now()
	doc := rememberedDocument{Schema: rememberedSchema, Sessions: []rememberedSession{}}
	for hash, s := range g.sessions {
		if s.Remembered && now.Before(s.ExpiresAt) {
			doc.Sessions = append(doc.Sessions, rememberedSession{Hash: hex.EncodeToString(hash[:]), CreatedAt: s.CreatedAt, ExpiresAt: s.ExpiresAt,
				LastSeenAt: s.LastSeenAt, RemoteIP: s.RemoteIP, UserAgent: s.UserAgent})
		}
	}
	sort.Slice(doc.Sessions, func(i, j int) bool { return doc.Sessions[i].CreatedAt.Before(doc.Sessions[j].CreatedAt) })
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return writePrivateFileWithSync(g.sessionsPath, append(data, '\n'), g.privateDirSync)
}

// dropRememberedOverflowLocked keeps room for one more remembered session by
// forgetting the oldest ones.
func (g *Gate) dropRememberedOverflowLocked() {
	type entry struct {
		hash    [sha256.Size]byte
		created time.Time
	}
	remembered := []entry{}
	for hash, s := range g.sessions {
		if s.Remembered {
			remembered = append(remembered, entry{hash, s.CreatedAt})
		}
	}
	sort.Slice(remembered, func(i, j int) bool { return remembered[i].created.Before(remembered[j].created) })
	for len(remembered) >= maxRememberedSessions {
		delete(g.sessions, remembered[0].hash)
		remembered = remembered[1:]
	}
}

// revokeAllLocked forgets every session, including the remembered ones on
// disk. If the file cannot be rewritten it is removed, so no revoked session
// can return after a restart; only when both fail is an error returned.
func (g *Gate) revokeAllLocked() error {
	g.sessions = map[[sha256.Size]byte]sessionRecord{}
	if err := g.persistRememberedLocked(); err != nil {
		if removeErr := removePrivateFileWithSync(g.sessionsPath, g.privateDirSync); removeErr != nil {
			return fmt.Errorf("revoke remembered sessions: %w", errors.Join(err, removeErr))
		}
	}
	return nil
}

func boundedText(value string, limit int) string {
	if len(value) > limit {
		return value[:limit]
	}
	return value
}

func SetRememberedSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil, MaxAge: int(rememberedSessionLifetime.Seconds())})
}
