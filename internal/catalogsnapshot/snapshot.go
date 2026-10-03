// Package catalogsnapshot encodes a bounded public catalogue checkpoint.
// A saved catalogue is data for browsing, never a route/service proof. Digests
// detect corruption, not authenticity; callers must revalidate source policy.
package catalogsnapshot

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"
)

const MaxBody = 2 << 20
const MaxEnvelope = 3 << 20

var ErrInvalid = errors.New("invalid catalogue checkpoint")

type Snapshot struct {
	Schema     int       `json:"schema"`
	Origin     string    `json:"origin"`
	CapturedAt time.Time `json:"captured_at"`
	SHA256     string    `json:"sha256"`
	Body       []byte    `json:"body"`
}

func Encode(origin string, body []byte, now time.Time) ([]byte, error) {
	if origin == "" || len(origin) > 512 || now.IsZero() || len(body) == 0 || len(body) > MaxBody {
		return nil, ErrInvalid
	}
	sum := sha256.Sum256(body)
	return json.Marshal(Snapshot{Schema: 1, Origin: origin, CapturedAt: now.UTC(), SHA256: hex.EncodeToString(sum[:]), Body: body})
}
func Decode(b []byte, origin string, now time.Time, maxAge time.Duration) (Snapshot, error) {
	var s Snapshot
	if len(b) == 0 || len(b) > MaxEnvelope || origin == "" || now.IsZero() || maxAge <= 0 {
		return s, ErrInvalid
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if dec.Decode(&s) != nil || dec.Decode(new(any)) != io.EOF || s.Schema != 1 || s.Origin != origin ||
		s.CapturedAt.IsZero() || s.CapturedAt.After(now) || now.Sub(s.CapturedAt) > maxAge || len(s.Body) == 0 || len(s.Body) > MaxBody {
		return Snapshot{}, ErrInvalid
	}
	sum := sha256.Sum256(s.Body)
	if s.SHA256 != hex.EncodeToString(sum[:]) {
		return Snapshot{}, ErrInvalid
	}
	return s, nil
}
