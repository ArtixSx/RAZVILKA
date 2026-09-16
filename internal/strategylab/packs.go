package strategylab

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const MaxPackBytes = 256 << 10
const maxPackCandidates = 512
const packDomain = "RAZVILKA_STRATEGY_PACK_V1\x00"

var ErrPack = errors.New("strategy pack rejected: format, compatibility, signature or revision")
var ErrPackChanged = errors.New("strategy pack review changed")
var packID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
var packArgument = regexp.MustCompile(`^--[a-z0-9-]+(?:=[a-zA-Z0-9_.,:=+!*-]+)?$`)

type PackEntry struct {
	PoolID    string `json:"pool_id"`
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}
type StrategyPack struct {
	Schema          int         `json:"schema"`
	ID              string      `json:"id"`
	Sequence        uint64      `json:"sequence"`
	IssuedAt        time.Time   `json:"issued_at"`
	ExpiresAt       time.Time   `json:"expires_at"`
	CompatibilityID string      `json:"compatibility_id"`
	Entries         []PackEntry `json:"entries"`
}
type SignedPack struct {
	KeyID     string          `json:"key_id"`
	Payload   json.RawMessage `json:"payload"`
	Signature []byte          `json:"signature"`
}
type PackReceipt struct {
	Sequence uint64 `json:"sequence"`
	SHA256   string `json:"sha256"`
}
type PackReview struct {
	ID             string      `json:"id"`
	Sequence       uint64      `json:"sequence"`
	SHA256         string      `json:"sha256"`
	Publisher      string      `json:"publisher"`
	Entries        []PackEntry `json:"entries"`
	NativeRequired bool        `json:"native_required"`
	LiveApplied    bool        `json:"live_applied"`
}
type PackImportResult struct {
	Added        int      `json:"added"`
	Preserved    int      `json:"preserved"`
	SHA256       string   `json:"sha256"`
	CandidateIDs []string `json:"candidate_ids"`
	LiveApplied  bool     `json:"live_applied"`
}

// strictPackJSON rejects duplicate keys at any depth before typed decoding.
func strictPackJSON(data []byte, dst any) error {
	if !utf8.Valid(data) || len(data) == 0 || len(data) > MaxPackBytes {
		return ErrPack
	}
	d := json.NewDecoder(bytes.NewReader(data))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 12 {
			return ErrPack
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					key, e := d.Token()
					if e != nil {
						return e
					}
					s, ok := key.(string)
					if !ok || seen[strings.ToLower(s)] {
						return ErrPack
					}
					seen[strings.ToLower(s)] = true
					if e = walk(depth + 1); e != nil {
						return e
					}
				}
			case '[':
				for d.More() {
					if e := walk(depth + 1); e != nil {
						return e
					}
				}
			default:
				return ErrPack
			}
			_, err = d.Token()
			return err
		}
		return nil
	}
	if walk(0) != nil {
		return ErrPack
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrPack
	}
	typed := json.NewDecoder(bytes.NewReader(data))
	typed.DisallowUnknownFields()
	if typed.Decode(dst) != nil || typed.Decode(&struct{}{}) != io.EOF {
		return ErrPack
	}
	return nil
}

// ExportableArguments admits a narrow data-only subset. In particular, a pack
// cannot load Lua/scripts/files, own NFQUEUE, or set a runtime/output path.
// Unknown functionality stays local until a future compiler explicitly supports it.
func ExportableArguments(raw string) error {
	args, err := parseArguments(raw)
	if err != nil || len(args) > 96 {
		return ErrPack
	}
	for _, arg := range args {
		if len(arg) > 1024 || !packArgument.MatchString(arg) {
			return ErrPack
		}
		key, val, _ := strings.Cut(strings.TrimPrefix(arg, "--"), "=")
		switch key {
		case "filter-tcp", "filter-udp", "filter-l7", "payload":
			if val == "" {
				return ErrPack
			}
		case "new":
			if val != "" {
				return ErrPack
			}
		case "lua-desync":
			fields := strings.Split(val, ":")
			switch fields[0] {
			case "fake", "multisplit", "hostfakesplit", "http_methodeol", "circular", "autocircular":
			default:
				return ErrPack
			}
			for _, field := range fields[1:] {
				k, v, _ := strings.Cut(field, "=")
				switch k {
				case "repeats":
					n, e := strconv.Atoi(v)
					if e != nil || n < 1 || n > 32 {
						return ErrPack
					}
				case "blob", "seqovl_pattern":
					if v != "tls_clienthello" && v != "quic_initial" && v != "0x00000000" {
						return ErrPack
					}
				case "strategy", "fails", "time", "retrans", "nld", "tls_mod", "tcp_seq", "tcp_ack", "pos", "seqovl", "tcp_ts_up", "host", "midhost", "badsum", "tcp_md5":
				default:
					return ErrPack
				}
			}
		default:
			return ErrPack
		}
	}
	return nil
}

func ReviewPack(data []byte, signed bool, keys map[string]ed25519.PublicKey, now time.Time) (PackReview, error) {
	var result PackReview
	payload := data
	publisher := "personal"
	if signed {
		var env SignedPack
		if strictPackJSON(data, &env) != nil || !packID.MatchString(env.KeyID) {
			return result, ErrPack
		}
		key := keys[env.KeyID]
		if len(key) != ed25519.PublicKeySize || len(env.Signature) != ed25519.SignatureSize || !ed25519.Verify(key, append([]byte(packDomain), env.Payload...), env.Signature) {
			return result, ErrPack
		}
		payload = env.Payload
		publisher = "signed:" + env.KeyID
	}
	var p StrategyPack
	if strictPackJSON(payload, &p) != nil || p.Schema != 1 || !packID.MatchString(p.ID) || p.Sequence == 0 || p.Sequence > 9007199254740991 || p.CompatibilityID != "nfqws2-zapret-auto-v1" || len(p.Entries) == 0 || len(p.Entries) > 64 || p.IssuedAt.IsZero() || p.IssuedAt.After(now) || !p.ExpiresAt.After(now) || !p.ExpiresAt.After(p.IssuedAt) || p.ExpiresAt.Sub(p.IssuedAt) > 90*24*time.Hour {
		return result, ErrPack
	}
	seen := map[string]bool{}
	for _, entry := range p.Entries {
		if ExportableArguments(entry.Arguments) != nil {
			return result, ErrPack
		}
		c, e := buildCandidate(CandidateInput{PoolID: entry.PoolID, Name: entry.Name, Arguments: entry.Arguments}, now)
		if e != nil || seen[c.ID] {
			return result, ErrPack
		}
		seen[c.ID] = true
	}
	sum := sha256.Sum256(data)
	return PackReview{ID: p.ID, Sequence: p.Sequence, SHA256: hex.EncodeToString(sum[:]), Publisher: publisher, Entries: p.Entries, NativeRequired: true}, nil
}

// ImportPack is additive and commits candidates and anti-rollback receipt in one
// file write. It preserves ALL existing experiments, validation and selections.
// Imported evidence is structurally impossible: it is absent from the schema.
func (m *Manager) ImportPack(data []byte, signed bool, review string) (PackImportResult, error) {
	r, e := ReviewPack(data, signed, m.PackKeys, m.now())
	if e != nil {
		return PackImportResult{}, e
	}
	if review == "" || review != r.SHA256 {
		return PackImportResult{}, ErrPackChanged
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	receiptKey := r.Publisher + ":" + r.ID
	previous := m.state.PackReceipts[receiptKey]
	if r.Sequence < previous.Sequence || r.Sequence == previous.Sequence && previous.SHA256 != r.SHA256 {
		return PackImportResult{}, ErrPack
	}
	if len(m.state.PackReceipts) >= 128 && previous.Sequence == 0 {
		return PackImportResult{}, ErrPack
	}
	next := make(map[string]Candidate, len(m.state.Candidates)+len(r.Entries))
	for id, c := range m.state.Candidates {
		next[id] = c
	}
	result := PackImportResult{SHA256: r.SHA256, CandidateIDs: []string{}}
	for _, entry := range r.Entries {
		c, e := buildCandidate(CandidateInput{PoolID: entry.PoolID, Name: entry.Name, Arguments: entry.Arguments, Origin: "pack:" + r.Publisher + ":" + r.ID}, m.now())
		if e != nil {
			return PackImportResult{}, e
		}
		result.CandidateIDs = append(result.CandidateIDs, c.ID)
		if _, exists := next[c.ID]; exists {
			result.Preserved++
			continue
		}
		next[c.ID] = c
		result.Added++
	}
	if len(next) > maxPackCandidates {
		return PackImportResult{}, ErrPack
	}
	if previous.Sequence == r.Sequence && result.Added == 0 {
		return result, nil
	}
	receipts := make(map[string]PackReceipt, len(m.state.PackReceipts)+1)
	for id, v := range m.state.PackReceipts {
		receipts[id] = v
	}
	receipts[receiptKey] = PackReceipt{Sequence: r.Sequence, SHA256: r.SHA256}
	oldCandidates, oldReceipts := m.state.Candidates, m.state.PackReceipts
	m.state.Candidates, m.state.PackReceipts = next, receipts
	if e = m.saveLocked(); e != nil {
		m.state.Candidates, m.state.PackReceipts = oldCandidates, oldReceipts
		return PackImportResult{}, e
	}
	return result, nil
}

// ExportPack is an explicit portable file, not telemetry. SNI/name parameters
// remain visible and must be reviewed by the user before sharing the file.
func (m *Manager) ExportPack(ids []string) ([]byte, error) {
	if len(ids) == 0 || len(ids) > 64 {
		return nil, ErrPack
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	entries := []PackEntry{}
	seen := map[string]bool{}
	sorted := append([]string(nil), ids...)
	sort.Strings(sorted)
	for _, id := range sorted {
		c, ok := m.state.Candidates[id]
		if !ok || seen[id] || ExportableArguments(c.Arguments) != nil {
			return nil, ErrPack
		}
		seen[id] = true
		entries = append(entries, PackEntry{PoolID: c.PoolID, Name: c.Name, Arguments: c.Arguments})
	}
	now := m.now().UTC().Truncate(time.Second)
	canonical, _ := json.Marshal(entries)
	hash := sha256.Sum256(canonical)
	return json.MarshalIndent(StrategyPack{Schema: 1, ID: "personal-" + hex.EncodeToString(hash[:8]), Sequence: uint64(now.Unix()), IssuedAt: now, ExpiresAt: now.Add(30 * 24 * time.Hour), CompatibilityID: "nfqws2-zapret-auto-v1", Entries: entries}, "", "  ")
}

// SignPack is an offline publisher primitive. The private key never belongs on
// subscriber routers and is not embedded in a package or a build artifact.
func SignPack(payload []byte, keyID string, key ed25519.PrivateKey, now time.Time) ([]byte, error) {
	if !packID.MatchString(keyID) || len(key) != ed25519.PrivateKeySize {
		return nil, ErrPack
	}
	if _, e := ReviewPack(payload, false, nil, now); e != nil {
		return nil, e
	}
	// json.Marshal compacts embedded RawMessage: sign those exact bytes as well.
	var compact bytes.Buffer
	if json.Compact(&compact, payload) != nil {
		return nil, ErrPack
	}
	canonical := compact.Bytes()
	env := SignedPack{KeyID: keyID, Payload: canonical, Signature: ed25519.Sign(key, append([]byte(packDomain), canonical...))}
	return json.Marshal(env)
}
