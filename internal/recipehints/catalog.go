// Package recipehints validates signed references to existing local recipes.
// It does not execute strategies, fetch URLs, send reports, or authorize Apply.
package recipehints

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"regexp"
	"sort"
	"time"
	"unicode/utf8"
)

const MaxCatalogBytes = 256 << 10
const MaxRecipes = 256

var ErrCatalog = errors.New("community catalog rejected")
var ident = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

type Recipe struct {
	Schema          int    `json:"schema"`
	ServiceID       string `json:"service_id"`
	Scenario        string `json:"scenario"`
	ProviderID      string `json:"provider_id"`
	TrafficClass    string `json:"traffic_class"`
	StrategyID      string `json:"strategy_id,omitempty"`
	CompatibilityID string `json:"compatibility_id"`
	Family          string `json:"family"`
	ResolutionActor string `json:"resolution_actor"`
	DNSRequestPath  string `json:"dns_request_path"`
}

func (r Recipe) Validate() error {
	if r.Schema != 1 || !ident.MatchString(r.ServiceID) || !ident.MatchString(r.Scenario) || !ident.MatchString(r.ProviderID) || !ident.MatchString(r.CompatibilityID) {
		return ErrCatalog
	}
	if !member(r.TrafficClass, "direct", "nfqws2", "warp-wg", "usque", "amneziawg", "sing-box", "xray", "smart-dns") {
		return ErrCatalog
	}
	if r.TrafficClass == "nfqws2" {
		if !ident.MatchString(r.StrategyID) {
			return ErrCatalog
		}
	} else if r.StrategyID != "" {
		return ErrCatalog
	}
	if !member(r.Family, "ipv4", "ipv6") || !member(r.ResolutionActor, "router", "engine", "remote-proxy") || !member(r.DNSRequestPath, "system", "traffic-path", "independent") {
		return ErrCatalog
	}
	if r.ResolutionActor == "remote-proxy" && !member(r.TrafficClass, "sing-box", "xray") {
		return ErrCatalog
	}
	return nil
}
func (r Recipe) Hash() (string, error) {
	if err := r.Validate(); err != nil {
		return "", err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
func member(s string, values ...string) bool {
	for _, v := range values {
		if s == v {
			return true
		}
	}
	return false
}

type Aggregate struct {
	Recipe        Recipe    `json:"recipe"`
	Hash          string    `json:"hash"`
	Cohort        string    `json:"cohort,omitempty"`
	Successes     uint32    `json:"successes"`
	Failures      uint32    `json:"failures"`
	Installations uint32    `json:"installations"`
	ObservedAt    time.Time `json:"observed_at"`
}
type Document struct {
	Schema    int         `json:"schema"`
	Sequence  uint64      `json:"sequence"`
	IssuedAt  time.Time   `json:"issued_at"`
	ExpiresAt time.Time   `json:"expires_at"`
	Recipes   []Aggregate `json:"recipes"`
	Revoked   []string    `json:"revoked"`
}
type Envelope struct {
	KeyID     string          `json:"key_id"`
	Payload   json.RawMessage `json:"payload"`
	Signature []byte          `json:"signature"`
}

// Verified's fields are private: a caller cannot set Verified=true on arbitrary
// feed data. The key is provisioned out of band, never taken from the envelope.
type Verified struct {
	doc Document
}

func (v Verified) Sequence() uint64 { return v.doc.Sequence }

func Verify(data []byte, keys map[string]ed25519.PublicKey, minSequence uint64, now time.Time) (Verified, error) {
	var empty Verified
	if len(data) == 0 || len(data) > MaxCatalogBytes || now.IsZero() {
		return empty, ErrCatalog
	}
	var e Envelope
	if decodeStrict(data, &e) != nil {
		return empty, ErrCatalog
	}
	key := keys[e.KeyID]
	if len(key) != ed25519.PublicKeySize || len(e.Signature) != ed25519.SignatureSize || !ed25519.Verify(key, e.Payload, e.Signature) {
		return empty, ErrCatalog
	}
	var d Document
	if decodeStrict(e.Payload, &d) != nil {
		return empty, ErrCatalog
	}
	if d.Schema != 1 || d.Sequence == 0 || d.Sequence < minSequence || d.IssuedAt.IsZero() || d.IssuedAt.After(now) || !d.ExpiresAt.After(now) || !d.ExpiresAt.After(d.IssuedAt) || d.ExpiresAt.Sub(d.IssuedAt) > 7*24*time.Hour || len(d.Recipes) > MaxRecipes || len(d.Revoked) > MaxRecipes {
		return empty, ErrCatalog
	}
	seen := map[string]bool{}
	for _, a := range d.Recipes {
		h, err := a.Recipe.Hash()
		if err != nil || h != a.Hash || a.Successes > 1000000 || a.Failures > 1000000 || a.Installations > 1000000 || a.Installations > a.Successes+a.Failures || a.ObservedAt.IsZero() || a.ObservedAt.After(d.IssuedAt) || a.ObservedAt.Before(d.IssuedAt.Add(-30*24*time.Hour)) || a.Cohort != "" && !ident.MatchString(a.Cohort) {
			return empty, ErrCatalog
		}
		k := h + ":" + a.Cohort
		if seen[k] {
			return empty, ErrCatalog
		}
		seen[k] = true
	}
	for _, h := range d.Revoked {
		raw, err := hex.DecodeString(h)
		if err != nil || len(raw) != sha256.Size || hex.EncodeToString(raw) != h {
			return empty, ErrCatalog
		}
		if seen["revoked:"+h] {
			return empty, ErrCatalog
		}
		seen["revoked:"+h] = true
	}
	return Verified{doc: d}, nil
}

// Reject duplicate object keys, excessive nesting, trailing values and unknown
// fields. Exact field spelling and presence matter: encoding/json otherwise
// accepts case-insensitive aliases and treats absent/null counts as zero.
// Signature covers the exact payload bytes, not a reserialized object.
func decodeStrict(data []byte, dst any) error {
	if !utf8.Valid(data) {
		return ErrCatalog
	}
	d := json.NewDecoder(bytes.NewReader(data))
	if err := uniqueValue(d, 0); err != nil {
		return err
	}
	if _, e := d.Token(); e != io.EOF {
		return ErrCatalog
	}
	var shape *catalogJSONShape
	switch dst.(type) {
	case *Envelope:
		shape = envelopeJSONShape
	case *Document:
		shape = documentJSONShape
	default:
		return ErrCatalog
	}
	if validateJSONShape(data, shape) != nil {
		return ErrCatalog
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(dst) != nil || d.Decode(&struct{}{}) != io.EOF {
		return ErrCatalog
	}
	return nil
}

// A nil child is a scalar whose concrete type is checked by the final typed
// decode. Arrays must be explicit (including [] when empty); null never means
// a known zero count or an empty revocation set in a signed snapshot.
type catalogJSONShape struct {
	fields   map[string]*catalogJSONShape
	optional map[string]bool
	array    bool
	item     *catalogJSONShape
}

var recipeJSONShape = &catalogJSONShape{
	fields: map[string]*catalogJSONShape{
		"schema": nil, "service_id": nil, "scenario": nil, "provider_id": nil,
		"traffic_class": nil, "strategy_id": nil, "compatibility_id": nil,
		"family": nil, "resolution_actor": nil, "dns_request_path": nil,
	},
	optional: map[string]bool{"strategy_id": true},
}
var aggregateJSONShape = &catalogJSONShape{
	fields: map[string]*catalogJSONShape{
		"recipe": recipeJSONShape, "hash": nil, "cohort": nil, "successes": nil,
		"failures": nil, "installations": nil, "observed_at": nil,
	},
	optional: map[string]bool{"cohort": true},
}
var documentJSONShape = &catalogJSONShape{fields: map[string]*catalogJSONShape{
	"schema": nil, "sequence": nil, "issued_at": nil, "expires_at": nil,
	"recipes": {array: true, item: aggregateJSONShape}, "revoked": {array: true},
}}
var envelopeJSONShape = &catalogJSONShape{fields: map[string]*catalogJSONShape{
	"key_id": nil, "payload": documentJSONShape, "signature": nil,
}}

func validateJSONShape(data []byte, shape *catalogJSONShape) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return ErrCatalog
	}
	if shape == nil {
		return nil
	}
	if shape.array {
		var items []json.RawMessage
		if json.Unmarshal(data, &items) != nil {
			return ErrCatalog
		}
		for _, item := range items {
			if validateJSONShape(item, shape.item) != nil {
				return ErrCatalog
			}
		}
		return nil
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil {
		return ErrCatalog
	}
	for name, raw := range fields {
		child, known := shape.fields[name]
		if !known || validateJSONShape(raw, child) != nil {
			return ErrCatalog
		}
	}
	for name := range shape.fields {
		if _, present := fields[name]; !present && !shape.optional[name] {
			return ErrCatalog
		}
	}
	return nil
}

func uniqueValue(d *json.Decoder, depth int) error {
	if depth > 16 {
		return ErrCatalog
	}
	t, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		keys := map[string]bool{}
		for d.More() {
			t, e := d.Token()
			k, ok := t.(string)
			if e != nil || !ok || keys[k] {
				return ErrCatalog
			}
			keys[k] = true
			if e := uniqueValue(d, depth+1); e != nil {
				return e
			}
		}
		t, e := d.Token()
		if e != nil || t != json.Delim('}') {
			return ErrCatalog
		}
	case '[':
		for d.More() {
			if e := uniqueValue(d, depth+1); e != nil {
				return e
			}
		}
		t, e := d.Token()
		if e != nil || t != json.Delim(']') {
			return ErrCatalog
		}
	default:
		return ErrCatalog
	}
	return nil
}

type Context struct{ ServiceID, Scenario, CompatibilityID, Family, Cohort string }
type Policy struct {
	AllowedProviders, AllowedTraffic, AllowedStrategies map[string]bool
	Limit                                               int
}
type Recommendation struct {
	Recipe             Recipe  `json:"recipe"`
	Hash               string  `json:"hash"`
	Priority           float64 `json:"priority"`
	LocalCheckRequired bool    `json:"local_check_required"`
	EligibleForApply   bool    `json:"eligible_for_apply"`
}

// Shortlist orders candidates ONLY. Signed crowd counts are publisher assertions,
// not proof of independent people, trust in a provider, or a live local route.
func (v Verified) Shortlist(c Context, p Policy, now time.Time) []Recommendation {
	out := []Recommendation{}
	if v.doc.Sequence == 0 || now.Before(v.doc.IssuedAt) || !v.doc.ExpiresAt.After(now) || p.Limit < 1 || p.Limit > 8 {
		return out
	}
	revoked := map[string]bool{}
	for _, h := range v.doc.Revoked {
		revoked[h] = true
	}
	best := map[string]Recommendation{}
	for _, a := range v.doc.Recipes {
		r := a.Recipe
		if r.ServiceID != c.ServiceID || r.Scenario != c.Scenario || r.CompatibilityID != c.CompatibilityID || r.Family != c.Family || revoked[a.Hash] || !p.AllowedProviders[r.ProviderID] || !p.AllowedTraffic[r.TrafficClass] || r.StrategyID != "" && !p.AllowedStrategies[r.StrategyID] {
			continue
		}
		if a.Cohort != "" && a.Cohort != c.Cohort {
			continue
		}
		// Without a locally-managed remote proxy, claiming to set its resolver is
		// unsupported. This initial library only proposes router/engine recipes.
		if r.ResolutionActor == "remote-proxy" {
			continue
		}
		n := float64(a.Successes + a.Failures)
		if n == 0 || a.Successes == 0 || a.Installations < 3 {
			continue
		}
		ph := float64(a.Successes) / n
		z := 1.96
		wilson := (ph + z*z/(2*n) - z*math.Sqrt((ph*(1-ph)+z*z/(4*n))/n)) / (1 + z*z/n)
		age := now.Sub(a.ObservedAt).Hours()
		if age < 0 {
			continue
		}
		score := wilson * math.Exp2(-age/72)
		if a.Cohort != "" {
			score *= 1.2
		}
		rec := Recommendation{Recipe: r, Hash: a.Hash, Priority: score, LocalCheckRequired: true}
		if prev, ok := best[a.Hash]; !ok || rec.Priority > prev.Priority {
			best[a.Hash] = rec
		}
	}
	for _, r := range best {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Priority == out[j].Priority {
			return out[i].Hash < out[j].Hash
		}
		return out[i].Priority > out[j].Priority
	})
	if len(out) > p.Limit {
		out = out[:p.Limit]
	}
	return out
}
