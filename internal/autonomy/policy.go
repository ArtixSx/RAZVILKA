// Package autonomy contains the bounded, router-side autonomy policy.
// It grants no networking capability; the App adapter must recheck consent,
// configuration, origin and exact service proof at every transaction boundary.
package autonomy

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"
	_ "time/tzdata" // Entware need not have an IANA timezone database installed.
)

const Schema = 1
const MaxServices = 128
const MaxSources = 32

var ErrPolicy = errors.New("invalid autonomy policy")
var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)

type Window struct {
	Mode  string `json:"mode"` // off, check, prepare; automatic install is NOT enabled.
	Start string `json:"start"`
	End   string `json:"end"`
	Days  []int  `json:"days"` // Sunday = 0. Cross-midnight belongs to its start day.
}
type Policy struct {
	UpdateChannel         string   `json:"update_channel,omitempty"`
	PreferredRoutes       []string `json:"preferred_routes"`
	Schema                int      `json:"schema"`
	Revision              uint64   `json:"revision"`
	InheritNewServices    bool     `json:"inherit_new_services"`
	SetupComplete         bool     `json:"setup_complete"`
	Enabled               bool     `json:"enabled"`
	Timezone              string   `json:"timezone"`
	AllLAN                bool     `json:"all_lan"`
	DefaultSources        []string `json:"default_sources"`
	SourceIDs             []string `json:"source_ids"`
	Protocols             []string `json:"protocols"`
	CheckSeconds          int      `json:"check_seconds"`
	ReserveSeconds        int      `json:"reserve_seconds"`
	ReserveTarget         int      `json:"reserve_target"` // including the primary; 1..4
	CandidatesPerRound    int      `json:"candidates_per_round"`
	FailureConfirmSeconds int      `json:"failure_confirm_seconds"`
	MaxSwitchesPerHour    int      `json:"max_switches_per_hour"`
	Application           Window   `json:"application"`
	Components            Window   `json:"components"`
}

type Service struct {
	Removing         bool     `json:"removing"`
	DeleteDefinition bool     `json:"delete_definition"`
	DraftFingerprint string   `json:"draft_fingerprint"`
	ID               string   `json:"id"`
	Enabled          bool     `json:"enabled"`
	AllLAN           bool     `json:"all_lan"`
	Sources          []string `json:"sources"`
	Definition       string   `json:"definition"`     // catalog/probe fingerprint; not evidence
	ExpectedRoute    string   `json:"expected_route"` // fences subsequent manual changes
}

func Default() Policy {
	return Policy{PreferredRoutes: []string{"nfqws2", "usque", "warp-wg"}, Schema: Schema, Timezone: "UTC", Protocols: []string{"vless", "hysteria2", "tuic", "shadowsocks"},
		SourceIDs: []string{}, DefaultSources: []string{}, CheckSeconds: 120, ReserveSeconds: 300, ReserveTarget: 3, CandidatesPerRound: 2,
		FailureConfirmSeconds: 20, MaxSwitchesPerHour: 6,
		Application: Window{Mode: "check", Start: "03:00", End: "04:00", Days: []int{0, 1, 2, 3, 4, 5, 6}},
		Components:  Window{Mode: "check", Start: "04:00", End: "05:00", Days: []int{0, 1, 2, 3, 4, 5, 6}}}
}
func ValidID(id string) bool { return identifier.MatchString(id) }
func ValidateScope(all bool, values []string) error {
	if all && len(values) != 0 || !all && len(values) == 0 || len(values) > 128 {
		return ErrPolicy
	}
	seen := map[string]bool{}
	for _, s := range values {
		if seen[s] {
			return ErrPolicy
		}
		seen[s] = true
		a, err := netip.ParseAddr(s)
		if err != nil {
			p, e := netip.ParsePrefix(s)
			if e != nil || p.Bits() == 0 || p != p.Masked() {
				return ErrPolicy
			}
			a = p.Addr()
		}
		if !a.IsValid() || a.IsUnspecified() || a.IsMulticast() || a.IsLoopback() {
			return ErrPolicy
		}
	}
	return nil
}
func Validate(p Policy) error {
	if (p.UpdateChannel != "" && p.UpdateChannel != "stable" && p.UpdateChannel != "preview") || p.Schema != Schema || p.Revision == ^uint64(0) || p.Enabled && !p.SetupComplete || p.Timezone == "" || len(p.Timezone) > 96 || p.Timezone == "Local" {
		return ErrPolicy
	}
	if _, e := time.LoadLocation(p.Timezone); e != nil {
		return fmt.Errorf("%w: timezone", ErrPolicy)
	}
	if p.SetupComplete {
		if e := ValidateScope(p.AllLAN, p.DefaultSources); e != nil {
			return e
		}
	}
	if len(p.SourceIDs) > MaxSources || len(p.Protocols) == 0 || len(p.Protocols) > 4 {
		return ErrPolicy
	}
	if len(p.PreferredRoutes) > 3 {
		return ErrPolicy
	}
	routes := map[string]bool{}
	for _, r := range p.PreferredRoutes {
		if !slices.Contains([]string{"nfqws2", "usque", "warp-wg"}, r) || routes[r] {
			return ErrPolicy
		}
		routes[r] = true
	}
	seen := map[string]bool{}
	for _, id := range p.SourceIDs {
		if !ValidID(id) || seen[id] {
			return ErrPolicy
		}
		seen[id] = true
	}
	seen = map[string]bool{}
	for _, id := range p.Protocols {
		if !slices.Contains([]string{"vless", "hysteria2", "tuic", "shadowsocks"}, id) || seen[id] {
			return ErrPolicy
		}
		seen[id] = true
	}
	if p.Enabled && len(p.SourceIDs) == 0 && len(p.PreferredRoutes) == 0 || p.CheckSeconds < 60 || p.CheckSeconds > 3600 || p.ReserveSeconds < p.CheckSeconds || p.ReserveSeconds > 86400 || p.ReserveTarget < 1 || p.ReserveTarget > 4 || p.CandidatesPerRound < 1 || p.CandidatesPerRound > 4 || p.FailureConfirmSeconds < 10 || p.FailureConfirmSeconds > 300 || p.MaxSwitchesPerHour < 1 || p.MaxSwitchesPerHour > 20 {
		return ErrPolicy
	}
	if ValidateWindow(p.Application) != nil || ValidateWindow(p.Components) != nil || p.Components.Mode == "prepare" {
		return ErrPolicy
	}
	return nil
}
func Clone(p Policy) Policy {
	p.PreferredRoutes = slices.Clone(p.PreferredRoutes)
	p.DefaultSources = slices.Clone(p.DefaultSources)
	p.SourceIDs = slices.Clone(p.SourceIDs)
	p.Protocols = slices.Clone(p.Protocols)
	p.Application.Days = slices.Clone(p.Application.Days)
	p.Components.Days = slices.Clone(p.Components.Days)
	return p
}
func Minute(s string) (int, error) {
	if len(s) != 5 || s[2] != ':' || strings.Trim(s[:2]+s[3:], "0123456789") != "" {
		return 0, ErrPolicy
	}
	h := int(s[0]-'0')*10 + int(s[1]-'0')
	m := int(s[3]-'0')*10 + int(s[4]-'0')
	if h > 23 || m > 59 {
		return 0, ErrPolicy
	}
	return h*60 + m, nil
}
func ValidateWindow(w Window) error {
	a, e := Minute(w.Start)
	b, f := Minute(w.End)
	if e != nil || f != nil || a == b || len(w.Days) == 0 || len(w.Days) > 7 || !slices.Contains([]string{"off", "check", "prepare"}, w.Mode) {
		return ErrPolicy
	}
	seen := map[int]bool{}
	for _, d := range w.Days {
		if d < 0 || d > 6 || seen[d] {
			return ErrPolicy
		}
		seen[d] = true
	}
	return nil
}

// WindowKey is stable across a repeated DST hour. Skipped windows never cause
// a catch-up installation outside the selected local window.
func WindowKey(w Window, timezone string, now time.Time) (string, bool) {
	if ValidateWindow(w) != nil || w.Mode == "off" || now.IsZero() {
		return "", false
	}
	loc, e := time.LoadLocation(timezone)
	if e != nil {
		return "", false
	}
	n := now.In(loc)
	start, _ := Minute(w.Start)
	end, _ := Minute(w.End)
	m := n.Hour()*60 + n.Minute()
	day := n
	if start < end {
		if m < start || m >= end {
			return "", false
		}
	} else {
		if m >= end && m < start {
			return "", false
		}
		if m < end {
			day = n.AddDate(0, 0, -1)
		}
	}
	if !slices.Contains(w.Days, int(day.Weekday())) {
		return "", false
	}
	return day.Format("2006-01-02") + "/" + w.Start + "/" + w.End, true
}

// NextWindow walks real minutes, so DST gaps/overlaps follow the same rule as
// dispatch. It is used by the UI, not a high-frequency data-plane loop.
func NextWindow(w Window, timezone string, now time.Time) time.Time {
	if ValidateWindow(w) != nil || w.Mode == "off" {
		return time.Time{}
	}
	n := now.Truncate(time.Minute)
	for i := 0; i < 8*24*60; i++ {
		if _, ok := WindowKey(w, timezone, n); ok {
			return n
		}
		n = n.Add(time.Minute)
	}
	return time.Time{}
}
