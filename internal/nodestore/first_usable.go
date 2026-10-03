package nodestore

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/nodequality"
	"github.com/ArtixSx/razvilka/internal/systemprobe"
)

var (
	ErrSearchRequest      = errors.New("invalid bounded candidate search")
	ErrSearchInconclusive = errors.New("candidate search has no definite exact observation")
)

// SearchRequest is trusted, consented scheduling input, never an HTTP Apply
// permission. CORE calls this only for a cold path or an authorized replacement,
// while retaining its existing exclusive operation lease and failure quorum.
type SearchRequest struct {
	Engine, ServiceID, NetworkProfile string
	Ordered                           []string
	Current                           string
	Cursor, Limit                     int
	AllowedSources, Protocols         []string
}

type SearchOutcome string

const (
	SearchUsable          SearchOutcome = "usable"
	SearchDefiniteFailure SearchOutcome = "definite-failure"
	SearchUnsupported     SearchOutcome = "unsupported"
)

// SearchCheck identifies a NEW exact record already saved by CORE's existing
// guarded check-and-record operation. The outcome itself grants no authority.
// Unsupported is neutral and must have no probe/time/record.
type SearchCheck struct {
	Outcome   SearchOutcome
	ProbeID   string
	CheckedAt time.Time
}

// SearchHooks are trusted application callbacks. There is no worker, goroutine,
// network owner or direct route mutation in this library. Guard and Apply must
// retain consent, Stop/SafeMode, CAS, network, definition and scope checks.
type SearchHooks struct {
	Guard         func(context.Context) error
	Check         func(context.Context, string) (SearchCheck, error)
	PersistCursor func(context.Context, int) error
	Apply         func(context.Context, ResolvedRoute) error
	// A true result is allowed ONLY after CORE checks the typed candidate
	// Health cause and matching verified rollback of every adapter/config,
	// persists the failure/budget, and rechecks the same authority/epoch.
	// Unknown/local/cleanup/cancel/rollback-failed never permits continuation.
	ContinueAfterRollback func(context.Context, ResolvedRoute, error) (bool, error)
	Now                   func() time.Time
}

type SearchResult struct {
	Applied                                 ResolvedRoute
	Cursor, Examined, Checks, ApplyAttempts int
	Unsupported, Rejected                   []string
}

// SearchFirstUsable checks candidates sequentially within the shared checker
// budget (1..4) and applies the first usable one immediately. It never waits for
// a reserve target. After a verified B rollback, C always gets a NEW check; a
// cached PASS or a check before the rollback cannot stand in for that check.
// Cursor advances only over consumed candidates, not a planned batch. The
// caller must freeze ordering while resuming it, and persist it in its existing
// runtime journal. A healthy primary must use the separate reserve path.
func (s *Store) SearchFirstUsable(ctx context.Context, req SearchRequest, hooks SearchHooks) (SearchResult, error) {
	result := SearchResult{Unsupported: []string{}, Rejected: []string{}}
	if err := validateSearchRequest(req, hooks); err != nil {
		return result, err
	}
	req.Ordered = slices.Clone(req.Ordered)
	req.AllowedSources = slices.Clone(req.AllowedSources)
	req.Protocols = slices.Clone(req.Protocols)
	now := hooks.Now
	if now == nil {
		now = time.Now
	}
	guard := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return hooks.Guard(ctx)
	}
	if err := guard(); err != nil {
		return result, err
	}
	if len(req.Ordered) == 0 {
		return result, nil
	}
	result.Cursor = req.Cursor % len(req.Ordered)
	advance := func(next int) error {
		if err := guard(); err != nil {
			return err
		}
		if err := hooks.PersistCursor(ctx, next); err != nil {
			return err
		}
		result.Cursor = next
		return guard()
	}
	for result.Examined < len(req.Ordered) && result.Checks < req.Limit {
		if err := guard(); err != nil {
			return result, err
		}
		id := req.Ordered[result.Cursor]
		next := (result.Cursor + 1) % len(req.Ordered)
		eligible, err := s.searchEligible(ctx, req, id, now().UTC())
		if err != nil {
			return result, err
		}
		if id == req.Current || !eligible {
			if err := advance(next); err != nil {
				return result, err
			}
			result.Examined++
			continue
		}
		started := now().UTC()
		if started.IsZero() {
			return result, ErrSearchRequest
		}
		check, err := hooks.Check(ctx, id)
		result.Checks++
		if err != nil {
			return result, err
		}
		if err := guard(); err != nil {
			return result, err
		}
		if check.Outcome == SearchUnsupported {
			if check.ProbeID != "" || !check.CheckedAt.IsZero() {
				return result, ErrSearchInconclusive
			}
			if err := advance(next); err != nil {
				return result, err
			}
			result.Examined++
			result.Unsupported = append(result.Unsupported, id)
			continue
		}
		if check.Outcome != SearchUsable && check.Outcome != SearchDefiniteFailure {
			return result, ErrSearchInconclusive
		}
		if err := s.verifySearchRecord(ctx, req, id, check, started, now().UTC()); err != nil {
			return result, err
		}
		if err := advance(next); err != nil {
			return result, err
		}
		result.Examined++
		if check.Outcome == SearchDefiniteFailure {
			continue
		}
		if err := guard(); err != nil {
			return result, err
		}
		// Re-read fresh eligibility and the same exact record after cursor I/O.
		if err := s.verifySearchRecord(ctx, req, id, check, started, now().UTC()); err != nil {
			return result, err
		}
		route := ResolvedRoute{Route: req.Engine + ":" + id, NodeID: id, Reason: "first-usable"}
		if err := guard(); err != nil {
			return result, err
		}
		result.ApplyAttempts++
		applyErr := hooks.Apply(ctx, route)
		if applyErr == nil {
			result.Applied = route
			// Apply has committed; a revoked post-commit guard is reported without
			// claiming that the mutation did not happen or repeating it.
			return result, guard()
		}
		if err := guard(); err != nil {
			return result, errors.Join(applyErr, err)
		}
		if hooks.ContinueAfterRollback == nil {
			return result, applyErr
		}
		verified, err := hooks.ContinueAfterRollback(ctx, route, applyErr)
		if err != nil {
			return result, errors.Join(applyErr, err)
		}
		if !verified {
			return result, applyErr
		}
		if err := guard(); err != nil {
			return result, errors.Join(applyErr, err)
		}
		result.Rejected = append(result.Rejected, id)
	}
	return result, nil
}

func validateSearchRequest(req SearchRequest, hooks SearchHooks) error {
	if !validRouteEngine(req.Engine) || !sourcePattern.MatchString(req.ServiceID) || !systemprobe.ValidWANProfileID(req.NetworkProfile) || len(req.Ordered) > MaxNodes || req.Cursor < 0 || req.Limit < 1 || req.Limit > 4 || len(req.AllowedSources) < 1 || len(req.AllowedSources) > MaxSources || len(req.Protocols) < 1 || len(req.Protocols) > 16 || hooks.Guard == nil || hooks.Check == nil || hooks.PersistCursor == nil || hooks.Apply == nil {
		return ErrSearchRequest
	}
	seen := map[string]bool{}
	for _, id := range req.Ordered {
		if !validNodeID(id) || seen[id] {
			return ErrSearchRequest
		}
		seen[id] = true
	}
	if req.Current != "" && !validNodeID(req.Current) {
		return ErrSearchRequest
	}
	for _, id := range req.AllowedSources {
		if !sourcePattern.MatchString(id) {
			return ErrSearchRequest
		}
	}
	for _, protocol := range req.Protocols {
		switch protocol {
		case "vless", "hysteria2", "tuic", "shadowsocks":
		default:
			return ErrSearchRequest
		}
	}
	return nil
}

func searchNodeEligible(doc document, req SearchRequest, id string, now time.Time) bool {
	i := nodeIndex(doc, id)
	if i < 0 || doc.Nodes[i].Disabled || now.IsZero() {
		return false
	}
	node := doc.Nodes[i]
	originAllowed := false
	for _, origin := range node.Origins {
		if slices.Contains(req.AllowedSources, origin.SourceID) && !now.Before(origin.ReceivedAt) && now.Before(origin.ExpiresAt) {
			originAllowed = true
		}
	}
	if !originAllowed {
		return false
	}
	for _, secret := range doc.Secrets {
		if secret.Ref == node.SecretRef {
			var material struct {
				Type string `json:"type"`
			}
			if json.Unmarshal(secret.Outbound, &material) != nil {
				return false
			}
			return slices.Contains(req.Protocols, strings.ToLower(material.Type))
		}
	}
	return false
}

func (s *Store) searchEligible(ctx context.Context, req SearchRequest, id string, now time.Time) (bool, error) {
	if err := s.lockRouteSnapshot(ctx); err != nil {
		return false, err
	}
	defer s.mu.Unlock()
	doc, _, err := s.load(ctx)
	if err != nil {
		return false, err
	}
	return searchNodeEligible(doc, req, id, now), nil
}

func (s *Store) verifySearchRecord(ctx context.Context, req SearchRequest, id string, check SearchCheck, started, now time.Time) error {
	if err := s.lockRouteSnapshot(ctx); err != nil {
		return err
	}
	defer s.mu.Unlock()
	doc, _, err := s.load(ctx)
	if err != nil {
		return err
	}
	if !searchNodeEligible(doc, req, id, now) || check.ProbeID == "" || check.CheckedAt.Before(started) || check.CheckedAt.After(now) {
		return ErrRouteProof
	}
	var latest CheckRecord
	for _, record := range doc.Nodes[nodeIndex(doc, id)].Checks {
		if record.ServiceID == req.ServiceID && record.NetworkProfile == req.NetworkProfile && record.RoutePathID == req.Engine+":"+id {
			latest = record
		}
	}
	if latest.ProbeID != check.ProbeID || !latest.CheckedAt.Equal(check.CheckedAt) || !now.Before(latest.ExpiresAt) {
		return ErrRouteProof
	}
	if check.Outcome == SearchUsable {
		if !routeCheckUsableForEngine(latest, req.Engine, id, req.ServiceID, req.NetworkProfile, now) {
			return ErrRouteProof
		}
	} else if !nodequality.ServiceFailure(latest.Verdict, latest.TestLevel, latest.Stage, latest.ErrorCode, latest.DirectLeak) {
		return ErrSearchInconclusive
	}
	return nil
}
