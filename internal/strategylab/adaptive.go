package strategylab

import (
	"context"
	"errors"
	"sync"
	"time"
)

type AdaptiveMode string

const (
	ModePreferred         AdaptiveMode = "preferred"
	ModeOnly              AdaptiveMode = "only"
	ModeManual            AdaptiveMode = "manual"
	MaxAdaptiveCandidates              = 4
	MaxAdaptiveScopes                  = 128
)

type AdaptiveLimits struct {
	Candidates int
	Budget     time.Duration
	Attempt    time.Duration
	Cooldown   time.Duration
}

func DefaultAdaptiveLimits() AdaptiveLimits {
	return AdaptiveLimits{Candidates: MaxAdaptiveCandidates, Budget: time.Minute, Attempt: 15 * time.Second, Cooldown: 5 * time.Minute}
}

type AdaptiveRequest struct {
	Mode               AdaptiveMode
	Frozen             bool
	NetworkID          string    // trusted network epoch; mandatory before probing
	NotBefore          time.Time // persisted RetryAt from CORE, including after restart
	Target             ProbeTarget
	RequiredLevel      string
	Candidates         []Candidate // ordered, reviewed local candidates; no generation/import
	VLESSAllowed       bool
	VLESSFreshVerified bool // recommendation only; CORE must recheck before Apply
}

type AdaptiveAttempt struct {
	CandidateID string     `json:"candidate_id"`
	Validation  Validation `json:"validation"`
	Evidence    []Evidence `json:"evidence,omitempty"`
	Code        string     `json:"code"`
}

type AdaptiveResult struct {
	Mode             AdaptiveMode      `json:"mode"`
	NetworkID        string            `json:"network_id"`
	Code             string            `json:"code"`
	CandidateID      string            `json:"candidate_id,omitempty"`
	Level            string            `json:"level"`
	CheckedAt        time.Time         `json:"checked_at"`
	RetryAt          time.Time         `json:"retry_at,omitempty"`
	FallbackEligible bool              `json:"fallback_eligible"`
	Attempts         []AdaptiveAttempt `json:"attempts,omitempty"`
}

type adaptiveSlot struct {
	running bool
	retryAt time.Time
}

// AdaptiveSelector is a process-local, bounded library. It never selects a
// Manager draft, edits a user's strategy, applies a route or awards node
// reputation. Construct one instance per worker, not per tick. Stop cancels
// the supplied context; the executor must return only after cleanup.
type AdaptiveSelector struct {
	Validator Validator
	Executor  ProbeExecutor
	Resources ResourceInspector
	Limits    AdaptiveLimits
	Now       func() time.Time // configure dependencies before concurrent use
	mu        sync.Mutex
	slots     map[string]adaptiveSlot
	active    bool // one validator/probe batch across services on a weak router
}

func (s *AdaptiveSelector) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *AdaptiveSelector) Evaluate(parent context.Context, request AdaptiveRequest) (result AdaptiveResult, err error) {
	result = AdaptiveResult{Mode: request.Mode, NetworkID: request.NetworkID, Level: request.RequiredLevel, CheckedAt: s.now()}
	if request.Mode != ModePreferred && request.Mode != ModeOnly && request.Mode != ModeManual {
		return result, errors.New("explicit preferred/only/manual mode is required")
	}
	if err := parent.Err(); err != nil {
		result.Code = "cancelled"
		return result, err
	}
	if request.Mode == ModeManual || request.Frozen {
		result.Code = "manual"
		return result, nil
	}
	if request.RequiredLevel == "" {
		request.RequiredLevel, result.Level = LevelHTTP, LevelHTTP
	}
	if request.NetworkID == "" || len(request.NetworkID) > 256 || request.Target.ServiceID == "" || len(request.Target.ServiceID) > 128 || len(request.Candidates) > maxPackCandidates || !validProtocol(request.Target.Protocol) || !validFamily(request.Target.IPFamily) || !validLevel(request.RequiredLevel) {
		return result, errors.New("network, service, protocol, family and evidence level are required")
	}
	if request.NotBefore.After(result.CheckedAt) {
		result.Code, result.RetryAt = "cooldown", request.NotBefore
		return result, nil
	}
	limits := s.Limits
	if limits == (AdaptiveLimits{}) {
		limits = DefaultAdaptiveLimits()
	}
	if limits.Candidates < 1 || limits.Candidates > MaxAdaptiveCandidates || limits.Budget <= 0 || limits.Budget > time.Minute || limits.Attempt <= 0 || limits.Attempt > ProbeTimeout || limits.Cooldown < time.Second || limits.Cooldown > time.Hour {
		return result, errors.New("adaptive limits exceed the bounded local budget")
	}
	key := selectionKey(request.Target.ServiceID, request.Target.Protocol, request.Target.IPFamily)
	s.mu.Lock()
	if s.slots == nil {
		s.slots = map[string]adaptiveSlot{}
	}
	for key, slot := range s.slots {
		if !slot.running && !slot.retryAt.After(result.CheckedAt) {
			delete(s.slots, key)
		}
	}
	slot := s.slots[key]
	if slot.running || slot.retryAt.After(result.CheckedAt) {
		result.Code, result.RetryAt = "cooldown", slot.retryAt
		s.mu.Unlock()
		return result, nil
	}
	if s.active {
		s.mu.Unlock()
		result.Code = "busy"
		return result, nil
	}
	if len(s.slots) >= MaxAdaptiveScopes {
		s.mu.Unlock()
		result.Code = "capacity"
		return result, nil
	}
	s.slots[key] = adaptiveSlot{running: true}
	s.active = true
	s.mu.Unlock()
	defer func() {
		if parent.Err() != nil {
			result.Code, err = "cancelled", parent.Err()
		}
		result.CheckedAt = s.now()
		result.RetryAt = result.CheckedAt.Add(limits.Cooldown)
		s.mu.Lock()
		s.slots[key] = adaptiveSlot{retryAt: result.RetryAt}
		s.active = false
		s.mu.Unlock()
		if err != nil {
			result.CandidateID, result.FallbackEligible = "", false
		}
	}()
	ctx, cancel := context.WithTimeout(parent, limits.Budget)
	defer cancel()
	fallback := func(code string) (AdaptiveResult, error) {
		result.Code = code
		result.FallbackEligible = request.Mode == ModePreferred && request.VLESSAllowed && request.VLESSFreshVerified
		return result, nil
	}
	if s.Validator == nil || s.Executor == nil || s.Resources == nil {
		return fallback("local-unavailable")
	}
	if !evaluateResourceBudget(s.Resources.Inspect()).Allowed {
		return fallback("resource-limited")
	}
	seen := map[string]bool{}
	for _, candidate := range request.Candidates {
		if err := ctx.Err(); err != nil {
			result.Code = "cancelled"
			return result, err
		}
		if len(result.Attempts) >= limits.Candidates {
			break
		}
		if candidate.ID == "" || seen[candidate.ID] {
			continue
		}
		seen[candidate.ID] = true
		matches := false
		for _, pool := range Pools {
			if pool.ID == candidate.PoolID && pool.Protocol == request.Target.Protocol {
				matches = true
			}
		}
		if !matches {
			continue
		}
		attempt := AdaptiveAttempt{CandidateID: candidate.ID}
		result.Attempts = append(result.Attempts, attempt)
		last := &result.Attempts[len(result.Attempts)-1]
		// A reviewed data-only subset can call compatible installed functions;
		// expert/custom Lua remains preserved for explicit manual management.
		if ExportableArguments(candidate.Arguments) != nil {
			last.Code = "manual-strategy"
			continue
		}
		args, parseErr := parseArguments(candidate.Arguments)
		if parseErr != nil {
			last.Code = "incompatible"
			continue
		}
		validationCtx, validationCancel := context.WithTimeout(ctx, limits.Attempt)
		last.Validation = s.Validator.Validate(validationCtx, args)
		validationErr := validationCtx.Err()
		validationCancel()
		if ctx.Err() != nil {
			result.Code = "cancelled"
			return result, ctx.Err()
		}
		if validationErr != nil || !last.Validation.OK || !last.Validation.Native || !last.Validation.LuaChecked {
			last.Code = "incompatible"
			continue
		}
		candidate.Validation = last.Validation // local copy; caller's strategies unchanged
		for pass := 0; pass < RequiredPasses; pass++ {
			probeCtx, probeCancel := context.WithTimeout(ctx, limits.Attempt)
			evidence, probeErr := s.Executor.Execute(probeCtx, candidate, request.Target)
			if probeCtx.Err() != nil {
				probeErr = probeCtx.Err()
			}
			probeCancel()
			if ctx.Err() != nil {
				result.Code = "cancelled"
				return result, ctx.Err()
			}
			if probeErr != nil {
				last.Code = "local-error"
				return fallback("local-unavailable")
			}
			checked, timestampErr := time.Parse(time.RFC3339, evidence.CheckedAt)
			if evidence.CandidateID != candidate.ID || evidence.ServiceID != request.Target.ServiceID || evidence.Protocol != request.Target.Protocol || evidence.IPFamily != request.Target.IPFamily || timestampErr != nil || checked.After(s.now()) || s.now().Sub(checked) > EvidenceFreshness || len(evidence.Stages) == 0 || normalizeEvidence(&evidence) != nil {
				last.Code = "invalid-evidence"
				return fallback("inconclusive")
			}
			last.Evidence = append(last.Evidence, evidence)
			if evidence.Outcome == OutcomeLocalError {
				last.Code = "local-error"
				return fallback("local-unavailable")
			}
			if !evidence.Success || !containsLevel(evidenceLevels(evidence), request.RequiredLevel) {
				last.Code = "unconfirmed"
				break
			}
			if pass == RequiredPasses-1 {
				last.Code, result.Code, result.CandidateID = "confirmed", "candidate-ready", candidate.ID
				return result, nil
			}
		}
	}
	return fallback("bounded-exhausted")
}
