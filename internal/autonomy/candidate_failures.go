package autonomy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"time"
)

// A short, service-local cooldown avoids retrying the same failed Apply on
// every round/restart. It is never a global node blacklist or positive proof.
type CandidateFailure struct {
	NodeID     string    `json:"node_id"`
	Network    string    `json:"network"`
	Definition string    `json:"definition"`
	Scope      string    `json:"scope"`
	PlanID     string    `json:"plan_id"`
	Code       string    `json:"code"`
	ObservedAt time.Time `json:"observed_at"`
	Until      time.Time `json:"until"`
}

func ScopeFingerprint(sources []string) string {
	ordered := slices.Clone(sources)
	slices.Sort(ordered)
	data, _ := json.Marshal(ordered)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func (r *Runtime) PruneCandidateFailures(network, definition, scope string, now time.Time) {
	r.CandidateFailures = slices.DeleteFunc(r.CandidateFailures, func(f CandidateFailure) bool {
		return f.Network != network || f.Definition != definition || f.Scope != scope ||
			f.ObservedAt.IsZero() || f.ObservedAt.After(now) || !f.Until.After(now) ||
			f.Until.After(f.ObservedAt.Add(5*time.Minute)) || (f.Code != "http-403" && f.Code != "http-451")
	})
	if len(r.CandidateFailures) > 4 {
		r.CandidateFailures = slices.Clone(r.CandidateFailures[len(r.CandidateFailures)-4:])
	}
}

func (r Runtime) CandidateCoolingDown(id string) bool {
	return slices.ContainsFunc(r.CandidateFailures, func(f CandidateFailure) bool { return f.NodeID == id })
}

func (r *Runtime) RecordCandidateFailure(f CandidateFailure) {
	r.CandidateFailures = slices.DeleteFunc(r.CandidateFailures, func(old CandidateFailure) bool { return old.NodeID == f.NodeID })
	f.Until = f.ObservedAt.Add(5 * time.Minute)
	r.CandidateFailures = append(r.CandidateFailures, f)
	r.PruneCandidateFailures(f.Network, f.Definition, f.Scope, f.ObservedAt)
}
