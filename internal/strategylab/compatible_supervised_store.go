package strategylab

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// No second journal: the same descriptor CAS and per-file kernel lease used by
// ordinary Strategy Lab writers own the command intent and helper receipts.
type compatibilityStateLease struct {
	target *restorejournal.FileTarget
	image  restorejournal.Image
	state  State
}

func decodeCompatibilityState(image restorejournal.Image) (State, error) {
	var state State
	if !image.Exists {
		return state, ErrCompatibilityQuiescenceUnknown
	}
	if compatibilityJSONUnique(image.Data) != nil {
		return state, ErrCompatibilityQuiescenceUnknown
	}
	d := json.NewDecoder(bytes.NewReader(image.Data))
	d.DisallowUnknownFields()
	if d.Decode(&state) != nil || d.Decode(new(any)) != io.EOF || !supervisedStrategySchema(state.SchemaVersion) || state.CompatibilitySession == nil || validateCompatibilitySession(*state.CompatibilitySession) != nil {
		return state, ErrCompatibilityQuiescenceUnknown
	}
	if state.Candidates == nil {
		state.Candidates = map[string]Candidate{}
	}
	if state.Selections == nil {
		state.Selections = map[string]Selection{}
	}
	return state, nil
}

func (s *compatibilityStateLease) close() { _ = s.target.Close() }

func openCompatibilityStateLease(ctx context.Context, path, invocationID string) (*compatibilityStateLease, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrCompatibilityQuiescenceUnknown
	}
	target, err := restorejournal.OpenFileTarget(path)
	if err != nil {
		return nil, errors.Join(ErrCompatibilityQuiescenceUnknown, err)
	}
	s := &compatibilityStateLease{target: target}
	s.image, err = target.Read(ctx)
	if err == nil {
		s.state, err = decodeCompatibilityState(s.image)
	}
	if err == nil {
		current := compatibilityActiveInvocation(s.state.CompatibilitySession)
		if !s.state.CompatibilityFinalizing || current == nil || current.Command.ID != invocationID || current.Receipt.State != "intent" || current.Acknowledged || s.state.CompatibilitySession.Unknown {
			err = ErrCompatibilityQuiescenceUnknown
		}
	}
	if err != nil {
		s.close()
		return nil, errors.Join(ErrCompatibilityQuiescenceUnknown, err)
	}
	return s, nil
}

func compatibilityActiveInvocation(session *compatibilitySession) *compatibilityInvocation {
	if session == nil {
		return nil
	}
	if session.Active == "dry-run" {
		return session.DryRun
	}
	if session.Active == "lua-init" {
		return session.LuaInit
	}
	return nil
}

func compatibilityStateImage(state State) (restorejournal.Image, error) {
	if !supervisedStrategySchema(state.SchemaVersion) || state.CompatibilitySession == nil || validateCompatibilitySession(*state.CompatibilitySession) != nil {
		return restorejournal.Image{}, ErrCompatibilityQuiescenceUnknown
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return restorejournal.Image{}, err
	}
	return restorejournal.Image{Exists: true, Data: append(data, '\n')}, nil
}

func (s *compatibilityStateLease) publish(ctx context.Context) error {
	after, err := compatibilityStateImage(s.state)
	if err != nil {
		return err
	}
	if err = s.target.CompareAndSwap(ctx, s.image, after); err != nil {
		return errors.Join(ErrCompatibilityQuiescenceUnknown, err)
	}
	s.image = after
	return nil
}

// Caller holds Manager.mu. Pending records are published only by this private
// path; ordinary saveLocked refuses them. Never reset a historical unknown.
func (m *Manager) beginCompatibilitySessionLocked(ctx context.Context, session compatibilitySession) error {
	continuation := m.nativeRunning && m.state.CompatibilityFinalizing && session.Active == "lua-init" && m.state.CompatibilitySession != nil && !compatibilitySessionUnknown(*m.state.CompatibilitySession) && compatibilityNextIntent(m.state.CompatibilitySession, session)
	if m.compatibilityRetainedUnknownLocked() || (m.compatibilityUnknownLocked() && !continuation) || m.writeBlocked || !filepath.IsAbs(m.Path) || filepath.Clean(m.Path) != m.Path || validateCompatibilitySession(session) != nil || !compatibilityNextIntent(m.state.CompatibilitySession, session) {
		return ErrCompatibilityQuiescenceUnknown
	}
	state := m.state
	state.SchemaVersion = compatibilitySupervisedSchema
	state.CompatibilitySession = &session
	state.CompatibilityFinalizing = true
	after, err := compatibilityStateImage(state)
	if err != nil {
		return err
	}
	target, err := restorejournal.OpenFileTarget(m.Path)
	if err != nil {
		return errors.Join(ErrCompatibilityQuiescenceUnknown, err)
	}
	defer target.Close()
	if err = target.CompareAndSwap(ctx, m.image, after); err != nil {
		// Even a failed sync may have published the intent. It cannot authorize
		// spawn/replay and a stale reader must not overwrite it.
		m.compatibilityUnknown, m.writeBlocked = true, true
		return errors.Join(ErrCompatibilityQuiescenceUnknown, err)
	}
	m.state, m.image = state, after
	// A late intent cannot authorize Start, even after successful fsync.
	if ctx.Err() != nil {
		m.compatibilityUnknown = true
		return errors.Join(ErrCompatibilityQuiescenceUnknown, ctx.Err())
	}
	return nil
}

// Accept only changes to the exact active receipt/output. The helper cannot
// alter the frozen command, the prior phase, candidates, evidence or packs.
func (m *Manager) readCompatibilityResultLocked(ctx context.Context, expected compatibilitySession) (State, restorejournal.Image, error) {
	image, err := restorejournal.ReadFileImage(ctx, m.Path)
	if err != nil {
		return State{}, image, errors.Join(ErrCompatibilityQuiescenceUnknown, err)
	}
	state, err := decodeCompatibilityState(image)
	if err != nil {
		return state, image, err
	}
	actual := compatibilityActiveInvocation(state.CompatibilitySession)
	prior := compatibilityActiveInvocation(&expected)
	if actual == nil || prior == nil || state.CompatibilitySession.ID != expected.ID || state.CompatibilitySession.Active != expected.Active || actual.CommandSHA256 != prior.CommandSHA256 || actual.Acknowledged || compatibilitySessionUnknownTerminal(*actual) {
		return state, image, ErrCompatibilityQuiescenceUnknown
	}
	if !compatibilityResultMatches(m.state, state) {
		return state, image, ErrCompatibilityQuiescenceUnknown
	}
	return state, image, nil
}

func compatibilitySessionUnknownTerminal(invocation compatibilityInvocation) bool {
	return invocation.Receipt.State != "reaped" && invocation.Receipt.State != "not-started"
}

// Caller already verified exact terminal proof and owns Manager.mu. Parent
// acknowledgement prevents a late helper or crash from silently retrying work.
func (m *Manager) acknowledgeCompatibilityResultLocked(ctx context.Context, state State, image restorejournal.Image) error {
	if m.compatibilityRetainedUnknownLocked() || m.writeBlocked || ctx.Err() != nil {
		return errors.Join(ErrCompatibilityQuiescenceUnknown, ctx.Err())
	}
	active := compatibilityActiveInvocation(state.CompatibilitySession)
	stored, decodeErr := decodeCompatibilityState(image)
	if active == nil || active.Acknowledged || compatibilitySessionUnknownTerminal(*active) || decodeErr != nil || !compatibilityJSONEqual(stored, state) || !compatibilityResultMatches(m.state, state) {
		return ErrCompatibilityQuiescenceUnknown
	}
	active.Acknowledged = true
	after, err := compatibilityStateImage(state)
	if err != nil {
		return err
	}
	target, err := restorejournal.OpenFileTarget(m.Path)
	if err != nil {
		return errors.Join(ErrCompatibilityQuiescenceUnknown, err)
	}
	defer target.Close()
	if err = target.CompareAndSwap(ctx, image, after); err != nil {
		m.compatibilityUnknown, m.writeBlocked = true, true
		return errors.Join(ErrCompatibilityQuiescenceUnknown, err)
	}
	m.state, m.image = state, after
	// ACK is phase evidence, not top-level publication. The durable
	// finalizing marker remains set across this fsync, even if it runs late.
	if ctx.Err() != nil {
		m.compatibilityUnknown = true
		return errors.Join(ErrCompatibilityQuiescenceUnknown, ctx.Err())
	}
	return nil
}

func compatibilityNextIntent(previous *compatibilitySession, next compatibilitySession) bool {
	active := compatibilityActiveInvocation(&next)
	if next.Unknown || active == nil || active.Receipt.State != "intent" || active.Acknowledged {
		return false
	}
	if next.Active == "dry-run" {
		return previous == nil || previous.ID != next.ID
	}
	return previous != nil && previous.ID == next.ID && previous.Active == "dry-run" && compatibilityInvocationSucceeded(*previous.DryRun) && compatibilityJSONEqual(previous.DryRun, next.DryRun)
}

func compatibilityResultMatches(before, after State) bool {
	if before.CompatibilitySession == nil || after.CompatibilitySession == nil {
		return false
	}
	old := compatibilityActiveInvocation(before.CompatibilitySession)
	actual := compatibilityActiveInvocation(after.CompatibilitySession)
	if old == nil || actual == nil || old.Receipt.State != "intent" || old.Acknowledged || actual.Acknowledged || !compatibilityReceiptTerminal(actual.Receipt) {
		return false
	}
	// Copy the parent record and substitute only the two fields the helper
	// owns. Never temporarily mutate a shared session pointer for comparison.
	allowed := before
	session := *before.CompatibilitySession
	invocation := *old
	invocation.Receipt, invocation.Output = actual.Receipt, actual.Output
	if session.Active == "dry-run" {
		session.DryRun = &invocation
	} else {
		session.LuaInit = &invocation
	}
	allowed.CompatibilitySession = &session
	return compatibilityJSONEqual(allowed, after)
}

func compatibilityJSONEqual(a, b any) bool {
	x, xErr := json.Marshal(a)
	y, yErr := json.Marshal(b)
	return xErr == nil && yErr == nil && bytes.Equal(x, y)
}

// Duplicate fields are ambiguous authority records even when encoding/json
// would otherwise accept their final value. Limit nesting as well as bytes.
func compatibilityJSONUnique(data []byte) error {
	if !utf8.Valid(data) {
		return ErrCompatibilityQuiescenceUnknown
	}
	d := json.NewDecoder(bytes.NewReader(data))
	var value func(int) error
	value = func(depth int) error {
		if depth > 64 {
			return ErrCompatibilityQuiescenceUnknown
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		if delim != '{' && delim != '[' {
			return ErrCompatibilityQuiescenceUnknown
		}
		keys := map[string]bool{}
		for d.More() {
			if delim == '{' {
				key, err := d.Token()
				name, ok := key.(string)
				name = compatibilityJSONFieldFold(name)
				if err != nil || !ok || keys[name] {
					return ErrCompatibilityQuiescenceUnknown
				}
				keys[name] = true
			}
			if err := value(depth + 1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || (delim == '{' && end != json.Delim('}')) || (delim == '[' && end != json.Delim(']')) {
			return ErrCompatibilityQuiescenceUnknown
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrCompatibilityQuiescenceUnknown
	}
	return nil
}

// Match encoding/json's Unicode simple-fold equivalence as well as ASCII
// case. For example state and \u017ftate must not become two typed fields.
func compatibilityJSONFieldFold(key string) string {
	var folded strings.Builder
	for _, r := range key {
		minimum := r
		for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
			if next < minimum {
				minimum = next
			}
		}
		folded.WriteRune(minimum)
	}
	return folded.String()
}
