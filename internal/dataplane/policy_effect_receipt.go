package dataplane

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"unicode/utf8"

	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

// PolicyEffectTool identifies a trusted startup binary mapping. It is never an
// executable path read from a receipt or a request.
type PolicyEffectTool string

const (
	PolicyEffectIP              PolicyEffectTool = "ip"
	PolicyEffectIPTables        PolicyEffectTool = "iptables"
	PolicyEffectIP6Tables       PolicyEffectTool = "ip6tables"
	MaxPolicyEffects                             = 4096
	maxPolicyEffectArgs                          = 128
	maxPolicyEffectArgBytes                      = 1024
	maxPolicyEffectPlanRawBytes                  = policyAdditionMaxBytes / 2
	maxPolicyEffectPlanArgs                      = 128 << 10
	maxPolicyEffectPlanNeeds                     = 64 << 10
)

// PolicyEffect is compiler-owned intent, not a cleanup grant. Needs contains
// strictly increasing indexes of earlier effects needed by this effect. An
// attachment must depend on its entire required classifier body and routing
// prerequisites, not merely on chain creation.
type PolicyEffect struct {
	Tool   PolicyEffectTool
	Add    []string
	Delete []string
	Needs  []int
}

// PolicyEffectPlan must be reconstructed from the manager's trusted immutable
// payload for EVERY operation. Generation is its lowercase SHA256 identity.
// Do not deserialize HTTP input into this API as authority. The backend copies
// and hashes the complete expected plan, then only compares persisted commands;
// persisted commands and paths are never used as an execution source.
type PolicyEffectPlan struct {
	Generation string
	Effects    []PolicyEffect
}

type PolicyEffectTools struct {
	IP, IPTables, IP6Tables string
}

// PolicyEffectRuntime is wired only by trusted local owners. Preflight must
// inspect both families and shared namespace conflicts before the first ledger
// or kernel mutation. ExactPresence must
// inspect the exact compiled effect, returning 0 or 1; unknown syntax, foreign
// conflicts and duplicates must fail. BeforeDelete must reject live foreign
// references or other dependencies not represented by Needs. Both callbacks
// are read-only and bound to the same immutable plan as the operation.
// Guard checks current admission before each effect and immediately before RPC;
// Runner must also consume CORE admission at its actual process-start boundary.
// A successful Runner result acknowledges the actual mutation, not its enqueue.
type PolicyEffectRuntime struct {
	Runner        NFQWS2Runner
	Tools         PolicyEffectTools
	Preflight     func(context.Context) error
	ExactPresence func(context.Context, int) (int, error)
	BeforeDelete  func(context.Context, int) error
	Guard         func(context.Context, int) error
}

func (t PolicyEffectTools) command(tool PolicyEffectTool) string {
	switch tool {
	case PolicyEffectIP:
		return t.IP
	case PolicyEffectIPTables:
		return t.IPTables
	case PolicyEffectIP6Tables:
		return t.IP6Tables
	}
	return ""
}

func validPolicyEffectArgs(args []string) bool {
	if len(args) == 0 || len(args) > maxPolicyEffectArgs {
		return false
	}
	for _, arg := range args {
		if arg == "" || len(arg) > maxPolicyEffectArgBytes || !utf8.ValidString(arg) || strings.ContainsAny(arg, "\x00\r\n") {
			return false
		}
	}
	return true
}

func copyPolicyEffectPlan(plan PolicyEffectPlan) (PolicyEffectPlan, string, error) {
	if len(plan.Generation) != 64 || strings.ToLower(plan.Generation) != plan.Generation || len(plan.Effects) == 0 || len(plan.Effects) > MaxPolicyEffects {
		return PolicyEffectPlan{}, "", ErrPolicyAdditionReceipt
	}
	if _, err := hex.DecodeString(plan.Generation); err != nil {
		return PolicyEffectPlan{}, "", ErrPolicyAdditionReceipt
	}
	// Bound aggregate work BEFORE copying caller slices or JSON serialization.
	// Per-argument bounds alone would still permit hundreds of MiB of input.
	rawBytes, argumentCount, dependencyCount := len(plan.Generation), 0, 0
	for i, effect := range plan.Effects {
		switch effect.Tool {
		case PolicyEffectIP, PolicyEffectIPTables, PolicyEffectIP6Tables:
		default:
			return PolicyEffectPlan{}, "", ErrPolicyAdditionReceipt
		}
		if !validPolicyEffectArgs(effect.Add) || !validPolicyEffectArgs(effect.Delete) || len(effect.Needs) > i {
			return PolicyEffectPlan{}, "", ErrPolicyAdditionReceipt
		}
		argumentCount += len(effect.Add) + len(effect.Delete)
		dependencyCount += len(effect.Needs)
		rawBytes += len(effect.Tool) + 64 + len(effect.Needs)*8
		for _, args := range [][]string{effect.Add, effect.Delete} {
			for _, arg := range args {
				rawBytes += len(arg) + 4
			}
		}
		if rawBytes > maxPolicyEffectPlanRawBytes || argumentCount > maxPolicyEffectPlanArgs || dependencyCount > maxPolicyEffectPlanNeeds {
			return PolicyEffectPlan{}, "", ErrPolicyAdditionReceipt
		}
		previous := -1
		for _, parent := range effect.Needs {
			if parent <= previous || parent >= i {
				return PolicyEffectPlan{}, "", ErrPolicyAdditionReceipt
			}
			previous = parent
		}
	}
	result := PolicyEffectPlan{Generation: plan.Generation, Effects: make([]PolicyEffect, len(plan.Effects))}
	for i, effect := range plan.Effects {
		result.Effects[i] = PolicyEffect{Tool: effect.Tool, Add: append([]string(nil), effect.Add...), Delete: append([]string(nil), effect.Delete...), Needs: append([]int(nil), effect.Needs...)}
	}
	data, err := json.Marshal(result)
	// Leave space for receipt states, identities and command metadata inside the
	// same existing 2 MiB receipt bound before the first kernel mutation.
	if err != nil || len(data) > policyAdditionMaxBytes/2 {
		return PolicyEffectPlan{}, "", ErrPolicyAdditionReceipt
	}
	return result, routeidentity.Hash(append([]byte("policy-effects-plan-v2\x00"), data...)), nil
}

// PolicyEffectPlanDigest validates and hashes complete compiler intent. This is
// metadata only; a matching digest grants neither apply nor cleanup permission.
func PolicyEffectPlanDigest(plan PolicyEffectPlan) (string, error) {
	_, hash, err := copyPolicyEffectPlan(plan)
	return hash, err
}

type policyEffectSession struct {
	*policyAdditionSession
	plan   PolicyEffectPlan
	hash   string
	borrow *policyEffectReceiptBorrow
}

func (s *policyEffectSession) save(ctx context.Context) error {
	if err := s.policyAdditionSession.save(ctx); err != nil {
		return err
	}
	if s.borrow != nil {
		return s.borrow.saved()
	}
	return nil
}

func openPolicyEffectSession(ctx context.Context, plan PolicyEffectPlan, path string, options policyAdditionOptions) (*policyEffectSession, error) {
	plan, hash, err := copyPolicyEffectPlan(plan)
	if err != nil {
		return nil, err
	}
	s, err := openPolicyAdditionRootSession(ctx, path, options)
	if err != nil {
		return nil, err
	}
	return &policyEffectSession{policyAdditionSession: s, plan: plan, hash: hash}, nil
}

func (s *policyEffectSession) load(ctx context.Context) error {
	if err := s.loadDocument(ctx); err != nil {
		return err
	}
	if s.doc.Schema != 2 || s.doc.PolicyHash != "" || s.doc.Generation != s.plan.Generation || s.doc.EffectsHash != s.hash || len(s.doc.Steps) != len(s.plan.Effects) {
		return ErrPolicyAdditionReceipt
	}
	if err := s.validateIdentity(ctx); err != nil {
		return err
	}
	for i, step := range s.doc.Steps {
		wanted := s.plan.Effects[i]
		if step.Tool != wanted.Tool || !reflect.DeepEqual(step.Add, wanted.Add) || !reflect.DeepEqual(step.Delete, wanted.Delete) || !reflect.DeepEqual(step.Needs, wanted.Needs) || !validPolicyAdditionStepState(step.State) {
			return ErrPolicyAdditionReceipt
		}
		if step.State == "added" || step.State == "intent" || step.State == "cleanup-intent" {
			for _, parent := range wanted.Needs {
				// An initially absent ACKed prerequisite is durably fenced below.
				// Its children stay retained and the reader must report Unknown.
				parentState := s.doc.Steps[parent].State
				if parentState != "added" && parentState != "cleanup-intent" {
					return ErrPolicyAdditionReceipt
				}
			}
		}
	}
	return ctx.Err()
}

func (s *policyEffectSession) validateRuntime(runtime PolicyEffectRuntime) error {
	if runtime.Runner == nil || runtime.Preflight == nil || runtime.ExactPresence == nil || runtime.BeforeDelete == nil || runtime.Guard == nil {
		return ErrPolicyAdditionReceipt
	}
	for _, effect := range s.plan.Effects {
		name := runtime.Tools.command(effect.Tool)
		if name == "" || strings.ContainsAny(name, "\x00\r\n") {
			return ErrPolicyAdditionReceipt
		}
	}
	return nil
}

func (s *policyEffectSession) guard(ctx context.Context, runtime PolicyEffectRuntime, index int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := runtime.Guard(ctx, index); err != nil {
		return err
	}
	return ctx.Err()
}

func (s *policyEffectSession) add(ctx context.Context, runtime PolicyEffectRuntime, index int) error {
	if s.doc.Steps[index].State != "planned" {
		return ErrPolicyAdditionUnknown
	}
	for _, parent := range s.plan.Effects[index].Needs {
		if s.doc.Steps[parent].State != "added" {
			return ErrPolicyAdditionUnknown
		}
	}
	if err := s.guard(ctx, runtime, index); err != nil {
		return err
	}
	// Persist the whole-generation fence BEFORE inspecting this effect. A late
	// preexisting attachment can already reference earlier acknowledged guards;
	// it must not leave a "planned" child that cleanup would otherwise skip.
	s.doc.Steps[index].State = "intent"
	if err := s.save(ctx); err != nil {
		return errors.Join(ErrPolicyAdditionUnknown, err)
	}
	if err := s.fault("intent", index); err != nil {
		return errors.Join(ErrPolicyAdditionUnknown, err)
	}
	present, err := runtime.ExactPresence(ctx, index)
	if err != nil || present != 0 {
		return errors.Join(ErrPolicyAdditionUnknown, ErrPolicyAdditionReceipt, err)
	}
	if err := s.guard(ctx, runtime, index); err != nil {
		return errors.Join(ErrPolicyAdditionUnknown, err)
	}
	// Execute only the private copy of the caller's reconstructed expected plan.
	// A foreign copy may have appeared during durable intent IO. Never append
	// another indistinguishable copy even though the initial preflight was clear.
	present, err = runtime.ExactPresence(ctx, index)
	if err != nil || present != 0 {
		return errors.Join(ErrPolicyAdditionUnknown, err)
	}
	if err := s.guard(ctx, runtime, index); err != nil {
		return errors.Join(ErrPolicyAdditionUnknown, err)
	}
	effect := s.plan.Effects[index]
	if _, err := s.runCommand(ctx, runtime, index, false, effect.Add); err != nil {
		return errors.Join(ErrPolicyAdditionUnknown, err)
	}
	if err := s.fault("add", index); err != nil {
		return errors.Join(ErrPolicyAdditionUnknown, err)
	}
	s.doc.Steps[index].State = "added"
	if err := s.save(ctx); err != nil {
		s.doc.Steps[index].State = "intent"
		return errors.Join(ErrPolicyAdditionUnknown, err)
	}
	return s.fault("added", index)
}

// An earlier parent cannot be removed while any direct child remains active or
// unknown. The same check at each parent protects its complete prerequisite
// subtree in reverse topological cleanup; removed/planned children grant no RPC.
func (s *policyEffectSession) hasUnsettledChild(index int) bool {
	for child := index + 1; child < len(s.plan.Effects); child++ {
		state := s.doc.Steps[child].State
		if state != "added" && state != "intent" && state != "cleanup-intent" {
			continue
		}
		for _, parent := range s.plan.Effects[child].Needs {
			if parent == index {
				return true
			}
		}
	}
	return false
}

func (s *policyEffectSession) remove(ctx context.Context, runtime PolicyEffectRuntime, index int) error {
	if s.doc.Steps[index].State != "added" || s.hasUnsettledChild(index) {
		return ErrPolicyAdditionUnknown
	}
	if err := s.guard(ctx, runtime, index); err != nil {
		return err
	}
	// Fence the grant before any per-effect kernel inspection as well. If a
	// disappearance is observed, failed settlement must retain durable intent,
	// never the old ACK that could adopt a later identical external copy.
	s.doc.Steps[index].State = "cleanup-intent"
	if err := s.save(ctx); err != nil {
		s.doc.Steps[index].State = "added"
		return err
	}
	if err := s.fault("cleanup-intent", index); err != nil {
		return errors.Join(ErrPolicyAdditionUnknown, err)
	}
	if err := s.guard(ctx, runtime, index); err != nil {
		return errors.Join(ErrPolicyAdditionUnknown, err)
	}
	// Inspect foreign references and exact cardinality after durable intent IO,
	// immediately before RPC. Failure retains cleanup-intent without deletion.
	if err := runtime.BeforeDelete(ctx, index); err != nil {
		return errors.Join(ErrPolicyAdditionUnknown, err)
	}
	present, err := runtime.ExactPresence(ctx, index)
	if err != nil || present < 0 || present > 1 {
		return errors.Join(ErrPolicyAdditionUnknown, err)
	}
	if present == 0 {
		if err := s.fault("cleanup-absent-settlement", index); err != nil {
			return errors.Join(ErrPolicyAdditionUnknown, err)
		}
		s.doc.Steps[index].State = "removed"
		if err := s.save(ctx); err != nil {
			s.doc.Steps[index].State = "cleanup-intent"
			return errors.Join(ErrPolicyAdditionUnknown, err)
		}
		return s.fault("removed", index)
	}
	if err := s.guard(ctx, runtime, index); err != nil {
		return errors.Join(ErrPolicyAdditionUnknown, err)
	}
	effect := s.plan.Effects[index]
	if _, err := s.runCommand(ctx, runtime, index, true, effect.Delete); err != nil {
		return errors.Join(ErrPolicyAdditionUnknown, err)
	}
	if err := s.fault("delete", index); err != nil {
		return errors.Join(ErrPolicyAdditionUnknown, err)
	}
	present, err = runtime.ExactPresence(ctx, index)
	if err != nil || present != 0 {
		return errors.Join(ErrPolicyAdditionUnknown, err)
	}
	s.doc.Steps[index].State = "removed"
	if err := s.save(ctx); err != nil {
		s.doc.Steps[index].State = "cleanup-intent"
		return errors.Join(ErrPolicyAdditionUnknown, err)
	}
	return s.fault("removed", index)
}

func ApplyPolicyEffectsWithReceipt(ctx context.Context, runtime PolicyEffectRuntime, plan PolicyEffectPlan, root string) error {
	return applyPolicyEffects(ctx, runtime, plan, root, policyAdditionOptions{})
}

func applyPolicyEffects(ctx context.Context, runtime PolicyEffectRuntime, plan PolicyEffectPlan, root string, options policyAdditionOptions) error {
	s, err := openPolicyEffectSession(ctx, plan, root, options)
	if err != nil {
		return err
	}
	defer s.close()
	if err := s.validateRuntime(runtime); err != nil {
		return err
	}
	if err := s.load(ctx); !errors.Is(err, os.ErrNotExist) {
		if err != nil {
			return err
		}
		return ErrPolicyAdditionExists
	}
	// Shared consumer observations may borrow this actual existing writer;
	// recursively acquiring its permanent lock would refuse a valid Apply.
	borrow, err := newPolicyEffectReceiptBorrow(s)
	if err != nil {
		return err
	}
	defer borrow.close()
	s.borrow = borrow
	ctx = context.WithValue(ctx, policyEffectReceiptBorrowKey{}, borrow)
	if err := s.guard(ctx, runtime, 0); err != nil {
		return err
	}
	// The compiler owner checks BOTH families and the complete shared namespace
	// before any ledger or kernel mutation. Per-effect inspection is additional.
	if err := runtime.Preflight(ctx); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	boot, err := s.options.boot()
	if err != nil || boot == "" {
		return ErrPolicyAdditionReceipt
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return ErrPolicyAdditionReceipt
	}
	steps := make([]policyAdditionStep, len(s.plan.Effects))
	for i, effect := range s.plan.Effects {
		steps[i] = policyAdditionStep{Tool: effect.Tool, Add: effect.Add, Delete: effect.Delete, Needs: effect.Needs, State: "planned"}
	}
	s.doc = policyAdditionDocument{Schema: 2, ID: hex.EncodeToString(nonce[:]), Boot: boot, Generation: s.plan.Generation, EffectsHash: s.hash, RootHash: policyAdditionRootHash(root), Phase: "active", Steps: steps}
	borrow.requireDocument()
	if err := s.save(ctx); err != nil {
		return err
	}
	for i := range s.plan.Effects {
		if err := s.add(ctx, runtime, i); err != nil {
			return err
		}
	}
	if !s.status().Complete {
		return ErrPolicyAdditionUnknown
	}
	return ctx.Err()
}

func RemovePolicyEffectsWithReceipt(ctx context.Context, runtime PolicyEffectRuntime, plan PolicyEffectPlan, root string) error {
	return removePolicyEffects(ctx, runtime, plan, root, policyAdditionOptions{})
}

// A Guard can refuse a later effect before its durable intent; an external
// exact attachment may still exist at that planned index. Likewise a removed
// attachment can be reinserted by somebody else. Neither observation grants us
// ownership, and neither may let cleanup strip their ACKed prerequisites.
func (s *policyEffectSession) inspectCleanupPlan(ctx context.Context, runtime PolicyEffectRuntime) error {
	// Capture existing durable grants, then fence them BEFORE any kernel read.
	// A failed fence write leaves no observation of absence to forget; a crash,
	// error or absence during the scan leaves the saved whole-generation fence.
	grants := make([]bool, len(s.doc.Steps))
	firstGrant := -1
	for i, step := range s.doc.Steps {
		if step.State == "added" {
			grants[i] = true
			if firstGrant < 0 {
				firstGrant = i
			}
		}
	}
	if firstGrant >= 0 {
		if err := s.guard(ctx, runtime, firstGrant); err != nil {
			return errors.Join(ErrPolicyAdditionUnknown, err)
		}
		for i, granted := range grants {
			if granted {
				s.doc.Steps[i].State = "cleanup-intent"
			}
		}
		if err := s.fault("cleanup-scan-save", -1); err != nil {
			return errors.Join(ErrPolicyAdditionUnknown, err)
		}
		if err := s.save(ctx); err != nil {
			return errors.Join(ErrPolicyAdditionUnknown, ErrPolicyAdditionReceipt, err)
		}
		if err := s.fault("cleanup-scan-intent", -1); err != nil {
			return errors.Join(ErrPolicyAdditionUnknown, err)
		}
	}
	for i := range s.doc.Steps {
		if err := s.guard(ctx, runtime, i); err != nil {
			return errors.Join(ErrPolicyAdditionUnknown, err)
		}
		count, err := runtime.ExactPresence(ctx, i)
		wanted := 0
		if grants[i] {
			wanted = 1
		}
		if err != nil || count != wanted {
			return errors.Join(ErrPolicyAdditionUnknown, err, ctx.Err())
		}
		if err := ctx.Err(); err != nil {
			return errors.Join(ErrPolicyAdditionUnknown, err)
		}
	}
	if firstGrant >= 0 {
		if err := s.guard(ctx, runtime, firstGrant); err != nil {
			return errors.Join(ErrPolicyAdditionUnknown, err)
		}
		if err := s.fault("cleanup-scan-restore", -1); err != nil {
			return errors.Join(ErrPolicyAdditionUnknown, err)
		}
		// Restore ONLY the original ACKs after every count is consistent. This
		// is not readback adoption: no missing/ungranted effect is ever restored.
		for i, granted := range grants {
			if granted {
				s.doc.Steps[i].State = "added"
			}
		}
		if err := s.save(ctx); err != nil {
			return errors.Join(ErrPolicyAdditionUnknown, ErrPolicyAdditionReceipt, err)
		}
		if err := s.fault("cleanup-scan-restored", -1); err != nil {
			return errors.Join(ErrPolicyAdditionUnknown, err)
		}
	}
	return nil
}

func removePolicyEffects(ctx context.Context, runtime PolicyEffectRuntime, plan PolicyEffectPlan, root string, options policyAdditionOptions) error {
	s, err := openPolicyEffectSession(ctx, plan, root, options)
	if err != nil {
		return err
	}
	defer s.close()
	if err := s.validateRuntime(runtime); err != nil {
		return err
	}
	if err := s.load(ctx); err != nil {
		return errors.Join(ErrPolicyAdditionReceipt, err)
	}
	// Mixed gates deliberately do not clean even an independent ACKed subset
	// under any unknown outcome. This retains all safety guards and prerequisites.
	if s.doc.Phase != "active" || s.status().Unknown {
		return ErrPolicyAdditionUnknown
	}
	// Borrow only this genuine strict loaded Remove writer. An existing
	// receipt is mandatory and its original image is retained before checks.
	borrow, err := newPolicyEffectReceiptBorrow(s)
	if err != nil {
		return err
	}
	defer borrow.close()
	borrow.requireDocument()
	if err := borrow.saved(); err != nil {
		return err
	}
	s.borrow = borrow
	ctx = context.WithValue(ctx, policyEffectReceiptBorrowKey{}, borrow)
	if err := s.inspectCleanupPlan(ctx, runtime); err != nil {
		return err
	}
	for i := len(s.plan.Effects) - 1; i >= 0; i-- {
		if s.doc.Steps[i].State != "added" {
			continue
		}
		if err := s.remove(ctx, runtime, i); err != nil {
			return err
		}
	}
	if !s.status().Removed {
		return ErrPolicyAdditionUnknown
	}
	return nil
}

// InspectPolicyEffectsReceipt reads durable metadata only. Complete is not a
// kernel readback, admission grant, process identity or network health proof.
func InspectPolicyEffectsReceipt(ctx context.Context, plan PolicyEffectPlan, root string) (PolicyAdditionStatus, error) {
	return inspectPolicyEffects(ctx, plan, root, policyAdditionOptions{})
}

func inspectPolicyEffects(ctx context.Context, plan PolicyEffectPlan, root string, options policyAdditionOptions) (PolicyAdditionStatus, error) {
	s, err := openPolicyEffectSession(ctx, plan, root, options)
	if err != nil {
		return PolicyAdditionStatus{}, err
	}
	defer s.close()
	if err := s.load(ctx); err != nil {
		return PolicyAdditionStatus{}, err
	}
	return s.status(), nil
}

func PromotePolicyEffectsReceipt(ctx context.Context, plan PolicyEffectPlan, source, destination string) error {
	return promotePolicyEffects(ctx, plan, source, destination, policyAdditionOptions{})
}

func promotePolicyEffects(ctx context.Context, plan PolicyEffectPlan, source, destination string, options policyAdditionOptions) error {
	if policyAdditionRootHash(source) == policyAdditionRootHash(destination) {
		return ErrPolicyAdditionReceipt
	}
	s, err := openPolicyEffectSession(ctx, plan, source, options)
	if err != nil {
		return err
	}
	defer s.close()
	d, err := openPolicyEffectSession(ctx, s.plan, destination, options)
	if err != nil {
		return err
	}
	defer d.close()
	return promotePolicyAdditionSessions(ctx, s.policyAdditionSession, d.policyAdditionSession, s.load, d.load)
}
