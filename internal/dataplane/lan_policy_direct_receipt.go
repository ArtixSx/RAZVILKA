package dataplane

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
)

// Schema 3 is a preparation record for exact physical NFQ consumer intent.
// It has no native command steps and grants no effect/deletion authority. The
// ordinary schema 1/2 effect readers reject it. Its original compiler, guards,
// boot, anchored root and single-owner promotion are still mandatory.
const lanDirectPreparationSchema = 3

func (b *LANPolicyReceiptBinding) directGuard(ctx context.Context, p *LANPolicyRuntimePlan, cleanup bool) error {
	if b == nil || b.Runtime == nil || b.ApplyGuard == nil || b.CleanupGuard == nil || b.RetireCheck == nil || ValidateLANPolicyRuntime(p) != nil || p.Mode != LANPolicyNFQWSDirectMode {
		return ErrLANPolicyRuntime
	}
	if err := b.Runtime.checkTools(ctx, p); err != nil {
		return err
	}
	guard := b.ApplyGuard
	if cleanup {
		guard = b.CleanupGuard
	}
	return errors.Join(guard(ctx, CloneLANPolicyRuntime(p), LANPolicyEffect{}), ctx.Err())
}

func loadLANDirectPreparation(ctx context.Context, s *policyAdditionSession, p *LANPolicyRuntimePlan) error {
	if ValidateLANPolicyRuntime(p) != nil || p.Mode != LANPolicyNFQWSDirectMode {
		return ErrPolicyAdditionReceipt
	}
	if err := s.loadDocument(ctx); err != nil {
		return err
	}
	if s.doc.Schema != lanDirectPreparationSchema || s.doc.Generation != p.Generation || s.doc.PolicyHash != p.Digest || s.doc.EffectsHash != "" || len(s.doc.Steps) != 0 || !nfqws2ManagedHex(s.doc.ID, 32) || s.doc.RootHash != policyAdditionRootHash(s.path) {
		return ErrPolicyAdditionReceipt
	}
	boot, err := s.options.boot()
	if err != nil || boot == "" || boot != s.doc.Boot {
		return errors.Join(ErrPolicyAdditionUnknown, err)
	}
	switch s.doc.Phase {
	case "active", "removed":
		if s.doc.PromotionTarget != "" {
			return ErrPolicyAdditionReceipt
		}
	case "promotion-intent", "promoted":
		if !lanPolicyHash(s.doc.PromotionTarget) || s.doc.PromotionTarget == s.doc.RootHash {
			return ErrPolicyAdditionReceipt
		}
	default:
		return ErrPolicyAdditionReceipt
	}
	return ctx.Err()
}

func lanDirectPreparationStatus(s *policyAdditionSession) PolicyAdditionStatus {
	return PolicyAdditionStatus{ID: s.doc.ID, Complete: s.doc.Phase == "active", Removed: s.doc.Phase == "removed", Promoted: s.doc.Phase == "promoted", Unknown: s.doc.Phase == "promotion-intent"}
}

func (b *LANPolicyReceiptBinding) applyDirect(ctx context.Context, p *LANPolicyRuntimePlan, root string) error {
	if err := b.directGuard(ctx, p, false); err != nil {
		return err
	}
	s, err := openPolicyAdditionRootSession(ctx, root, b.options)
	if err != nil {
		return err
	}
	defer s.close()
	if err := loadLANDirectPreparation(ctx, s, p); !errors.Is(err, os.ErrNotExist) {
		if err != nil {
			return err
		}
		return ErrPolicyAdditionExists
	}
	if err := b.Runtime.Preflight(ctx, p); err != nil {
		return err
	}
	boot, err := s.options.boot()
	if err != nil || boot == "" {
		return errors.Join(ErrPolicyAdditionReceipt, err)
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	if err := b.directGuard(ctx, p, false); err != nil {
		return err
	}
	s.doc = policyAdditionDocument{Schema: lanDirectPreparationSchema, ID: hex.EncodeToString(nonce[:]), Boot: boot, Generation: p.Generation, PolicyHash: p.Digest, RootHash: policyAdditionRootHash(root), Phase: "active"}
	if err := s.save(ctx); err != nil {
		return err
	}
	if err := loadLANDirectPreparation(ctx, s, p); err != nil {
		return err
	}
	return b.directGuard(ctx, p, false)
}

func (b *LANPolicyReceiptBinding) inspectDirect(ctx context.Context, p *LANPolicyRuntimePlan, root string) (PolicyAdditionStatus, error) {
	s, err := openPolicyAdditionRootSession(ctx, root, b.options)
	if err != nil {
		return PolicyAdditionStatus{}, err
	}
	defer s.close()
	if err := loadLANDirectPreparation(ctx, s, p); err != nil {
		return PolicyAdditionStatus{}, err
	}
	return lanDirectPreparationStatus(s), ctx.Err()
}

func (b *LANPolicyReceiptBinding) removeDirect(ctx context.Context, p *LANPolicyRuntimePlan, root string) error {
	if err := b.directGuard(ctx, p, true); err != nil {
		return err
	}
	s, err := openPolicyAdditionRootSession(ctx, root, b.options)
	if err != nil {
		return err
	}
	defer s.close()
	if err := loadLANDirectPreparation(ctx, s, p); err != nil {
		return err
	}
	status := lanDirectPreparationStatus(s)
	if status.Unknown || status.Promoted {
		return ErrPolicyAdditionUnknown
	}
	if err := b.RetireCheck(ctx, CloneLANPolicyRuntime(p)); err != nil {
		return err
	}
	if err := b.directGuard(ctx, p, true); err != nil {
		return err
	}
	s.doc.Phase = "removed"
	if err := s.save(ctx); err != nil {
		return err
	}
	if err := loadLANDirectPreparation(ctx, s, p); err != nil {
		return err
	}
	return b.directGuard(ctx, p, true)
}

func (b *LANPolicyReceiptBinding) promoteDirect(ctx context.Context, p *LANPolicyRuntimePlan, source, destination string) error {
	if policyAdditionRootHash(source) == policyAdditionRootHash(destination) {
		return ErrPolicyAdditionReceipt
	}
	if err := b.directGuard(ctx, p, false); err != nil {
		return err
	}
	if err := b.Runtime.Verify(ctx, p); err != nil {
		return err
	}
	s, err := openPolicyAdditionRootSession(ctx, source, b.options)
	if err != nil {
		return err
	}
	defer s.close()
	d, err := openPolicyAdditionRootSession(ctx, destination, b.options)
	if err != nil {
		return err
	}
	defer d.close()
	// This neutral durability protocol transfers the original preparation ID;
	// it executes no command and does not relax either effect-plan validator.
	if err := promotePolicyAdditionSessions(ctx, s, d, func(c context.Context) error { return loadLANDirectPreparation(c, s, p) }, func(c context.Context) error { return loadLANDirectPreparation(c, d, p) }); err != nil {
		return err
	}
	return b.directGuard(ctx, p, false)
}
