package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
)

// Health precedes Commit: its applied policy lives in the transaction, while
// policy.json may be absent or still describe the removed predecessor. Hold
// that exact authority for the whole probe; callbacks must not select another
// candidate or switch to a later committed generation.
type nodeTransitPolicyAuthority struct {
	digest     string
	boot       string
	root       string
	info       os.FileInfo
	generation string
	receiptID  string
	candidate  bool
}

func (a *ProxyTunnelAdapter) nodeTransitCandidateRoot(planID string) (string, error) {
	if a == nil || !validPlanID(planID) || !filepath.IsAbs(a.StateRoot) || filepath.Clean(a.StateRoot) != a.StateRoot || filepath.Base(a.StateRoot) != a.ID() {
		return "", ErrNodeTransitUnavailable
	}
	return filepath.Join(filepath.Dir(a.StateRoot), "transactions", planID, a.ID()), nil
}

// An active or pending committed binding must never be bypassed by falling
// back to an old complete candidate. A removed predecessor is normal during
// replacement and does not supply the candidate's state or generation.
func (a *ProxyTunnelAdapter) nodeTransitCandidateBindingIdle(candidate PolicyState) error {
	state, exists, err := a.loadPolicy()
	if err != nil {
		return errors.Join(ErrNodeTransitUnavailable, err)
	}
	if !exists {
		state = candidate
	}
	binding, bound, err := a.readPolicyBinding(state)
	if err != nil || bound && (!exists || binding.Phase != "removed") {
		return errors.Join(ErrNodeTransitUnavailable, err)
	}
	return nil
}

func (a *ProxyTunnelAdapter) captureNodeTransitPolicyAuthority(ctx context.Context, planID string, state PolicyState, root, generation string) (*nodeTransitPolicyAuthority, error) {
	canonical, err := a.nodeTransitCandidateRoot(planID)
	if err != nil {
		return nil, err
	}
	resource := root
	if root == "" {
		resource, err = a.policyGenerationRoot(generation)
	} else if root != canonical || a.xraySnapshotHash != "" && root != a.xraySnapshotRoot {
		return nil, ErrNodeTransitUnavailable
	}
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(resource)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 || !os.SameFile(info, info) {
		return nil, ErrNodeTransitUnavailable
	}
	boot, err := a.currentBootIdentity()
	if err != nil || boot == "" {
		return nil, ErrNodeTransitUnavailable
	}
	b := &nodeTransitPolicyAuthority{digest: proxyPolicyDigest(state), boot: boot, root: resource, info: info, generation: generation, candidate: root != ""}
	if !b.candidate {
		binding, exists, err := a.readPolicyBinding(state)
		if err != nil || !exists || binding.Phase != "active" || binding.Generation != generation {
			return nil, ErrNodeTransitUnavailable
		}
		b.receiptID = binding.ReceiptID
	}
	if err := b.verify(ctx, a); err != nil {
		return nil, err
	}
	return b, nil
}

func (b *nodeTransitPolicyAuthority) verify(ctx context.Context, a *ProxyTunnelAdapter) error {
	if ctx == nil || ctx.Err() != nil || a == nil || b == nil || b.info == nil {
		return ErrNodeTransitUnavailable
	}
	checkRoot := func() error {
		info, err := os.Lstat(b.root)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !os.SameFile(b.info, info) || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
			return ErrNodeTransitUnavailable
		}
		return nil
	}
	if err := checkRoot(); err != nil {
		return err
	}
	boot, err := a.currentBootIdentity()
	if err != nil || boot != b.boot {
		return ErrNodeTransitUnavailable
	}
	var state PolicyState
	argument := ""
	if b.candidate {
		if err := a.checkXrayTransactionSnapshot(); err != nil {
			return err
		}
		state, err = a.readStagedPolicy(b.root)
		argument = b.root
	} else {
		var exists bool
		state, exists, err = a.loadPolicy()
		if !exists {
			return ErrNodeTransitUnavailable
		}
	}
	if err != nil || proxyPolicyDigest(state) != b.digest {
		return errors.Join(ErrNodeTransitUnavailable, err)
	}
	if b.candidate {
		if err := a.nodeTransitCandidateBindingIdle(state); err != nil {
			return err
		}
		receipt, err := a.readCandidatePolicyReceipt(b.root, state)
		if err != nil || receipt.Boot != b.boot {
			return ErrNodeTransitUnavailable
		}
	}
	generation, err := a.nodeRouterPolicyGeneration(ctx, state, argument)
	if err != nil || generation != b.generation {
		return errors.Join(ErrNodeTransitUnavailable, err)
	}
	boot, err = a.currentBootIdentity()
	if err != nil || boot != b.boot {
		return ErrNodeTransitUnavailable
	}
	// Close after boot/receipt callbacks with fresh local state and binding,
	// without selecting a different authority.
	if b.candidate {
		if err := a.checkXrayTransactionSnapshot(); err != nil {
			return err
		}
		state, err = a.readStagedPolicy(b.root)
		if err != nil || proxyPolicyDigest(state) != b.digest {
			return ErrNodeTransitUnavailable
		}
		if err := a.nodeTransitCandidateBindingIdle(state); err != nil {
			return err
		}
		receipt, err := a.readCandidatePolicyReceipt(b.root, state)
		if err != nil || receipt.Phase != "complete" || receipt.Boot != b.boot {
			return ErrNodeTransitUnavailable
		}
	} else {
		var exists bool
		state, exists, err = a.loadPolicy()
		if err != nil || !exists || proxyPolicyDigest(state) != b.digest {
			return ErrNodeTransitUnavailable
		}
		binding, exists, err := a.readPolicyBinding(state)
		if err != nil || !exists || binding.Phase != "active" || binding.Generation != b.generation || binding.ReceiptID != b.receiptID {
			return ErrNodeTransitUnavailable
		}
	}
	return errors.Join(ctx.Err(), checkRoot())
}

func (a *ProxyTunnelAdapter) nodeTransitPolicyAuthorityFor(ctx context.Context, spec NodeTransitSpec) (*nodeTransitPolicyAuthority, error) {
	if a == nil || validateNodeTransitSpec(spec) != nil {
		return nil, ErrNodeTransitUnavailable
	}
	boot, err := a.currentBootIdentity()
	if err != nil || boot != spec.BootID {
		return nil, ErrNodeTransitUnavailable
	}
	state, exists, err := a.loadPolicy()
	if err != nil {
		return nil, errors.Join(ErrNodeTransitUnavailable, err)
	}
	if exists {
		binding, bound, err := a.readPolicyBinding(state)
		if err != nil {
			return nil, errors.Join(ErrNodeTransitUnavailable, err)
		}
		if bound && binding.Phase == "active" {
			if binding.Generation != spec.PolicyGeneration {
				return nil, ErrNodeTransitUnavailable
			}
			return a.captureNodeTransitPolicyAuthority(ctx, spec.PlanID, state, "", spec.PolicyGeneration)
		}
	}
	root, err := a.nodeTransitCandidateRoot(spec.PlanID)
	if err != nil {
		return nil, err
	}
	state, err = a.readStagedPolicy(root)
	if err != nil {
		return nil, errors.Join(ErrNodeTransitUnavailable, err)
	}
	return a.captureNodeTransitPolicyAuthority(ctx, spec.PlanID, state, root, spec.PolicyGeneration)
}
