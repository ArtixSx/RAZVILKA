package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

var ErrProxyPolicyUnknown = errors.New("proxy policy addition acknowledgement is unknown; automatic compensation is fenced")

// A complete receipt acknowledges ALL successful adds of one transaction.
// Unknown/partial operations confer no deletion authority. CORE's primitive
// may clean its known subset in-call; the adapter never reconstructs that
// subset from staged intent after an error or crash.
type proxyPolicyReceipt struct {
	Schema                      int `json:"schema"`
	Engine, Boot, Digest, Phase string
	Generation                  string `json:"generation,omitempty"`
	RestorationGeneration       string `json:"restoration_generation,omitempty"`
	RetirementSnapshot          string `json:"retirement_snapshot_sha256,omitempty"`
	RetirementReceiptID         string `json:"retirement_receipt_id,omitempty"`
	Checksum                    string `json:"receipt_sha256,omitempty"`
}

func proxyPolicyReceiptPath(root string) string { return filepath.Join(root, "policy-additions.json") }
func proxyPolicyDigest(state PolicyState) string {
	data, _ := json.Marshal(state)
	return routeidentity.Hash(data)
}
func writeProxyPolicyReceipt(root string, receipt proxyPolicyReceipt) error {
	receipt.Checksum = ""
	canonical, _ := json.Marshal(receipt)
	receipt.Checksum = routeidentity.Hash(canonical)
	data, _ := json.Marshal(receipt)
	owned, err := ownedfs.Open(root)
	if err != nil {
		return err
	}
	defer owned.Close()
	if err := owned.WriteAtomic(filepath.Base(proxyPolicyReceiptPath(root)), data, 0600); err != nil {
		return err
	}
	if runtime.GOOS == "linux" {
		return owned.Sync()
	}
	return nil
}

func (a *ProxyTunnelAdapter) prepareCandidatePolicy(root string, state PolicyState) error {
	if _, err := os.Lstat(proxyPolicyReceiptPath(root)); !errors.Is(err, os.ErrNotExist) {
		return ErrProxyPolicyUnknown
	}
	return writeProxyPolicyReceipt(root, proxyPolicyReceipt{Schema: 1, Engine: a.ID(), Digest: proxyPolicyDigest(state), Phase: "prepared"})
}

func (a *ProxyTunnelAdapter) readCandidatePolicyReceipt(root string, state PolicyState) (proxyPolicyReceipt, error) {
	owned, err := ownedfs.Open(root)
	if err != nil {
		return proxyPolicyReceipt{}, ErrProxyPolicyUnknown
	}
	defer owned.Close()
	data, err := owned.ReadLimited(filepath.Base(proxyPolicyReceiptPath(root)), 4096)
	if err != nil {
		return proxyPolicyReceipt{}, ErrProxyPolicyUnknown
	}
	var receipt proxyPolicyReceipt
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&receipt) != nil || decoder.Decode(new(any)) != io.EOF || receipt.Schema != 1 || receipt.Engine != a.ID() || receipt.Digest != proxyPolicyDigest(state) {
		return receipt, ErrProxyPolicyUnknown
	}
	canonical, _ := json.Marshal(receipt)
	checksum := receipt.Checksum
	receipt.Checksum = ""
	unsigned, _ := json.Marshal(receipt)
	receipt.Checksum = checksum
	if !bytes.Equal(canonical, data) || checksum != routeidentity.Hash(unsigned) {
		return receipt, ErrProxyPolicyUnknown
	}
	if receipt.RetirementSnapshot != "" {
		if err := a.validateXrayRetirementReceipt(root, receipt); err != nil {
			return receipt, err
		}
	} else if a.isXrayRetirement() || receipt.RetirementReceiptID != "" {
		return receipt, ErrProxyPolicyUnknown
	}
	if receipt.Generation != "" {
		if _, err := a.policyGenerationRoot(receipt.Generation); err != nil {
			return receipt, err
		}
	}
	if receipt.RestorationGeneration != "" {
		if _, err := a.policyGenerationRoot(receipt.RestorationGeneration); err != nil || receipt.Phase != "restoring" && receipt.Phase != "restored" {
			return receipt, ErrProxyPolicyUnknown
		}
	}
	switch receipt.Phase {
	case "prepared", "unknown", "complete", "removed", "restoring", "restored":
	default:
		return receipt, ErrProxyPolicyUnknown
	}
	return receipt, nil
}

func (a *ProxyTunnelAdapter) beginCandidatePolicy(root string, state PolicyState) error {
	receipt, err := a.readCandidatePolicyReceipt(root, state)
	if err != nil || receipt.Phase != "prepared" {
		return ErrProxyPolicyUnknown
	}
	boot, err := a.currentBootIdentity()
	if err != nil || boot == "" {
		return ErrProxyPolicyUnknown
	}
	receipt.Boot, receipt.Phase = boot, "unknown"
	// This durable fence precedes even the removal of the previous policy.
	return writeProxyPolicyReceipt(root, receipt)
}

func (a *ProxyTunnelAdapter) applyCandidatePolicy(ctx context.Context, state PolicyState, root string) error {
	receipt, err := a.readCandidatePolicyReceipt(root, state)
	if err != nil || receipt.Phase != "unknown" {
		return ErrProxyPolicyUnknown
	}
	if err := a.installForwarding(ctx, state); err != nil {
		return err
	}
	if err := applyPolicyAddition(ctx, a.Runner, a.ip(), state, root, a.additionOptions()); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	boot, err := a.currentBootIdentity()
	if err != nil || boot != receipt.Boot {
		return ErrProxyPolicyUnknown
	}
	receipt.Phase = "complete"
	return writeProxyPolicyReceipt(root, receipt)
}

func (a *ProxyTunnelAdapter) removeCandidatePolicy(ctx context.Context, root string) error {
	state, err := a.readStagedPolicy(root)
	if errors.Is(err, os.ErrNotExist) {
		if _, err := os.Lstat(proxyPolicyReceiptPath(root)); !errors.Is(err, os.ErrNotExist) {
			return ErrProxyPolicyUnknown
		}
		return nil
	}
	if err != nil {
		return ErrProxyPolicyUnknown
	}
	receipt, err := a.readCandidatePolicyReceipt(root, state)
	if err != nil {
		return err
	}
	if receipt.Phase == "prepared" || receipt.Phase == "removed" || receipt.Phase == "restored" {
		return nil
	}
	boot, err := a.currentBootIdentity()
	if err != nil || receipt.Boot != boot || receipt.Phase != "complete" && receipt.Phase != "unknown" {
		return ErrProxyPolicyUnknown
	}
	additionRoot := root
	if receipt.Generation != "" {
		additionRoot, err = a.policyGenerationRoot(receipt.Generation)
		if err != nil {
			return err
		}
		status, err := a.additionStatus(ctx, state, additionRoot)
		if err != nil || status.ID != receipt.Generation {
			return errors.Join(ErrProxyPolicyUnknown, err)
		}
	}
	if err := removePolicyAddition(ctx, a.Runner, a.ip(), state, additionRoot, a.additionOptions()); err != nil {
		return errors.Join(ErrProxyPolicyUnknown, err)
	}
	receipt.Phase = "removed"
	return writeProxyPolicyReceipt(root, receipt)
}

func (a *ProxyTunnelAdapter) verifyCandidateReceipt(ctx context.Context, root string, state PolicyState, active bool) error {
	if a.isXrayRetirement() && !active {
		snapshot, err := readProxySnapshot(root)
		if err != nil || a.verifyXrayTransactionSnapshot(snapshot) != nil {
			return errors.Join(ErrProxyPolicyUnknown, err)
		}
		return a.verifyXrayRetirementVerificationGrant(ctx, snapshot, root)
	}
	receipt, err := a.readCandidatePolicyReceipt(root, state)
	if err != nil {
		return err
	}
	if !active && receipt.Phase == "prepared" {
		return nil
	}
	if active && receipt.Phase != "complete" || !active && receipt.Phase != "restored" {
		return ErrProxyPolicyUnknown
	}
	additionRoot := root
	if receipt.Generation != "" {
		additionRoot, err = a.policyGenerationRoot(receipt.Generation)
		if err != nil {
			return err
		}
	}
	status, err := a.additionStatus(ctx, state, additionRoot)
	if err != nil || receipt.Generation != "" && status.ID != receipt.Generation || active && !status.Complete || !active && !status.Removed {
		return errors.Join(ErrProxyPolicyUnknown, err)
	}
	return nil
}

func (a *ProxyTunnelAdapter) markCandidatePolicyPhase(root string, phase string) error {
	state, err := a.rollbackPolicyState(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return ErrProxyPolicyUnknown
	}
	receipt, err := a.readCandidatePolicyReceipt(root, state)
	if err != nil {
		return err
	}
	receipt.Phase = phase
	return writeProxyPolicyReceipt(root, receipt)
}
