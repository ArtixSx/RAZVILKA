package dataplane

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// Paths come only from the adapter root plus a validated random ID. Neither
// a public route nor a persisted DTO can nominate a cleanup directory.
type proxyPolicyBinding struct {
	Schema     int    `json:"schema"`
	Engine     string `json:"engine"`
	Digest     string `json:"policy_sha256"`
	Generation string `json:"generation"`
	ReceiptID  string `json:"receipt_id,omitempty"`
	Phase      string `json:"phase"`
}

// The version distinguishes new committed policy from legacy history even
// when its separate binding is missing. PolicyState readers ignore this
// private scalar; no path or cleanup grant is embedded in policy.json.
type proxyPolicyJournal struct {
	PolicyState
	AdditionReceiptVersion int `json:"addition_receipt_version,omitempty"`
}

func (a *ProxyTunnelAdapter) additionOptions() policyAdditionOptions {
	return policyAdditionOptions{boot: a.bootIdentity}
}
func (a *ProxyTunnelAdapter) policyBindingPath() string {
	return filepath.Join(a.StateRoot, "policy-generation.json")
}
func (a *ProxyTunnelAdapter) policyGenerationRoot(id string) (string, error) {
	if len(id) != 32 {
		return "", ErrProxyPolicyUnknown
	}
	data, err := hex.DecodeString(id)
	if err != nil || hex.EncodeToString(data) != id {
		return "", ErrProxyPolicyUnknown
	}
	return filepath.Join(a.StateRoot, "policy-generations", id), nil
}
func (a *ProxyTunnelAdapter) createPolicyGeneration(id string) (string, error) {
	path, err := a.policyGenerationRoot(id)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(a.StateRoot, 0700); err != nil {
		return "", err
	}
	root, err := ownedfs.Open(a.StateRoot)
	if err != nil {
		return "", err
	}
	defer root.Close()
	if err := root.MkdirAll("policy-generations", 0700); err != nil {
		return "", err
	}
	name := filepath.Join("policy-generations", id)
	if _, err := root.Stat(name); !errors.Is(err, os.ErrNotExist) {
		return "", ErrPolicyAdditionExists
	}
	if err := root.MkdirAll(name, 0700); err != nil {
		return "", err
	}
	if runtime.GOOS == "linux" {
		parent, err := ownedfs.Open(filepath.Dir(path))
		if err != nil {
			return "", err
		}
		err = parent.Sync()
		parent.Close()
		if err != nil || root.Sync() != nil {
			return "", ErrProxyPolicyUnknown
		}
	}
	return path, nil
}
func (a *ProxyTunnelAdapter) writePolicyBinding(binding proxyPolicyBinding) error {
	data, _ := json.Marshal(binding)
	root, err := ownedfs.Open(a.StateRoot)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.WriteAtomic(filepath.Base(a.policyBindingPath()), data, 0600); err != nil {
		return err
	}
	if runtime.GOOS == "linux" {
		return root.Sync()
	}
	return nil
}
func (a *ProxyTunnelAdapter) readPolicyBinding(state PolicyState) (proxyPolicyBinding, bool, error) {
	var binding proxyPolicyBinding
	root, err := ownedfs.Open(a.StateRoot)
	if errors.Is(err, os.ErrNotExist) {
		return binding, false, nil
	}
	if err != nil {
		return binding, false, ErrProxyPolicyUnknown
	}
	defer root.Close()
	info, err := root.Stat(filepath.Base(a.policyBindingPath()))
	if errors.Is(err, os.ErrNotExist) {
		return binding, false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > 4096 || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return binding, true, ErrProxyPolicyUnknown
	}
	data, err := root.ReadLimited(filepath.Base(a.policyBindingPath()), 4096)
	if errors.Is(err, os.ErrNotExist) {
		return binding, false, nil
	}
	if err != nil {
		return binding, false, ErrProxyPolicyUnknown
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&binding) != nil || d.Decode(new(any)) != io.EOF {
		return binding, true, ErrProxyPolicyUnknown
	}
	canonical, _ := json.Marshal(binding)
	if !bytes.Equal(canonical, data) || binding.Schema != 1 || binding.Engine != a.ID() || binding.Digest != proxyPolicyDigest(state) {
		return binding, true, ErrProxyPolicyUnknown
	}
	if _, err := a.policyGenerationRoot(binding.Generation); err != nil {
		return binding, true, err
	}
	if binding.Phase != "pending" && binding.Phase != "active" && binding.Phase != "removed" {
		return binding, true, ErrProxyPolicyUnknown
	}
	return binding, true, nil
}
func (a *ProxyTunnelAdapter) additionStatus(ctx context.Context, state PolicyState, root string) (PolicyAdditionStatus, error) {
	s, err := openPolicyAdditionSession(ctx, state, root, a.additionOptions())
	if err != nil {
		return PolicyAdditionStatus{}, err
	}
	defer s.close()
	if err := s.load(ctx); err != nil {
		return PolicyAdditionStatus{}, err
	}
	return s.status(), nil
}
func (a *ProxyTunnelAdapter) trackedPolicyJournal() (bool, error) {
	data, err := readBoundedSidecar(a.policyPath())
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	var journal proxyPolicyJournal
	if err != nil || json.Unmarshal(data, &journal) != nil || journal.AdditionReceiptVersion < 0 || journal.AdditionReceiptVersion > 1 {
		return false, ErrProxyPolicyUnknown
	}
	return journal.AdditionReceiptVersion == 1, nil
}
func (a *ProxyTunnelAdapter) savePolicyJournal(state PolicyState, tracked bool) error {
	version := 0
	if tracked {
		version = 1
	}
	data, _ := json.MarshalIndent(proxyPolicyJournal{state, version}, "", "  ")
	if err := writeAtomic(a.policyPath(), data, 0600); err != nil {
		return err
	}
	if runtime.GOOS == "linux" {
		root, err := ownedfs.Open(a.StateRoot)
		if err != nil {
			return err
		}
		defer root.Close()
		return root.Sync()
	}
	return nil
}

// Called before Commit drops the transaction. The transaction first records
// the receiver ID, then transfers the grant, then writes the committed binding.
// A later outer Commit failure can still clean via this exact receiver root.
func (a *ProxyTunnelAdapter) promoteCandidatePolicy(ctx context.Context, state PolicyState, root string) error {
	receipt, err := a.readCandidatePolicyReceipt(root, state)
	if err != nil || receipt.Phase != "complete" {
		return ErrProxyPolicyUnknown
	}
	if receipt.Generation == "" {
		status, err := a.additionStatus(ctx, state, root)
		if err != nil || !status.Complete {
			return errors.Join(ErrProxyPolicyUnknown, err)
		}
		if _, err := a.createPolicyGeneration(status.ID); err != nil {
			return err
		}
		receipt.Generation = status.ID
		if err := writeProxyPolicyReceipt(root, receipt); err != nil {
			return err
		}
	}
	destination, err := a.policyGenerationRoot(receipt.Generation)
	if err != nil {
		return err
	}
	if err := promotePolicyAddition(ctx, state, root, destination, a.additionOptions()); err != nil {
		return errors.Join(ErrProxyPolicyUnknown, err)
	}
	status, err := a.additionStatus(ctx, state, destination)
	if err != nil || !status.Complete || status.ID != receipt.Generation {
		return errors.Join(ErrProxyPolicyUnknown, err)
	}
	return a.writePolicyBinding(proxyPolicyBinding{Schema: 1, Engine: a.ID(), Digest: proxyPolicyDigest(state), Generation: receipt.Generation, ReceiptID: status.ID, Phase: "active"})
}

// New recovery/restoration attempts never revive an old removed receipt.
// The pending reference is durable before any add. Failure leaves it and the
// generation intact so later cleanup cannot fall back to broad legacy intent.
func (a *ProxyTunnelAdapter) applyRetainedPolicy(ctx context.Context, state PolicyState) error {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	id := hex.EncodeToString(nonce[:])
	root, err := a.createPolicyGeneration(id)
	if err != nil {
		return err
	}
	binding := proxyPolicyBinding{Schema: 1, Engine: a.ID(), Digest: proxyPolicyDigest(state), Generation: id, Phase: "pending"}
	// Keep the exact candidate state for trusted reconciliation after a cut;
	// the public/committed policy file may still contain the previous state.
	data, _ := json.Marshal(state)
	if err := writeAtomic(filepath.Join(root, "policy-state.json"), data, 0600); err != nil {
		return err
	}
	if err := a.writePolicyBinding(binding); err != nil {
		return err
	}
	if err := a.installForwarding(ctx, state); err != nil {
		return err
	}
	if err := applyPolicyAddition(ctx, a.Runner, a.ip(), state, root, a.additionOptions()); err != nil {
		return errors.Join(ErrProxyPolicyUnknown, err)
	}
	status, err := a.additionStatus(ctx, state, root)
	if err != nil || !status.Complete {
		return errors.Join(ErrProxyPolicyUnknown, err)
	}
	binding.Phase, binding.ReceiptID = "active", status.ID
	if err := a.writePolicyBinding(binding); err != nil {
		return err
	}
	return a.savePolicyJournal(state, true)
}

func (a *ProxyTunnelAdapter) restoreHistoricalPolicyBinding(snapshot proxySnapshot) error {
	if snapshot.PolicyBinding != nil {
		binding := *snapshot.PolicyBinding
		if binding.Digest != proxyPolicyDigest(snapshot.Policy) || binding.Engine != a.ID() {
			return ErrProxyPolicyUnknown
		}
		if _, err := a.policyGenerationRoot(binding.Generation); err != nil {
			return err
		}
		// Prior additions were consumed during Activate. Historical restoration
		// keeps their reference, without claiming the removed runtime is active.
		binding.Phase = "removed"
		return a.writePolicyBinding(binding)
	}
	if snapshot.PolicyTracked {
		return ErrProxyPolicyUnknown
	}
	if _, err := os.Stat(a.StateRoot); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	root, err := ownedfs.Open(a.StateRoot)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.Remove(filepath.Base(a.policyBindingPath())); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if runtime.GOOS == "linux" {
		return root.Sync()
	}
	return nil
}

func (a *ProxyTunnelAdapter) removeCommittedPolicy(ctx context.Context, state PolicyState) error {
	binding, exists, err := a.readPolicyBinding(state)
	if err != nil {
		return err
	}
	tracked, err := a.trackedPolicyJournal()
	if err != nil {
		return err
	}
	if !exists {
		if tracked {
			return ErrProxyPolicyUnknown
		}
		return a.removeOwnedPolicy(ctx, state) // Existing legacy boundary only.
	}
	root, err := a.policyGenerationRoot(binding.Generation)
	if err != nil {
		return err
	}
	status, err := a.additionStatus(ctx, state, root)
	if err != nil || binding.ReceiptID != "" && status.ID != binding.ReceiptID {
		return errors.Join(ErrProxyPolicyUnknown, err)
	}
	if err := removePolicyAddition(ctx, a.Runner, a.ip(), state, root, a.additionOptions()); err != nil {
		return errors.Join(ErrProxyPolicyUnknown, err)
	}
	binding.Phase = "removed"
	if err := a.writePolicyBinding(binding); err != nil {
		return err
	}
	return a.removeForwarding(ctx)
}

func (a *ProxyTunnelAdapter) verifyCommittedReceipt(ctx context.Context, state PolicyState) error {
	return a.checkCommittedReceipt(ctx, state, true)
}
func (a *ProxyTunnelAdapter) checkCommittedReceipt(ctx context.Context, state PolicyState, requireActive bool) error {
	binding, exists, err := a.readPolicyBinding(state)
	if err != nil {
		return err
	}
	tracked, err := a.trackedPolicyJournal()
	if err != nil || tracked && !exists {
		return errors.Join(ErrProxyPolicyUnknown, err)
	}
	if !exists {
		return nil // Legacy committed runtime has its existing authority.
	}
	root, err := a.policyGenerationRoot(binding.Generation)
	if err != nil {
		return err
	}
	status, err := a.additionStatus(ctx, state, root)
	valid := status.Complete && binding.Phase == "active" || !requireActive && status.Removed && binding.Phase == "removed"
	if err != nil || !valid || status.ID != binding.ReceiptID {
		return errors.Join(ErrProxyPolicyUnknown, err)
	}
	return nil
}
