package dataplane

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

const wgPolicyReferenceFile = "wg-policy-generation-v1.json"
const wgPolicyRollbackFile = "wg-policy-rollback-v1.json"
const wgPolicyCandidateDirectory = "wg-policy-generation"
const wgPolicyOperationDirectory = "wg-policy-operation"

func cloneWGPolicyState(state PolicyState) PolicyState {
	if state.WireGuardEndpoint != nil {
		copy := *state.WireGuardEndpoint
		state.WireGuardEndpoint = &copy
	}
	return state
}

func writeWGTransactionMarker(ctx context.Context, dir, name string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	root, err := ownedfs.Open(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.WriteAtomic(name, []byte("owned"), 0600); err != nil {
		return err
	}
	if runtime.GOOS == "linux" {
		if err := root.Sync(); err != nil {
			return err
		}
	}
	return ctx.Err()
}

// Policy is the immutable, full PolicyState supplied to the common receipt.
// Runtime fallback/lease metadata may subsequently change without changing
// kernel policy tuples. No file contains an arbitrary cleanup directory.
type warpWGPolicyReference struct {
	Schema   int         `json:"schema"`
	ID       string      `json:"id,omitempty"`
	Boot     string      `json:"boot"`
	Policy   PolicyState `json:"policy"`
	Checksum string      `json:"checksum"`
}

func wgPolicyReferenceChecksum(ref warpWGPolicyReference) string {
	ref.Checksum = ""
	data, _ := json.Marshal(ref)
	return warpRuntimeDigest(data)
}

func (a *WARPWireGuardAdapter) validWGPolicyReference(ref warpWGPolicyReference) error {
	if ref.Schema != 1 || ref.Checksum != wgPolicyReferenceChecksum(ref) || len(ref.Boot) == 0 || len(ref.Boot) > 128 || strings.ContainsAny(ref.Boot, "\r\n\x00") || ref.Policy.Interface != a.interfaceName() || ref.Policy.Table != a.table() || ref.Policy.PriorityBase != a.priorityBase() {
		return ErrPolicyAdditionReceipt
	}
	if ref.ID != "" {
		if len(ref.ID) != 32 || ref.ID != strings.ToLower(ref.ID) {
			return ErrPolicyAdditionReceipt
		}
		if _, err := hex.DecodeString(ref.ID); err != nil {
			return ErrPolicyAdditionReceipt
		}
	}
	_, err := policyAdditionExpected(ref.Policy)
	return err
}

func (a *WARPWireGuardAdapter) validWGSnapshotPolicyReference(snapshot warpWGSnapshot) error {
	if !snapshot.StateExisted {
		return nil
	}
	if snapshot.PolicyGeneration == nil || snapshot.PolicyGeneration.ID == "" || !samePolicy(snapshot.PolicyGeneration.Policy, snapshot.State) {
		return ErrPolicyAdditionReceipt
	}
	return a.validWGPolicyReference(*snapshot.PolicyGeneration)
}

func (a *WARPWireGuardAdapter) wgPolicyBoot() (string, error) {
	if a.policyReceiptOptions.boot != nil {
		return a.policyReceiptOptions.boot()
	}
	return (&ProxyTunnelAdapter{}).currentBootIdentity()
}

func (a *WARPWireGuardAdapter) wgPolicyGenerationRoot(ref warpWGPolicyReference, transaction string) string {
	if ref.ID == "" {
		return filepath.Join(transaction, wgPolicyCandidateDirectory)
	}
	return filepath.Join(a.StateRoot, "policy-generations", ref.ID)
}

func writeWGPolicyReference(ctx context.Context, dir string, ref warpWGPolicyReference) error {
	return writeWGPolicyReferenceNamed(ctx, dir, wgPolicyReferenceFile, ref)
}

func writeWGPolicyReferenceNamed(ctx context.Context, dir, file string, ref warpWGPolicyReference) error {
	if file != wgPolicyReferenceFile && file != wgPolicyRollbackFile {
		return ErrPolicyAdditionReceipt
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	root, err := ownedfs.Open(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	ref.Checksum = wgPolicyReferenceChecksum(ref)
	data, err := json.Marshal(ref)
	if err != nil || len(data) > policyAdditionMaxBytes {
		return ErrPolicyAdditionReceipt
	}
	if err := root.WriteAtomic(file, data, 0600); err != nil {
		return err
	}
	if runtime.GOOS == "linux" {
		if err := root.Sync(); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func (a *WARPWireGuardAdapter) readWGPolicyReference(dir string, state PolicyState, retained bool) (warpWGPolicyReference, bool, error) {
	return a.readWGPolicyReferenceNamed(dir, wgPolicyReferenceFile, state, retained)
}

func (a *WARPWireGuardAdapter) readWGPolicyReferenceNamed(dir, file string, state PolicyState, retained bool) (warpWGPolicyReference, bool, error) {
	var ref warpWGPolicyReference
	if file != wgPolicyReferenceFile && file != wgPolicyRollbackFile {
		return ref, false, ErrPolicyAdditionReceipt
	}
	path := filepath.Join(dir, file)
	data, exists, err := readWARPCleanupFile(path, policyAdditionMaxBytes)
	if err != nil || !exists {
		return ref, exists, err
	}
	info, err := os.Lstat(path)
	if err != nil || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return ref, true, ErrPolicyAdditionReceipt
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&ref) != nil || decoder.Decode(new(any)) != io.EOF {
		return ref, true, ErrPolicyAdditionReceipt
	}
	canonical, _ := json.Marshal(ref)
	var compact bytes.Buffer
	if json.Compact(&compact, data) != nil || !bytes.Equal(compact.Bytes(), canonical) || a.validWGPolicyReference(ref) != nil || len(state.Prefixes) > 0 && !samePolicy(ref.Policy, state) {
		return ref, true, ErrPolicyAdditionReceipt
	}
	if ref.ID == "" && retained {
		return ref, true, ErrPolicyAdditionReceipt
	}
	return ref, true, nil
}

func (a *WARPWireGuardAdapter) inspectWGPolicyReference(ctx context.Context, ref warpWGPolicyReference, transaction string) (PolicyAdditionStatus, error) {
	if err := a.validWGPolicyReference(ref); err != nil {
		return PolicyAdditionStatus{}, err
	}
	s, err := openPolicyAdditionSession(ctx, ref.Policy, a.wgPolicyGenerationRoot(ref, transaction), a.policyReceiptOptions)
	if err != nil {
		return PolicyAdditionStatus{}, err
	}
	defer s.close()
	if err := s.load(ctx); err != nil {
		return PolicyAdditionStatus{}, err
	}
	status := s.status()
	if ref.ID != "" && status.ID != ref.ID {
		return PolicyAdditionStatus{}, ErrPolicyAdditionReceipt
	}
	return status, nil
}

func (a *WARPWireGuardAdapter) applyWGPolicyGeneration(ctx context.Context, state PolicyState, transaction string) error {
	if _, exists, err := a.readWGPolicyReference(transaction, state, false); err != nil || exists {
		return errors.Join(err, ErrPolicyAdditionExists)
	}
	boot, err := a.wgPolicyBoot()
	if err != nil {
		return err
	}
	ref := warpWGPolicyReference{Schema: 1, Boot: boot, Policy: state}
	ref.Checksum = wgPolicyReferenceChecksum(ref)
	if err := os.Mkdir(filepath.Join(transaction, wgPolicyCandidateDirectory), 0700); err != nil {
		return err
	}
	// Publish the immutable binding before invoking any policy command. A
	// missing/corrupt common receipt thereafter fences cleanup and recovery.
	if err := writeWGPolicyReference(ctx, transaction, ref); err != nil {
		return err
	}
	return applyPolicyAddition(ctx, a.Runner, a.ip(), state, a.wgPolicyGenerationRoot(ref, transaction), a.policyReceiptOptions)
}

func (a *WARPWireGuardAdapter) removeWGPolicyReference(ctx context.Context, ref warpWGPolicyReference, transaction string) error {
	if err := a.validWGPolicyReference(ref); err != nil {
		return err
	}
	return removePolicyAddition(ctx, a.Runner, a.ip(), ref.Policy, a.wgPolicyGenerationRoot(ref, transaction), a.policyReceiptOptions)
}

func (a *WARPWireGuardAdapter) committedWGPolicyReference(state PolicyState) (warpWGPolicyReference, error) {
	ref, exists, err := a.readWGPolicyReference(a.StateRoot, state, true)
	if err != nil || !exists {
		return ref, errors.Join(err, ErrPolicyAdditionReceipt)
	}
	return ref, nil
}

func (a *WARPWireGuardAdapter) promoteWGPolicyGeneration(ctx context.Context, state PolicyState, transaction string) (warpWGPolicyReference, error) {
	ref, exists, err := a.readWGPolicyReference(transaction, state, false)
	if err != nil || !exists {
		return ref, errors.Join(err, ErrPolicyAdditionReceipt)
	}
	if ref.ID != "" {
		status, err := a.inspectWGPolicyReference(ctx, ref, transaction)
		if err != nil || !status.Complete || status.Removed || status.Unknown {
			return ref, errors.Join(err, ErrPolicyAdditionUnknown)
		}
		return ref, nil
	}
	status, err := a.inspectWGPolicyReference(ctx, ref, transaction)
	if err != nil || !status.Complete || status.Unknown || status.Promoted {
		return ref, errors.Join(err, ErrPolicyAdditionUnknown)
	}
	source := a.wgPolicyGenerationRoot(ref, transaction)
	ref.ID = status.ID
	ref.Checksum = wgPolicyReferenceChecksum(ref)
	destination := a.wgPolicyGenerationRoot(ref, transaction)
	if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
		return ref, err
	}
	if err := os.Mkdir(destination, 0700); err != nil {
		return ref, err
	}
	// Rollback must know the recipient even if promotion or commit crashes.
	if err := writeWGPolicyReference(ctx, transaction, ref); err != nil {
		return ref, err
	}
	if err := promotePolicyAddition(ctx, ref.Policy, source, destination, a.policyReceiptOptions); err != nil {
		return ref, err
	}
	return ref, nil
}

func (a *WARPWireGuardAdapter) publishWGPolicyGeneration(ctx context.Context, state PolicyState, ref warpWGPolicyReference) error {
	status, err := a.inspectWGPolicyReference(ctx, ref, "")
	if err != nil || !status.Complete || status.Unknown || status.Promoted {
		return errors.Join(err, ErrPolicyAdditionUnknown)
	}
	if err := writeWGPolicyReference(ctx, a.StateRoot, ref); err != nil {
		return err
	}
	root, err := ownedfs.Open(a.StateRoot)
	if err != nil {
		return err
	}
	defer root.Close()
	data, _ := json.MarshalIndent(state, "", "  ")
	if err := root.WriteAtomic(filepath.Base(a.statePath()), data, 0600); err != nil {
		return err
	}
	if runtime.GOOS == "linux" {
		if err := root.Sync(); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func (a *WARPWireGuardAdapter) freshWGPolicyGeneration(ctx context.Context, state PolicyState) (warpWGPolicyReference, error) {
	if err := os.MkdirAll(a.StateRoot, 0700); err != nil {
		return warpWGPolicyReference{}, err
	}
	transaction := filepath.Join(a.StateRoot, wgPolicyOperationDirectory)
	if err := os.Mkdir(transaction, 0700); err != nil {
		return warpWGPolicyReference{}, err
	}
	if err := a.applyWGPolicyGeneration(ctx, state, transaction); err != nil {
		return warpWGPolicyReference{}, err // keep unknown/failed receipts
	}
	ref, err := a.promoteWGPolicyGeneration(ctx, state, transaction)
	if err != nil {
		return ref, err
	}
	if err := a.publishWGPolicyGeneration(ctx, state, ref); err != nil {
		return ref, err
	}
	return ref, a.removeSettledWGPolicyOperation(ctx, ref)
}

func (a *WARPWireGuardAdapter) checkWGPolicyOperation() error {
	_, err := os.Lstat(filepath.Join(a.StateRoot, wgPolicyOperationDirectory))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return errors.Join(err, ErrPolicyAdditionUnknown)
}

func (a *WARPWireGuardAdapter) removeSettledWGPolicyOperation(ctx context.Context, ref warpWGPolicyReference) error {
	transaction := filepath.Join(a.StateRoot, wgPolicyOperationDirectory)
	source := ref
	source.ID = ""
	source.Checksum = wgPolicyReferenceChecksum(source)
	status, err := a.inspectWGPolicyReference(ctx, source, transaction)
	if err != nil || status.Unknown || !(status.Removed || status.Promoted) {
		return errors.Join(err, ErrPolicyAdditionUnknown)
	}
	root, err := ownedfs.Open(a.StateRoot)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.RemoveAll(wgPolicyOperationDirectory); err != nil {
		return err
	}
	if runtime.GOOS == "linux" {
		return root.Sync()
	}
	return ctx.Err()
}

func (a *WARPWireGuardAdapter) settleWGPolicyOperationForStop(ctx context.Context) error {
	if err := a.checkWGPolicyOperation(); err == nil {
		return nil
	}
	transaction := filepath.Join(a.StateRoot, wgPolicyOperationDirectory)
	// The pending operation has its own immutable policy, which may differ
	// from the last committed policy. The common receipt binds it exactly.
	ref, exists, err := a.readWGPolicyReference(transaction, PolicyState{}, false)
	if err != nil || !exists {
		return errors.Join(err, ErrPolicyAdditionUnknown)
	}
	if err := a.removeWGPolicyReference(ctx, ref, transaction); err != nil {
		return err
	}
	return a.removeSettledWGPolicyOperation(ctx, ref)
}

func (a *WARPWireGuardAdapter) wgPolicyAbsent(ctx context.Context, ref warpWGPolicyReference) error {
	steps, err := policyAdditionExpected(ref.Policy)
	if err != nil {
		return err
	}
	for i := range steps {
		present, err := policyAdditionPresence(ctx, a.Runner, a.ip(), ref.Policy, i)
		if err != nil || present != 0 {
			return errors.Join(err, ErrPolicyAdditionUnknown)
		}
	}
	return ctx.Err()
}
