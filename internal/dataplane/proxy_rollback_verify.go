package dataplane

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
)

// VerifyRollback is deliberately read-only. A successful Start/restore command
// is not enough: processes may already have died, a file may differ, or router
// hooks may have removed/reordered the restored RPDB/firewall rules.
func (a *ProxyTunnelAdapter) VerifyRollback(ctx context.Context, _ Plan, root string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	s, err := readProxySnapshot(root)
	if err != nil {
		return false, err
	}
	if err := a.checkSnapshotSidecar(s); err != nil {
		return false, err
	}
	for _, file := range []struct {
		path   string
		data   []byte
		exists bool
	}{
		{a.engineConfigPath(), s.RuntimeEngine, s.RuntimeEngineExists},
		{a.sidecarConfigPath(), s.RuntimeSidecar, s.RuntimeSideExists},
		{a.transportPath(), s.Transport, s.TransportExists},
		{a.evidencePath(), s.Evidence, s.EvidenceExists},
	} {
		if err := verifyRestoredFile(file.path, file.data, file.exists); err != nil {
			return false, err
		}
	}
	if s.ConfigDraft {
		if err := verifyRestoredFile(s.ConfigPath, s.Config, s.ConfigExisted); err != nil {
			return false, err
		}
	}
	policy, exists, err := a.loadPolicy()
	if err != nil {
		return false, err
	}
	if exists != s.PolicyExists || exists && !reflect.DeepEqual(policy, s.Policy) {
		return false, errors.New("restored proxy policy journal differs from snapshot")
	}
	boot, bootErr := a.currentBootIdentity()
	sameBoot := bootErr == nil && s.BootID != "" && boot == s.BootID
	if a.Processes.Running(a.engineProcess()) != (sameBoot && s.EngineWasRunning) || a.Processes.Running(a.sidecarProcess()) != (sameBoot && s.SidecarWasRunning) {
		return false, errors.New("restored proxy processes differ from snapshot")
	}
	packageRunning, err := a.packageRuntimeRunning(ctx)
	if err != nil {
		return false, err
	}
	if packageRunning != (sameBoot && s.PackageWasRunning) {
		return false, errors.New("restored package runtime differs from snapshot")
	}
	// Cold/legacy restoration retains its existing cleanup behavior but cannot
	// acquire a verified live receipt without exact boot and forwarding authority.
	if !sameBoot || !s.PolicyExists || !s.PolicyWasActive || !s.EngineWasRunning || !s.SidecarWasRunning || policy.RuleLayout != 2 || policy.Forwarding == nil {
		return false, nil
	}
	if err := a.waitForSOCKS(ctx); err != nil {
		return false, err
	}
	if err := a.verifyForwarding(ctx, policy); err != nil {
		return false, err
	}
	if err := verifyPolicyEvidence(ctx, a.Runner, a.ip(), policy); err != nil {
		return false, err
	}
	staged, err := a.readStagedPolicy(root)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil // No complete candidate journal: do not grant a receipt.
	}
	if err != nil {
		return false, err
	}
	if err := a.verifyCandidateRemoved(ctx, policy, staged); err != nil {
		return false, err
	}
	// Kernel inspection can take time. A process which exited during readback
	// must not acquire a live restoration receipt.
	if !a.Processes.Running(a.engineProcess()) || !a.Processes.Running(a.sidecarProcess()) {
		return false, errors.New("restored proxy process exited during verification")
	}
	// The caller still must verify network epoch, service definition and cause
	// attribution before any next Apply. A broken old service A can be restored
	// exactly; that does not make it healthy or give candidate B a bad reputation.
	return true, ctx.Err()
}

// Include the candidate's families and coordinates: checking only the restored
// IPv4 policy would otherwise overlook candidate-only IPv6 selectors/chains.
// This is inspection only; foreign occupants are never deleted to obtain proof.
func (a *ProxyTunnelAdapter) verifyCandidateRemoved(ctx context.Context, restored, candidate PolicyState) error {
	want, err := kernelRulesForPolicy(restored)
	if err != nil {
		return err
	}
	staged, err := kernelRulesForPolicy(candidate)
	if err != nil {
		return err
	}
	wanted := map[kernelPolicyRule]bool{}
	for _, rule := range want {
		wanted[rule] = true
	}
	for _, family := range []int{4, 6} {
		priorities := map[int]bool{}
		for _, rules := range [][]kernelPolicyRule{want, staged} {
			for _, rule := range rules {
				if rule.family == family {
					priorities[rule.priority] = true
				}
			}
		}
		if len(priorities) == 0 {
			continue
		}
		lines, err := readPolicyRules(ctx, a.Runner, a.ip(), family)
		if err != nil {
			return err
		}
		seen := map[kernelPolicyRule]bool{}
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			priority, ok := policyLinePriority(line)
			if !ok {
				return errors.New("unrecognized policy rule after rollback")
			}
			if !priorities[priority] {
				continue
			}
			rule, ok := parseKernelPolicyRule(family, line)
			if !ok || !wanted[rule] || seen[rule] {
				return errors.New("candidate or foreign policy selector remains after rollback")
			}
			seen[rule] = true
		}
		for _, rule := range want {
			if rule.family == family && !seen[rule] {
				return errors.New("restored policy selector disappeared during verification")
			}
		}
	}
	for _, table := range proxyFirewallTables(candidate) {
		retained := false
		for _, old := range proxyFirewallTables(restored) {
			if old.v6 == table.v6 && old.table == table.table && old.chain == table.chain {
				retained = true
			}
		}
		if retained {
			continue // verifyForwarding checked this exact chain and its attachments.
		}
		snapshot, err := a.firewallSnapshot(ctx, table)
		if err != nil {
			return err
		}
		if snapshot.declared || len(snapshot.own) != 0 || len(snapshot.references) != 0 {
			return errors.New("candidate forwarding chain remains after rollback")
		}
	}
	return ctx.Err()
}

func verifyRestoredFile(path string, expected []byte, exists bool) error {
	info, err := os.Lstat(path)
	if !exists && errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !exists || !info.Mode().IsRegular() || info.Size() != int64(len(expected)) {
		return errors.New("restored proxy file does not match snapshot")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, int64(len(expected))+1))
	if err != nil {
		return err
	}
	if !bytes.Equal(data, expected) {
		return errors.New("restored proxy file contents differ from snapshot")
	}
	return nil
}
