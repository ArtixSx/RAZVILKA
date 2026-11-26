package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"time"

	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

// firstXrayLANRetirementRefusal identifies the first managed Xray Apply whose
// LAN activation and rollback were unconfirmed. The original Xray rollback
// only left unused resource metadata. This evidence can improve a refusal but
// cannot restore the original live owner's descriptors or prove native absence.
func (m *Manager) firstXrayLANRetirementRefusal(ctx context.Context, state *os.Root, planID, digest string) error {
	if ctx.Err() != nil {
		return nil
	}
	if _, err := state.Lstat("latest-committed-plan.json"); !errors.Is(err, os.ErrNotExist) {
		return nil
	}

	planData, err := bootRetirementRead(state, "latest-plan.json")
	var plan Plan
	if err != nil || json.Unmarshal(planData, &plan) != nil || plan.SchemaVersion != SchemaVersion ||
		plan.PlanID != planID || plan.Digest != digest || plan.State != "rollback-failed" ||
		plan.Ready || plan.Noop || plan.SafeMode || plan.LAN == nil || plan.LAN.Mode != LANPolicyXraySelectedTCPMode ||
		plan.DNS != nil || plan.DomainPolicy != nil || plan.SyntheticDNS != nil || plan.SuspendDNS || plan.DiscardDNS ||
		len(plan.RetiringAdapters) != 0 || !slices.Equal(plan.Adapters, []string{NetworkPolicyAdapterID, "xray"}) {
		return nil
	}

	root := filepath.Join("transactions", planID)
	latest, err := bootRetirementRead(state, "latest-execution.json")
	transaction, txnErr := bootRetirementRead(state, filepath.Join(root, "execution.json"))
	var e Execution
	if err != nil || txnErr != nil || !bytes.Equal(latest, transaction) || json.Unmarshal(latest, &e) != nil ||
		e.PlanID != planID || e.Digest != digest || e.State != "rollback-failed" || e.RollbackVerified ||
		e.ResourcePlanID != "" || len(e.Resources) != 1 || validateExecutionResources(e, true) != nil ||
		!firstXrayLANRetirementSteps(e) {
		return nil
	}
	resource := e.Resources[0]
	definition := resource.XraySelectedTCP
	if resource.State != "unused" || resource.Phase != "unused" || definition == nil ||
		definition.NetworkProfile != plan.NetworkProfileID || !reflect.DeepEqual(definition.Match.LAN, plan.LAN) {
		return nil
	}

	snapshotPath := filepath.Join(root, NetworkPolicyAdapterID, "snapshot.json")
	snapshot, err := bootRetirementRead(state, snapshotPath)
	expectedSnapshot, _ := json.Marshal(networkPolicyGateSnapshot{})
	if err != nil || !bytes.Equal(bytes.TrimSpace(snapshot), expectedSnapshot) {
		return nil
	}
	configPath := filepath.Join(root, "execution-resources", resource.ID, definition.Process.ConfigName)
	config, err := bootRetirementRead(state, configPath)
	if err != nil || len(config) == 0 || routeidentity.Hash(config) != definition.ConfigSHA256 {
		clear(config)
		return nil
	}
	clear(config)
	if ctx.Err() != nil {
		return nil
	}

	registered, _ := m.adapter("xray")
	xray, ok := registered.(*ProxyTunnelAdapter)
	if !ok || xray == nil || xray.StateRoot != filepath.Join(m.StateRoot, "xray") {
		return bootRetirementAt("first-xray-lan-boot-unavailable", nil)
	}
	boot, err := xray.currentBootIdentity()
	if err != nil || !kernelBootIDPattern.MatchString(boot) {
		return bootRetirementAt("first-xray-lan-boot-unavailable", err)
	}

	// The same files and absence of a previous commit must still agree after
	// reading the platform. Even after reboot this remains a refusal.
	for path, image := range map[string][]byte{
		"latest-plan.json": planData, "latest-execution.json": latest,
		filepath.Join(root, "execution.json"): transaction, snapshotPath: snapshot,
	} {
		current, err := bootRetirementRead(state, path)
		if err != nil || !bytes.Equal(current, image) {
			return nil
		}
	}
	currentConfig, err := bootRetirementRead(state, configPath)
	currentHash := routeidentity.Hash(currentConfig)
	clear(currentConfig)
	if err != nil || currentHash != definition.ConfigSHA256 || ctx.Err() != nil {
		return nil
	}
	if _, err := state.Lstat("latest-committed-plan.json"); !errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if boot == definition.NetworkIdentity.BootID {
		return bootRetirementAt("first-xray-lan-same-boot", nil)
	}
	return bootRetirementAt("first-xray-lan-offline-unsupported", nil)
}

func firstXrayLANRetirementSteps(e Execution) bool {
	expected := [...]struct{ adapter, phase, state string }{
		{NetworkPolicyAdapterID, "snapshot", "passed"},
		{"xray", "snapshot", "passed"},
		{NetworkPolicyAdapterID, "stage", "passed"},
		{"xray", "stage", "passed"},
		{NetworkPolicyAdapterID, "validate", "passed"},
		{"xray", "validate", "passed"},
		{"xray", "canary", "passed"},
		{NetworkPolicyAdapterID, "activate", "failed"},
		{"xray", "rollback", "passed"},
		{"xray", "verify-rollback", "passed"},
		{NetworkPolicyAdapterID, "rollback", "failed"},
		{NetworkPolicyAdapterID, "verify-rollback", "failed"},
	}
	started, startErr := time.Parse(time.RFC3339Nano, e.StartedAt)
	finished, finishErr := time.Parse(time.RFC3339Nano, e.FinishedAt)
	if startErr != nil || finishErr != nil || started.After(finished) || len(e.Steps) != len(expected) {
		return false
	}
	previous := started
	for i, step := range e.Steps {
		wanted := expected[i]
		start, startErr := time.Parse(time.RFC3339Nano, step.StartedAt)
		end, endErr := time.Parse(time.RFC3339Nano, step.FinishedAt)
		if step.Adapter != wanted.adapter || step.Phase != wanted.phase || step.State != wanted.state ||
			startErr != nil || endErr != nil || start.Before(previous) || end.Before(start) || end.After(finished) {
			return false
		}
		previous = end
	}
	return true
}
