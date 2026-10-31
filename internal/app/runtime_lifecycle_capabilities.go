package app

import (
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/engine"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

func registeredLifecycleOperation(registered bool, reason string) engine.LifecycleOperation {
	if registered {
		return engine.LifecycleOperation{Registration: "registered", Reason: reason}
	}
	no := false
	return engine.LifecycleOperation{Registration: "absent", Available: &no, Reason: reason}
}
func unknownLifecycleOperation(reason string) engine.LifecycleOperation {
	return engine.LifecycleOperation{Registration: "unknown", Reason: reason}
}
func (a *App) runtimeLifecycle(id string) *engine.Lifecycle {
	registration := a.Dataplane.AdapterLifecycleRegistration(id)
	operations := map[string]engine.LifecycleOperation{
		"installer":         registeredLifecycleOperation(false, "installer-not-registered"),
		"import_export":     registeredLifecycleOperation(false, "profile-interface-not-registered"),
		"staged_validation": registeredLifecycleOperation(registration.StagedValidation, "staged-adapter-validation"),
		"native_validation": unknownLifecycleOperation("native-validation-not-observed"),
		"isolated_probe":    registeredLifecycleOperation(registration.IsolatedProbe, "scoped-canary-requires-admission"),
		"live_apply":        registeredLifecycleOperation(registration.LiveApply, "scope-and-transaction-admission-required"),
		"live_health":       registeredLifecycleOperation(registration.LiveHealth, "committed-route-and-fresh-service-proof-required"),
		"recovery":          registeredLifecycleOperation(registration.Recovery, "original-retained-owner-required"),
		"rollback":          registeredLifecycleOperation(registration.Rollback, "original-transaction-and-cleanup-owner-required"),
		"package_update":    registeredLifecycleOperation(false, "managed-package-update-not-registered"),
	}
	prerequisites := []string{}
	componentID := id
	if id == "hev" {
		componentID = "hev-socks5-tunnel"
	}
	for _, spec := range components.Specs() {
		if spec.ID == componentID {
			if spec.Requirement != "" {
				prerequisites = append(prerequisites, spec.Requirement)
			}
			install := a.Components != nil && spec.Provider == "opkg"
			if componentID == "hev-socks5-tunnel" {
				install = a.Components != nil && spec.Provider == "github-release"
			}
			reason := "package-policy-and-ownership-admission-required"
			if spec.Provider == "platform" {
				reason = "external-platform-module-and-tools-required"
			}
			operations["installer"] = registeredLifecycleOperation(install, reason)
			operations["package_update"] = registeredLifecycleOperation(install && components.ManagedUpdateSupported(id), "managed-package-journal-and-rollback-admission-required")
		}
	}
	if a.EngineConfigs != nil {
		for _, spec := range engineconfig.Specs() {
			if spec.ID == id {
				operations["import_export"] = registeredLifecycleOperation(true, "profile-read-stage-interface-only")
				operations["staged_validation"] = registeredLifecycleOperation(true, "profile-syntax-validation-only")
				break
			}
		}
	}
	if checker, err := a.nodeCheckerForEngine(id); err == nil {
		operations["isolated_probe"] = registeredLifecycleOperation(true, "exact-node-checker-requires-current-node-and-scope")
		if source, ok := checker.(interface {
			NodeCheckLifecycleRegistration() dataplane.NodeCheckLifecycleRegistration
		}); ok {
			pipeline := source.NodeCheckLifecycleRegistration()
			operations["native_validation"] = registeredLifecycleOperation(pipeline.NativeValidation, "native-validation-within-exact-checker")
			operations["isolated_probe"] = registeredLifecycleOperation(pipeline.IsolatedProbe, "exact-node-checker-requires-current-node-and-scope")
		}
	}
	if id == "nfqws2" {
		registration := a.StrategyLab.LifecycleRegistration()
		native := registeredLifecycleOperation(registration.NativeValidation == "registered", "candidate-validation-requires-managed-source")
		if registration.NativeValidation == "unknown" {
			native = unknownLifecycleOperation("managed-native-validator-registration-unconfirmed")
		}
		probe := registeredLifecycleOperation(registration.ManagedCandidateProbe == "registered", "managed-scoped-executor-required")
		if registration.ManagedCandidateProbe == "unknown" {
			probe = unknownLifecycleOperation("managed-network-consumer-registration-unconfirmed")
		}
		operations["native_validation"], operations["managed_candidate_probe"] = native, probe
	}

	if id == "mihomo" || id == "hev" {
		operations["import_export"] = engine.LifecycleOperation{Registration: "lab-only", Reason: "extension-api-config-generation-only"}
		operations["native_validation"] = registeredLifecycleOperation(false, "extension-does-not-native-validate")
	}
	return &engine.Lifecycle{Schema: 1, Operations: operations, Prerequisites: prerequisites, Evidence: "registration-only; no applied route, live health, platform acceptance or operation permission"}
}
func (a *App) withRuntimeLifecycle(in []engine.Status) []engine.Status {
	out := append([]engine.Status(nil), in...)
	for i := range out {
		out[i].Lifecycle = a.runtimeLifecycle(out[i].ID)
	}
	return out
}
