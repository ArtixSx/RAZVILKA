package dataplane

import "errors"

// Diagnostics expose only closed branch labels. Underlying filesystem,
// process, command and settings errors remain available to errors.Is/As but
// never contribute their text or private values to the operator message.
type bootRetirementDiagnostic struct {
	stage string
	cause error
}

func (e *bootRetirementDiagnostic) Error() string {
	return ErrBootRetirement.Error() + "; stage=" + e.stage
}
func (e *bootRetirementDiagnostic) Unwrap() []error { return []error{ErrBootRetirement, e.cause} }

func bootRetirementAt(stage string, cause error) error {
	switch stage {
	case "inputs", "platform", "operation", "retained-nfq-owner", "retained-xray-owner", "retained-wg-owner", "pending-managed-nfq", "state-root", "manifest-read", "publication-read", "publication-without-manifest", "history-review", "history-shape", "history-resources", "proxy-adapter", "settings-guard", "writer-roots", "current-boot", "manifest-collect", "manifest-identity", "old-boot", "manifest-current-boot", "metadata-validation", "runtime-files", "evidence", "closing-context", "closing-writer", "closing-evidence", "closing-files", "receipt-locks", "manifest-write", "manifest-pin", "witness-publication", "publication-resume",
		"proxy-coordinates", "proxy-processes", "proxy-interfaces", "proxy-interface-inventory", "proxy-interface-present", "proxy-loopback", "proxy-default-references", "proxy-rules-read", "proxy-rules-inventory", "proxy-rules-owned", "proxy-rules-unrecognized", "proxy-rules-required", "proxy-table-read", "proxy-table-present", "proxy-firewall-read", "proxy-firewall-present", "proxy-context",
		"nfq-source", "nfq-processes", "nfq-files", "nfq-kernel", "nfq-identity", "nfq-participants", "nfq-absence",
		"metadata-manifest", "metadata-history-images", "metadata-original-history", "metadata-snapshot", "metadata-bound-policy", "metadata-policy-coordinates", "metadata-committed-receipt", "metadata-file-shape", "metadata-generation-receipt-bound", "metadata-generation-receipt-orphan":
	default:
		stage = "unknown"
	}
	return &bootRetirementDiagnostic{stage: stage, cause: cause}
}

// BootRetirementStage returns a safe diagnostic label; an arbitrary error's
// message is never parsed or exposed as a stage.
func BootRetirementStage(err error) string {
	var diagnostic *bootRetirementDiagnostic
	if errors.As(err, &diagnostic) && diagnostic != nil {
		return diagnostic.stage
	}
	return ""
}

func bootProxyRetirementAt(stage string, cause error) error {
	return bootRetirementAt(stage, errors.Join(ErrProxyRuntimeInactive, cause))
}
