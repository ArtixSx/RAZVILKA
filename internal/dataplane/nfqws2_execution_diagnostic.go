package dataplane

// A diagnostic wrapper must preserve the original error classification. In
// particular preflight failures do not become possibly-issued process failures.
type nfqwsExecutionDiagnostic struct {
	stage string
	cause error
}

func (e *nfqwsExecutionDiagnostic) Error() string { return "NFQWS execution refused at " + e.stage }
func (e *nfqwsExecutionDiagnostic) Unwrap() error { return e.cause }
func nfqwsExecutionFailure(stage string, cause error) error {
	if cause == nil {
		return nil
	}
	return &nfqwsExecutionDiagnostic{stage: stage, cause: cause}
}

// NFQWSExecutionFailureStages projects bounded, closed labels from original
// typed causes, including joined activation/cleanup failures. It never formats
// an error, path, command or observed network/configuration data.
func NFQWSExecutionFailureStages(err error) []string {
	var stages []string
	visited := 0
	var visit func(error, int)
	visit = func(e error, depth int) {
		if e == nil || depth > 24 || visited >= 128 || len(stages) >= 24 {
			return
		}
		visited++
		label := ""
		switch d := e.(type) {
		case *nfqwsExecutionDiagnostic:
			label = d.stage
		case *nfqws2ActiveDiagnostic:
			label = d.stage
		}
		switch label {
		case "activation.prepare", "activation.registrar", "activation.scope", "activation.lan", "activation.absence", "activation.parent", "activation.forward", "activation.lease-absence", "activation.material", "activation.deadline", "activation.selection", "activation.closing-deadline", "activation.retain-selection",
			"activate.issue", "activate.guards", "activate.consume", "activate.associate", "activate.resource", "activate.configure", "activate.process-directory", "activate.binding", "activate.start", "activate.health",
			"StartPrepared.admission", "StartPrepared.panel-lifetime", "StartPrepared.activation-context", "StartPrepared.network-identity", "StartPrepared.adapter-owner", "StartPrepared.parent-files-control", "StartPrepared.executable", "StartPrepared.state-root", "StartPrepared.before-start", "StartPrepared.intent", "StartPrepared.transport", "StartPrepared.native-launch",
			"READY", "PERMIT", "STARTED", "TRANSFER", "TRANSFER ACK", "provisional BOTH", "FINALIZE", "final ACTIVE ACK", "execution.activation-seal", "prepared Observe", "prepared owner proof", "prepared Stop", "CommitPrepared", "active owner proof", "active cleanup proof", "Current", "active Stop", "retired owner proof", "retire prepared", "retire active":
			stages = append(stages, label)
		}
		switch u := e.(type) {
		case interface{ Unwrap() []error }:
			for _, child := range u.Unwrap() {
				visit(child, depth+1)
			}
		case interface{ Unwrap() error }:
			visit(u.Unwrap(), depth+1)
		}
	}
	visit(err, 0)
	return stages
}
