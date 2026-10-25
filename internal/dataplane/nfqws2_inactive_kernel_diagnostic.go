package dataplane

// No captured row, queue, address, PID or foreign error text is a diagnostic
// field. Only this bounded private vocabulary reaches the public outer error.
type nfqws2InactiveKernelFailure struct {
	stage string
	cause error
}

func (e *nfqws2InactiveKernelFailure) Error() string {
	return "NFQWS kernel inactivity refused at " + nfqws2InactiveKernelLabel(e.stage)
}
func (e *nfqws2InactiveKernelFailure) Unwrap() error { return e.cause }
func nfqws2InactiveKernelAt(stage string, cause error) error {
	return &nfqws2InactiveKernelFailure{stage: stage, cause: cause}
}
func nfqws2InactiveKernelLabel(stage string) string {
	switch stage {
	case "source", "inventory.open", "inventory.close", "inventory.changed", "rules.open", "rules.close",
		"frame.source", "frame.comparison", "queue.inventory", "socket.inventory", "socket.table", "queue.registration",
		"socket.owner", "frame.context", "frame.changed":
		return stage
	default:
		return "unknown"
	}
}
