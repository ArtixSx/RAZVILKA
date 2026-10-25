package dataplane

// This diagnostic carries only a closed branch label and the original refusal.
// Process identities, paths and command lines are never diagnostic fields.
type nfqws2InactiveProcessFailure struct {
	stage string
	cause error
}

func (e *nfqws2InactiveProcessFailure) Error() string {
	return "NFQWS process inventory refused at " + nfqws2InactiveProcessLabel(e.stage)
}
func (e *nfqws2InactiveProcessFailure) Unwrap() error { return e.cause }

func nfqws2InactiveProcessAt(stage string, cause error) error {
	return &nfqws2InactiveProcessFailure{stage: stage, cause: cause}
}

func nfqws2InactiveProcessLabel(stage string) string {
	switch stage {
	case "coordinates", "exemption", "inventory.open", "inventory.read", "inventory.entry", "stat.read", "stat.parse",
		"exemption.current", "name", "zombie", "self.state", "cmdline.read", "budget", "cmdline.empty", "cmdline.parse",
		"exemption.wrapper", "exe", "exe.name", "argument", "stat.close", "startticks", "inventory.closure", "context":
		return stage
	default:
		return "unknown"
	}
}
