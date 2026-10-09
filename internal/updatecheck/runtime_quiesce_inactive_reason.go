package updatecheck

import "strings"

// Reasons name only sentinels observed in the actual Manager error chain.
// Their absence never proves another observer succeeded or grants inactivity.
type RuntimeQuiesceInactiveReasons uint8

const (
	QuiesceInactiveDeadline RuntimeQuiesceInactiveReasons = 1 << iota
	QuiesceInactiveCanceled
	QuiesceInactiveScopedDNS
	QuiesceInactiveProxy
	QuiesceInactiveNFQProcess
	QuiesceInactiveNFQKernel
)

const quiesceInactiveAll = QuiesceInactiveDeadline | QuiesceInactiveCanceled | QuiesceInactiveScopedDNS | QuiesceInactiveProxy | QuiesceInactiveNFQProcess | QuiesceInactiveNFQKernel

// RuntimeQuiesceInactiveFailureStage has a closed, bounded vocabulary. A
// combination retains every observed cause instead of hiding joined failures
// behind the first sentinel. Unknown input falls back to the original refusal.
func RuntimeQuiesceInactiveFailureStage(reasons RuntimeQuiesceInactiveReasons) string {
	if reasons == 0 || reasons&^quiesceInactiveAll != 0 {
		return "runtime-inactivity"
	}
	labels := []string{"runtime-inactivity"}
	for _, reason := range []struct {
		bit   RuntimeQuiesceInactiveReasons
		label string
	}{{QuiesceInactiveDeadline, "deadline"}, {QuiesceInactiveCanceled, "canceled"}, {QuiesceInactiveScopedDNS, "scoped-dns"}, {QuiesceInactiveProxy, "proxy"}, {QuiesceInactiveNFQProcess, "nfq-process"}, {QuiesceInactiveNFQKernel, "nfq-kernel"}} {
		if reasons&reason.bit != 0 {
			labels = append(labels, reason.label)
		}
	}
	return strings.Join(labels, "-")
}

func runtimeQuiesceInactiveFailureStages() []string {
	stages := make([]string, 0, int(quiesceInactiveAll))
	for reasons := RuntimeQuiesceInactiveReasons(1); reasons <= quiesceInactiveAll; reasons++ {
		stages = append(stages, RuntimeQuiesceInactiveFailureStage(reasons))
	}
	return stages
}
