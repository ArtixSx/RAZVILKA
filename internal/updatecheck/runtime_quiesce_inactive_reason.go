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

var runtimeQuiesceDNSObservationStages = []string{"source", "platform", "identity-validation", "lifecycle-opening", "intent-opening",
	"proc-opening", "backend-inventory", "proc-closing", "intent-closing", "lifecycle-closing", "callback-closing", "identity-opening", "identity-closing", "intent-final", "lifecycle-final"}

var runtimeQuiesceDNSProcStages = []string{"proc.thread-net-path", "proc.self-exe", "proc.enumerate", "proc.pid-shape", "proc.stat-read", "proc.stat-decode",
	"proc.cmdline-read", "proc.cmdline-shape", "proc.cmdline-empty.kthread-flag-false", "proc.cmdline-empty.self-true",
	"proc.cmdline-nonempty.argc-bounded-false", "proc.cmdline-nonempty.argv0-nonempty-false", "proc.exe-read", "proc.exe-incarnation",
	"proc.controller-ownership", "proc.installer-role-open", "proc.argv-recheck", "proc.exe-recheck", "proc.stat-recheck", "proc.installer-role-close",
	"socket.tcp.read", "socket.tcp.parse", "socket.tcp6.read", "socket.tcp6.parse", "socket.udp.read", "socket.udp.parse", "socket.udp6.read", "socket.udp6.parse", "proc-socket.complete"}

func runtimeQuiesceDNSObservationValid(stage string) bool {
	for _, known := range runtimeQuiesceDNSObservationStages {
		if stage == known {
			return true
		}
	}
	for _, phase := range []string{"proc-opening-", "proc-closing-"} {
		if !strings.HasPrefix(stage, phase) {
			continue
		}
		for _, known := range runtimeQuiesceDNSProcStages {
			if stage == phase+known {
				return true
			}
		}
	}
	return false
}

func runtimeQuiesceDNSRoleObservation(stage string) bool {
	return stage == "proc-opening-proc.installer-role-open" || stage == "proc-opening-proc.installer-role-close" ||
		stage == "proc-closing-proc.installer-role-open" || stage == "proc-closing-proc.installer-role-close"
}

// Details name only the original failed reader boundary. They grant nothing
// and cannot replace any joined causal bit with a successful observation.
func RuntimeQuiesceInactiveObservationFailureStage(reasons RuntimeQuiesceInactiveReasons, dns, ordinary string) string {
	base := RuntimeQuiesceInactiveFailureStage(reasons)
	if reasons&^quiesceInactiveAll != 0 || reasons&QuiesceInactiveScopedDNS == 0 || !runtimeQuiesceDNSObservationValid(dns) {
		return base
	}
	stage := base + "-dns-observation-" + dns
	if runtimeQuiesceDNSRoleObservation(dns) && ordinaryInstallerRoleStageValid(ordinary) {
		stage += "-ordinary-observation-" + ordinary
	}
	return stage
}

func knownRuntimeQuiesceInactiveObservation(stage string) bool {
	base, detail, present := strings.Cut(stage, "-dns-observation-")
	if !present || !strings.Contains(base, "-scoped-dns") {
		return false
	}
	baseKnown := false
	for _, known := range runtimeQuiesceInactiveFailureStages() {
		if base == known {
			baseKnown = true
			break
		}
	}
	if !baseKnown {
		return false
	}
	dns, ordinary, hasOrdinary := strings.Cut(detail, "-ordinary-observation-")
	return runtimeQuiesceDNSObservationValid(dns) && (!hasOrdinary || runtimeQuiesceDNSRoleObservation(dns) && ordinaryInstallerRoleStageValid(ordinary))
}
