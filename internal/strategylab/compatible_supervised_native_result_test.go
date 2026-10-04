package strategylab

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// ROOT genuine-root42 reviewed the official v1.0.5.2 LuaJIT assertion trace.
// A nonzero exit or an echoed assertion is not evidence that Lua executed it.
const compatibilityNativeCircularError = "LUA ERROR: [string \"assert(type(circular)=='function','missing ci...\"]:1: missing circular"

// Shared by the opt-in native fixture and ordinary modeled regressions. This
// predicate grants no production capability and executes no process or Lua.
func compatibilityNativeMissingCircularRejected(state State, checked Candidate) bool {
	stored, exists := state.Candidates[checked.ID]
	if !exists || !compatibilityJSONEqual(stored, checked) || state.SchemaVersion != compatibilitySupervisedSchema || state.CompatibilityFinalizing {
		return false
	}
	for _, candidate := range state.Candidates {
		if candidate.Validation.QuiescenceUnknown {
			return false
		}
	}
	validation := checked.Validation
	if validation.QuiescenceUnknown || validation.OK || validation.Native || validation.LuaChecked || validation.Code != "COMPATIBILITY_REJECTED" {
		return false
	}
	session := state.CompatibilitySession
	if session == nil || session.Unknown || validateCompatibilitySession(*session) != nil || compatibilitySessionUnknown(*session) || session.Active != "lua-init" || session.DryRun == nil || session.LuaInit == nil || !compatibilityInvocationSucceeded(*session.DryRun) {
		return false
	}
	lua := session.LuaInit
	receipt := lua.Receipt
	if !lua.Acknowledged || receipt.State != "reaped" || !receipt.Started || !receipt.DirectReaped || !receipt.WaitECHILD || receipt.Reaped < 1 || receipt.Cancelled || receipt.ExitCode != 1 {
		return false
	}
	arguments, err := parseArguments(checked.Arguments)
	if err != nil || !slices.Equal(arguments, validation.Arguments) {
		return false
	}
	base := lua.Command.Review.BaseArguments
	dryOffset := 2 + len(base)
	if len(session.DryRun.Command.Args) < dryOffset || !slices.Equal(session.DryRun.Command.Args[dryOffset:], arguments) {
		return false
	}
	assertions, err := compatibilityAssertions(base, arguments)
	if err != nil || !strings.HasPrefix(assertions, "assert(type(circular)=='function','missing circular')") || len(lua.Command.Args) == 0 || lua.Command.Args[len(lua.Command.Args)-1] != "--lua-init="+assertions {
		return false
	}
	// Validation.Output is only a short prefix. The durable receipt retains
	// the bounded tail containing the actual terminal diagnostic.
	if validation.Output != shortProbeText(lua.Output) {
		return false
	}
	lines := strings.Split(strings.TrimRight(lua.Output, "\r\n"), "\n")
	return len(lines) > 0 && strings.TrimSuffix(lines[len(lines)-1], "\r") == compatibilityNativeCircularError
}

// These records model a reviewed rejection; they establish no native PASS.
func compatibilityNativeCircularResultFixture(t *testing.T, prelude string) (State, Candidate) {
	t.Helper()
	m, _, candidate, validation := compatibilityStoreFinalizationFixture(t, "lua-init", 1)
	state := m.state
	state.CompatibilityFinalizing = false
	session := compatibilityRecordClone(t, *state.CompatibilitySession)
	session.LuaInit.Output = prelude + "LUA v5.1 LuaJIT 2.1.1756211046 OpenResty\n" + compatibilityNativeCircularError + "\n"
	state.CompatibilitySession = &session
	validation.Output = shortProbeText(session.LuaInit.Output)
	candidate.Validation = validation
	state.Candidates = map[string]Candidate{candidate.ID: candidate}
	return state, candidate
}

func TestCompatibilityNativeCircularResultRequiresFramedAssertion(t *testing.T) {
	for _, diagnostic := range []string{
		"setpcap: Operation not permitted\n",
		"cannot initialize raw sockets\n",
		"missing circular\n",
		"--lua-init=assert(type(circular)=='function','missing circular')\n",
		"argv: " + compatibilityNativeCircularError + "\n",
		"LUA ERROR: [string \"assert(type(fake)=='function','missing fake')\"]:1: missing fake\n",
		"LUA ERROR: [string \"assert(type(circular)=='function','missing ci...\"]:2: missing circular\n",
		compatibilityNativeCircularError + " extra text\n",
		compatibilityNativeCircularError + "\nsetpcap: Operation not permitted\n",
	} {
		t.Run(diagnostic, func(t *testing.T) {
			state, candidate := compatibilityNativeCircularResultFixture(t, "")
			state.CompatibilitySession.LuaInit.Output = diagnostic
			candidate.Validation.Output = shortProbeText(diagnostic)
			state.Candidates[candidate.ID] = candidate
			if compatibilityNativeMissingCircularRejected(state, candidate) {
				t.Fatal("pre-Lua failure, echoed text or another assertion was accepted")
			}
		})
	}
}

func TestCompatibilityNativeCircularResultRequiresExactKnownReceipts(t *testing.T) {
	for _, condition := range []string{
		"wrong-exit", "zero-exit", "cancelled", "not-started", "no-direct-reap", "no-echild", "no-ack",
		"dry-rejected", "dry-unacknowledged", "wrong-digest", "unknown", "finalizing", "validation-unknown",
		"native-pass", "different-validation-output", "different-arguments", "different-stored-candidate",
	} {
		t.Run(condition, func(t *testing.T) {
			state, candidate := compatibilityNativeCircularResultFixture(t, "")
			lua := state.CompatibilitySession.LuaInit
			switch condition {
			case "wrong-exit":
				lua.Receipt.ExitCode = 7
			case "zero-exit":
				lua.Receipt.ExitCode = 0
			case "cancelled":
				lua.Receipt.Cancelled = true
			case "not-started":
				lua.Receipt.Started = false
			case "no-direct-reap":
				lua.Receipt.DirectReaped = false
			case "no-echild":
				lua.Receipt.WaitECHILD = false
			case "no-ack":
				lua.Acknowledged = false
			case "dry-rejected":
				state.CompatibilitySession.DryRun.Receipt.ExitCode = 1
			case "dry-unacknowledged":
				state.CompatibilitySession.DryRun.Acknowledged = false
			case "wrong-digest":
				lua.Receipt.CommandSHA256 = strings.Repeat("0", 64)
			case "unknown":
				state.CompatibilitySession.Unknown = true
			case "finalizing":
				state.CompatibilityFinalizing = true
			case "validation-unknown":
				candidate.Validation.QuiescenceUnknown = true
			case "native-pass":
				candidate.Validation.Native = true
			case "different-validation-output":
				candidate.Validation.Output = "another completion"
			case "different-arguments":
				candidate.Validation.Arguments = []string{"--filter-tcp=80"}
			case "different-stored-candidate":
				stored := candidate
				stored.Origin = "another candidate owner"
				state.Candidates[candidate.ID] = stored
			}
			if condition != "different-stored-candidate" {
				state.Candidates[candidate.ID] = candidate
			}
			if compatibilityNativeMissingCircularRejected(state, candidate) {
				t.Fatal("unbound, unsettled or wrong completion was accepted")
			}
		})
	}
}

func TestCompatibilityNativeCircularResultUsesDurableTailAfterLongPrelude(t *testing.T) {
	for _, prelude := range []string{"", strings.Repeat("startup information\n", 40)} {
		state, candidate := compatibilityNativeCircularResultFixture(t, prelude)
		if !compatibilityNativeMissingCircularRejected(state, candidate) {
			t.Fatal("exact acknowledged assertion rejection was not recognized")
		}
		if prelude != "" && strings.Contains(candidate.Validation.Output, "missing circular") {
			t.Fatal("long-prelude regression did not exercise the short-prefix boundary")
		}
	}
}

func TestCompatibilityNativeCircularResultExactSessionSurvivesModeledReload(t *testing.T) {
	state, candidate := compatibilityNativeCircularResultFixture(t, "")
	m, err := New(filepath.Join(t.TempDir(), "strategy-lab.json"))
	if err != nil {
		t.Fatal(err)
	}
	compatibilityStoreRawState(t, m, state)
	reopened, err := New(m.Path)
	if err != nil || reopened.Snapshot().QuiescenceUnknown || !compatibilityJSONEqual(reopened.state.CompatibilitySession, state.CompatibilitySession) || !compatibilityJSONEqual(reopened.state.Candidates[candidate.ID], candidate) {
		t.Fatalf("modeled known rejection lost exact receipt/candidate binding on reload: %v", err)
	}
	if !compatibilityNativeMissingCircularRejected(reopened.state, reopened.state.Candidates[candidate.ID]) {
		t.Fatal("modeled exact missing-circular diagnostic did not survive reload")
	}
}
