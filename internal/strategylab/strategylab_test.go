package strategylab

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

type fakeValidator struct {
	result Validation
}

type fakeProbeExecutor struct {
	evidence Evidence
	target   ProbeTarget
}

func (f *fakeProbeExecutor) Execute(_ context.Context, candidate Candidate, target ProbeTarget) (Evidence, error) {
	f.target = target
	result := f.evidence
	result.CandidateID = candidate.ID
	result.ServiceID = target.ServiceID
	result.Protocol = target.Protocol
	result.IPFamily = target.IPFamily
	return result, nil
}

func (v fakeValidator) Validate(_ context.Context, arguments []string) Validation {
	result := v.result
	result.Arguments = arguments
	return result
}

func TestArgumentsRejectShellAndRuntimeOwnership(t *testing.T) {
	for _, input := range []string{
		"--filter-tcp=443; reboot",
		"--filter-tcp=443 $(reboot)",
		"--qnum=100 --filter-tcp=443",
		"filter-tcp=443",
	} {
		if _, err := parseArguments(input); err == nil {
			t.Fatalf("unsafe arguments accepted: %q", input)
		}
	}
	parsed, err := parseArguments("# comment\n--filter-tcp=443 --payload='tls_client_hello'")
	if err != nil || len(parsed) != 2 || parsed[1] != "--payload=tls_client_hello" {
		t.Fatalf("valid arguments rejected: %v %+v", err, parsed)
	}
}

func TestCandidateNeedsNativeValidationAndConfirmedRepeatedEvidence(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	manager, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	manager.Now = func() time.Time { return now }
	manager.Validator = fakeValidator{result: Validation{OK: true, Native: true, Code: "PASS", Output: "dry-run ok"}}
	candidate, err := manager.AddCandidate("tcp-tls", "TLS candidate", "--filter-tcp=443 --payload=tls_client_hello", "expert")
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Validation.OK {
		t.Fatal("candidate became eligible before native validation")
	}
	candidate, err = manager.Validate(context.Background(), candidate.ID)
	if err != nil || !candidate.Validation.OK || !candidate.Validation.Native {
		t.Fatalf("native validation failed: %v %+v", err, candidate.Validation)
	}
	base := Evidence{CandidateID: candidate.ID, ServiceID: "youtube", Protocol: "tcp", IPFamily: "ipv4", Success: true, RouteConfirmed: true, LatencyMS: 25, Stages: []StageEvidence{{Stage: "dns", Status: "pass"}, {Stage: "tls", Status: "pass"}, {Stage: "read", Status: "pass"}}}
	for i := 0; i < RequiredPasses-1; i++ {
		now = now.Add(time.Minute)
		if err := manager.Record(base); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := manager.Select("youtube", "tcp", "ipv4", candidate.ID, true); err == nil {
		t.Fatal("candidate selected before repeated evidence threshold")
	}
	now = now.Add(time.Minute)
	if err := manager.Record(base); err != nil {
		t.Fatal(err)
	}
	selection, err := manager.Select("youtube", "tcp", "ipv4", candidate.ID, true)
	if err != nil || !selection.Frozen {
		t.Fatalf("eligible candidate was not selected: %v %+v", err, selection)
	}
}

func TestStateReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "strategy-lab.json")
	manager, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	added, err := manager.AddCandidate("quic-udp", "QUIC", "--filter-udp=443 --payload=quic_initial", "expert")
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := reloaded.Snapshot()
	if len(snapshot.Candidates) != 1 || snapshot.Candidates[0].ID != added.ID || len(snapshot.Pools) != 6 {
		t.Fatalf("unexpected reloaded state: %+v", snapshot)
	}
}

func TestCandidateBatchIsValidatedBeforeCommit(t *testing.T) {
	manager, err := New(filepath.Join(t.TempDir(), "strategy-lab.json"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = manager.AddCandidates([]CandidateInput{
		{PoolID: "tcp-tls", Name: "valid", Arguments: "--filter-tcp=443", Origin: "z2k"},
		{PoolID: "tcp-tls", Name: "unsafe", Arguments: "--filter-tcp=443; reboot", Origin: "z2k"},
	})
	if err == nil {
		t.Fatal("unsafe batch was accepted")
	}
	if got := len(manager.Snapshot().Candidates); got != 0 {
		t.Fatalf("partial batch committed %d candidates", got)
	}
}

func TestProbeRequiresNativeValidationAndRecordsTypedEvidence(t *testing.T) {
	manager, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := manager.AddCandidate("tcp-tls", "isolated", "--filter-tcp=443", "expert")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Probe(context.Background(), candidate.ID, ProbeTarget{ServiceID: "video", ProbeURL: "https://example.com/", IPFamily: "ipv4"}); err == nil {
		t.Fatal("probe ran before native validation")
	}
	manager.Validator = fakeValidator{result: Validation{OK: true, Native: true, Code: "PASS"}}
	if _, err := manager.Validate(context.Background(), candidate.ID); err != nil {
		t.Fatal(err)
	}
	executor := &fakeProbeExecutor{evidence: Evidence{Success: true, RouteConfirmed: true, LatencyMS: 12, Stages: []StageEvidence{{Stage: "route", Status: "pass"}}}}
	manager.Executor = executor
	evidence, err := manager.Probe(context.Background(), candidate.ID, ProbeTarget{ServiceID: "video", ProbeURL: "https://example.com/", IPFamily: "ipv4"})
	if err != nil {
		t.Fatal(err)
	}
	if !evidence.Success || executor.target.Protocol != "tcp" || len(manager.Snapshot().Evidence) != 1 {
		t.Fatalf("unexpected isolated evidence: %+v target=%+v", evidence, executor.target)
	}
}

func TestQUICCandidateUsesTrueHTTP3ProbeProtocol(t *testing.T) {
	manager, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := manager.AddCandidate("quic-udp", "HTTP/3 candidate", "--filter-udp=443 --payload=quic_initial", "expert")
	if err != nil {
		t.Fatal(err)
	}
	manager.Validator = fakeValidator{result: Validation{OK: true, Native: true, Code: "PASS"}}
	if _, err := manager.Validate(context.Background(), candidate.ID); err != nil {
		t.Fatal(err)
	}
	executor := &fakeProbeExecutor{evidence: Evidence{Success: true, RouteConfirmed: true, Stages: []StageEvidence{{Stage: "quic-handshake", Status: "pass"}}}}
	manager.Executor = executor
	evidence, err := manager.Probe(context.Background(), candidate.ID, ProbeTarget{ServiceID: "video", ProbeURL: "https://example.com/", IPFamily: "ipv4"})
	if err != nil {
		t.Fatal(err)
	}
	if executor.target.Protocol != "quic" || evidence.Protocol != "quic" || len(manager.Snapshot().Evidence) != 1 {
		t.Fatalf("unexpected QUIC evidence: %+v target=%+v", evidence, executor.target)
	}
}

func TestDeleteCandidateRemovesOnlyItsDraftEvidenceAndSelections(t *testing.T) {
	manager, err := New(filepath.Join(t.TempDir(), "strategy-lab.json"))
	if err != nil {
		t.Fatal(err)
	}
	manager.Now = func() time.Time { return time.Unix(1000, 0).UTC() }
	manager.Validator = fakeValidator{result: Validation{OK: true, Native: true, Code: "PASS"}}
	first, _ := manager.AddCandidate("tcp-tls", "first", "--filter-tcp=443", "expert")
	second, _ := manager.AddCandidate("tcp-tls", "second", "--filter-tcp=443 --payload=tls_client_hello", "expert")
	first, _ = manager.Validate(context.Background(), first.ID)
	second, _ = manager.Validate(context.Background(), second.ID)
	for index := 0; index < RequiredPasses; index++ {
		for _, candidate := range []Candidate{first, second} {
			if err := manager.Record(Evidence{CandidateID: candidate.ID, ServiceID: "video", Protocol: "tcp", IPFamily: "ipv4", Success: true, RouteConfirmed: true, Stages: []StageEvidence{{Stage: "route", Status: "pass"}}}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := manager.Select("video", "tcp", "ipv4", first.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := manager.DeleteCandidate(first.ID); err != nil {
		t.Fatal(err)
	}
	snapshot := manager.Snapshot()
	if len(snapshot.Candidates) != 1 || snapshot.Candidates[0].ID != second.ID || len(snapshot.Evidence) != RequiredPasses || len(snapshot.Selections) != 0 {
		t.Fatalf("unexpected state after deletion: %+v", snapshot)
	}
}

func TestConfidenceDecayStopsOldFailuresFromOutvotingFreshPasses(t *testing.T) {
	now := time.Date(2026, time.August, 24, 12, 0, 0, 0, time.UTC)
	manager, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	manager.Now = func() time.Time { return now }
	manager.Validator = fakeValidator{result: Validation{OK: true, Native: true, Code: "PASS"}}
	candidate, err := manager.AddCandidate("tcp-tls", "fresh wins", "--filter-tcp=443", "expert")
	if err != nil {
		t.Fatal(err)
	}
	candidate, err = manager.Validate(context.Background(), candidate.ID)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 20; index++ {
		if err := manager.Record(Evidence{CandidateID: candidate.ID, ServiceID: "video", Protocol: "tcp", IPFamily: "ipv4", Success: false, CheckedAt: now.Add(-72 * time.Hour).Add(time.Duration(index) * time.Minute).Format(time.RFC3339), Stages: []StageEvidence{{Stage: "route", Status: "fail"}}}); err != nil {
			t.Fatal(err)
		}
	}
	for index := 0; index < RequiredPasses; index++ {
		if err := manager.Record(Evidence{CandidateID: candidate.ID, ServiceID: "video", Protocol: "tcp", IPFamily: "ipv4", Success: true, RouteConfirmed: true, CheckedAt: now.Add(time.Duration(index) * time.Second).Format(time.RFC3339), Stages: []StageEvidence{{Stage: "route", Status: "pass"}}}); err != nil {
			t.Fatal(err)
		}
	}
	summary := manager.Snapshot().Summaries[0]
	if !summary.Eligible || summary.FreshPasses != RequiredPasses || summary.SuccessRate >= 0.75 || summary.Confidence < 0.75 {
		t.Fatalf("confidence decay did not prefer fresh confirmed evidence: %+v", summary)
	}
}

func TestSelectionRollsBackAfterRepeatedFreshFailures(t *testing.T) {
	now := time.Date(2026, time.August, 24, 12, 0, 0, 0, time.UTC)
	manager, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	manager.Now = func() time.Time { return now }
	manager.Validator = fakeValidator{result: Validation{OK: true, Native: true, Code: "PASS"}}
	first, _ := manager.AddCandidate("tcp-tls", "first", "--filter-tcp=443", "expert")
	second, _ := manager.AddCandidate("tcp-tls", "second", "--filter-tcp=443 --payload=tls_client_hello", "expert")
	first, _ = manager.Validate(context.Background(), first.ID)
	second, _ = manager.Validate(context.Background(), second.ID)
	pass := func(candidate Candidate) {
		now = now.Add(time.Second)
		if err := manager.Record(Evidence{CandidateID: candidate.ID, ServiceID: "video", Protocol: "tcp", IPFamily: "ipv4", Success: true, RouteConfirmed: true, Stages: []StageEvidence{{Stage: "route", Status: "pass"}}}); err != nil {
			t.Fatal(err)
		}
	}
	for index := 0; index < RequiredPasses; index++ {
		pass(first)
		pass(second)
	}
	if _, err := manager.Select("video", "tcp", "ipv4", first.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Select("video", "tcp", "ipv4", second.ID, false); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < RollbackFailures; index++ {
		now = now.Add(time.Minute)
		if err := manager.Record(Evidence{CandidateID: second.ID, ServiceID: "video", Protocol: "tcp", IPFamily: "ipv4", Success: false, Stages: []StageEvidence{{Stage: "route", Status: "fail"}}}); err != nil {
			t.Fatal(err)
		}
	}
	selection := manager.Snapshot().Selections[0]
	if selection.CandidateID != first.ID || selection.PreviousCandidateID != second.ID || selection.RolledBackAt == "" || selection.RollbackReason == "" || !selection.Healthy {
		t.Fatalf("selection was not rolled back to the fresh alternative: %+v", selection)
	}
}

func TestFrozenSelectionReportsDegradationWithoutRollback(t *testing.T) {
	now := time.Date(2026, time.August, 24, 12, 0, 0, 0, time.UTC)
	manager, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	manager.Now = func() time.Time { return now }
	manager.Validator = fakeValidator{result: Validation{OK: true, Native: true, Code: "PASS"}}
	candidate, _ := manager.AddCandidate("tcp-tls", "frozen", "--filter-tcp=443", "expert")
	candidate, _ = manager.Validate(context.Background(), candidate.ID)
	for index := 0; index < RequiredPasses; index++ {
		now = now.Add(time.Second)
		if err := manager.Record(Evidence{CandidateID: candidate.ID, ServiceID: "video", Protocol: "tcp", IPFamily: "ipv4", Success: true, RouteConfirmed: true, Stages: []StageEvidence{{Stage: "route", Status: "pass"}}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := manager.Select("video", "tcp", "ipv4", candidate.ID, true); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < RollbackFailures; index++ {
		now = now.Add(time.Minute)
		if err := manager.Record(Evidence{CandidateID: candidate.ID, ServiceID: "video", Protocol: "tcp", IPFamily: "ipv4", Success: false, Stages: []StageEvidence{{Stage: "route", Status: "fail"}}}); err != nil {
			t.Fatal(err)
		}
	}
	selection := manager.Snapshot().Selections[0]
	if selection.CandidateID != candidate.ID || selection.Status != "frozen-degraded" || selection.ConsecutiveFailures != RollbackFailures {
		t.Fatalf("frozen selection did not remain visible and unchanged: %+v", selection)
	}
}

func TestParseNFQueuePackets(t *testing.T) {
	output := "Chain RZST1234 (1 references)\n pkts bytes target prot opt in out source destination\n 7 420 NFQUEUE all -- * * 0.0.0.0/0 0.0.0.0/0 NFQUEUE num 64610\n"
	if got := parseNFQueuePackets(output); got != 7 {
		t.Fatalf("packets=%d", got)
	}
}

func TestShellAssignmentReadsMultilineBaseArgumentsWithoutExecution(t *testing.T) {
	config := "OTHER=1\nNFQWS_BASE_ARGS=\"--lua-init=@/opt/lib.lua\n--blob=tls:@/opt/tls.bin\"\nDANGER=$(reboot)\n"
	value, ok := shellAssignment(config, "NFQWS_BASE_ARGS")
	if !ok {
		t.Fatal("multiline assignment was not found")
	}
	arguments, err := parseArguments(value)
	if err != nil || len(arguments) != 2 || arguments[0] != "--lua-init=@/opt/lib.lua" {
		t.Fatalf("base args=%q parsed=%v err=%v", value, arguments, err)
	}
	if _, ok := shellAssignment(config, "DANGER"); !ok {
		t.Fatal("plain assignment lookup failed")
	}
}
