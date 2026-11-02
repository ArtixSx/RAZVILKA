package dataplane

import (
	"encoding/json"
	"strings"
	"testing"
)

func mihomoCheckingExecutionFixture(t *testing.T) Execution {
	t.Helper()
	_, _, _, original := mihomoLiveRecordModel(t)
	before, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	e := *original
	e.Resources = cloneExecutionResources(original.Resources)
	e.State, e.FinishedAt = mihomoActiveCheckingState, ""
	e.MihomoLiveHealthOperation = &ExecutionMihomoLiveHealthOperation{Schema: 1, ID: strings.Repeat("a", 64), PlanID: e.PlanID, PlanDigest: e.Digest, BeforeSHA256: nodeDefaultSourceMaterialHash(before), Phase: "checking"}
	return e
}

func TestMihomoActiveCheckingStrictOriginalDefinition(t *testing.T) {
	fresh := func() Execution {
		return mihomoCheckingExecutionFixture(t)
	}
	e := fresh()
	if err := validateExecutionResources(e, false); err != nil {
		t.Fatal(err)
	}
	if err := validateExecutionResources(e, true); err == nil {
		t.Fatal("active check accepted as terminal")
	}
	for name, change := range map[string]func(*Execution){
		"finished":       func(e *Execution) { e.FinishedAt = e.StartedAt },
		"foreign plan":   func(e *Execution) { e.PlanID = "dp-00000000000000000000000000000000" },
		"duplicate live": func(e *Execution) { e.Resources = append(e.Resources, e.Resources[0]) },
		"untyped row": func(e *Execution) {
			e.Resources = append(e.Resources, ExecutionResource{ID: "foreign", Kind: "future"})
		},
		"receipt missing":   func(e *Execution) { e.Resources[0].MihomoLive.Observation = nil },
		"mixed DNS owner":   func(e *Execution) { e.DomainDNSCoexistence = &ExecutionDomainDNSCoexistenceDefinition{} },
		"missing header":    func(e *Execution) { e.MihomoLiveHealthOperation = nil },
		"future header":     func(e *Execution) { e.MihomoLiveHealthOperation.Schema = 2 },
		"unknown phase":     func(e *Execution) { e.MihomoLiveHealthOperation.Phase = "unknown" },
		"premature settled": func(e *Execution) { e.MihomoLiveHealthOperation.Phase = "settled" },
		"foreign nonce":     func(e *Execution) { e.MihomoLiveHealthOperation.ID = "NOT-CANONICAL" },
		"foreign anchor":    func(e *Execution) { e.MihomoLiveHealthOperation.BeforeSHA256 = "unknown" },
		"nonactive phase":   func(e *Execution) { e.Resources[0].State = "prepared"; e.Resources[0].Phase = "process-pending" },
	} {
		t.Run(name, func(t *testing.T) {
			e := fresh()
			change(&e)
			if validateExecutionResources(e, false) == nil {
				t.Fatal("invalid check accepted")
			}
		})
	}
}

func TestMihomoActiveCheckingArchivePreservesHeaderAndRejectsDowngrade(t *testing.T) {
	h, archive, after := mihomoTransitArchiveFixture(t)
	var before Execution
	if err := json.Unmarshal(h.OriginBefore, &before); err != nil {
		t.Fatal(err)
	}
	header := ExecutionMihomoLiveHealthOperation{Schema: 1, ID: strings.Repeat("a", 64), PlanID: before.PlanID, PlanDigest: before.Digest, BeforeSHA256: strings.Repeat("b", 64), Phase: "settled"}
	before.MihomoLiveHealthOperation = &header
	after.MihomoLiveHealthOperation = &header
	archive.MihomoLiveHealthOperation = &header
	rawBefore, _ := json.Marshal(before)
	rawAfter, _ := json.Marshal(after)
	h.OriginBefore, h.OriginBeforeSHA256, h.OriginAfterSHA256 = rawBefore, nodeDefaultSourceMaterialHash(rawBefore), nodeDefaultSourceMaterialHash(rawAfter)
	archive.MihomoTransitHistoryArchive = &h
	if err := validateExecutionResources(archive, true); err != nil {
		t.Fatal(err)
	}
	archive.MihomoLiveHealthOperation = nil
	if err := validateExecutionResources(archive, true); err == nil {
		t.Fatal("archive9 downgraded to headerless8")
	}
}
