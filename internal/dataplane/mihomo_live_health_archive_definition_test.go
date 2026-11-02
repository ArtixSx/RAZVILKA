package dataplane

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Structural comparison data only. No native join, source or writer owner is
// issued by these modeled rows, regardless of their terminal state strings.
func mihomoTransitArchiveFixture(t *testing.T) (MihomoTransitHistoryArchive, Execution, Execution) {
	h, archive, after, _ := mihomoTransitArchiveOwnerFixture(t)
	return h, archive, after
}

func mihomoTransitArchiveOwnerFixture(t *testing.T) (MihomoTransitHistoryArchive, Execution, Execution, *mihomoLiveResource) {
	t.Helper()
	_, _, r, original := mihomoLiveRecordModel(t)
	before := *original
	before.Resources = cloneExecutionResources(original.Resources)
	spec := nodeTransitFixtureSpec()
	spec.Engine, spec.PlanID, spec.PlanDigest = "mihomo", before.PlanID, before.Digest
	spec.BootID, spec.NetworkProfile, spec.RuntimeID = r.definition.NetworkIdentity.BootID, r.definition.NetworkProfile, r.definition.Profile.ConfigSHA256
	spec.Interface, spec.Table, spec.Priority = r.definition.Policy.Interface, r.definition.Policy.Table, 80
	compiled, err := CompileNodeTransit(spec)
	if err != nil {
		t.Fatal(err)
	}
	effects, err := PolicyEffectPlanDigest(compiled)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < mihomoTransitArchiveRows; i++ {
		copy := spec
		before.Resources = append(before.Resources, ExecutionResource{ID: fmt.Sprintf("nt-%032x", i+1), Kind: "node-transit", State: "removed", Generation: compiled.Generation, EffectsDigest: effects, NodeTransit: &copy})
	}
	after := before
	after.Resources = cloneExecutionResources(before.Resources[:1])
	rawBefore, err := json.Marshal(before)
	if err != nil {
		t.Fatal(err)
	}
	rawAfter, err := json.Marshal(after)
	if err != nil {
		t.Fatal(err)
	}
	h := MihomoTransitHistoryArchive{Schema: 1, OriginExecutionID: before.PlanID, OriginPlanID: before.PlanID, OriginDigest: before.Digest, OriginBefore: rawBefore, OriginBeforeSHA256: nodeDefaultSourceMaterialHash(rawBefore), OriginAfterSHA256: nodeDefaultSourceMaterialHash(rawAfter)}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	archive := Execution{PlanID: "dp-check-" + strings.Repeat("d", 32), ResourcePlanID: before.PlanID, Digest: before.Digest, State: "temporary-complete", StartedAt: now, FinishedAt: now, Resources: cloneExecutionResources(before.Resources[1:]), Steps: []ExecutionStep{{Adapter: "mihomo", Phase: "archive-joined-transit", State: "passed", StartedAt: now, FinishedAt: now}}}
	marker := h.Clone()
	archive.MihomoTransitHistoryArchive = &marker
	return h, archive, after, r
}

func TestMihomoTransitArchiveStrictOriginRowsAndDerivedImage(t *testing.T) {
	h, archive, expected := mihomoTransitArchiveFixture(t)
	if err := validateExecutionResources(archive, true); err != nil {
		t.Fatal(err)
	}
	after, err := h.deriveAfter(archive)
	if err != nil || !reflect.DeepEqual(after, expected) {
		t.Fatal("exact source image not preserved", err)
	}
	before := bytes.Clone(h.OriginBefore)
	copy := h.Clone()
	copy.OriginBefore[0] ^= 1
	if !bytes.Equal(before, h.OriginBefore) {
		t.Fatal("history clone aliases actual origin bytes")
	}
	for _, change := range []string{"schema", "origin", "before-hash", "after-hash", "before-bytes", "duplicate", "unsettled", "cohort", "row-data", "too-few", "state", "plan", "time", "step", "mixed", "different-marker"} {
		t.Run(change, func(t *testing.T) {
			marker := h.Clone()
			e := archive
			e.Resources = cloneExecutionResources(archive.Resources)
			e.Steps = append([]ExecutionStep(nil), archive.Steps...)
			switch change {
			case "schema":
				marker.Schema++
			case "origin":
				marker.OriginPlanID = "dp-0123456789abcdef"
			case "before-hash":
				marker.OriginBeforeSHA256 = strings.Repeat("f", 64)
			case "after-hash":
				marker.OriginAfterSHA256 = strings.Repeat("f", 64)
			case "before-bytes":
				marker.OriginBefore[0] ^= 1
			case "duplicate":
				e.Resources[1] = e.Resources[0]
			case "unsettled":
				e.Resources[0].State = "unknown"
			case "cohort":
				e.Resources[0].NodeTransit.IfIndex++
			case "row-data":
				e.Resources[0].EffectsDigest = strings.Repeat("f", 64)
			case "too-few":
				e.Resources = e.Resources[:127]
			case "state":
				e.State = "committed"
			case "plan":
				e.ResourcePlanID = "dp-0123456789abcdef"
			case "time":
				e.FinishedAt = "untrusted"
			case "step":
				e.Steps[0].Phase = "service-health-pass"
			case "mixed":
				e.Resources[0].Kind = "domain-dns-coexistence"
			case "different-marker":
				other := h.Clone()
				other.OriginAfterSHA256 = strings.Repeat("f", 64)
				e.MihomoTransitHistoryArchive = &other
			}
			if change != "different-marker" {
				attached := marker.Clone()
				e.MihomoTransitHistoryArchive = &attached
			}
			if marker.validate(e) == nil {
				t.Fatal("changed archive accepted", change)
			}
		})
	}
}

func TestMihomoTransitArchiveRejectsRecursionAndEmbeddedOversize(t *testing.T) {
	h, e, _ := mihomoTransitArchiveFixture(t)
	for _, change := range []string{"recursive", "duplicate", "unknown", "noncanonical", "embedded-oversize"} {
		t.Run(change, func(t *testing.T) {
			marker := h.Clone()
			var before Execution
			if err := json.Unmarshal(marker.OriginBefore, &before); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "recursive":
				marker.OriginBefore = bytes.Replace(marker.OriginBefore, []byte("{"), []byte(`{"mihomo_transit_history_archive":null,`), 1)
			case "duplicate":
				marker.OriginBefore = bytes.Replace(marker.OriginBefore, []byte("{"), []byte(`{"plan_id":"duplicate",`), 1)
			case "unknown":
				marker.OriginBefore = bytes.Replace(marker.OriginBefore, []byte("{"), []byte(`{"future_unknown":true,`), 1)
			case "noncanonical":
				marker.OriginBefore = append([]byte(" "), marker.OriginBefore...)
			case "embedded-oversize":
				before.Error = strings.Repeat("x", 3<<20)
				marker.OriginBefore, _ = json.Marshal(before)
			}
			marker.OriginBeforeSHA256 = nodeDefaultSourceMaterialHash(marker.OriginBefore)
			if change == "embedded-oversize" {
				if len(marker.OriginBefore) > mihomoTransitArchiveImageLimit {
					t.Fatal("test did not isolate encoded archive size")
				}
				after := before
				after.Resources = cloneExecutionResources(before.Resources[:1])
				raw, _ := json.Marshal(after)
				marker.OriginAfterSHA256 = nodeDefaultSourceMaterialHash(raw)
			}
			archive := e
			attached := marker.Clone()
			archive.MihomoTransitHistoryArchive = &attached
			if marker.validate(archive) == nil {
				t.Fatal("unsafe origin/complete archive wire accepted", change)
			}
		})
	}
}

func TestMihomoTransitArchivePreparationRequiresOriginalJoinedRegistrations(t *testing.T) {
	for _, change := range []string{"valid", "no-owner", "not-joined", "not-admitted", "changed-spec", "too-few"} {
		t.Run(change, func(t *testing.T) {
			h, archive, _, r := mihomoTransitArchiveOwnerFixture(t)
			var before Execution
			if err := json.Unmarshal(h.OriginBefore, &before); err != nil {
				t.Fatal(err)
			}
			r.scope.execution = &before
			for _, row := range archive.Resources {
				r.scope.issued[row.ID] = &executionTransitResource{finished: true, admitted: true, spec: *row.NodeTransit, digest: row.Generation, effects: row.EffectsDigest}
			}
			first := archive.Resources[0].ID
			switch change {
			case "no-owner":
				delete(r.scope.issued, first)
			case "not-joined":
				r.scope.issued[first].finished = false
			case "not-admitted":
				r.scope.issued[first].admitted = false
			case "changed-spec":
				r.scope.issued[first].spec.IfIndex++
			case "too-few":
				r.scope.execution.Resources = r.scope.execution.Resources[:128]
			}
			cursor, err := r.prepareTransitArchiveLocked()
			if change == "valid" {
				if err != nil || cursor == nil || len(cursor.selected) != 128 || !bytes.Equal(cursor.before, h.OriginBefore) {
					t.Fatal("original modeled joins not retained", err)
				}
			} else if change == "too-few" || change == "not-joined" || change == "not-admitted" {
				if err != nil || cursor != nil {
					t.Fatal("threshold bypassed", err)
				}
			} else if err == nil || cursor != nil {
				t.Fatal("documentary row replaced original join owner", change)
			}
			if r.transitHistory != nil || r.scope.pending || len(r.scope.execution.Resources) < 128 {
				t.Fatal("pure preparation mutated original custody")
			}
		})
	}
}

func TestMihomoTransitArchivePreservesOtherOriginalCohorts(t *testing.T) {
	h, archive, _, r := mihomoTransitArchiveOwnerFixture(t)
	var before Execution
	if err := json.Unmarshal(h.OriginBefore, &before); err != nil {
		t.Fatal(err)
	}
	for _, row := range archive.Resources {
		r.scope.issued[row.ID] = &executionTransitResource{finished: true, admitted: true, spec: *row.NodeTransit, digest: row.Generation, effects: row.EffectsDigest}
	}
	other := cloneExecutionResources(archive.Resources[:1])[0]
	other.ID = "nt-" + strings.Repeat("f", 32)
	other.NodeTransit.IfIndex++
	plan, err := CompileNodeTransit(*other.NodeTransit)
	if err != nil {
		t.Fatal(err)
	}
	other.Generation = plan.Generation
	other.EffectsDigest, err = PolicyEffectPlanDigest(plan)
	if err != nil {
		t.Fatal(err)
	}
	r.scope.issued[other.ID] = &executionTransitResource{finished: true, admitted: true, spec: *other.NodeTransit, digest: other.Generation, effects: other.EffectsDigest}
	// A small first cohort must not hide a later complete cohort near the cap.
	before.Resources = append(append(cloneExecutionResources(before.Resources[:1]), other), before.Resources[1:]...)
	r.scope.execution = &before
	c, err := r.prepareTransitArchiveLocked()
	if err != nil || c == nil || len(c.selected) != 128 || c.selected[other.ID] != nil {
		t.Fatal("wrong cohort selected", err)
	}
	after, err := c.archive.MihomoTransitHistoryArchive.deriveAfter(c.archive)
	if err != nil || len(after.Resources) != 2 || !reflect.DeepEqual(after.Resources[1], other) || r.scope.issued[other.ID] == nil || len(r.scope.issued) != 129 {
		t.Fatal("other original history/owner changed", err)
	}
}

func TestMihomoTransitArchiveUnusedRowsNeedOriginalSettlementProvenance(t *testing.T) {
	h, archive, _, r := mihomoTransitArchiveOwnerFixture(t)
	var before Execution
	if err := json.Unmarshal(h.OriginBefore, &before); err != nil {
		t.Fatal(err)
	}
	for i := 1; i < len(before.Resources); i++ {
		row := &before.Resources[i]
		row.State = "unused"
		r.scope.issued[row.ID] = &executionTransitResource{finished: true, spec: *row.NodeTransit, digest: row.Generation, effects: row.EffectsDigest}
	}
	r.scope.execution = &before
	if c, err := r.prepareTransitArchiveLocked(); err != nil || c != nil {
		t.Fatal("unused documentary state created original proof", err)
	}
	for _, row := range archive.Resources {
		r.scope.issued[row.ID].unusedSettled = true
	} // Modeled real settlement ACK; actual one-shot test is separate.
	if c, err := r.prepareTransitArchiveLocked(); err != nil || c == nil || len(c.selected) != 128 {
		t.Fatal("known original unused joins not retained", err)
	}
}
