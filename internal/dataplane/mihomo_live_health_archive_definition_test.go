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
				e.DomainDNSCoexistence = &ExecutionDomainDNSCoexistenceDefinition{}
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
