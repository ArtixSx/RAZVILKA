//go:build linux

package dataplane

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/components"
)

func TestMihomoParentOriginRequiresReader5WithoutChangingLegacy4(t *testing.T) {
	root := filepath.Join(t.TempDir(), "private-history")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	write := func(origin bool) Execution {
		d := mihomoProbeDefinitionFixture(t)
		if origin {
			d.Source.ParentOrigin = components.MihomoProbeParentOrigin{Schema: 1, BootID: d.NetworkIdentity.BootID, PID: 2, StartTicks: 3, ExecutableInode: 4, ExecutableSize: 10, ExecutableSHA256: strings.Repeat("d", 64), PIDNamespaceInode: 5, ProcInode: 6, DeathSignal: "linux-pdeathsig-sigkill-v1"}
		}
		p := mihomoProbePlan(d)
		d.PlanID, d.PlanDigest = p.PlanID, p.Digest
		e := Execution{PlanID: d.PlanID, Digest: d.PlanDigest, State: "resource-failed", Resources: []ExecutionResource{{ID: "mp-" + strings.Repeat("a", 32), Kind: "mihomo-probe", State: "prepared", Phase: "process-pending", Generation: d.Source.ConfigSHA256, EffectsDigest: d.Source.ConfigSHA256, MihomoProbe: &d}}}
		raw, _ := json.Marshal(e)
		directory := filepath.Join(root, "transactions", e.PlanID)
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "execution.json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "latest-execution.json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
		return e
	}
	write(false)
	if version, _, err := InspectRetainedExecutionReadVersion(context.Background(), root); err != nil || version != 4 {
		t.Fatal("legacy meaning changed", version, err)
	}
	write(true)
	if version, _, err := InspectRetainedExecutionReadVersion(context.Background(), root); err != nil || version != 5 {
		t.Fatal("new lineage reader missing", version, err)
	}
	write(false) // A later legacy latest record cannot hide retained reader5.
	if version, _, err := InspectRetainedExecutionReadVersion(context.Background(), root); err != nil || version != 5 {
		t.Fatal("retained lineage hidden by legacy latest", version, err)
	}
}
