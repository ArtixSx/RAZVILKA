package dataplane

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// Actual ordinary child/sole Wait, with comparison-only restoration metadata.
// This tests revocation/CAS, not a fabricated positive standby/source grant.
func TestDomainFailureRestorationRevokesOnlyJoinedOriginalListener(t *testing.T) {
	for _, change := range []string{"none", "no-ack", "wrong-stage", "no-alias", "inactive", "copy", "foreign-current", "foreign-resource", "foreign-control", "foreign-endpoint", "foreign-birth", "closed-files", "done-without-wait", "canceled"} {
		t.Run(change, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.Command(os.Args[0], "-test.run=^$")
			cmd.Dir = t.TempDir()
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			child, err := retainXraySelectedTCPProcessWait(ctx, cmd)
			if err != nil {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				t.Fatal(err)
			}
			defer child.cancel()
			if err := child.Joined(ctx); err != nil {
				t.Fatal(err)
			}
			file, err := os.Open(os.Args[0])
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			info, err := file.Stat()
			if err != nil {
				t.Fatal(err)
			}
			birth := &xraySelectedTCPProcessObservation{pid: child.pid, config: info, executable: info}
			control := &operationgate.ControlEpochReview{}
			c := &domainTCPGlobalSuccessor{}
			c.self = c
			c.failedCustody.Store(true)
			s := &executionResourceScope{domainSuccessor: c, pending: true}
			material := &XrayDomainTCPOperationMaterial{control: control}
			material.self = material
			p := &XrayDomainTCPExecutionResource{scope: s, material: material, child: child, birth: birth, config: file, executable: &xrayDomainTCPExecutable{file: file}, records: &xraySelectedTCPExecutionRecords{}}
			p.self = p
			p.definition.PrivateEndpoint = netip.MustParseAddrPort("127.0.0.1:10808")
			material.resource = p
			p.records.standbyAlias.Store(true)
			c.records = p.records
			o := &DomainTCPOriginalScope{process: p}
			owner := &domainTCPStandbyOwner{original: o, process: p}
			owner.self = owner
			retained := &retainedXrayExecution{scope: s, records: p.records, standby: owner, pending: true}
			retained.self = retained
			r := &domainTCPFailureCleanup{cursor: c, resource: p, control: control, cleanup: &operationgate.ExclusiveCleanupReview{}, standby: owner, retained: retained, imageACK: true, imageStage: "standby"}
			r.self = r
			r.ctx = context.WithValue(ctx, domainTCPFailureCleanupKey{}, r)
			r.active.Store(true)
			c.cleanup = r
			w := &domainTCPPoolListenerWitness{cursor: c, resource: p, process: child, birth: birth, frozenBirth: *birth, control: control, config: file, executable: file, endpoint: p.definition.PrivateEndpoint, inode: 7}
			w.self = w
			c.listener.Store(w)
			if err := r.restorationListenerCurrent(r.ctx, w); err != nil {
				t.Fatal("invalid comparison fixture", err)
			}
			switch change {
			case "no-ack":
				r.imageACK = false
			case "wrong-stage":
				r.imageStage = "capture"
			case "no-alias":
				p.records.standbyAlias.Store(false)
			case "inactive":
				r.active.Store(false)
			case "copy":
				copy := *w
				w = &copy
			case "foreign-current":
				c.listener.Store(&domainTCPPoolListenerWitness{})
			case "foreign-resource":
				w.resource = &XrayDomainTCPExecutionResource{}
			case "foreign-control":
				w.control = &operationgate.ControlEpochReview{}
			case "foreign-endpoint":
				w.endpoint = netip.MustParseAddrPort("127.0.0.1:10809")
			case "foreign-birth":
				birth.start = "changed"
			case "closed-files":
				p.descriptorsClosed.Store(true)
			case "done-without-wait":
				child.state = nil
			case "canceled":
				cancel()
			}
			before := c.listener.Load()
			err = r.revokeRestorationListener(r.ctx, w)
			if change == "none" {
				if err != nil || c.listener.Load() != nil {
					t.Fatal("original joined witness not revoked", err)
				}
			} else if err == nil || c.listener.Load() != before {
				t.Fatal("foreign or incomplete witness revoked", change, err)
			}
			if !c.failedCustody.Load() || !s.pending || !retained.pending || r.restored {
				t.Fatal("revocation helper released restoration fences")
			}
		})
	}
}
