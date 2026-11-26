//go:build linux

package dataplane

import (
	"context"
	"net/netip"
	"testing"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// Original-pointer association model over real journal descriptors. There is
// NO actual child/Control admission here: current must always refuse. Actual
// owned-child/listener FD comparisons run in the separate native workflow.
func TestDomainPoolListenerAssociationCannotBecomeNativePermission(t *testing.T) {
	for _, change := range []string{"original-shape", "copy", "expired", "foreign-context", "foreign-cursor", "foreign-file", "wrong-port", "wrong-old", "old-not-joined", "revoked-operation"} {
		t.Run(change, func(t *testing.T) {
			k, ctx := domainTCPKeeperFilesFixture(t)
			c, s := k.cursor, k.cursor.scope
			s.ctx = ctx
			c.request = ctx
			a := &domainTCPContinuationAdmission{manager: s.manager, request: ctx, digest: s.plan.Digest, cursor: c}
			a.self = a
			a.active.Store(true)
			c.admission = a
			ni := netidentity.Identity{Version: 1, Kind: netidentity.ProcNetInode, BootID: "11111111-2222-3333-4444-555555555555", Inode: 42}
			endpoint := netip.MustParseAddrPort("127.0.0.1:10808")
			birth := xraySelectedTCPProcessObservation{pid: 42, parent: 41, group: 42, start: "99", network: ni, config: k.records.infos[0], executable: k.records.infos[1]}
			child := &xraySelectedTCPProcess{done: make(chan struct{})}
			child.self = child
			material := &XrayDomainTCPOperationMaterial{control: &operationgate.ControlEpochReview{}}
			material.self = material
			r := &XrayDomainTCPExecutionResource{scope: s, records: k.records, child: child, birth: &birth, material: material, config: k.records.files[0], executable: &xrayDomainTCPExecutable{file: k.records.files[1]}, definition: ExecutionXrayDomainTCPDefinition{PrivateEndpoint: endpoint, NetworkIdentity: ni}}
			r.self = r
			material.resource = r
			oldChild := &xraySelectedTCPProcess{done: make(chan struct{})}
			oldChild.self = oldChild
			if change != "old-not-joined" {
				close(oldChild.done)
			}
			old := &XrayDomainTCPExecutionResource{scope: &executionResourceScope{manager: s.manager}, child: oldChild, birth: &birth, definition: r.definition}
			old.scope.plan.NetworkProfileID = s.plan.NetworkProfileID
			old.records = c.pool.entries[0].history.records
			old.self = old
			owner := &domainTCPStandbyOwner{process: old}
			owner.self = owner
			detached := &DomainTCPDetachedStandby{owner: owner}
			detached.self = detached
			retained := &retainedXrayExecution{scope: old.scope, standby: owner, records: old.records}
			retained.self = retained
			c.pool.entries = []*domainTCPStandbyPoolEntry{{detached: detached, retained: retained}}
			w := &domainTCPPoolListenerWitness{cursor: c, resource: r, process: child, birth: &birth, frozenBirth: birth, control: material.control, config: r.config, executable: r.executable.file, endpoint: endpoint, inode: 7, ctx: ctx}
			w.self = w
			c.listener.Store(w)
			switch change {
			case "copy":
				w.self = &domainTCPPoolListenerWitness{}
			case "expired":
				var cancel context.CancelFunc
				s.ctx, cancel = context.WithCancel(ctx)
				cancel()
				w.ctx = s.ctx
				c.request = s.ctx
				a.request = s.ctx
			case "foreign-context":
				w.ctx = context.WithValue(ctx, struct{}{}, true)
			case "foreign-cursor":
				w.cursor = &domainTCPGlobalSuccessor{}
			case "foreign-file":
				w.config = k.records.files[1]
			case "wrong-port":
				w.endpoint = netip.MustParseAddrPort("127.0.0.1:10809")
			case "wrong-old":
				c.pool.entries = nil
			case "revoked-operation":
				a.active.Store(false)
			}
			err := w.original(old)
			if change == "original-shape" {
				if err != nil {
					t.Fatal("pointer fixture invalid", err)
				}
			} else if err == nil {
				t.Fatal("foreign/revoked association accepted")
			}
			if err := w.current(ctx, old); err == nil {
				t.Fatal("comparison model became native permission")
			}
		})
	}
}
