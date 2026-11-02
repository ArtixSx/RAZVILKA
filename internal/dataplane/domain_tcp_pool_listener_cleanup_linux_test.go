//go:build linux

package dataplane

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"golang.org/x/sys/unix"
)

// Ordinary child sole-Wait, actual original journal/config FDs, real Gate and
// complete proc socket tables only. The shaped Xray/source association is a
// comparison model, never an actual native Xray issuer/readiness proof.
func TestDomainPoolCanceledWitnessOnlyReachesFreshGlobalAbsence(t *testing.T) {
	for _, change := range []string{"none", "removed", "copy", "foreign-child", "done-without-wait", "occupied", "registry", "config", "journal-definition", "revoked-cleanup"} {
		t.Run(change, func(t *testing.T) {
			k, base := domainTCPKeeperFilesFixture(t)
			ctx, cancel := context.WithTimeout(base, 15*time.Second)
			defer cancel()
			gate := &operationgate.Gate{}
			held, release, err := gate.ExclusiveContext(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			controlRoot := filepath.Join(t.TempDir(), "control")
			if _, err := operationgate.InitializeSelfUpdateControl(held, controlRoot); err != nil {
				t.Fatal(err)
			}
			control, err := gate.ReviewControlEpoch(held, controlRoot)
			if err != nil {
				t.Fatal(err)
			}
			defer control.Close()
			cleanupReview, err := control.ReviewExclusiveCleanup(held)
			if err != nil {
				t.Fatal(err)
			}
			fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(fd)
			if err := unix.Bind(fd, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
				t.Fatal(err)
			}
			bound, err := unix.Getsockname(fd)
			if err != nil {
				t.Fatal(err)
			}
			endpoint := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(bound.(*unix.SockaddrInet4).Port))
			provider := netidentity.NewProcProvider()
			identity, err := provider.Observe(held)
			if err != nil {
				t.Fatal(err)
			}
			c, s := k.cursor, k.cursor.scope
			network := &networkPolicyIdentity{value: identity, provider: provider}
			s.networkIdentity = network
			s.manager.Adapters[NetworkPolicyAdapterID] = &NetworkPolicyAdapter{identity: network}
			configBytes, executableBytes := []byte("original-config"), []byte("comparison-only-image")
			config, err := s.owned.WriteAtomicRetained(xrayDomainTCPConfigName, configBytes, 0600)
			if err != nil {
				t.Fatal(err)
			}
			defer config.Close()
			configInfo, err := config.Stat()
			if err != nil {
				t.Fatal(err)
			}
			executable, err := s.owned.WriteAtomicRetained("comparison-image", executableBytes, 0600)
			if err != nil {
				t.Fatal(err)
			}
			defer executable.Close()
			executableInfo, err := executable.Stat()
			if err != nil {
				t.Fatal(err)
			}
			executablePath := filepath.Join(s.root, "comparison-image")
			adapter := &ProxyTunnelAdapter{EngineID: "xray", StateRoot: filepath.Join(s.managerRoot, "xray"), EngineBin: executablePath, SOCKSPort: int(endpoint.Port()), xrayPlanDispatch: true, nodeRouterVerifier: true}
			s.adapter, s.adapterOwner = "xray", adapter
			s.manager.Adapters[s.adapter] = adapter
			s.registryGeneration = s.manager.registryGeneration
			material := &XrayDomainTCPOperationMaterial{manager: s.manager, managerRoot: s.managerRoot, adapter: adapter, adapterRoot: adapter.StateRoot, binaryField: executablePath, binary: executablePath, registration: &XrayRegistrationReview{}, nodeSource: &NodeDefaultSourceReview{}, private: endpoint, control: control}
			material.self = material
			cmd := exec.Command(os.Args[0], "-test.run=^$")
			cmd.Dir = s.root
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			child, err := retainXraySelectedTCPProcessWait(held, cmd)
			if err != nil {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				t.Fatal(err)
			}
			if err := child.Joined(held); err != nil {
				t.Fatal(err)
			}
			defer child.cancel()
			birth := &xraySelectedTCPProcessObservation{pid: child.pid, parent: os.Getpid(), group: child.pid, start: "model-birth", network: identity, executable: executableInfo, config: configInfo}
			r := &XrayDomainTCPExecutionResource{scope: s, records: k.records, material: material, child: child, birth: birth, root: s.owned, rootPath: s.root, anchor: s.anchor, config: config, configInfo: configInfo, executable: &xrayDomainTCPExecutable{file: executable, info: executableInfo, path: executablePath, sha256: nodeDefaultSourceMaterialHash(executableBytes)}, definition: ExecutionXrayDomainTCPDefinition{NetworkIdentity: identity, PrivateEndpoint: endpoint, ConfigSHA256: nodeDefaultSourceMaterialHash(configBytes)}}
			r.self = r
			material.resource = r
			r.id = "xd-model"
			r.definition.Domain = CloneDomainPolicyRuntimePlan(s.plan.DomainPolicy)
			definition := r.definition.Clone()
			s.execution.Resources = []ExecutionResource{{ID: r.id, Kind: "xray-domain-tcp", State: "prepared", Phase: "listener-ready", EffectsDigest: definition.ConfigSHA256, Generation: definition.Domain.Generation, XrayDomainTCP: &definition}}
			publishModel := func() {
				t.Helper()
				image, err := json.Marshal(s.execution)
				if err != nil {
					t.Fatal(err)
				}
				for i := range 2 {
					if err := k.records.publishOriginalDurable(i, image, syncDataplaneJournalDirectory); err != nil {
						t.Fatal(err)
					}
				}
			}
			publishModel()
			oldChild := &xraySelectedTCPProcess{done: make(chan struct{})}
			oldChild.self = oldChild
			close(oldChild.done)
			old := &XrayDomainTCPExecutionResource{scope: &executionResourceScope{manager: s.manager, networkIdentity: network}, child: oldChild, birth: birth, definition: r.definition, records: c.pool.entries[0].history.records}
			old.self = old
			old.scope.plan.NetworkProfileID = s.plan.NetworkProfileID
			owner := &domainTCPStandbyOwner{process: old}
			owner.self = owner
			detached := &DomainTCPDetachedStandby{owner: owner}
			detached.self = detached
			retained := &retainedXrayExecution{scope: old.scope, standby: owner, records: old.records}
			retained.self = retained
			c.pool.entries = []*domainTCPStandbyPoolEntry{{detached: detached, retained: retained}}
			s.ctx, s.cancel = context.WithCancel(held)
			c.request = s.ctx
			admission := &domainTCPContinuationAdmission{manager: s.manager, cursor: c, request: c.request, digest: s.plan.Digest}
			admission.self = admission // Deliberately already revoked.
			c.admission = admission
			w := &domainTCPPoolListenerWitness{cursor: c, resource: r, process: child, birth: birth, frozenBirth: *birth, control: control, config: config, executable: executable, endpoint: endpoint, inode: 7, ctx: s.ctx}
			w.self = w
			c.listener.Store(w)
			cleanup := &domainTCPFailureCleanup{cursor: c, resource: r, control: control, cleanup: cleanupReview}
			cleanup.self = cleanup
			c.cleanup = cleanup
			c.failedCustody.Store(true)
			cleanup.ctx = s.contextWith(context.WithValue(held, domainTCPFailureCleanupKey{}, cleanup))
			cleanup.active.Store(true)
			defer cleanup.active.Store(false)
			s.cancel()
			if w.original(old) == nil {
				t.Fatal("revoked witness became live attribution")
			}
			switch change {
			case "removed":
				s.execution.Resources[0].State, s.execution.Resources[0].Phase = "removed", "removed"
				publishModel()
			case "copy":
				w.self = &domainTCPPoolListenerWitness{}
			case "foreign-child":
				w.process = oldChild
			case "done-without-wait":
				child.state = nil
			case "occupied":
				if err := unix.Listen(fd, 1); err != nil {
					t.Fatal(err)
				}
			case "registry":
				s.manager.registryGeneration++
			case "config":
				// The original retained FD is deliberately readonly. This test
				// mutator is never substituted for its actual read custody.
				mutator, err := s.owned.OpenFile(xrayDomainTCPConfigName, os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				info, err := mutator.Stat()
				if err != nil || !os.SameFile(info, configInfo) {
					_ = mutator.Close()
					t.Fatal("config mutator lost original inode", err)
				}
				_, writeErr := mutator.WriteAt([]byte("changed"), 0)
				closeErr := mutator.Close()
				if writeErr != nil || closeErr != nil {
					t.Fatal(writeErr, closeErr)
				}
			case "journal-definition":
				s.execution.Resources[0].XrayDomainTCP.ConfigSHA256 = nodeDefaultSourceMaterialHash([]byte("foreign definition"))
				publishModel()
			case "revoked-cleanup":
				cleanup.active.Store(false)
			}
			err = old.observeRetainedDomainListener(cleanup.ctx)
			positive := change == "none" || change == "removed"
			if positive && err != nil {
				t.Fatal("joined canceled witness blocked actual global absence", err)
			}
			if !positive && err == nil {
				t.Fatal("invalid custody or real listener accepted", change)
			}
			if admission.active.Load() || w.current(held, old) == nil {
				t.Fatal("absence revived forward witness")
			}
		})
	}
}
