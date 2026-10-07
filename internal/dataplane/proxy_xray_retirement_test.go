package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

type proxyXrayRetirementOriginal struct {
	engine, sidecar, manifest []byte
	policy                    PolicyState
	processes                 map[string]ProcessSpec
}

func proxyXrayRetirementCapture(t *testing.T, f *xrayDispatchFixture, mode string) proxyXrayRetirementOriginal {
	t.Helper()
	var original proxyXrayRetirementOriginal
	var err error
	original.engine, err = os.ReadFile(f.a.engineConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	original.sidecar, err = os.ReadFile(f.a.sidecarConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	if mode == "node" {
		original.manifest, err = os.ReadFile(f.a.nodeManifestPath())
		if err != nil {
			t.Fatal(err)
		}
	}
	var exists bool
	original.policy, exists, err = f.a.loadPolicy()
	if err != nil || !exists {
		t.Fatal("original A has no committed policy", err)
	}
	original.processes = make(map[string]ProcessSpec, len(f.processes.active))
	for id, spec := range f.processes.active {
		spec.Args = append([]string(nil), spec.Args...)
		original.processes[id] = spec
	}
	return original
}

func proxyXrayRetirementSnapshot(t *testing.T, f *xrayDispatchFixture) (Plan, string) {
	t.Helper()
	plan := Plan{NetworkProfileID: executionNetwork, RetiringAdapters: []string{"xray"}, Routes: []Route{{ServiceID: "other", Selected: "sing-box", Resolved: "sing-box"}}}
	root := privateScopedXrayFixtureDir(t)
	if err := f.a.Snapshot(f.ctx, plan, root); err != nil {
		t.Fatal("retirement Snapshot", err)
	}
	if _, err := f.a.readStagedPolicy(root); !os.IsNotExist(err) {
		t.Fatal("retiring adapter acquired a staged candidate without Stage", err)
	}
	f.constantOwner()
	return plan, root
}

func proxyXrayRetirementAssertOriginal(t *testing.T, f *xrayDispatchFixture, mode string, original proxyXrayRetirementOriginal) {
	t.Helper()
	engine, engineErr := os.ReadFile(f.a.engineConfigPath())
	sidecar, sidecarErr := os.ReadFile(f.a.sidecarConfigPath())
	policy, exists, policyErr := f.a.loadPolicy()
	if engineErr != nil || sidecarErr != nil || policyErr != nil || !exists || !reflect.DeepEqual(engine, original.engine) ||
		!reflect.DeepEqual(sidecar, original.sidecar) || !reflect.DeepEqual(policy, original.policy) || !reflect.DeepEqual(f.processes.active, original.processes) {
		t.Fatal("retirement rollback changed original exact config, policy or process specs", engineErr, sidecarErr, policyErr)
	}
	if mode == "node" {
		manifest, err := os.ReadFile(f.a.nodeManifestPath())
		if err != nil || !reflect.DeepEqual(manifest, original.manifest) {
			t.Fatal("retirement rollback changed original node materialization", err)
		}
	}
	f.current(mode)
}

func TestProxyXrayRetirementPublicRollbackRestoresOriginalWithoutStage(t *testing.T) {
	for _, mode := range []string{"generic", "node"} {
		for _, fresh := range []bool{false, true} {
			name := mode + "/same-owner"
			if fresh {
				name = mode + "/fresh-owner"
			}
			t.Run(name, func(t *testing.T) {
				f := newXrayDispatchFixture(t)
				f.commit(mode)
				original := proxyXrayRetirementCapture(t, f, mode)
				plan, root := proxyXrayRetirementSnapshot(t, f)
				if err := f.a.Deactivate(f.ctx); err != nil {
					t.Fatal("retirement Deactivate", err)
				}
				if len(f.processes.active) != 0 {
					t.Fatal("retirement left old processes active")
				}
				actor := f.a
				if fresh {
					actor = f.freshOwner()
				}
				if err := actor.Rollback(f.ctx, plan, root); err != nil {
					t.Fatal("retirement Rollback", err)
				}
				proxyXrayRetirementAssertOriginal(t, f, mode, original)
				if ok, err := actor.VerifyRollback(f.ctx, plan, root); err != nil || !ok {
					t.Fatal("restored retirement has no verified receipt", ok, err)
				}
			})
		}
	}
}

func TestProxyXrayRetirementUntouchedOriginalRollbackDoesNotReplay(t *testing.T) {
	for _, mode := range []string{"generic", "node"} {
		t.Run(mode, func(t *testing.T) {
			f := newXrayDispatchFixture(t)
			f.commit(mode)
			original := proxyXrayRetirementCapture(t, f, mode)
			plan, root := proxyXrayRetirementSnapshot(t, f)
			starts, stops := f.processes.starts, f.processes.stops
			mutationStart := len(receiptMutationCalls(f.commands))
			stateBefore := nodeRouterTransitReadbackTree(t, f.a.StateRoot)
			if err := f.a.Rollback(f.ctx, plan, root); err != nil {
				t.Fatal("untouched A retirement Rollback", err)
			}
			if ok, err := f.a.VerifyRollback(f.ctx, plan, root); err != nil || !ok {
				t.Fatal("untouched original A was not verified", ok, err)
			}
			if f.processes.starts != starts || f.processes.stops != stops || len(receiptMutationCalls(f.commands)) != mutationStart ||
				!reflect.DeepEqual(stateBefore, nodeRouterTransitReadbackTree(t, f.a.StateRoot)) {
				t.Fatal("untouched retirement compensation replayed original A")
			}
			proxyXrayRetirementAssertOriginal(t, f, mode, original)
		})
	}
}

func TestProxyXrayRetirementPreviouslyRestoredGenerationCanRetireAgain(t *testing.T) {
	for _, mode := range []string{"generic", "node"} {
		t.Run(mode, func(t *testing.T) {
			f := newXrayDispatchFixture(t)
			f.commit(mode)
			original := proxyXrayRetirementCapture(t, f, mode)
			for cycle := 0; cycle < 2; cycle++ {
				plan, root := proxyXrayRetirementSnapshot(t, f)
				if err := f.a.Deactivate(f.ctx); err != nil {
					t.Fatal("retirement Deactivate", cycle, err)
				}
				fresh := f.freshOwner()
				if err := fresh.Rollback(f.ctx, plan, root); err != nil {
					t.Fatal("retirement Rollback", cycle, err)
				}
				if ok, err := fresh.VerifyRollback(f.ctx, plan, root); err != nil || !ok {
					t.Fatal("restored generation failed verification", cycle, ok, err)
				}
				proxyXrayRetirementAssertOriginal(t, f, mode, original)
				binding, exists, err := fresh.readPolicyBinding(original.policy)
				if err != nil || !exists || binding.Phase != "active" || binding.ReceiptID == "" || binding.ReceiptID == binding.Generation {
					t.Fatal("fixture did not preserve distinct restoration directory and receipt IDs", binding, exists, err)
				}
			}
		})
	}
}

func TestProxyXrayRetirementInterruptedRestorationRetriesWithFreshOwner(t *testing.T) {
	for _, mode := range []string{"generic", "node"} {
		t.Run(mode, func(t *testing.T) {
			f := newXrayDispatchFixture(t)
			f.commit(mode)
			original := proxyXrayRetirementCapture(t, f, mode)
			plan, root := proxyXrayRetirementSnapshot(t, f)
			if err := f.a.Deactivate(f.ctx); err != nil {
				t.Fatal(err)
			}
			processes := &proxyRollbackRetryProcesses{base: f.processes, failStopID: "xray-engine", failStopOnce: true}
			f.a.Processes = processes
			if err := f.a.Rollback(f.ctx, plan, root); err == nil || processes.failStopOnce {
				t.Fatal("retirement did not exercise transient Stop failure", err)
			}
			receipt, err := f.a.readCandidatePolicyReceipt(root, original.policy)
			if err != nil || receipt.Phase != "restoring" || receipt.RestorationGeneration != "" || len(f.processes.active) != 0 {
				t.Fatal("early failure did not retain only known restoration intent", receipt, err)
			}
			fresh := f.freshOwner()
			if err := fresh.Rollback(f.ctx, plan, root); err != nil {
				t.Fatal("fresh retry refused known early retirement failure", err)
			}
			if ok, err := fresh.VerifyRollback(f.ctx, plan, root); err != nil || !ok {
				t.Fatal("fresh retirement retry lacks verified restoration", ok, err)
			}
			proxyXrayRetirementAssertOriginal(t, f, mode, original)
		})
	}
}

func TestProxyXrayRetirementUnknownRestorationFreshRetryKeepsPendingGeneration(t *testing.T) {
	for _, mode := range []string{"generic", "node"} {
		t.Run(mode, func(t *testing.T) {
			f := newXrayDispatchFixture(t)
			f.commit(mode)
			original := proxyXrayRetirementCapture(t, f, mode)
			plan, root := proxyXrayRetirementSnapshot(t, f)
			if err := f.a.Deactivate(f.ctx); err != nil {
				t.Fatal(err)
			}
			base, injected := f.a.Runner, false
			f.a.Runner = networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
				out, err := base.Run(ctx, name, args...)
				if !injected && name == "ip" && strings.Contains(strings.Join(args, " "), "rule add") && err == nil {
					injected = true
					return out, errors.New("lost retirement restoration add acknowledgement")
				}
				return out, err
			})
			if err := f.a.Rollback(f.ctx, plan, root); !errors.Is(err, ErrProxyPolicyUnknown) || !injected {
				t.Fatal("retirement restoration uncertainty was not fenced", err, injected)
			}
			binding, exists, err := f.a.readPolicyBinding(original.policy)
			if err != nil || !exists || binding.Phase != "pending" {
				t.Fatal("unknown retirement restoration lost pending reference", binding, exists, err)
			}
			receipt, err := f.a.readCandidatePolicyReceipt(root, original.policy)
			if err != nil || receipt.Phase != "restoring" || receipt.RestorationGeneration != binding.Generation {
				t.Fatal("unknown retirement restoration was not linked before RPC", receipt, err)
			}
			generation, err := f.a.policyGenerationRoot(binding.Generation)
			if err != nil {
				t.Fatal(err)
			}
			status, err := f.a.additionStatus(f.ctx, original.policy, generation)
			if err != nil || !status.Unknown {
				t.Fatal("lost retirement add acknowledgement became known authority", status, err)
			}
			fresh := f.freshOwner()
			proxyXrayRetirementAssertRefusedWithoutEffects(t, f, fresh, plan, root)
			current, exists, err := fresh.readPolicyBinding(original.policy)
			if err != nil || !exists || current != binding {
				t.Fatal("fresh retirement retry changed pending generation", current, exists, err)
			}
		})
	}
}

func proxyXrayRetirementAssertRefusedWithoutEffects(t *testing.T, f *xrayDispatchFixture, actor *ProxyTunnelAdapter, plan Plan, root string) {
	t.Helper()
	before := proxyRollbackRetryFiles(t, f.a.StateRoot, root)
	active := make(map[string]ProcessSpec, len(f.processes.active))
	for id, spec := range f.processes.active {
		spec.Args = append([]string(nil), spec.Args...)
		active[id] = spec
	}
	starts, stops, mutations := f.processes.starts, f.processes.stops, len(receiptMutationCalls(f.commands))
	if err := actor.Rollback(f.ctx, plan, root); !errors.Is(err, ErrProxyPolicyUnknown) {
		t.Fatal("unowned retirement state acquired rollback authority", err)
	}
	if ok, err := actor.VerifyRollback(f.ctx, plan, root); ok || !errors.Is(err, ErrProxyPolicyUnknown) {
		t.Fatal("unowned retirement state acquired verified receipt", ok, err)
	}
	if f.processes.starts != starts || f.processes.stops != stops || len(receiptMutationCalls(f.commands)) != mutations ||
		!reflect.DeepEqual(active, f.processes.active) || !reflect.DeepEqual(before, proxyRollbackRetryFiles(t, f.a.StateRoot, root)) {
		t.Fatal("refused retirement retry changed kernel, processes, files or receipt")
	}
	f.constantOwner()
}

func TestProxyXrayRetirementMissingTamperedReceiptOrForeignBindingCannotRestore(t *testing.T) {
	for _, mode := range []string{"generic", "node"} {
		for _, cut := range []string{"missing-receipt", "tampered-receipt", "foreign-pending-binding", "foreign-active-binding"} {
			t.Run(mode+"/"+cut, func(t *testing.T) {
				f := newXrayDispatchFixture(t)
				f.commit(mode)
				original := proxyXrayRetirementCapture(t, f, mode)
				binding, exists, err := f.a.readPolicyBinding(original.policy)
				if err != nil || !exists || binding.Phase != "active" {
					t.Fatal("original A lacks active generation", binding, exists, err)
				}
				plan, root := proxyXrayRetirementSnapshot(t, f)
				if err := f.a.Deactivate(f.ctx); err != nil {
					t.Fatal(err)
				}
				switch cut {
				case "missing-receipt":
					if err := os.Remove(proxyPolicyReceiptPath(root)); err != nil {
						t.Fatal(err)
					}
				case "tampered-receipt":
					receipt, err := f.a.readCandidatePolicyReceipt(root, original.policy)
					if err != nil {
						t.Fatal(err)
					}
					// Preserve valid canonical JSON and checksum. A receipt bound to
					// a different policy still cannot authorize replay of original A.
					receipt.Digest = strings.Repeat("0", 64)
					if err := writeProxyPolicyReceipt(root, receipt); err != nil {
						t.Fatal(err)
					}
				case "foreign-active-binding":
					// A separate complete generation with identical selectors is
					// still not the old generation captured by this retirement.
					if err := f.a.applyRetainedPolicy(f.ctx, original.policy); err != nil {
						t.Fatal("install independent fully acknowledged occupant", err)
					}
					foreign, exists, err := f.a.readPolicyBinding(original.policy)
					if err != nil || !exists || foreign.Phase != "active" || foreign.Generation == binding.Generation {
						t.Fatal("foreign active fixture did not publish another valid generation", foreign, exists, err)
					}
					generation, err := f.a.policyGenerationRoot(foreign.Generation)
					if err != nil {
						t.Fatal(err)
					}
					status, err := f.a.additionStatus(f.ctx, original.policy, generation)
					if err != nil || !status.Complete || status.Unknown {
						t.Fatal("foreign occupant lacks complete durable ACKs", status, err)
					}
				default:
					binding.Generation = strings.Repeat("f", 32)
					binding.ReceiptID = ""
					binding.Phase = "pending"
					if err := f.a.writePolicyBinding(binding); err != nil {
						t.Fatal(err)
					}
				}
				proxyXrayRetirementAssertRefusedWithoutEffects(t, f, f.freshOwner(), plan, root)
			})
		}
	}
}

type proxyXrayRetirementStopProcesses struct {
	ProcessController
	afterStop func(ProcessSpec, error)
}

func (p *proxyXrayRetirementStopProcesses) Stop(ctx context.Context, spec ProcessSpec) error {
	err := p.ProcessController.Stop(ctx, spec)
	if p.afterStop != nil {
		p.afterStop(spec, err)
	}
	return err
}

func TestProxyXrayRetirementClosingCallbacksCannotOverwriteNewForeignBinding(t *testing.T) {
	for _, mode := range []string{"generic", "node"} {
		for _, boundary := range []string{"final-preflight-readback", "final-owned-stop"} {
			t.Run(mode+"/"+boundary, func(t *testing.T) {
				f := newXrayDispatchFixture(t)
				f.commit(mode)
				original := proxyXrayRetirementCapture(t, f, mode)
				plan, root := proxyXrayRetirementSnapshot(t, f)
				if err := f.a.Deactivate(f.ctx); err != nil {
					t.Fatal(err)
				}
				foreign := proxyPolicyBinding{Schema: 1, Engine: "xray", Digest: proxyPolicyDigest(original.policy), Generation: strings.Repeat("e", 32), Phase: "pending"}
				cut := false
				var cutTree map[string]string
				var starts, stops, mutations int
				inject := func() {
					if cut {
						return
					}
					cut = true
					if err := f.a.writePolicyBinding(foreign); err != nil {
						t.Fatal(err)
					}
					cutTree = proxyRollbackRetryFiles(t, f.a.StateRoot, root)
					starts, stops, mutations = f.processes.starts, f.processes.stops, len(receiptMutationCalls(f.commands))
				}
				if boundary == "final-preflight-readback" {
					tables := proxyFirewallTables(original.policy)
					if len(tables) == 0 {
						t.Fatal("fixture lacks forwarding preflight")
					}
					last := tables[len(tables)-1]
					base := f.a.Runner
					f.a.Runner = networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
						out, err := base.Run(ctx, name, args...)
						command := " " + strings.Join(args, " ") + " "
						if err == nil && name == f.a.firewallBinary(last.v6) && strings.Contains(command, " -t "+last.table+" ") && strings.Contains(command, " -S ") {
							inject()
						}
						return out, err
					})
				} else {
					f.a.Processes = &proxyXrayRetirementStopProcesses{ProcessController: f.processes, afterStop: func(spec ProcessSpec, err error) {
						if err == nil && spec.ID == "xray-engine" {
							inject()
						}
					}}
				}
				err := f.a.Rollback(f.ctx, plan, root)
				current, exists, bindingErr := f.a.readPolicyBinding(original.policy)
				if !cut || !errors.Is(err, ErrProxyPolicyUnknown) || bindingErr != nil || !exists || current != foreign ||
					f.processes.starts != starts || f.processes.stops != stops || len(receiptMutationCalls(f.commands)) != mutations || len(f.processes.active) != 0 ||
					!reflect.DeepEqual(cutTree, proxyRollbackRetryFiles(t, f.a.StateRoot, root)) {
					t.Fatal("successful closing callback granted authority over new foreign binding", err, cut, current, bindingErr)
				}
				f.constantOwner()
			})
		}
	}
}

func TestProxyXrayRetirementSurvivingForeignRuntimeMarkersCannotRestore(t *testing.T) {
	for _, mode := range []string{"generic", "node"} {
		for _, marker := range []string{"engine-pid", "sidecar-pid", "engine-identity", "sidecar-identity", "interface"} {
			t.Run(mode+"/"+marker, func(t *testing.T) {
				f := newXrayDispatchFixture(t)
				f.commit(mode)
				plan, root := proxyXrayRetirementSnapshot(t, f)
				if err := f.a.Deactivate(f.ctx); err != nil {
					t.Fatal(err)
				}
				path, data := f.a.engineProcess().PIDPath, []byte("4231\n")
				switch marker {
				case "sidecar-pid":
					path = f.a.sidecarProcess().PIDPath
				case "engine-identity", "sidecar-identity":
					if marker == "sidecar-identity" {
						path = f.a.sidecarProcess().PIDPath
					}
					path += routeidentity.ReceiptSuffix
					var err error
					data, err = json.Marshal(routeidentity.Receipt{Version: 1, PID: 4231, BootID: "foreign-boot", StartTicks: "99", Executable: "foreign-engine", ArgsHash: strings.Repeat("e", 64), ConfigHash: strings.Repeat("f", 64)})
					if err != nil {
						t.Fatal(err)
					}
				case "interface":
					path = f.a.nodeInterfacePath()
					var err error
					data, err = json.Marshal(nodeInterfaceLease{Schema: 1, Boot: "foreign-boot", Interface: "foreign0", Index: 91, ConfigHash: strings.Repeat("f", 64)})
					if err != nil {
						t.Fatal(err)
					}
				}
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
				proxyXrayRetirementAssertRefusedWithoutEffects(t, f, f.freshOwner(), plan, root)
				retained, err := os.ReadFile(path)
				if err != nil || !reflect.DeepEqual(retained, data) {
					t.Fatal("foreign runtime marker was consumed", mode, err)
				}
			})
		}
	}
}

type proxyXrayRetirementRunningProcesses struct {
	ProcessController
	running int
	last    ProcessSpec
	after   func(ProcessSpec, bool)
}

func (p *proxyXrayRetirementRunningProcesses) Running(spec ProcessSpec) bool {
	running := p.ProcessController.Running(spec)
	p.running++
	p.last = spec
	if p.after != nil {
		p.after(spec, running)
	}
	return running
}

func TestProxyXrayRetirementFinalRunningCannotAdmitChangedMetadata(t *testing.T) {
	for _, mode := range []string{"generic", "node"} {
		for _, operation := range []string{"Rollback", "VerifyRollback"} {
			for _, change := range []string{"same-byte-root-replacement", "retirement-receipt", "foreign-binding", "interface", "engine-pid", "sidecar-pid", "engine-identity", "sidecar-identity"} {
				t.Run(mode+"/"+operation+"/"+change, func(t *testing.T) {
					f := newXrayDispatchFixture(t)
					f.commit(mode)
					original := proxyXrayRetirementCapture(t, f, mode)
					plan, root := proxyXrayRetirementSnapshot(t, f)
					if err := f.a.Deactivate(f.ctx); err != nil {
						t.Fatal(err)
					}
					if err := f.a.Rollback(f.ctx, plan, root); err != nil {
						t.Fatal("initial retirement restoration", err)
					}
					processes := &proxyXrayRetirementRunningProcesses{ProcessController: f.processes}
					f.a.Processes = processes
					run := func() (bool, error) {
						if operation == "Rollback" {
							err := f.a.Rollback(f.ctx, plan, root)
							return err == nil, err
						}
						return f.a.VerifyRollback(f.ctx, plan, root)
					}
					if ok, err := run(); err != nil || !ok {
						t.Fatal("baseline restored retirement readback", ok, err)
					}
					view, err := f.a.xrayModeView(proxyXrayMode(mode))
					finalRunning := processes.running
					if err != nil || finalRunning == 0 || !reflect.DeepEqual(processes.last, view.sidecarProcess()) {
						t.Fatal("baseline did not finish on exact restored old-sidecar Running", finalRunning, err)
					}
					snapshot, err := os.ReadFile(filepath.Join(root, "snapshot.json"))
					if err != nil {
						t.Fatal(err)
					}
					receiptBytes, err := os.ReadFile(proxyPolicyReceiptPath(root))
					if err != nil {
						t.Fatal(err)
					}
					held := filepath.Join(t.TempDir(), "original-retirement-transaction")
					rootBefore := nodeRouterTransitReadbackTree(t, root)
					processes.running = 0
					cut := false
					var cutTree map[string]string
					var starts, stops, mutations int
					processes.after = func(spec ProcessSpec, running bool) {
						if processes.running != finalRunning {
							return
						}
						if !running || !reflect.DeepEqual(spec, view.sidecarProcess()) {
							t.Fatal("cut replaced a failing or nonfinal process observation")
						}
						cut = true
						switch change {
						case "same-byte-root-replacement":
							if err := os.Rename(root, held); err != nil {
								t.Fatal(err)
							}
							if err := os.Mkdir(root, 0700); err != nil {
								t.Fatal(err)
							}
							if err := os.WriteFile(filepath.Join(root, "snapshot.json"), snapshot, 0600); err != nil {
								t.Fatal(err)
							}
							if err := os.WriteFile(proxyPolicyReceiptPath(root), receiptBytes, 0600); err != nil {
								t.Fatal(err)
							}
						case "retirement-receipt":
							var changed proxyPolicyReceipt
							if err := json.Unmarshal(receiptBytes, &changed); err != nil {
								t.Fatal(err)
							}
							// Keep canonical JSON, a valid checksum and the original
							// snapshot/old grant. Only the restoration reference drifts.
							changed.RestorationGeneration = strings.Repeat("d", 32)
							if err := writeProxyPolicyReceipt(root, changed); err != nil {
								t.Fatal(err)
							}
						case "foreign-binding":
							foreign := proxyPolicyBinding{Schema: 1, Engine: "xray", Digest: proxyPolicyDigest(original.policy), Generation: strings.Repeat("e", 32), Phase: "pending"}
							if err := f.a.writePolicyBinding(foreign); err != nil {
								t.Fatal(err)
							}
						case "interface":
							data, err := json.Marshal(nodeInterfaceLease{Schema: 1, Boot: "foreign-boot", Interface: "foreign0", Index: 91, ConfigHash: strings.Repeat("f", 64)})
							if err != nil {
								t.Fatal(err)
							}
							if err := os.WriteFile(f.a.nodeInterfacePath(), data, 0600); err != nil {
								t.Fatal(err)
							}
						default:
							path, data := view.engineProcess().PIDPath, []byte("4231\n")
							if strings.HasPrefix(change, "sidecar-") {
								path = view.sidecarProcess().PIDPath
							}
							if strings.HasSuffix(change, "-identity") {
								path += routeidentity.ReceiptSuffix
								var err error
								data, err = json.Marshal(routeidentity.Receipt{Version: 1, PID: 4231, BootID: "foreign-boot", StartTicks: "99", Executable: "foreign-engine", ArgsHash: strings.Repeat("e", 64), ConfigHash: strings.Repeat("f", 64)})
								if err != nil {
									t.Fatal(err)
								}
							}
							if err := os.WriteFile(path, data, 0600); err != nil {
								t.Fatal(err)
							}
						}
						cutTree = proxyRollbackRetryFiles(t, f.a.StateRoot, root)
						starts, stops, mutations = f.processes.starts, f.processes.stops, len(receiptMutationCalls(f.commands))
					}
					ok, err := run()
					if !cut || ok || !errors.Is(err, ErrProxyPolicyUnknown) || f.processes.starts != starts || f.processes.stops != stops ||
						len(receiptMutationCalls(f.commands)) != mutations || !reflect.DeepEqual(original.processes, f.processes.active) ||
						!reflect.DeepEqual(cutTree, proxyRollbackRetryFiles(t, f.a.StateRoot, root)) {
						t.Fatal("final successful Running admitted changed retirement metadata or caused effects", ok, err, cut)
					}
					if change == "same-byte-root-replacement" && !reflect.DeepEqual(rootBefore, nodeRouterTransitReadbackTree(t, held)) {
						t.Fatal("closing retirement readback mutated the retained original transaction")
					}
					f.constantOwner()
				})
			}
		}
	}
}

func TestProxyXrayRetirementCompleteRestorationFreshSettlementDoesNotReplay(t *testing.T) {
	for _, mode := range []string{"generic", "node"} {
		for _, phase := range []string{"active", "pending"} {
			t.Run(mode+"/"+phase, func(t *testing.T) {
				f := newXrayDispatchFixture(t)
				f.commit(mode)
				original := proxyXrayRetirementCapture(t, f, mode)
				journal, err := os.ReadFile(f.a.policyPath())
				if err != nil {
					t.Fatal(err)
				}
				plan, root := proxyXrayRetirementSnapshot(t, f)
				if err := f.a.Deactivate(f.ctx); err != nil {
					t.Fatal(err)
				}
				rules, err := kernelRulesForPolicy(original.policy)
				if err != nil || len(rules) == 0 {
					t.Fatal("fixture has no restoration selectors", err)
				}
				base, adds, injected := f.a.Runner, 0, false
				marker := filepath.Join(f.a.policyPath(), "keep")
				f.a.Runner = networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
					out, err := base.Run(ctx, name, args...)
					if name == "ip" && strings.Contains(strings.Join(args, " "), "rule add") && err == nil {
						adds++
						if adds == len(rules) {
							if _, err := os.Lstat(f.a.policyPath()); !os.IsNotExist(err) {
								t.Fatal("retirement did not leave the journal path absent before restoration publication", err)
							}
							if err := os.Mkdir(f.a.policyPath(), 0700); err != nil {
								t.Fatal(err)
							}
							if err := os.WriteFile(marker, []byte("keep"), 0600); err != nil {
								t.Fatal(err)
							}
							injected = true
						}
					}
					return out, err
				})
				if err := f.a.Rollback(f.ctx, plan, root); err == nil || !injected || adds != len(rules) {
					t.Fatal("last-ACK journal write cut did not interrupt completed retirement restoration", err, injected, adds)
				}
				binding, exists, err := f.a.readPolicyBinding(original.policy)
				if err != nil || !exists || binding.Phase != "active" {
					t.Fatal("full restoration did not publish acknowledged binding before journal cut", binding, exists, err)
				}
				receipt, err := f.a.readCandidatePolicyReceipt(root, original.policy)
				if err != nil || receipt.Phase != "restoring" || receipt.RestorationGeneration != binding.Generation {
					t.Fatal("journal cut lost exact linked retirement restoration reference", receipt, err)
				}
				generation, err := f.a.policyGenerationRoot(binding.Generation)
				if err != nil {
					t.Fatal(err)
				}
				status, err := f.a.additionStatus(f.ctx, original.policy, generation)
				if err != nil || !status.Complete || status.Unknown || status.ID != binding.ReceiptID || status.ID == binding.Generation {
					t.Fatal("cut did not retain full ACKs with distinct directory and receipt IDs", status, err)
				}
				if phase == "pending" {
					binding.Phase, binding.ReceiptID = "pending", ""
					if err := f.a.writePolicyBinding(binding); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Remove(marker); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(f.a.policyPath()); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(f.a.policyPath(), journal, 0600); err != nil {
					t.Fatal(err)
				}
				f.a.Runner = base
				starts, stops, mutations := f.processes.starts, f.processes.stops, len(receiptMutationCalls(f.commands))
				fresh := f.freshOwner()
				if err := fresh.Rollback(f.ctx, plan, root); err != nil {
					t.Fatal("fresh retirement retry could not settle full ACK generation", err)
				}
				if ok, err := fresh.VerifyRollback(f.ctx, plan, root); err != nil || !ok {
					t.Fatal("settled retirement restoration was not verified", ok, err)
				}
				current, exists, err := fresh.readPolicyBinding(original.policy)
				if err != nil || !exists || current.Generation != binding.Generation || current.Phase != "active" || current.ReceiptID != status.ID {
					t.Fatal("fresh retirement retry replaced acknowledged generation", current, exists, err)
				}
				restored, err := fresh.readCandidatePolicyReceipt(root, original.policy)
				if err != nil || restored.Phase != "restored" || restored.RestorationGeneration != binding.Generation {
					t.Fatal("fresh retirement retry lost original restoration linkage", restored, err)
				}
				if f.processes.starts != starts || f.processes.stops != stops || len(receiptMutationCalls(f.commands)) != mutations {
					t.Fatal("complete retirement retry replayed process or kernel operations")
				}
				proxyXrayRetirementAssertOriginal(t, f, mode, original)
			})
		}
	}
}
