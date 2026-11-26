package dataplane

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Only fixture construction applies a policy, through the existing in-memory
// kernel model. All assertions exercise production readers with actual common
// receipts; no process, interface, namespace or native command is observed.
func nodeTransitPolicyAuthorityFixture(t *testing.T) (*ProxyTunnelAdapter, PolicyState, string, NodeTransitSpec, *recordedPolicyFakeRunner) {
	t.Helper()
	spec := nodeTransitFixtureSpec()
	a := &ProxyTunnelAdapter{EngineID: spec.Engine, Interface: spec.Interface, Table: spec.Table,
		StateRoot:    filepath.Join(privateScopedXrayFixtureDir(t), spec.Engine),
		bootIdentity: func() (string, error) { return spec.BootID, nil }}
	for _, owner := range PolicyOwnershipSpecs() {
		if owner.Adapter == spec.Engine {
			a.Priority = owner.PriorityBase
		}
	}
	state := testEarlyPolicy()
	state.Interface, state.Table, state.PriorityBase = a.Interface, a.Table, a.Priority
	state.RuleLayout, state.SharedPriorityBase = 0, 0
	initializePolicyLayout(&state)
	root, err := a.nodeTransitCandidateRoot(spec.PlanID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	nodeTransitPolicyAuthorityWriteState(t, root, state)
	runner := &recordedPolicyFakeRunner{}
	options := policyAdditionOptions{boot: a.currentBootIdentity}
	if err := applyPolicyAddition(context.Background(), runner, "ip", state, root, options); err != nil {
		t.Fatal(err)
	}
	doc := readAdditionFixture(t, state, root, options)
	spec.PolicyGeneration = doc.ID
	if err := writeProxyPolicyReceipt(root, proxyPolicyReceipt{Schema: 1, Engine: a.ID(), Boot: spec.BootID, Digest: proxyPolicyDigest(state), Phase: "complete"}); err != nil {
		t.Fatal(err)
	}
	return a, state, root, spec, runner
}

func nodeTransitPolicyAuthorityWriteState(t *testing.T, root string, state PolicyState) {
	t.Helper()
	data, _ := json.Marshal(state)
	if err := os.WriteFile(filepath.Join(root, "policy.staged.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
}

func nodeTransitPolicyAuthorityPredecessor(t *testing.T, a *ProxyTunnelAdapter, state PolicyState, phase string) {
	t.Helper()
	state.Prefixes = []string{"149.154.167.100/32"}
	state.Rules = []PolicyRule{{Source: "192.168.1.40/32", Destination: state.Prefixes[0]}}
	if err := os.MkdirAll(a.StateRoot, 0700); err != nil {
		t.Fatal(err)
	}
	if err := a.savePolicyJournal(state, true); err != nil {
		t.Fatal(err)
	}
	if err := a.writePolicyBinding(proxyPolicyBinding{Schema: 1, Engine: a.ID(), Digest: proxyPolicyDigest(state), Generation: strings.Repeat("d", 32), ReceiptID: strings.Repeat("e", 32), Phase: phase}); err != nil {
		t.Fatal(err)
	}
}

func TestNodeTransitPolicyAuthorityCandidateBeforeCommit(t *testing.T) {
	for _, previous := range []string{"first-A-no-journal", "candidate-B-removed-A"} {
		t.Run(previous, func(t *testing.T) {
			a, state, root, spec, runner := nodeTransitPolicyAuthorityFixture(t)
			if previous == "candidate-B-removed-A" {
				nodeTransitPolicyAuthorityPredecessor(t, a, state, "removed")
			}
			before := nodeRouterTransitReadbackTree(t, filepath.Dir(a.StateRoot))
			calls := len(runner.calls)
			// This is the same explicit candidate authority used by router Health.
			health, err := a.captureNodeTransitPolicyAuthority(context.Background(), spec.PlanID, state, root, spec.PolicyGeneration)
			if err != nil {
				t.Fatal("applied pre-Commit candidate rejected", err)
			}
			// Manager's independently reconstructed observer uses the same state.
			observer, err := a.nodeTransitPolicyAuthorityFor(context.Background(), spec)
			if err != nil || !observer.candidate || observer.root != root || observer.digest != health.digest || observer.generation != health.generation {
				t.Fatal("observer used absent/old committed journal", observer, err)
			}
			if err := observer.verify(context.Background(), a); err != nil {
				t.Fatal(err)
			}
			if _, err := a.captureNodeTransitPolicyAuthority(context.Background(), spec.PlanID, state, filepath.Dir(root), spec.PolicyGeneration); err == nil {
				t.Fatal("noncanonical supplied transaction root obtained authority")
			}
			if calls != len(runner.calls) || !reflect.DeepEqual(before, nodeRouterTransitReadbackTree(t, filepath.Dir(a.StateRoot))) {
				t.Fatal("candidate readback published a journal, wrote metadata or invoked runner")
			}
		})
	}
}

func TestNodeTransitPolicyAuthorityCommittedDoesNotFallBackToCandidate(t *testing.T) {
	a, state, candidate, spec, runner := nodeTransitPolicyAuthorityFixture(t)
	// A retained generation has a directory ID independent of its receipt ID.
	committed, err := a.createPolicyGeneration(spec.PolicyGeneration)
	if err != nil {
		t.Fatal(err)
	}
	options := policyAdditionOptions{boot: a.currentBootIdentity}
	if err := applyPolicyAddition(context.Background(), &recordedPolicyFakeRunner{}, "ip", state, committed, options); err != nil {
		t.Fatal(err)
	}
	doc := readAdditionFixture(t, state, committed, options)
	if doc.ID == spec.PolicyGeneration {
		t.Fatal("fixture did not distinguish receipt from generation")
	}
	if err := a.savePolicyJournal(state, true); err != nil {
		t.Fatal(err)
	}
	binding := proxyPolicyBinding{Schema: 1, Engine: a.ID(), Digest: proxyPolicyDigest(state), Generation: spec.PolicyGeneration, ReceiptID: doc.ID, Phase: "active"}
	if err := a.writePolicyBinding(binding); err != nil {
		t.Fatal(err)
	}
	before := nodeRouterTransitReadbackTree(t, filepath.Dir(a.StateRoot))
	calls := len(runner.calls)
	health, err := a.captureNodeTransitPolicyAuthority(context.Background(), spec.PlanID, state, "", spec.PolicyGeneration)
	if err != nil {
		t.Fatal(err)
	}
	observer, err := a.nodeTransitPolicyAuthorityFor(context.Background(), spec)
	if err != nil || observer.candidate || observer.root != committed || observer.digest != health.digest {
		t.Fatal("active committed generation was not selected", observer, err)
	}
	if calls != len(runner.calls) || !reflect.DeepEqual(before, nodeRouterTransitReadbackTree(t, filepath.Dir(a.StateRoot))) {
		t.Fatal("committed readback changed state")
	}
	boots, changed := 0, false
	originalBoot := a.bootIdentity
	a.bootIdentity = func() (string, error) {
		boots++
		if boots == 3 {
			other := binding
			other.ReceiptID = strings.Repeat("f", 32)
			if err := a.writePolicyBinding(other); err != nil {
				t.Fatal(err)
			}
			changed = true
		}
		return spec.BootID, nil
	}
	if err := observer.verify(context.Background(), a); err == nil || !changed || calls != len(runner.calls) {
		t.Fatal("closing callback changed receipt identity without revoking held authority", changed, err)
	}
	a.bootIdentity = originalBoot
	if err := a.writePolicyBinding(binding); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(committed, policyAdditionLock)); err != nil {
		t.Fatal(err)
	}
	// The candidate remains complete: it must not rescue an invalid active grant.
	if generation, err := a.nodeRouterPolicyGeneration(context.Background(), state, candidate); err != nil || generation != spec.PolicyGeneration {
		t.Fatal("fixture candidate is not a valid alternative", generation, err)
	}
	before = nodeRouterTransitReadbackTree(t, filepath.Dir(a.StateRoot))
	if _, err := a.nodeTransitPolicyAuthorityFor(context.Background(), spec); err == nil {
		t.Fatal("corrupt committed generation fell back to candidate")
	}
	if err := observer.verify(context.Background(), a); err == nil {
		t.Fatal("held committed authority ignored missing marker")
	}
	if calls != len(runner.calls) || !reflect.DeepEqual(before, nodeRouterTransitReadbackTree(t, filepath.Dir(a.StateRoot))) {
		t.Fatal("failed committed readback recreated its marker or invoked runner")
	}
}

func TestNodeTransitPolicyAuthorityRejectsIncompleteForeignOrChangedCandidate(t *testing.T) {
	for _, kind := range []string{"missing-receipt", "prepared", "unknown", "wrong-receipt-boot", "missing-common", "incomplete-common", "unknown-common", "missing-marker", "corrupt-marker", "wrong-generation", "wrong-plan", "wrong-boot", "staged-drift", "oversized-staged", "active-predecessor", "pending-predecessor", "orphan-active-binding", "corrupt-journal"} {
		t.Run(kind, func(t *testing.T) {
			a, state, root, spec, runner := nodeTransitPolicyAuthorityFixture(t)
			var mutationErr error
			switch kind {
			case "missing-receipt":
				mutationErr = os.Remove(proxyPolicyReceiptPath(root))
			case "prepared", "unknown", "wrong-receipt-boot":
				receipt, err := a.readCandidatePolicyReceipt(root, state)
				if err != nil {
					t.Fatal(err)
				}
				if kind == "wrong-receipt-boot" {
					receipt.Boot = "00000000-0000-0000-0000-000000000002"
				} else {
					receipt.Phase = kind
				}
				mutationErr = writeProxyPolicyReceipt(root, receipt)
			case "missing-common":
				mutationErr = os.Remove(filepath.Join(root, policyAdditionFile))
			case "incomplete-common", "unknown-common":
				doc := readAdditionFixture(t, state, root, policyAdditionOptions{boot: a.currentBootIdentity})
				doc.Steps[0].State = "planned"
				if kind == "unknown-common" {
					doc.Steps[0].State = "intent"
				}
				doc.Checksum = policyAdditionChecksum(doc)
				data, _ := json.Marshal(doc)
				mutationErr = os.WriteFile(filepath.Join(root, policyAdditionFile), data, 0600)
			case "missing-marker":
				mutationErr = os.Remove(filepath.Join(root, policyAdditionLock))
			case "corrupt-marker":
				mutationErr = os.WriteFile(filepath.Join(root, policyAdditionLock), []byte("foreign marker"), 0600)
			case "wrong-generation":
				spec.PolicyGeneration = strings.Repeat("f", 32)
			case "wrong-plan":
				spec.PlanID = "dp-fedcba9876543210"
			case "wrong-boot":
				spec.BootID = "00000000-0000-0000-0000-000000000002"
			case "staged-drift":
				changed := state
				changed.Rules = []PolicyRule{{Source: "192.168.1.41/32", Destination: state.Prefixes[0]}}
				nodeTransitPolicyAuthorityWriteState(t, root, changed)
			case "oversized-staged":
				mutationErr = os.WriteFile(filepath.Join(root, "policy.staged.json"), []byte(strings.Repeat(" ", (4<<20)+1)), 0600)
			case "active-predecessor", "pending-predecessor":
				nodeTransitPolicyAuthorityPredecessor(t, a, state, strings.TrimSuffix(kind, "-predecessor"))
			case "orphan-active-binding":
				if err := os.MkdirAll(a.StateRoot, 0700); err != nil {
					t.Fatal(err)
				}
				mutationErr = a.writePolicyBinding(proxyPolicyBinding{Schema: 1, Engine: a.ID(), Digest: proxyPolicyDigest(state), Generation: spec.PolicyGeneration, ReceiptID: spec.PolicyGeneration, Phase: "active"})
			case "corrupt-journal":
				if err := os.MkdirAll(a.StateRoot, 0700); err != nil {
					t.Fatal(err)
				}
				mutationErr = os.WriteFile(a.policyPath(), []byte("{broken"), 0600)
			}
			if mutationErr != nil {
				t.Fatal(mutationErr)
			}
			before := nodeRouterTransitReadbackTree(t, filepath.Dir(a.StateRoot))
			calls := len(runner.calls)
			if _, err := a.nodeTransitPolicyAuthorityFor(context.Background(), spec); err == nil {
				t.Fatal("foreign or incomplete candidate obtained owner authority")
			}
			if calls != len(runner.calls) || !reflect.DeepEqual(before, nodeRouterTransitReadbackTree(t, filepath.Dir(a.StateRoot))) {
				t.Fatal("refusal wrote files or invoked runner")
			}
		})
	}
}

func TestNodeTransitPolicyAuthorityHoldsCandidateAcrossCallbacks(t *testing.T) {
	for _, change := range []string{"root-incarnation", "policy-drift", "new-committed-binding", "boot-drift", "closing-policy-drift", "closing-receipt-drift"} {
		t.Run(change, func(t *testing.T) {
			a, state, root, spec, runner := nodeTransitPolicyAuthorityFixture(t)
			b, err := a.nodeTransitPolicyAuthorityFor(context.Background(), spec)
			if err != nil {
				t.Fatal(err)
			}
			closingMutation := false
			switch change {
			case "root-incarnation":
				// Identical bytes at the same canonical path do not renew this hold.
				backup := filepath.Join(filepath.Dir(root), "original-root")
				if err := os.Rename(root, backup); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(root, 0700); err != nil {
					t.Fatal(err)
				}
				for _, name := range []string{"policy.staged.json", "policy-additions.json", policyAdditionFile, policyAdditionLock} {
					data, err := os.ReadFile(filepath.Join(backup, name))
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(root, name), data, 0600); err != nil {
						t.Fatal(err)
					}
				}
			case "policy-drift":
				state.Rules = []PolicyRule{{Source: "192.168.1.41/32", Destination: state.Prefixes[0]}}
				nodeTransitPolicyAuthorityWriteState(t, root, state)
			case "new-committed-binding":
				nodeTransitPolicyAuthorityPredecessor(t, a, state, "active")
			case "boot-drift":
				a.bootIdentity = func() (string, error) { return "00000000-0000-0000-0000-000000000002", nil }
			case "closing-policy-drift", "closing-receipt-drift":
				boots := 0
				a.bootIdentity = func() (string, error) {
					boots++
					if boots == 3 { // final boot check after the common receipt loader
						closingMutation = true
						if change == "closing-policy-drift" {
							state.Rules = []PolicyRule{{Source: "192.168.1.41/32", Destination: state.Prefixes[0]}}
							nodeTransitPolicyAuthorityWriteState(t, root, state)
						} else {
							receipt, err := a.readCandidatePolicyReceipt(root, state)
							if err != nil {
								t.Fatal(err)
							}
							receipt.Phase = "unknown"
							if err := writeProxyPolicyReceipt(root, receipt); err != nil {
								t.Fatal(err)
							}
						}
					}
					return spec.BootID, nil
				}
			}
			before := nodeRouterTransitReadbackTree(t, filepath.Dir(a.StateRoot))
			calls := len(runner.calls)
			if err := b.verify(context.Background(), a); err == nil {
				t.Fatal("held authority adopted changed state or a new root")
			}
			if strings.HasPrefix(change, "closing-") && !closingMutation {
				t.Fatal("fixture never reached its closing mutation")
			}
			// The two closing cases mutate only through their fixture callback;
			// the production reader still must not invoke any effect command.
			if calls != len(runner.calls) || !strings.HasPrefix(change, "closing-") && !reflect.DeepEqual(before, nodeRouterTransitReadbackTree(t, filepath.Dir(a.StateRoot))) {
				t.Fatal("held authority refusal changed state")
			}
		})
	}
}

func TestNodeTransitPolicyAuthorityClosingCommonReceiptDrift(t *testing.T) {
	for _, mode := range []string{"candidate", "committed"} {
		for _, cut := range []string{"unknown-common", "changed-common-id", "corrupt-common-marker"} {
			t.Run(mode+"/"+cut, func(t *testing.T) {
				a, state, root, spec, runner := nodeTransitPolicyAuthorityFixture(t)
				argument := root
				if mode == "committed" {
					var err error
					root, err = a.createPolicyGeneration(spec.PolicyGeneration)
					if err != nil {
						t.Fatal(err)
					}
					if err := applyPolicyAddition(context.Background(), &recordedPolicyFakeRunner{}, "ip", state, root, policyAdditionOptions{boot: a.currentBootIdentity}); err != nil {
						t.Fatal(err)
					}
					doc := readAdditionFixture(t, state, root, policyAdditionOptions{boot: a.currentBootIdentity})
					if err := a.savePolicyJournal(state, true); err != nil {
						t.Fatal(err)
					}
					if err := a.writePolicyBinding(proxyPolicyBinding{Schema: 1, Engine: a.ID(), Digest: proxyPolicyDigest(state), Generation: spec.PolicyGeneration, ReceiptID: doc.ID, Phase: "active"}); err != nil {
						t.Fatal(err)
					}
					argument = ""
				}
				held, err := a.nodeTransitPolicyAuthorityFor(context.Background(), spec)
				if err != nil {
					t.Fatal("valid baseline authority refused", err)
				}
				doc := readAdditionFixture(t, state, root, policyAdditionOptions{boot: a.currentBootIdentity})
				status, err := nodeTransitReadAddition(context.Background(), state, root, a.currentBootIdentity)
				if err != nil || !status.Complete || status.Unknown || held.root != root || held.generation != spec.PolicyGeneration {
					t.Fatal("cut baseline is not the exact complete held common authority", status, held, err)
				}
				calls, boots, fired := len(runner.calls), 0, false
				originalBoot := a.bootIdentity
				a.bootIdentity = func() (string, error) {
					boots++
					if boots == 3 {
						fired = true
						if cut == "corrupt-common-marker" {
							if err := os.WriteFile(filepath.Join(root, policyAdditionLock), []byte("foreign marker"), 0600); err != nil {
								t.Fatal(err)
							}
						} else {
							if cut == "unknown-common" {
								doc.Steps[0].State = "intent"
							} else {
								doc.ID = strings.Repeat("f", 32)
								if doc.ID == status.ID {
									doc.ID = strings.Repeat("e", 32)
								}
							}
							doc.Checksum = policyAdditionChecksum(doc)
							data, err := json.Marshal(doc)
							if err != nil {
								t.Fatal(err)
							}
							if err := os.WriteFile(filepath.Join(root, policyAdditionFile), data, 0600); err != nil {
								t.Fatal(err)
							}
						}
					}
					return spec.BootID, nil
				}
				err = held.verify(context.Background(), a)
				a.bootIdentity = originalBoot
				if !fired || boots < 3 || len(runner.calls) != calls {
					t.Fatal("did not reach the last boot cut without a mutation RPC", fired, boots, calls, len(runner.calls), err)
				}
				freshGeneration, freshErr := a.nodeRouterPolicyGeneration(context.Background(), state, argument)
				if freshErr == nil && freshGeneration == held.generation {
					t.Fatal("cut did not invalidate the exact common receipt authority", freshGeneration)
				}
				if err == nil {
					t.Fatalf("held %s authority accepted %s during the closing boot callback: freshGeneration=%q freshErr=%v", mode, cut, freshGeneration, freshErr)
				}
			})
		}
	}
}
