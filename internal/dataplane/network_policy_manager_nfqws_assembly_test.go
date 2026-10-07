package dataplane

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
)

func nfqwsExecutionAssemblyCommand(t *testing.T) (*NFQWS2Adapter, nfqws2ManagedProcessCommand, NFQWSScopedSpec) {
	t.Helper()
	a, lease := nfqws2ManagedRecordFixture(t)
	_, spec, _ := nfqwsScopedFixture(t)
	command := lease.Command
	command.Args = []string{"--intercept=1", "--qnum=40321", "--filter-udp=443"}
	command.Assets = []nfqws2ManagedFile{{Path: filepath.Join(a.StateRoot, "reviewed-asset"), SHA256: strings.Repeat("1", 64)}}
	command.Deadline = time.Now().Add(15 * time.Second).UTC()
	spec.SessionID, spec.BootID = command.ID, command.Parent.BootID
	spec.CommandSHA256 = nfqws2ManagedCommandDigest(command)
	spec.Candidate.ArgumentsSHA256 = components.NFQWSRuntimeArgumentsSHA256(command.Program.Path, command.Args)
	return a, command, spec
}

func TestNetworkPolicyManagerNFQWSAssemblyRefusesCommandBeforeReservation(t *testing.T) {
	f := executionNFQWSManagerFixture(t)
	a, command, spec := nfqwsExecutionAssemblyCommand(t)
	runtime := nfqwsExecutionRuntime{Runner: f.b.Runner, Tools: f.b.Tools, VerifyLAN: f.b.VerifyLAN, AdditionalReadback: f.b.AdditionalReadback}
	err := f.m.WithExecutionResources(f.ctx, f.p, "nfqws2", func(ctx context.Context) error {
		for name, mutate := range map[string]func(*nfqws2ManagedProcessCommand, *NFQWSScopedSpec){
			"wrong queue":         func(c *nfqws2ManagedProcessCommand, _ *NFQWSScopedSpec) { c.Args[1] = "--qnum=40322" },
			"duplicate queue":     func(c *nfqws2ManagedProcessCommand, _ *NFQWSScopedSpec) { c.Args = append(c.Args, c.Args[1]) },
			"noncanonical queue":  func(c *nfqws2ManagedProcessCommand, _ *NFQWSScopedSpec) { c.Args[1] = "--qnum=040321" },
			"split queue":         func(c *nfqws2ManagedProcessCommand, _ *NFQWSScopedSpec) { c.Args[1] = "--qnum" },
			"no interception":     func(c *nfqws2ManagedProcessCommand, _ *NFQWSScopedSpec) { c.Args[0] = "--intercept=0" },
			"duplicate intercept": func(c *nfqws2ManagedProcessCommand, _ *NFQWSScopedSpec) { c.Args = append(c.Args, c.Args[0]) },
			"daemon":              func(c *nfqws2ManagedProcessCommand, _ *NFQWSScopedSpec) { c.Args = append(c.Args, "--daemon") },
			"end options":         func(c *nfqws2ManagedProcessCommand, _ *NFQWSScopedSpec) { c.Args = append([]string{"--"}, c.Args...) },
			"wrong session":       func(_ *nfqws2ManagedProcessCommand, s *NFQWSScopedSpec) { s.SessionID = strings.Repeat("2", 32) },
			"wrong boot": func(_ *nfqws2ManagedProcessCommand, s *NFQWSScopedSpec) {
				s.BootID = "11234567-89ab-cdef-0123-456789abcdef"
			},
			"wrong command digest": func(_ *nfqws2ManagedProcessCommand, s *NFQWSScopedSpec) { s.CommandSHA256 = strings.Repeat("3", 64) },
			"wrong argv digest": func(_ *nfqws2ManagedProcessCommand, s *NFQWSScopedSpec) {
				s.Candidate.ArgumentsSHA256 = strings.Repeat("4", 64)
			},
			"unbounded": func(c *nfqws2ManagedProcessCommand, s *NFQWSScopedSpec) {
				c.Deadline = time.Now().Add(16 * time.Second)
				s.CommandSHA256 = nfqws2ManagedCommandDigest(*c)
			},
		} {
			c, s := command, spec
			c.Args = slices.Clone(command.Args)
			mutate(&c, &s)
			// For argv-shape cases, keep hashes exact so refusal checks the
			// actual pre-start queue/foreground contract, not only the hash.
			if name != "wrong command digest" {
				s.CommandSHA256 = nfqws2ManagedCommandDigest(c)
			}
			if name != "wrong argv digest" {
				s.Candidate.ArgumentsSHA256 = components.NFQWSRuntimeArgumentsSHA256(c.Program.Path, c.Args)
			}
			if e, err := newNFQWSExecutionAssembly(ctx, a, c, s, nil, runtime); err == nil || e != nil {
				t.Fatalf("%s acquired launch resource: %v", name, err)
			}
		}
		if len(f.latest(t).Resources) != 0 {
			t.Fatal("invalid command allocated a common resource")
		}
		if _, err := os.Stat(filepath.Join(a.StateRoot, nfqws2LeaseFile)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("invalid command wrote process ownership intent", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestNetworkPolicyManagerNFQWSAssemblyFreezesCommandAndSpec(t *testing.T) {
	f := executionNFQWSManagerFixture(t)
	a, command, spec := nfqwsExecutionAssemblyCommand(t)
	prefix := []string{"private-native-entry"}
	var retained *nfqwsExecutionAssembly
	err := f.m.WithExecutionResources(f.ctx, f.p, "nfqws2", func(ctx context.Context) error {
		e, err := newNFQWSExecutionAssembly(ctx, a, command, spec, prefix, nfqwsExecutionRuntime{Runner: f.b.Runner, Tools: f.b.Tools, VerifyLAN: f.b.VerifyLAN, AdditionalReadback: f.b.AdditionalReadback})
		if err != nil {
			t.Fatal(err)
		}
		retained = e
		command.Args[1], command.Assets[0].SHA256, prefix[0] = "--qnum=1", strings.Repeat("5", 64), "foreign-entry"
		spec.Candidate.Traffic[0].First = 1
		if err := nfqwsExecutionCommandMatches(e.command, e.resource.Plan().Spec()); err != nil || e.prefix[0] != "private-native-entry" || e.command.Assets[0].SHA256 != strings.Repeat("1", 64) {
			t.Fatal("caller changed retained command/spec", err)
		}
		return nil // Deliberately no unused proof; this must retain a fence.
	})
	if err == nil || f.latest(t).Resources[0].Phase != "closed" {
		t.Fatal("unstarted assembly fabricated terminal resource", err)
	}
	if err := retained.current(context.Background(), retained.resource.Plan()); err == nil {
		t.Fatal("borrowed assembly survived issuer close")
	}
}

func TestNetworkPolicyManagerNFQWSAssemblyReadiness(t *testing.T) {
	for _, mode := range []string{"known-empty-to-owned", "foreign-queue", "missing-inventory", "foreign-capture", "unknown-child", "late-review", "cancel-in-probe", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			b, model, _ := nfqwsScopedBindingFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
			defer cancel()
			ownedProbes, emptyProbes, processProbes := 0, 0, 0
			process := b.ProcessRunning
			b.ProcessRunning = func(c context.Context, p *NFQWSScopedPlan) (NFQWSScopedProcessProof, error) {
				processProbes++
				if mode == "unknown-child" {
					return NFQWSScopedProcessProof{}, ErrNFQWSManagedProcessUnknown
				}
				return process(c, p)
			}
			b.QueueCheck = func(_ context.Context, _ string, _ uint16, child *components.NFQWSRuntimeProcessIdentity) error {
				if child != nil {
					ownedProbes++
					if mode == "cancel-in-probe" {
						cancel()
						return nil
					}
					if mode == "known-empty-to-owned" && ownedProbes >= 2 {
						return nil
					}
					return ErrNFQWSScopedOwner
				}
				emptyProbes++
				if mode == "foreign-queue" || mode == "missing-inventory" {
					return ErrNFQWSScopedQueueInventory
				}
				return nil
			}
			if mode == "foreign-capture" {
				model.foreign["ip6tables:raw"] = "-A FOREIGN -j NFQUEUE --queue-num 40321"
			}
			current := func(c context.Context, p *NFQWSScopedPlan) error {
				if p != model.p {
					return ErrNFQWSScopedOwner
				}
				if mode == "late-review" && emptyProbes > 0 {
					return ErrReviewChanged
				}
				return c.Err()
			}
			err := nfqwsExecutionAwaitQueue(ctx, b, model.p, current)
			if mode == "known-empty-to-owned" {
				if err != nil || ownedProbes != 2 || emptyProbes < 3 || model.lanReads == 0 {
					t.Fatal("known empty wait lost independent preflight", err, ownedProbes, emptyProbes)
				}
			} else if err == nil {
				t.Fatal("unknown or expired readiness became permission")
			}
			if len(model.calls) != 0 {
				t.Fatal("readiness wait wrote a kernel effect")
			}
			if (mode == "foreign-queue" || mode == "missing-inventory" || mode == "foreign-capture" || mode == "unknown-child") && processProbes != 1 {
				t.Fatal("unknown readiness was retried", processProbes)
			}
		})
	}
}

type nfqwsExecutionCanceledImpostor struct{}

func (nfqwsExecutionCanceledImpostor) Error() string        { return "unknown cancellation-like error" }
func (nfqwsExecutionCanceledImpostor) Is(target error) bool { return target == context.Canceled }

func TestNetworkPolicyManagerNFQWSAssemblyInternalStopDoesNotHideErrors(t *testing.T) {
	for _, err := range []error{context.Canceled, errors.Join(context.Canceled, context.Canceled), fmt.Errorf("internal stop: %w", context.Canceled)} {
		if !nfqwsExecutionOnlyCanceled(err, 0) {
			t.Fatal("pure internal cancellation refused", err)
		}
	}
	for _, err := range []error{nil, context.DeadlineExceeded, errors.Join(context.Canceled, ErrNFQWSManagedProcessUnknown),
		errors.Join(context.Canceled, ErrReviewChanged), nfqwsExecutionCanceledImpostor{}, errors.New("context canceled")} {
		if nfqwsExecutionOnlyCanceled(err, 0) {
			t.Fatal("unknown/late callback error hidden by cancellation", err)
		}
	}
}
