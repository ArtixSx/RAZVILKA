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
		issuer := ctx.Value(nfqwsExecutionRegistrarKey{}).(nfqwsExecutionRegistrar)
		reservations := 0
		ctx = context.WithValue(ctx, nfqwsExecutionRegistrarKey{}, nfqwsExecutionRegistrar(func(c context.Context, s NFQWSScopedSpec) (*NFQWSExecutionResource, error) {
			reservations++
			return issuer(c, s)
		}))
		for name, mutate := range map[string]func(*nfqws2ManagedProcessCommand, *NFQWSScopedSpec){
			"wrong queue":                   func(c *nfqws2ManagedProcessCommand, _ *NFQWSScopedSpec) { c.Args[1] = "--qnum=40322" },
			"duplicate queue":               func(c *nfqws2ManagedProcessCommand, _ *NFQWSScopedSpec) { c.Args = append(c.Args, c.Args[1]) },
			"noncanonical queue":            func(c *nfqws2ManagedProcessCommand, _ *NFQWSScopedSpec) { c.Args[1] = "--qnum=040321" },
			"split queue":                   func(c *nfqws2ManagedProcessCommand, _ *NFQWSScopedSpec) { c.Args[1] = "--qnum" },
			"no interception":               func(c *nfqws2ManagedProcessCommand, _ *NFQWSScopedSpec) { c.Args[0] = "--intercept=0" },
			"duplicate intercept":           func(c *nfqws2ManagedProcessCommand, _ *NFQWSScopedSpec) { c.Args = append(c.Args, c.Args[0]) },
			"daemon":                        func(c *nfqws2ManagedProcessCommand, _ *NFQWSScopedSpec) { c.Args = append(c.Args, "--daemon") },
			"single-dash queue":             func(c *nfqws2ManagedProcessCommand, _ *NFQWSScopedSpec) { c.Args = append(c.Args, "-qnum=40322") },
			"single-dash intercept":         func(c *nfqws2ManagedProcessCommand, _ *NFQWSScopedSpec) { c.Args = append(c.Args, "-intercept=0") },
			"single-dash daemon":            func(c *nfqws2ManagedProcessCommand, _ *NFQWSScopedSpec) { c.Args = append(c.Args, "-daemon") },
			"abbreviated queue":             func(c *nfqws2ManagedProcessCommand, _ *NFQWSScopedSpec) { c.Args = append(c.Args, "--q=40322") },
			"abbreviated intercept":         func(c *nfqws2ManagedProcessCommand, _ *NFQWSScopedSpec) { c.Args = append(c.Args, "--inter=0") },
			"abbreviated daemon":            func(c *nfqws2ManagedProcessCommand, _ *NFQWSScopedSpec) { c.Args = append(c.Args, "--daem") },
			"single-dash abbreviated queue": func(c *nfqws2ManagedProcessCommand, _ *NFQWSScopedSpec) { c.Args = append(c.Args, "-qn=40322") },
			"split abbreviated queue":       func(c *nfqws2ManagedProcessCommand, _ *NFQWSScopedSpec) { c.Args = append(c.Args, "--qn", "40322") },
			"first at config": func(c *nfqws2ManagedProcessCommand, _ *NFQWSScopedSpec) {
				c.Args = append([]string{"@/reviewed/nfqws.conf"}, c.Args...)
			},
			"first dollar config": func(c *nfqws2ManagedProcessCommand, _ *NFQWSScopedSpec) {
				c.Args = append([]string{"$/reviewed/nfqws.conf"}, c.Args...)
			},
			"later positional config": func(c *nfqws2ManagedProcessCommand, _ *NFQWSScopedSpec) {
				c.Args = append(c.Args, "@/reviewed/nfqws.conf")
			},
			"fuzz disables intercept": func(c *nfqws2ManagedProcessCommand, _ *NFQWSScopedSpec) { c.Args = append(c.Args, "--fuzz=1") },
			"abbreviated candidate":   func(c *nfqws2ManagedProcessCommand, _ *NFQWSScopedSpec) { c.Args[2] = "--filter-u=443" },
			"split candidate value": func(c *nfqws2ManagedProcessCommand, _ *NFQWSScopedSpec) {
				c.Args = append(c.Args[:2], "--filter-udp", "443")
			},
			"unknown global": func(c *nfqws2ManagedProcessCommand, _ *NFQWSScopedSpec) {
				c.Args = append(c.Args, "--future-runtime=1")
			},
			"end options":   func(c *nfqws2ManagedProcessCommand, _ *NFQWSScopedSpec) { c.Args = append([]string{"--"}, c.Args...) },
			"wrong session": func(_ *nfqws2ManagedProcessCommand, s *NFQWSScopedSpec) { s.SessionID = strings.Repeat("2", 32) },
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
		if reservations != 0 || len(f.latest(t).Resources) != 0 {
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

func TestNetworkPolicyManagerNFQWSAssemblyCanonicalManagedArguments(t *testing.T) {
	_, command, spec := nfqwsExecutionAssemblyCommand(t)
	command.Args = []string{"--qnum=40321", "--intercept=1",
		"--lua-init=@" + command.Assets[0].Path,
		"--blob=tls_clienthello:@" + command.Assets[0].Path,
		"--filter-tcp=443,80", "--filter-l7=http,tls", "--payload=tls_client_hello",
		"--lua-desync=circular:fails=2:time=300", "--lua-desync=fake:blob=tls_clienthello:repeats=11",
		"--new", "--filter-udp=443", "--filter-l7=quic", "--payload=quic_initial",
		"--lua-desync=fake:blob=0x00000000"}
	spec.CommandSHA256 = nfqws2ManagedCommandDigest(command)
	spec.Candidate.ArgumentsSHA256 = components.NFQWSRuntimeArgumentsSHA256(command.Program.Path, command.Args)
	if err := nfqwsExecutionCommandMatches(command, spec); err != nil {
		t.Fatal("canonical reviewed base/multi-profile managed candidate rejected", err)
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
			if mode == "unknown-child" && (!strings.Contains(err.Error(), "running process readback") || !errors.Is(err, ErrNFQWSManagedProcessUnknown)) {
				t.Fatal("process failure lost its stage or original cause", err)
			}
			if (mode == "foreign-queue" || mode == "missing-inventory") && (!strings.Contains(err.Error(), "owned queue readback") || !strings.Contains(err.Error(), "whole empty queue readback") || !errors.Is(err, ErrNFQWSScopedQueueInventory)) {
				t.Fatal("queue failures lost an independent stage or original cause", err)
			}
			if mode == "foreign-capture" && !strings.Contains(err.Error(), "empty queue LAN/capture preflight") {
				t.Fatal("preflight failure lost its stage", err)
			}
			if mode == "cancel-in-probe" && (!strings.Contains(err.Error(), "closing current after owned queue") || !errors.Is(err, context.Canceled)) {
				t.Fatal("post-probe cancellation lost its stage or original cause", err)
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
