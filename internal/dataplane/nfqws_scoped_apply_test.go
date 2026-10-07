package dataplane

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestNFQWSScopedApplyBoundedScanCounts(t *testing.T) {
	b, m, root := nfqwsScopedBindingFixture(t)
	reads, processReads, additional := 0, 0, 0
	b.Runner = networkCleanupRunner(func(c context.Context, command string, args ...string) ([]byte, error) {
		if len(args) == 3 && args[0] == "-t" && args[2] == "-S" {
			reads++
		}
		return m.Run(c, command, args...)
	})
	process := b.ProcessRunning
	b.ProcessRunning = func(c context.Context, p *NFQWSScopedPlan) (NFQWSScopedProcessProof, error) {
		processReads++
		return process(c, p)
	}
	b.AdditionalReadback = func(context.Context, *NFQWSScopedPlan) error { additional++; return nil }
	if err := b.Apply(context.Background(), m.p, root); err != nil {
		t.Fatal(err)
	}
	n := len(m.p.mixed.Effects)
	// Direct model reads exclude the separate production LAN collector and
	// its ConsumerCheck. No production observer has been stubbed by this path.
	if reads != 10*(4*n+2)+n || additional != 2*(4*n+2) || m.lanReads != 2*(n+2) || processReads != 4*(n+2) || len(m.calls) != n {
		t.Fatal("duplicate full scans or missing actual proof", reads, additional, m.lanReads, processReads, len(m.calls), n)
	}
	status, err := b.Inspect(context.Background(), m.p, root)
	if err != nil || !status.Complete || status.Unknown || status.Added != n {
		t.Fatal("ordinary common receipt did not finish", status, err)
	}
}

func TestNFQWSScopedApplyPrefixDoesNotSurviveClosingLANCallback(t *testing.T) {
	for _, cut := range []string{"missing-peer-body", "future-copy", "foreign-queue"} {
		t.Run(cut, func(t *testing.T) {
			b, m, root := nfqwsScopedBindingFixture(t)
			lan := b.VerifyLAN
			fired := false
			attachment := -1
			for i, e := range m.p.mixed.Effects {
				if e.Add[2] == "-A" && e.Add[3] == "FORWARD" {
					attachment = i
					break
				}
			}
			if attachment < 1 || attachment+1 >= len(m.p.mixed.Effects) {
				t.Fatal("fixture has no paired attachment boundary")
			}
			b.VerifyLAN = func(c context.Context, p *LANPolicyRuntimePlan) error {
				if err := lan(c, p); err != nil {
					return err
				}
				// Preflight uses two calls; each mutation proof uses two more.
				if m.lanReads == 2+2*(attachment+1) {
					fired = true
					switch cut {
					case "missing-peer-body":
						m.present[attachment-1] = 0
					case "future-copy":
						m.present[attachment+1] = 1
					case "foreign-queue":
						m.foreign["ip6tables:raw"] = "-A FOREIGN -j NFQUEUE --queue-num 99\n"
					}
				}
				return nil
			}
			err := b.Apply(context.Background(), m.p, root)
			if !errors.Is(err, ErrPolicyAdditionUnknown) || !fired || len(m.calls) != attachment {
				t.Fatal("closing callback left a stale attachment grant", cut, err, fired, m.calls)
			}
			if m.present[attachment] != 0 {
				t.Fatal("attachment reached actual runner without both peer bodies")
			}
		})
	}
}

func TestNFQWSScopedApplyFinalGuardCannotInvalidateCompleteProof(t *testing.T) {
	for _, cut := range []string{"missing-body", "duplicate-body", "foreign-IPv4", "foreign-IPv6"} {
		t.Run(cut, func(t *testing.T) {
			b, m, root := nfqwsScopedBindingFixture(t)
			guard := b.ApplyGuard
			fired := false
			b.ApplyGuard = func(c context.Context, p *NFQWSScopedPlan, e PolicyEffect) error {
				if err := guard(c, p, e); err != nil {
					return err
				}
				complete := true
				for i := range p.mixed.Effects {
					complete = complete && m.present[i] == 1
				}
				if complete && !fired {
					fired = true // Last external Guard returns nominal success.
					switch cut {
					case "missing-body":
						m.present[1] = 0
					case "duplicate-body":
						m.present[1] = 2
					case "foreign-IPv4":
						m.foreign["iptables:raw"] = "-A FOREIGN -j NFQUEUE --queue-num 99\n"
					case "foreign-IPv6":
						m.foreign["ip6tables:security"] = "-A FOREIGN -j NFQUEUE --queue-num 99\n"
					}
				}
				return nil
			}
			if err := b.Apply(context.Background(), m.p, root); !errors.Is(err, ErrNFQWSScopedOwner) || !fired || len(m.calls) != len(m.p.mixed.Effects) {
				t.Fatal("closing guard drift returned false final success", cut, err, fired, m.calls)
			}
		})
	}
}

func TestNFQWSScopedApplyLateFullNamespaceConflictBeforeRPC(t *testing.T) {
	for _, tool := range []string{"iptables", "ip6tables"} {
		for _, table := range []string{"raw", "mangle", "nat", "filter", "security"} {
			t.Run(tool+"/"+table, func(t *testing.T) {
				b, m, root := nfqwsScopedBindingFixture(t)
				guard := b.ApplyGuard
				afterIntent, guards, fired := false, 0, false
				b.options.fault = func(point string, index int) error {
					if point == "intent" && index == 0 {
						afterIntent = true
					}
					return nil
				}
				b.ApplyGuard = func(c context.Context, p *NFQWSScopedPlan, e PolicyEffect) error {
					if err := guard(c, p, e); err != nil {
						return err
					}
					if afterIntent {
						guards++
						if guards == 2 {
							// Both ExactPresence reads were clear. The final
							// common Guard changes the other family/table.
							fired = true
							m.foreign[tool+":"+table] = "-A FOREIGN -j NFQUEUE --queue-num 99\n"
						}
					}
					return nil
				}
				err := b.Apply(context.Background(), m.p, root)
				status, inspectErr := b.Inspect(context.Background(), m.p, root)
				if !errors.Is(err, ErrPolicyAdditionUnknown) || !fired || len(m.calls) != 0 || inspectErr != nil || !status.Unknown || status.Pending != 1 {
					t.Fatal("late foreign namespace reached RPC or lost intent", err, status, inspectErr, fired, m.calls)
				}
			})
		}
	}
}

func TestNFQWSScopedApplyExactPrefixRefusesMissingACKAndFutureCopy(t *testing.T) {
	for _, cut := range []string{"missing-prior-ACK", "future-exact-copy"} {
		t.Run(cut, func(t *testing.T) {
			b, m, root := nfqwsScopedBindingFixture(t)
			fired := false
			b.options.fault = func(point string, index int) error {
				if point == "intent" && index == 1 {
					fired = true
					if cut == "missing-prior-ACK" {
						m.present[0] = 0
					} else {
						m.present[1+len(m.p.chains[0].body)] = 1 // A later declaration is a valid partial shape.
					}
				}
				return nil
			}
			if err := b.Apply(context.Background(), m.p, root); !errors.Is(err, ErrPolicyAdditionUnknown) || !fired || len(m.calls) != 1 {
				t.Fatal("valid partial shape replaced exact receipt prefix", cut, err, fired, m.calls)
			}
			status, err := b.Inspect(context.Background(), m.p, root)
			if err != nil || !status.Unknown || status.Added != 1 || status.Pending != 1 {
				t.Fatal("prefix refusal fabricated ACK or unused grant", status, err)
			}
		})
	}
}

func TestNFQWSScopedApplyPostRPCUnknownKeepsIntent(t *testing.T) {
	for _, cut := range []string{"absent", "duplicate", "unknown-row", "read-error", "cancel", "actual-error-after-write"} {
		t.Run(cut, func(t *testing.T) {
			b, m, root := nfqwsScopedBindingFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			mutated := false
			b.Runner = networkCleanupRunner(func(c context.Context, command string, args ...string) ([]byte, error) {
				out, err := m.Run(c, command, args...)
				if command == string(m.p.mixed.Effects[0].Tool) && slices.Equal(args, m.p.mixed.Effects[0].Add) {
					mutated = true
					switch cut {
					case "absent":
						m.present[0] = 0
					case "duplicate":
						m.present[0] = 2
					case "cancel":
						cancel()
					case "actual-error-after-write":
						return nil, errors.New("actual RPC failed after mutation")
					}
				}
				if mutated && len(args) == 3 && args[1] == "mangle" && args[2] == "-S" {
					if cut == "unknown-row" {
						return append(out, []byte("-A FOREIGN -j NFQUEUE --queue-num 99\n")...), nil
					}
					if cut == "read-error" {
						return nil, errors.New("post-RPC table unreadable")
					}
				}
				return out, err
			})
			err := b.Apply(ctx, m.p, root)
			status, inspectErr := b.Inspect(context.Background(), m.p, root)
			if !errors.Is(err, ErrPolicyAdditionUnknown) || !mutated || len(m.calls) != 1 || inspectErr != nil || !status.Unknown || status.Added != 0 || status.Pending != 1 {
				t.Fatal("post-RPC unknown became an ACK", cut, err, status, inspectErr, m.calls)
			}
			m.running = false
			before := len(m.calls)
			if err := b.Remove(context.Background(), m.p, root); err == nil || len(m.calls) != before {
				t.Fatal("unknown post-RPC result granted cleanup", cut, err, m.calls)
			}
		})
	}
}

func TestNFQWSScopedApplyWrapperRejectsWrongOrAmbiguousCommand(t *testing.T) {
	b, m, _ := nfqwsScopedBindingFixture(t)
	runtime, plan, err := b.prepare(m.p, false)
	if err != nil {
		t.Fatal(err)
	}
	r := nfqwsScopedApplyRunner{base: runtime.Runner, binding: b, scoped: m.p, plan: plan, tools: runtime.Tools, guard: runtime.Guard}
	for _, args := range [][]string{plan.Effects[0].Delete, {"-t", "mangle", "-N", "FOREIGN"}} {
		if _, err := r.Run(context.Background(), "iptables", args...); err == nil {
			t.Fatal("wrong command reached actual runner", args)
		}
	}
	if _, err := r.Run(context.Background(), "foreign-tool", plan.Effects[0].Add...); err == nil {
		t.Fatal("foreign tool reached actual runner")
	}
	r.plan.Effects = append(slices.Clone(plan.Effects), plan.Effects[0])
	if _, err := r.Run(context.Background(), "iptables", plan.Effects[0].Add...); err == nil || len(m.calls) != 0 {
		t.Fatal("ambiguous compiler command reached actual runner", err, m.calls)
	}
	if strings.Contains(strings.Join(plan.Effects[0].Add, " "), "FOREIGN") {
		t.Fatal("refusal changed frozen command")
	}
}
