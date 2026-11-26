package dataplane

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/components"
)

func nfqwsScopedRemoveFixture(t *testing.T) (*NFQWSScopedBinding, *nfqwsScopedModel, string) {
	t.Helper()
	b, m, root := nfqwsScopedBindingFixture(t)
	if err := b.Apply(context.Background(), m.p, root); err != nil {
		t.Fatal(err)
	}
	m.running, m.stopped = false, true
	return b, m, root
}

func TestNFQWSScopedRemoveBoundedScanCounts(t *testing.T) {
	b, m, root := nfqwsScopedRemoveFixture(t)
	reads, processReads, additional, guards := 0, 0, 0, 0
	b.Runner = networkCleanupRunner(func(c context.Context, command string, args ...string) ([]byte, error) {
		if len(args) == 3 && args[0] == "-t" && args[2] == "-S" {
			reads++
		}
		return m.Run(c, command, args...)
	})
	process, guard := b.ProcessInactive, b.CleanupGuard
	b.ProcessInactive = func(c context.Context, p *NFQWSScopedPlan) (NFQWSScopedProcessProof, error) {
		processReads++
		return process(c, p)
	}
	b.CleanupGuard = func(c context.Context, p *NFQWSScopedPlan, e PolicyEffect) error {
		guards++
		return guard(c, p, e)
	}
	b.AdditionalReadback = func(context.Context, *NFQWSScopedPlan) error { additional++; return nil }
	m.queueChecks, m.lanReads = 0, 0
	before := len(m.calls)
	if err := b.Remove(context.Background(), m.p, root); err != nil {
		t.Fatal(err)
	}
	n := len(m.p.mixed.Effects)
	// Includes the unchanged three full scans inside final VerifyInactive.
	// The runner discards images before closing process/backend callbacks.
	if reads != 10*(7*n+4)+n || additional != 2*(6*n+4) || processReads != 8*n+18 || m.queueChecks != 4*n+9 || guards != 5*n+4 || m.lanReads != 0 || len(m.calls)-before != n {
		t.Fatal("missing proof or redundant full cleanup scans", reads, additional, processReads, m.queueChecks, guards, m.lanReads, len(m.calls)-before, n)
	}
	status, err := b.Inspect(context.Background(), m.p, root)
	if err != nil || !status.Removed || status.Unknown || status.Cleaned != n {
		t.Fatal("common receipt did not finish", status, err)
	}
	for j, call := range m.calls[before:] {
		if call.add || call.index != n-1-j {
			t.Fatal("actual delete order changed", m.calls[before:])
		}
	}
}

func TestNFQWSScopedRemoveLateFullNamespaceConflictBeforeRPC(t *testing.T) {
	for _, tool := range []string{"iptables", "ip6tables"} {
		for _, table := range []string{"raw", "mangle", "nat", "filter", "security"} {
			t.Run(tool+"/"+table, func(t *testing.T) {
				b, m, root := nfqwsScopedRemoveFixture(t)
				guard := b.CleanupGuard
				afterIntent, guards, fired := false, 0, false
				last := len(m.p.mixed.Effects) - 1
				b.options.fault = func(point string, index int) error {
					if point == "cleanup-intent" && index == last {
						afterIntent = true
					}
					return nil
				}
				b.CleanupGuard = func(c context.Context, p *NFQWSScopedPlan, e PolicyEffect) error {
					if err := guard(c, p, e); err != nil {
						return err
					}
					if afterIntent {
						guards++
						if guards == 2 { // After BeforeDelete + full ExactPresence.
							fired = true
							m.foreign[tool+":"+table] = "-A FOREIGN -j NFQUEUE --queue-num 99\n"
						}
					}
					return nil
				}
				before := len(m.calls)
				if err := b.Remove(context.Background(), m.p, root); !errors.Is(err, ErrPolicyAdditionUnknown) || !fired || len(m.calls) != before {
					t.Fatal("late foreign capture reached actual Delete", err, fired, m.calls[before:])
				}
			})
		}
	}
}

func TestNFQWSScopedRemovePrefixDoesNotSurviveClosingProcessCallback(t *testing.T) {
	for _, cut := range []string{"missing-earlier-ACK", "reinserted-later-copy", "foreign-reference", "nonempty-last-chain"} {
		t.Run(cut, func(t *testing.T) {
			b, m, root := nfqwsScopedRemoveFixture(t)
			// A bare IPv6 declaration has a valid earlier IPv4 body prefix.
			target := 1 + len(m.p.chains[0].body)
			if cut == "reinserted-later-copy" {
				target-- // Later IPv6 declaration was already removed.
			}
			if cut == "foreign-reference" || cut == "nonempty-last-chain" {
				target = 0
			}
			afterIntent, processCalls, fired := false, 0, false
			b.options.fault = func(point string, index int) error {
				if point == "cleanup-intent" && index == target {
					afterIntent = true
				}
				return nil
			}
			process := b.ProcessInactive
			b.ProcessInactive = func(c context.Context, p *NFQWSScopedPlan) (NFQWSScopedProcessProof, error) {
				proof, err := process(c, p)
				if afterIntent {
					processCalls++
					if processCalls == 8 { // Closing callback inside actual wrapper.
						fired = true
						switch cut {
						case "missing-earlier-ACK":
							m.present[target-1] = 0
						case "reinserted-later-copy":
							m.present[target+1] = 1
						case "foreign-reference":
							m.foreign["ip6tables:security"] = "-A FOREIGN -g " + m.p.chains[0].name + "\n"
						case "nonempty-last-chain":
							m.present[1] = 1
						}
					}
				}
				return proof, err // Nominal successful inactive/ACK evidence.
			}
			before := len(m.calls)
			if err := b.Remove(context.Background(), m.p, root); !errors.Is(err, ErrPolicyAdditionUnknown) || !fired || len(m.calls)-before != len(m.p.mixed.Effects)-1-target {
				t.Fatal("closing process callback left a stale Delete grant", cut, err, fired, m.calls[before:])
			}
			status, err := b.Inspect(context.Background(), m.p, root)
			if err != nil || !status.Unknown || status.Pending != 1 || status.Removed {
				t.Fatal("reverse-prefix refusal fabricated removal", status, err)
			}
		})
	}
}

func TestNFQWSScopedRemovePrefixDoesNotSurviveClosingBackendCallback(t *testing.T) {
	for _, cut := range []string{"missing-earlier-ACK", "reinserted-later-copy", "last-chain-reference", "last-chain-body", "backend-error", "cancel"} {
		t.Run(cut, func(t *testing.T) {
			b, m, root := nfqwsScopedRemoveFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			target := 1 + len(m.p.chains[0].body)
			if cut == "reinserted-later-copy" {
				target--
			}
			if strings.HasPrefix(cut, "last-chain") {
				target = 0
			}
			afterIntent, guards, armed, backendReads, fired := false, 0, false, 0, false
			b.options.fault = func(point string, index int) error {
				if point == "cleanup-intent" && index == target {
					afterIntent = true
				}
				return nil
			}
			guard := b.CleanupGuard
			b.CleanupGuard = func(c context.Context, p *NFQWSScopedPlan, e PolicyEffect) error {
				if err := guard(c, p, e); err != nil {
					return err
				}
				if afterIntent {
					guards++
					if guards == 3 { // Original Guard inside exact Delete wrapper.
						armed = true
					}
				}
				return nil
			}
			b.AdditionalReadback = func(context.Context, *NFQWSScopedPlan) error {
				if armed && !fired {
					backendReads++
					if backendReads == 4 { // Closing callback of final whole bracket.
						fired = true
						switch cut {
						case "missing-earlier-ACK":
							m.present[target-1] = 0
						case "reinserted-later-copy":
							m.present[target+1] = 1
						case "last-chain-reference":
							m.foreign["ip6tables:raw"] = "-A FOREIGN -j " + m.p.chains[0].name + "\n"
						case "last-chain-body":
							m.present[1] = 1
						case "backend-error":
							return ErrNFQWSScopedOwner
						case "cancel":
							cancel()
						}
					}
				}
				return nil
			}
			before := len(m.calls)
			if err := b.Remove(ctx, m.p, root); !errors.Is(err, ErrPolicyAdditionUnknown) || !fired || len(m.calls)-before != len(m.p.mixed.Effects)-1-target {
				t.Fatal("closing backend callback left an actual Delete grant", cut, err, fired, m.calls[before:])
			}
		})
	}
}

func TestNFQWSScopedRemoveFreshAuthorityAndInactiveEvidence(t *testing.T) {
	for _, cut := range []string{"guard-after-intent", "guard-before-RPC", "guard-in-wrapper", "live-child", "unACKed-ECHILD", "foreign-queue", "changed-child", "cancel"} {
		t.Run(cut, func(t *testing.T) {
			b, m, root := nfqwsScopedRemoveFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			last, afterIntent, guards, fired := len(m.p.mixed.Effects)-1, false, 0, false
			b.options.fault = func(point string, index int) error {
				if point == "cleanup-intent" && index == last {
					afterIntent = true
				}
				return nil
			}
			guard := b.CleanupGuard
			b.CleanupGuard = func(c context.Context, p *NFQWSScopedPlan, e PolicyEffect) error {
				if err := guard(c, p, e); err != nil {
					return err
				}
				if !afterIntent {
					return nil
				}
				guards++
				at := 3
				if cut == "guard-after-intent" {
					at = 1
				} else if cut == "guard-before-RPC" {
					at = 2
				}
				if guards != at {
					return nil
				}
				fired = true
				switch cut {
				case "guard-after-intent", "guard-before-RPC", "guard-in-wrapper":
					return ErrReviewChanged
				case "live-child":
					m.running = true
				case "unACKed-ECHILD":
					m.unknownACK = true
				case "foreign-queue":
					m.foreignQueue = true
				case "changed-child":
					// The proof changes between the two-sided Queue observation.
					queue := b.QueueCheck
					b.QueueCheck = func(c context.Context, ns string, q uint16, child *components.NFQWSRuntimeProcessIdentity) error {
						err := queue(c, ns, q, child)
						m.changedChild = true
						return err
					}
				case "cancel":
					cancel()
				}
				return nil
			}
			before := len(m.calls)
			if err := b.Remove(ctx, m.p, root); !errors.Is(err, ErrPolicyAdditionUnknown) || !fired || len(m.calls) != before {
				t.Fatal("late authority/process refusal reached Delete", cut, err, fired, m.calls[before:])
			}
		})
	}
}

func TestNFQWSScopedRemovePostRPCUnknownKeepsIntent(t *testing.T) {
	for _, cut := range []string{"still-present", "duplicate", "unknown-row", "malformed-row", "read-error", "cancel", "actual-error-after-write", "foreign-after-post"} {
		t.Run(cut, func(t *testing.T) {
			b, m, root := nfqwsScopedRemoveFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			last, mutated := len(m.p.mixed.Effects)-1, false
			b.Runner = networkCleanupRunner(func(c context.Context, command string, args ...string) ([]byte, error) {
				out, err := m.Run(c, command, args...)
				if command == string(m.p.mixed.Effects[last].Tool) && slices.Equal(args, m.p.mixed.Effects[last].Delete) {
					mutated = true
					switch cut {
					case "still-present":
						m.present[last] = 1
					case "duplicate":
						m.present[last] = 2
					case "cancel":
						cancel()
					case "actual-error-after-write":
						return nil, errors.New("actual Delete failed after mutation")
					}
				}
				if mutated && len(args) == 3 && args[1] == "mangle" && args[2] == "-S" {
					switch cut {
					case "unknown-row":
						return append(out, []byte("-A FOREIGN -j NFQUEUE --queue-num 99\n")...), nil
					case "malformed-row":
						return []byte("-A\n"), nil
					case "read-error":
						return nil, errors.New("post-Delete table unreadable")
					}
				}
				return out, err
			})
			b.options.fault = func(point string, index int) error {
				if cut == "foreign-after-post" && point == "delete" && index == last {
					m.foreign["iptables:raw"] = "-A FOREIGN -j NFQUEUE --queue-num 99\n"
				}
				return nil
			}
			before := len(m.calls)
			err := b.Remove(ctx, m.p, root)
			status, inspectErr := b.Inspect(context.Background(), m.p, root)
			if !errors.Is(err, ErrPolicyAdditionUnknown) || !mutated || len(m.calls)-before != 1 || inspectErr != nil || !status.Unknown || status.Pending != 1 || status.Cleaned != 0 || status.Removed {
				t.Fatal("uncertain Delete became removed", cut, err, status, inspectErr, m.calls[before:])
			}
			before = len(m.calls)
			if err := b.Remove(context.Background(), m.p, root); err == nil || len(m.calls) != before {
				t.Fatal("unknown result granted another Delete", cut, err, m.calls[before:])
			}
		})
	}
}

func TestNFQWSScopedRemoveAbsentTargetSettlementRemainsFull(t *testing.T) {
	for _, cut := range []string{"absent-attachment", "absent-last-chain-with-reference", "absent-last-chain-with-body"} {
		t.Run(cut, func(t *testing.T) {
			b, m, root := nfqwsScopedRemoveFixture(t)
			target := 0
			if cut == "absent-attachment" {
				target = len(m.p.mixed.Effects) - 1
			}
			fired := false
			b.options.fault = func(point string, index int) error {
				if point == "cleanup-intent" && index == target {
					fired = true
					m.present[target] = 0
					if cut == "absent-last-chain-with-reference" {
						m.foreign["ip6tables:nat"] = "-A FOREIGN -j " + m.p.chains[0].name + "\n"
					} else if cut == "absent-last-chain-with-body" {
						m.present[1] = 1
					}
				}
				return nil
			}
			before := len(m.calls)
			err := b.Remove(context.Background(), m.p, root)
			status, inspectErr := b.Inspect(context.Background(), m.p, root)
			if !fired || inspectErr != nil {
				t.Fatal("absent cut did not run", fired, inspectErr)
			}
			if cut == "absent-attachment" {
				if err != nil || !status.Removed || status.Unknown || len(m.calls)-before != len(m.p.mixed.Effects)-1 {
					t.Fatal("strict absent settlement was lost", err, status, m.calls[before:])
				}
			} else if !errors.Is(err, ErrPolicyAdditionUnknown) || !status.Unknown || status.Removed || status.Pending != 1 {
				t.Fatal("absent chain hid live references/body", err, status)
			}
			for _, call := range m.calls[before:] {
				if call.index == target {
					t.Fatal("absent tuple issued an actual Delete", call)
				}
			}
		})
	}
}

func TestNFQWSScopedRemoveWrapperRejectsWrongOrAmbiguousCommand(t *testing.T) {
	b, m, _ := nfqwsScopedBindingFixture(t)
	runtime, plan, err := b.prepare(m.p, true)
	if err != nil {
		t.Fatal(err)
	}
	r := nfqwsScopedRemoveRunner{base: runtime.Runner, binding: b, scoped: m.p, plan: plan, tools: runtime.Tools, guard: runtime.Guard}
	for _, args := range [][]string{plan.Effects[0].Add, {"-t", "mangle", "-X", "FOREIGN"}} {
		if _, err := r.Run(context.Background(), "iptables", args...); err == nil {
			t.Fatal("wrong command reached actual runner", args)
		}
	}
	if _, err := r.Run(context.Background(), "foreign-tool", plan.Effects[0].Delete...); err == nil {
		t.Fatal("foreign tool reached actual runner")
	}
	r.plan.Effects = append(slices.Clone(plan.Effects), plan.Effects[0])
	if _, err := r.Run(context.Background(), "iptables", plan.Effects[0].Delete...); err == nil || len(m.calls) != 0 {
		t.Fatal("ambiguous compiler Delete reached actual runner", err, m.calls)
	}
	if strings.Contains(strings.Join(plan.Effects[0].Delete, " "), "FOREIGN") {
		t.Fatal("refusal changed frozen command")
	}
}
