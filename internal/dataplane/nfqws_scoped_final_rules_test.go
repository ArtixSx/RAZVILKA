package dataplane

import (
	"context"
	"errors"
	"testing"
)

func TestNFQWSScopedApplyFinalPrefixDoesNotSurviveClosingBackendCallback(t *testing.T) {
	for _, cut := range []string{"missing-peer-body", "future-copy", "foreign-queue", "backend-error", "cancel"} {
		t.Run(cut, func(t *testing.T) {
			b, m, root := nfqwsScopedBindingFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
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
			lan := b.VerifyLAN
			armed, fired, backendReads := false, false, 0
			b.VerifyLAN = func(c context.Context, p *LANPolicyRuntimePlan) error {
				if err := lan(c, p); err != nil {
					return err
				}
				if m.lanReads == 2+2*(attachment+1) {
					armed = true
				}
				return nil
			}
			b.AdditionalReadback = func(context.Context, *NFQWSScopedPlan) error {
				if armed && !fired {
					backendReads++
					if backendReads == 2 {
						fired = true
						switch cut {
						case "missing-peer-body":
							m.present[attachment-1] = 0
						case "future-copy":
							m.present[attachment+1] = 1
						case "foreign-queue":
							m.foreign["ip6tables:security"] = "-A FOREIGN -j NFQUEUE --queue-num 99\n"
						case "backend-error":
							return ErrNFQWSScopedOwner
						case "cancel":
							cancel()
						}
					}
				}
				return nil
			}
			if err := b.Apply(ctx, m.p, root); !errors.Is(err, ErrPolicyAdditionUnknown) || !fired || len(m.calls) != attachment || m.present[attachment] != 0 {
				t.Fatal("closing backend callback left an actual attachment grant", cut, err, fired, m.calls)
			}
		})
	}
}

func TestNFQWSScopedApplyCompleteDoesNotSurviveClosingBackendCallback(t *testing.T) {
	for _, cut := range []string{"missing-body", "duplicate-body", "foreign-queue", "backend-error"} {
		t.Run(cut, func(t *testing.T) {
			b, m, root := nfqwsScopedBindingFixture(t)
			guard := b.ApplyGuard
			armed, fired, backendReads := false, false, 0
			b.ApplyGuard = func(c context.Context, p *NFQWSScopedPlan, e PolicyEffect) error {
				if err := guard(c, p, e); err != nil {
					return err
				}
				complete := true
				for i := range p.mixed.Effects {
					complete = complete && m.present[i] == 1
				}
				armed = complete
				return nil
			}
			b.AdditionalReadback = func(context.Context, *NFQWSScopedPlan) error {
				if armed && !fired {
					backendReads++
					if backendReads == 4 { // Last backend callback after closing LAN.
						fired = true
						switch cut {
						case "missing-body":
							m.present[1] = 0
						case "duplicate-body":
							m.present[1] = 2
						case "foreign-queue":
							m.foreign["iptables:raw"] = "-A FOREIGN -j NFQUEUE --queue-num 99\n"
						case "backend-error":
							return ErrNFQWSScopedOwner
						}
					}
				}
				return nil
			}
			if err := b.Apply(context.Background(), m.p, root); !errors.Is(err, ErrNFQWSScopedOwner) || !fired || len(m.calls) != len(m.p.mixed.Effects) {
				t.Fatal("closing backend callback returned false COMPLETE", cut, err, fired, m.calls)
			}
		})
	}
}
