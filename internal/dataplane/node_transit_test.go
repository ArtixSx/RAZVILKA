package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

type nodeTransitTestRunner struct {
	spec                      NodeTransitSpec
	rules                     map[int][]string
	readErrors                map[int]error
	beforeRead                func(context.Context, int) error
	calls                     []string
	adds, deletes             int
	addErr                    error
	loseAddACK, loseDeleteACK bool
	route                     string
}

func (r *nodeTransitTestRunner) line() string {
	return fmt.Sprintf("%d: from %s to %s oif %s lookup %d", r.spec.Priority, r.spec.Source, r.spec.Destination, r.spec.Interface, r.spec.Table)
}

func (r *nodeTransitTestRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	if name != "ip" {
		return nil, errors.New("unexpected transit binary")
	}
	if reflect.DeepEqual(args, []string{"-N", "rule", "show"}) || reflect.DeepEqual(args, []string{"-N", "-6", "rule", "show"}) {
		family := 4
		if len(args) == 4 {
			family = 6
		}
		if r.beforeRead != nil {
			if err := r.beforeRead(ctx, family); err != nil {
				return nil, err
			}
		}
		if err := r.readErrors[family]; err != nil {
			return nil, err
		}
		return []byte("0: from all lookup 255\n32766: from all lookup 254\n32767: from all lookup 253\n" + strings.Join(r.rules[family], "\n") + "\n"), nil
	}
	if reflect.DeepEqual(args, []string{"-N", "-4", "route", "get", r.spec.Destination.String(), "from", r.spec.Source.String(), "oif", r.spec.Interface}) {
		return []byte(r.route), nil
	}
	if len(args) != 13 || args[0] != "-4" || args[1] != "rule" || args[3] != "priority" || args[4] != strconv.Itoa(r.spec.Priority) ||
		args[5] != "from" || args[6] != r.spec.Source.String()+"/32" || args[7] != "to" || args[8] != r.spec.Destination.String()+"/32" || args[9] != "oif" || args[10] != r.spec.Interface || args[11] != "lookup" || args[12] != strconv.Itoa(r.spec.Table) {
		return nil, errors.New("unexpected full transit mutation")
	}
	switch args[2] {
	case "add":
		r.adds++
		if r.addErr != nil {
			return nil, r.addErr
		}
		r.rules[4] = append(r.rules[4], r.line())
		if r.loseAddACK {
			return nil, errors.New("lost actual add acknowledgement")
		}
		return nil, nil
	case "del":
		for i, line := range r.rules[4] {
			if line == r.line() {
				r.deletes++
				r.rules[4] = append(r.rules[4][:i], r.rules[4][i+1:]...)
				if r.loseDeleteACK {
					return nil, errors.New("lost actual delete acknowledgement")
				}
				return nil, nil
			}
		}
		return nil, errors.New("exact transit selector absent")
	}
	return nil, errors.New("unexpected transit mutation action")
}

type nodeTransitAuthority struct {
	spec                                           NodeTransitSpec
	root, boot                                     string
	iface                                          net.Interface
	source                                         netip.Addr
	guardErr, preflightErr, deleteErr, registerErr error
	registrations                                  int
	firstRegisteredBeforeReceipt                   bool
}

func nodeTransitFixtureSpec() NodeTransitSpec {
	var owner NodeTransitOwnershipSpec
	for _, candidate := range NodeTransitOwnershipSpecs() {
		if candidate.Engine == "xray" {
			owner = candidate
		}
	}
	return NodeTransitSpec{Schema: 1, Engine: owner.Engine, BootID: "00000000-0000-0000-0000-000000000001", PlanID: "dp-0123456789abcdef", PlanDigest: strings.Repeat("a", 64),
		NetworkProfile: "wan-0123456789ab", RuntimeID: strings.Repeat("b", 64), PolicyGeneration: strings.Repeat("c", 32), Interface: owner.Interface, IfIndex: 77,
		Source: netip.MustParseAddr("172.31.22.1"), Destination: netip.MustParseAddr("1.1.1.1"), Table: owner.Table, Priority: owner.Priority}
}

// The fixture does no networking. Its inventory is explicitly local test data,
// while the stateful command runner records only real compiler-shaped intent.
func nodeTransitFixture(t *testing.T) (*nodeTransitLease, *nodeTransitTestRunner, *nodeTransitAuthority) {
	t.Helper()
	spec := nodeTransitFixtureSpec()
	a := &nodeTransitAuthority{spec: spec, root: privateScopedXrayFixtureDir(t), boot: spec.BootID, source: spec.Source,
		iface: net.Interface{Name: spec.Interface, Index: spec.IfIndex, Flags: net.FlagUp}}
	runner := &nodeTransitTestRunner{spec: spec, rules: map[int][]string{}, readErrors: map[int]error{}, route: fmt.Sprintf("%s from %s dev %s table %d uid 0\n    cache\n", spec.Destination, spec.Source, spec.Interface, spec.Table)}
	runtime := nodeTransitRuntime{runner: runner, ip: "ip",
		guard: func(ctx context.Context, got NodeTransitSpec) error {
			if got != a.spec {
				return ErrReviewChanged
			}
			return errors.Join(a.guardErr, ctx.Err())
		},
		preflight:    func(context.Context, NodeTransitSpec) error { return a.preflightErr },
		beforeDelete: func(context.Context, NodeTransitSpec) error { return a.deleteErr },
		register: func(ctx context.Context, got NodeTransitSpec, root, digest string) error {
			if got != a.spec || root != a.root || digest != mustNodeTransitDigest(t, got) {
				return errors.New("registration changed frozen resource intent")
			}
			a.registrations++
			if a.registrations == 1 {
				_, err := os.Stat(filepath.Join(root, policyAdditionFile))
				_, lockErr := os.Stat(filepath.Join(root, policyAdditionLock))
				a.firstRegisteredBeforeReceipt = errors.Is(err, os.ErrNotExist) && errors.Is(lockErr, os.ErrNotExist)
			}
			// Callback receives a value and cannot rewrite the lease or commands.
			got.Source = netip.MustParseAddr("172.31.22.2")
			return errors.Join(a.registerErr, ctx.Err())
		},
	}
	options := nodeTransitOptions{boot: func() (string, error) { return a.boot, nil },
		interfaces: func() ([]net.Interface, error) { return []net.Interface{a.iface}, nil },
		addresses: func(net.Interface) ([]net.Addr, error) {
			return []net.Addr{&net.IPNet{IP: net.IP(a.source.AsSlice()), Mask: net.CIDRMask(30, 32)}}, nil
		},
	}
	lease, err := newNodeTransitLeaseWithOptions(spec, a.root, runtime, options)
	if err != nil {
		t.Fatal(err)
	}
	return lease, runner, a
}

func mustNodeTransitDigest(t *testing.T, spec NodeTransitSpec) string {
	t.Helper()
	digest, err := nodeTransitSpecDigest(spec)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func TestNodeTransitLeaseRegistersBeforeEffectsAndUsesExistingReceipt(t *testing.T) {
	l, runner, authority := nodeTransitFixture(t)
	ctx := context.Background()
	if err := l.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	if !authority.firstRegisteredBeforeReceipt || authority.registrations != 1 || runner.adds != 1 || len(runner.rules[4]) != 1 {
		t.Fatal("unregistered or unacknowledged transit applied", authority, runner)
	}
	status, err := l.Inspect(ctx)
	if err != nil || !status.Complete || status.Unknown || status.Added != 1 {
		t.Fatal("exact addition was not durably acknowledged", status, err)
	}
	if err := l.VerifyRoute(ctx); err != nil {
		t.Fatal(err)
	}
	if err := l.Remove(ctx); err != nil || runner.deletes != 1 || len(runner.rules[4]) != 0 {
		t.Fatal("exact transit cleanup failed", err, runner)
	}
	status, err = l.Inspect(ctx)
	if err != nil || !status.Removed || status.Unknown || authority.registrations != 2 {
		t.Fatal("cleanup was not durably settled", status, err)
	}
	if err := l.Apply(ctx); !errors.Is(err, ErrPolicyAdditionExists) || isNodeTransitBeforeEffects(err) || runner.adds != 1 {
		t.Fatal("old generation was replayed", err)
	}
	if authority.registrations != 2 {
		t.Fatal("old generation replay registered a new resource")
	}
}

func TestNodeTransitLeasePreexistingForeignDuplicateAndUnknownSlotsNeverAdopt(t *testing.T) {
	for _, kind := range []string{"exact-copy", "duplicate", "foreign-source", "foreign-oif", "foreign-table", "table-alias", "unknown-selector", "IPv6-slot", "read4-error", "read6-error"} {
		t.Run(kind, func(t *testing.T) {
			l, runner, _ := nodeTransitFixture(t)
			line := runner.line()
			switch kind {
			case "exact-copy":
				runner.rules[4] = []string{line}
			case "duplicate":
				runner.rules[4] = []string{line, line}
			case "foreign-source":
				runner.rules[4] = []string{strings.Replace(line, l.spec.Source.String(), "172.31.22.2", 1)}
			case "foreign-oif":
				runner.rules[4] = []string{strings.Replace(line, l.spec.Interface, "eth0", 1)}
			case "foreign-table":
				runner.rules[4] = []string{strings.Replace(line, "lookup 204", "lookup 203", 1)}
			case "table-alias":
				runner.rules[4] = []string{strings.Replace(line, "lookup 204", "lookup main", 1)}
			case "unknown-selector":
				runner.rules[4] = []string{line + " suppress_prefixlength 0"}
			case "IPv6-slot":
				runner.rules[6] = []string{fmt.Sprintf("%d: from fd00::1 to 2606:4700::1111 oif %s lookup %d", l.spec.Priority, l.spec.Interface, l.spec.Table)}
			case "read4-error":
				runner.readErrors[4] = errors.New("unsupported numeric read")
			case "read6-error":
				runner.readErrors[6] = errors.New("failed numeric IPv6 read")
			}
			before := fmt.Sprint(runner.rules)
			if err := l.Apply(context.Background()); err == nil || runner.adds != 0 || runner.deletes != 0 || fmt.Sprint(runner.rules) != before {
				t.Fatal("preexisting/unknown state became ownership", err, runner)
			}
			if _, err := os.Stat(filepath.Join(l.root, policyAdditionFile)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("preflight failure wrote an effect receipt", err)
			}
		})
	}
}

func TestNodeTransitLeaseLateCopyAndLostAcknowledgementsKeepUnknownFence(t *testing.T) {
	for _, kind := range []string{"late-copy", "lost-add-ACK", "lost-delete-ACK", "late-cleanup-copy"} {
		t.Run(kind, func(t *testing.T) {
			l, runner, authority := nodeTransitFixture(t)
			if kind == "late-copy" {
				l.options.fault = func(point string, _ int) error {
					if point == "intent" {
						runner.rules[4] = append(runner.rules[4], runner.line())
					}
					return nil
				}
			} else if kind == "lost-add-ACK" {
				runner.loseAddACK = true
			}
			applyErr := l.Apply(context.Background())
			if kind == "lost-delete-ACK" || kind == "late-cleanup-copy" {
				if applyErr != nil {
					t.Fatal(applyErr)
				}
				if kind == "lost-delete-ACK" {
					runner.loseDeleteACK = true
				} else {
					l.options.fault = func(point string, _ int) error {
						if point == "cleanup-intent" {
							runner.rules[4] = append(runner.rules[4], runner.line())
						}
						return nil
					}
				}
				if err := l.Remove(context.Background()); !errors.Is(err, ErrPolicyAdditionUnknown) {
					t.Fatal("uncertain cleanup lost its fence", err)
				}
			} else if !errors.Is(applyErr, ErrPolicyAdditionUnknown) {
				t.Fatal("uncertain addition lost its fence", applyErr)
			}
			status, err := l.Inspect(context.Background())
			if err != nil || !status.Unknown || status.Pending != 1 {
				t.Fatal("fresh status adopted matching kernel state", status, err)
			}
			fresh, err := newNodeTransitLeaseWithOptions(l.spec, l.root, l.runtime, l.options)
			if err != nil {
				t.Fatal(err)
			}
			calls, registrations := len(runner.calls), authority.registrations
			if err := fresh.Remove(context.Background()); !errors.Is(err, ErrPolicyAdditionUnknown) || len(runner.calls) != calls || authority.registrations != registrations {
				t.Fatal("unknown generation replayed RPC or registration", err, runner.calls[calls:])
			}
			if err := fresh.Apply(context.Background()); !errors.Is(err, ErrPolicyAdditionUnknown) || isNodeTransitBeforeEffects(err) || len(runner.calls) != calls || authority.registrations != registrations {
				t.Fatal("unknown generation Apply replayed RPC or registration", err, runner.calls[calls:])
			}
			if err := fresh.VerifyUnused(context.Background()); err == nil || len(runner.calls) != calls || authority.registrations != registrations {
				t.Fatal("unknown generation obtained unused authority", err)
			}
		})
	}
}

func TestNodeTransitBeforeEffectsRefusalIsLiveOneShotAndNeverFreshReadback(t *testing.T) {
	for _, phase := range []string{"registration", "preflight"} {
		t.Run(phase, func(t *testing.T) {
			l, runner, authority := nodeTransitFixture(t)
			refusal := errors.New("live issuer or preflight refused")
			if phase == "registration" {
				authority.registerErr = refusal
			} else {
				authority.preflightErr = refusal
			}
			err := l.Apply(context.Background())
			if !isNodeTransitBeforeEffects(err) || !errors.Is(err, refusal) || len(runner.calls) != 0 || runner.adds != 0 || authority.registrations != 1 {
				t.Fatal("definite early refusal lost phase or invoked effects", err, runner)
			}
			for _, name := range []string{policyAdditionFile, policyAdditionLock} {
				if _, err := os.Lstat(filepath.Join(l.root, name)); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("early refusal invoked receipt backend", name, err)
				}
			}
			fresh, err := newNodeTransitLeaseWithOptions(l.spec, l.root, l.runtime, l.options)
			if err != nil {
				t.Fatal(err)
			}
			if err := fresh.VerifyUnused(context.Background()); err == nil || len(runner.calls) != 0 {
				t.Fatal("fresh lease granted settlement from absence", err)
			}
			// The separate cleanup authority still checks current source/boot.
			if err := l.VerifyUnused(context.Background()); err != nil || runner.adds != 0 || runner.deletes != 0 {
				t.Fatal("live definite refusal could not prove unused", err)
			}
			calls := len(runner.calls)
			if err := l.VerifyUnused(context.Background()); err == nil || len(runner.calls) != calls {
				t.Fatal("unused proof was replayed", err)
			}
		})
	}
}

func TestNodeTransitBeforeEffectsCannotSettleForeignUnknownOrChangedState(t *testing.T) {
	for _, kind := range []string{"foreign-slot", "unknown-read", "late-receipt", "late-lock", "late-source", "revoked-cleanup"} {
		t.Run(kind, func(t *testing.T) {
			l, runner, authority := nodeTransitFixture(t)
			authority.preflightErr = errors.New("active preflight refused")
			if err := l.Apply(context.Background()); !isNodeTransitBeforeEffects(err) {
				t.Fatal("fixture did not establish a live early refusal", err)
			}
			switch kind {
			case "foreign-slot":
				runner.rules[4] = []string{runner.line()}
			case "unknown-read":
				runner.readErrors[6] = errors.New("numeric inspection failed")
			case "late-receipt":
				if err := os.WriteFile(filepath.Join(l.root, policyAdditionFile), []byte("foreign receipt"), 0600); err != nil {
					t.Fatal(err)
				}
			case "late-lock":
				if err := os.WriteFile(filepath.Join(l.root, policyAdditionLock), []byte(policyAdditionMarker), 0600); err != nil {
					t.Fatal(err)
				}
			case "late-source":
				authority.source = netip.MustParseAddr("172.31.22.2")
			case "revoked-cleanup":
				authority.guardErr = ErrReviewChanged
			}
			before := fmt.Sprint(runner.rules)
			if err := l.VerifyUnused(context.Background()); err == nil || runner.adds != 0 || runner.deletes != 0 || before != fmt.Sprint(runner.rules) {
				t.Fatal("unused settlement widened into foreign/unknown state", err)
			}
		})
	}
}

func TestNodeTransitSharedBackendEntryNeverGrantsBeforeEffectsSettlement(t *testing.T) {
	for _, point := range []string{"second-preflight", "initial-save", "intent-save", "intent", "add-error", "lost-add-ACK"} {
		t.Run(point, func(t *testing.T) {
			l, runner, authority := nodeTransitFixture(t)
			failure := errors.New("shared backend failure")
			preflights := 0
			l.runtime.preflight = func(context.Context, NodeTransitSpec) error {
				preflights++
				if preflights == 2 {
					if point == "second-preflight" {
						return failure
					}
					if point == "initial-save" {
						// The common loader already observed absence. Block its
						// first actual atomic document write, not an early hook.
						return os.Mkdir(filepath.Join(l.root, policyAdditionFile), 0700)
					}
				}
				return nil
			}
			blockedIntent := false
			if point == "intent-save" {
				originalGuard := l.runtime.guard
				l.runtime.guard = func(ctx context.Context, spec NodeTransitSpec) error {
					if !blockedIntent {
						path := filepath.Join(l.root, policyAdditionFile)
						if data, err := os.ReadFile(path); err == nil {
							var doc policyAdditionDocument
							if json.Unmarshal(data, &doc) != nil || len(doc.Steps) != 1 || doc.Steps[0].State != "planned" {
								return errors.New("expected first actual planned document")
							}
							if err := os.Remove(path); err != nil {
								return err
							}
							if err := os.Mkdir(path, 0700); err != nil {
								return err
							}
							blockedIntent = true
						}
					}
					return originalGuard(ctx, spec)
				}
			}
			if point == "intent" {
				l.options.fault = func(at string, _ int) error {
					if at == "intent" {
						return failure
					}
					return nil
				}
			}
			if point == "add-error" {
				runner.addErr = failure
			}
			runner.loseAddACK = point == "lost-add-ACK"
			err := l.Apply(context.Background())
			if err == nil || isNodeTransitBeforeEffects(err) || !l.effects.Load() || preflights != 2 || point == "intent-save" && !blockedIntent {
				t.Fatal("shared-entry failure became an unused grant", err, preflights, blockedIntent)
			}
			calls, registrations := len(runner.calls), authority.registrations
			if err := l.VerifyUnused(context.Background()); err == nil || len(runner.calls) != calls || authority.registrations != registrations {
				t.Fatal("shared failure obtained authority from fresh absence", err)
			}
			if point == "second-preflight" {
				// A lock surviving before the initial document write also fences
				// a new object; it cannot reconstruct live pre-crash evidence.
				authority.registerErr = failure
				fresh, err := newNodeTransitLeaseWithOptions(l.spec, l.root, l.runtime, l.options)
				if err != nil {
					t.Fatal(err)
				}
				if err := fresh.Apply(context.Background()); !errors.Is(err, failure) || isNodeTransitBeforeEffects(err) {
					t.Fatal("old shared root regained before-effects classification", err)
				}
			}
		})
	}
}

func TestNodeTransitUnusedClosingGuardCannotIntroduceReceiptMarker(t *testing.T) {
	for _, name := range []string{policyAdditionFile, policyAdditionLock} {
		t.Run(name, func(t *testing.T) {
			l, runner, authority := nodeTransitFixture(t)
			authority.preflightErr = errors.New("live early preflight refusal")
			if err := l.Apply(context.Background()); !isNodeTransitBeforeEffects(err) {
				t.Fatal(err)
			}
			originalGuard := l.runtime.guard
			guards, inserted := 0, false
			l.runtime.guard = func(ctx context.Context, spec NodeTransitSpec) error {
				guards++
				if guards == 4 {
					// This final guard follows both numeric reads and their guard.
					if err := os.WriteFile(filepath.Join(l.root, name), []byte("late foreign marker"), 0600); err != nil {
						return err
					}
					inserted = true
				}
				return originalGuard(ctx, spec)
			}
			if err := l.VerifyUnused(context.Background()); err == nil || !inserted || guards != 4 || runner.adds != 0 || runner.deletes != 0 {
				t.Fatal("closing guard marker became unused settlement", err, guards, inserted)
			}
			if data, err := os.ReadFile(filepath.Join(l.root, name)); err != nil || string(data) != "late foreign marker" {
				t.Fatal("closing marker was removed or adopted", err)
			}
		})
	}
}

func TestNodeTransitLeaseRequiresFreshIdentityAndSeparateCleanupAuthority(t *testing.T) {
	for _, kind := range []string{"boot", "ifindex", "source", "down", "revoked", "registration", "before-delete", "closing-guard"} {
		t.Run(kind, func(t *testing.T) {
			l, runner, authority := nodeTransitFixture(t)
			if err := l.Apply(context.Background()); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "boot":
				authority.boot = "00000000-0000-0000-0000-000000000002"
			case "ifindex":
				authority.iface.Index++
			case "source":
				authority.source = netip.MustParseAddr("172.31.22.2")
			case "down":
				authority.iface.Flags = 0
			case "revoked":
				authority.guardErr = ErrReviewChanged
			case "registration":
				authority.registerErr = ErrReviewChanged
			case "before-delete":
				authority.deleteErr = errors.New("resource dependency remains")
			case "closing-guard":
				l.runtime.beforeDelete = func(context.Context, NodeTransitSpec) error { authority.guardErr = ErrReviewChanged; return nil }
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			// Detaching cancellation itself cannot renew the callback's revoked
			// authority, nor replace boot/runtime/source identity.
			if err := l.Remove(context.WithoutCancel(ctx)); err == nil || runner.deletes != 0 || len(runner.rules[4]) != 1 {
				t.Fatal("cleanup widened authority or identity", err, runner)
			}
		})
	}
}

func TestNodeTransitLeaseGenerationMutationCannotReinterpretReceipt(t *testing.T) {
	l, runner, authority := nodeTransitFixture(t)
	if err := l.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*NodeTransitSpec){
		func(s *NodeTransitSpec) { s.PolicyGeneration = strings.Repeat("d", 32) },
		func(s *NodeTransitSpec) { s.RuntimeID = strings.Repeat("e", 64) },
		func(s *NodeTransitSpec) { s.PlanDigest = strings.Repeat("f", 64) },
		func(s *NodeTransitSpec) { s.NetworkProfile = "wan-ffffffffffff" },
	} {
		changed := l.spec
		mutate(&changed)
		authority.spec = changed
		fresh, err := newNodeTransitLeaseWithOptions(changed, l.root, l.runtime, l.options)
		if err != nil {
			t.Fatal(err)
		}
		calls, registrations := len(runner.calls), authority.registrations
		if err := fresh.Remove(context.Background()); !errors.Is(err, ErrPolicyAdditionReceipt) || len(runner.calls) != calls || authority.registrations != registrations || runner.deletes != 0 {
			t.Fatal("changed metadata granted cleanup from old receipt", err)
		}
	}
}
