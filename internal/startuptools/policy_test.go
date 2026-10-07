package startuptools

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

type admissionFunc func(context.Context, string, []string, string, func() error) error

func (f admissionFunc) WithStart(c context.Context, n string, a []string, d string, b func() error) error {
	return f(c, n, a, d, b)
}

func TestAdmissionExactCommandOriginalContextAndArgumentIsolation(t *testing.T) {
	args := []string{"-t", "mangle", "-N", "RZG_owned"}
	want := slices.Clone(args)
	token := &struct{}{}
	original := context.WithValue(context.Background(), token, "original operation")
	digest := strings.Repeat("a", 64)
	calls := 0
	var ctx context.Context
	ctx = WithCommandAdmission(original, admissionFunc(func(c context.Context, name string, received []string, d string, begin func() error) error {
		if c != ctx || c.Value(token) != "original operation" || name != "/usr/sbin/iptables-legacy" || d != digest || !slices.Equal(received, want) {
			t.Fatal("barrier lost original command/context")
		}
		received[3] = "foreign command"
		return begin()
	}))
	err := invokeAdmission(ctx, "/usr/sbin/iptables-legacy", args, digest, func() bool { return true }, func() error {
		calls++
		if !slices.Equal(args, want) {
			t.Fatal("owner changed actual command argv")
		}
		return nil
	})
	if err != nil || calls != 1 {
		t.Fatal("valid start barrier refused", err, calls)
	}
}

func TestAdmissionRefusesMissingRepeatedAsyncAndSwallowedStartFailure(t *testing.T) {
	fault := errors.New("actual start failure")
	for _, tc := range []struct {
		name       string
		owner      admissionFunc
		thread     bool
		startError error
		starts     int
	}{
		{"missing", nil, true, nil, 0},
		{"not-called", func(context.Context, string, []string, string, func() error) error { return nil }, true, nil, 0},
		{"repeated", func(_ context.Context, _ string, _ []string, _ string, begin func() error) error {
			_ = begin()
			_ = begin()
			return nil
		}, true, nil, 1},
		{"wrong-thread", func(_ context.Context, _ string, _ []string, _ string, begin func() error) error {
			_ = begin()
			return nil
		}, false, nil, 0},
		{"swallowed", func(_ context.Context, _ string, _ []string, _ string, begin func() error) error {
			_ = begin()
			return nil
		}, true, fault, 1},
		{"propagated", func(_ context.Context, _ string, _ []string, _ string, begin func() error) error { return begin() }, true, fault, 1},
		{"refused-after-start", func(_ context.Context, _ string, _ []string, _ string, begin func() error) error {
			_ = begin()
			return fault
		}, true, nil, 1},
		{"panic-after-start", func(_ context.Context, _ string, _ []string, _ string, begin func() error) error {
			_ = begin()
			panic("owner failure")
		}, true, nil, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var owner CommandAdmission
			if tc.owner != nil {
				owner = tc.owner
			}
			ctx := WithCommandAdmission(context.Background(), owner)
			starts := 0
			err := invokeAdmission(ctx, "/fixed/alias", []string{"frozen"}, strings.Repeat("a", 64), func() bool { return tc.thread }, func() error { starts++; return tc.startError })
			if !errors.Is(err, ErrUnknown) || starts != tc.starts || tc.startError != nil && !errors.Is(err, tc.startError) {
				t.Fatal("invalid admission issued success", err, starts)
			}
		})
	}
	var saved func() error
	ctx := WithCommandAdmission(context.Background(), admissionFunc(func(_ context.Context, _ string, _ []string, _ string, begin func() error) error {
		saved = begin
		return nil
	}))
	var starts atomic.Int32
	if err := invokeAdmission(ctx, "/fixed/alias", nil, "digest", func() bool { return true }, func() error { starts.Add(1); return nil }); err == nil {
		t.Fatal("not-called admission succeeded")
	}
	done := make(chan error, 1)
	go func() { done <- saved() }()
	if err := <-done; !errors.Is(err, ErrUnknown) || starts.Load() != 0 {
		t.Fatal("asynchronous begin survived owner return", err)
	}
}

func TestPolicyLeaseScopeAndBoundedABI(t *testing.T) {
	l := unitLease(t)
	if _, runner, err := l.PolicyRuntimeTools(); !errors.Is(err, ErrUnknown) || runner != nil {
		t.Fatal("readonly lease issued policy runner", err)
	}
	for _, args := range [][]string{{"-4", "-N", "rule", "show"}, {"-6", "-N", "rule", "show"}} {
		if !ipReadArguments(args) {
			t.Fatal("numeric RPDB read refused")
		}
	}
	for _, args := range [][]string{{"-4", "rule", "show"}, {"-4", "-N", "rule", "flush"}, {"-4", "-N", "rule", "show", "extra"}} {
		if ipReadArguments(args) {
			t.Fatal("broad IP read accepted", args)
		}
	}
	for _, args := range [][]string{{"-4", "rule", "add", "priority", "53"}, {"-6", "route", "replace", "default", "dev", "rz0"}} {
		if !effectArguments(2, args) {
			t.Fatal("admitted IP ABI refused", args)
		}
	}
	for _, args := range [][]string{{"-t", "mangle", "-A", "RZG_owned", "-j", "RETURN"}, {"-t", "mangle", "-I", "PREROUTING", "1", "-j", "RZG_owned"}} {
		if !effectArguments(0, args) {
			t.Fatal("admitted xtables ABI refused", args)
		}
	}
	for _, args := range [][]string{{"-batch", "/foreign/file"}, {"-4", "rule", "flush", "all"}, {"-t", "mangle", "-F", "RZG_owned"}, {"-t", "mangle", "-P", "DROP"}, {"-t", "mangle", "-A", strings.Repeat("a", 1025)}, {"-t", "mangle", "-A", "bad\n"}} {
		if effectArguments(0, args) || effectArguments(2, args) {
			t.Fatal("broad effect ABI accepted", args)
		}
	}
}

func TestAdmissionCancellationRefusesBeforeActualStart(t *testing.T) {
	base, cancel := context.WithCancel(context.Background())
	starts := 0
	ctx := WithCommandAdmission(base, admissionFunc(func(_ context.Context, _ string, _ []string, _ string, begin func() error) error {
		cancel()
		_ = begin() // Even a swallowed cancellation cannot authorize Start.
		return nil
	}))
	if err := invokeAdmission(ctx, "/fixed/alias", nil, "digest", func() bool { return true }, func() error { starts++; return nil }); !errors.Is(err, ErrUnknown) || starts != 0 {
		t.Fatal("cancelled original operation started command", err, starts)
	}
	if got := WithCommandAdmission(nil, nil); got != nil {
		t.Fatal("nil context became authority")
	}
}

func TestCloseJoinsRetainedAdmissionWithoutHoldingReadGate(t *testing.T) {
	l := unitLease(t)
	file, err := os.CreateTemp(t.TempDir(), "held-policy-image")
	if err != nil {
		t.Fatal(err)
	}
	l.review.images[file.Name()] = &heldImage{file: file}
	if err := l.retain(context.Background()); err != nil {
		t.Fatal(err)
	}
	// An owner can reenter a read callback while its admission retains fds.
	if err := l.lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	l.unlock()
	done := make(chan error, 1)
	go func() { done <- l.Close() }()
	select {
	case <-l.lifetime.Done():
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel retained admission")
	}
	select {
	case <-done:
		t.Fatal("Close released descriptors during admission")
	default:
	}
	if err := l.retain(context.Background()); err == nil {
		t.Fatal("new retain survived Close")
	}
	if _, err := file.Stat(); err != nil {
		t.Fatal("held file closed before admission joined", err)
	}
	l.retained.Done()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := file.Stat(); err == nil {
		t.Fatal("Close leaked retained policy file")
	}
}

func TestActualTypedLANPlanFitsOnlyTheAdmittedCommandABI(t *testing.T) {
	plan, err := dataplane.CompileLANPolicyRuntime(strings.Repeat("a", 64), []dataplane.LANPolicyIngress{{
		SegmentID: "native-ingress", Interface: "br-lan", Membership: "mac",
		Sources: []string{"192.168.77.0/24", "fd00:77::/64"}, IncludedMACs: []string{"02:00:00:00:00:01"},
		ExcludedSources: []string{"192.168.77.9/32", "fd00:77::9/128"}, ExcludedMACs: []string{"02:00:00:00:00:09"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	effects, err := plan.Effects()
	if err != nil {
		t.Fatal(err)
	}
	for _, effect := range effects {
		index := map[string]int{"iptables": 0, "ip6tables": 1, "ip": 2}[effect.Tool]
		if !effectArguments(index, effect.Add) || !effectArguments(index, effect.Delete) {
			t.Fatal("actual owner compiler emitted unsupported command ABI", effect.Tool, effect.Add, effect.Delete)
		}
	}
}
