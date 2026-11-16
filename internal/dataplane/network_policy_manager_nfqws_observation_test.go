package dataplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func TestNetworkPolicyNFQReadBodySourceParity(t *testing.T) {
	data, err := os.ReadFile("network_policy_manager_nfqws_inventory.go")
	if err != nil {
		t.Fatal(err)
	}
	source := strings.ReplaceAll(string(data), "\r\n", "\n")
	start := strings.Index(source, "func (c *NetworkPolicyChecks) nfqConsumersObserved(")
	if start < 0 {
		t.Fatal("original observer missing")
	}
	end := strings.Index(source[start:], "\n// Pure conversion")
	if end < 0 {
		t.Fatal("original observer boundary missing")
	}
	body := strings.Replace(source[start:start+end], "nfqConsumersObserved(", "nfqConsumers(", 1)
	hash := sha256.Sum256([]byte(body))
	if hex.EncodeToString(hash[:]) != "5d5f60c0f345bbc232bc77368a79d9f9172ffdbe524ee3a8891904627edf94ee" {
		t.Fatal("complete preexisting observer changed")
	}
}

// Dispatch/lifetime model only; actual original source/process/kernel reads
// stay in the body pinned above and require the separate native LAN fixture.
func TestNetworkPolicyNFQReadOnceViewsAndFailures(t *testing.T) {
	for _, mode := range []string{"success", "zero", "double", "opening", "closing", "swallowed-body", "closing-association", "parent-cancel", "child-cancel", "foreign-execution", "extended", "unbounded", "foreign-borrow", "cleanup", "panic-closing"} {
		t.Run(mode, func(t *testing.T) {
			e := &nfqws2ActiveExecution{}
			e.self = e
			ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), nfqws2ActiveExecutionKey{}, e), time.Minute)
			defer cancel()
			first, err := os.CreateTemp(t.TempDir(), "receipt-")
			if err != nil {
				t.Fatal(err)
			}
			defer first.Close()
			second, err := os.CreateTemp(t.TempDir(), "borrow-")
			if err != nil {
				t.Fatal(err)
			}
			defer second.Close()
			views := []networkPolicyNFQObservation{{receipt: networkPolicyReceiptObservation{document: first}}, {borrow: policyEffectBorrowObservation{document: second}}}
			readCount := 0
			sentinel := errors.New("original body or source refusal")
			drift := false
			current := func(context.Context) error {
				if drift {
					return sentinel
				}
				return nil
			}
			read := func(context.Context) ([]networkPolicyNFQObservation, error) {
				readCount++
				if mode == "swallowed-body" {
					return views, sentinel
				}
				return views, nil
			}
			observe := func(use func(context.Context) error) error {
				if mode == "zero" || mode == "opening" {
					if mode == "opening" {
						return sentinel
					}
					return nil
				}
				child := ctx
				switch mode {
				case "foreign-execution":
					child = context.WithValue(ctx, nfqws2ActiveExecutionKey{}, &nfqws2ActiveExecution{})
				case "foreign-borrow":
					child = context.WithValue(ctx, policyEffectReceiptBorrowKey{}, &policyEffectReceiptBorrow{})
				case "cleanup":
					child = context.WithValue(ctx, nfqwsRetiredInventoryKey{}, true)
				case "extended":
					var done context.CancelFunc
					child, done = context.WithTimeout(context.WithValue(context.Background(), nfqws2ActiveExecutionKey{}, e), 2*time.Minute)
					defer done()
				case "unbounded":
					child = context.WithValue(context.Background(), nfqws2ActiveExecutionKey{}, e)
				case "child-cancel":
					var done context.CancelFunc
					child, done = context.WithCancel(ctx)
					done()
				}
				bodyErr := use(child)
				switch mode {
				case "double":
					_ = use(child) // Even a source that swallows this error refuses.
				case "closing":
					return errors.Join(bodyErr, sentinel)
				case "swallowed-body":
					return nil
				case "closing-association":
					drift = true
				case "parent-cancel":
					cancel()
				case "panic-closing":
					panic(sentinel)
				}
				return bodyErr
			}
			var out []networkPolicyNFQObservation
			var result error
			panicked := false
			func() {
				defer func() { panicked = recover() != nil }()
				out, result = networkPolicyNFQReadOnce(ctx, e, observe, current, read)
			}()
			if mode == "success" {
				if result != nil || panicked || len(out) != 2 || readCount != 1 {
					t.Fatal("original views not returned", result)
				}
				for _, f := range []*os.File{first, second} {
					if _, err := f.Stat(); err != nil {
						t.Fatal("success closed caller-owned view", err)
					}
				}
				for _, o := range out {
					o.close()
				}
				return
			}
			if len(out) != 0 || mode == "panic-closing" && !panicked || mode != "panic-closing" && (result == nil || panicked) || readCount > 1 {
				t.Fatal("invalid observer accepted or replayed", result, panicked, readCount)
			}
			if mode == "swallowed-body" && !errors.Is(result, sentinel) {
				t.Fatal("original body error swallowed")
			}
			if readCount > 0 {
				for _, f := range []*os.File{first, second} {
					if _, err := f.Read(make([]byte, 1)); !errors.Is(err, os.ErrClosed) {
						t.Fatal("failed outer observation leaked actual descriptor", err)
					}
				}
			}
		})
	}
}

func TestNetworkPolicyNFQReadUnsupportedFallback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c := &NetworkPolicyChecks{}
	before, beforeErr := c.nfqConsumersObserved(ctx, nil)
	after, afterErr := c.nfqConsumers(ctx, nil)
	if beforeErr != nil || afterErr != nil || len(before) != 0 || len(after) != 0 {
		t.Fatal("absent original adapter fallback changed", beforeErr, afterErr)
	}
}

func networkPolicyNFQReadSourcesFixture(t *testing.T) (*NetworkPolicyChecks, *networkPolicyNFQReadSources, context.Context) {
	t.Helper()
	e, ctx := nfqwsActiveCommandFixture(t)
	e.material.execution, e.material.executionBound = e, true
	e.gate = e.material.manager.Adapters[NetworkPolicyAdapterID].(*NetworkPolicyAdapter)
	e.identity, e.lan, e.runtime = e.gate.identity, e.gate.Binding, e.gate.Binding.Runtime
	provider := netidentity.NewProcProvider() // Structural model; never observed.
	e.identity.provider, e.material.provider = provider, provider
	e.inventory.reader.Provider = provider
	e.inventory.reader.Runner = &activeReadDispatchModel{}
	e.inventory.reader.IPTables, e.inventory.reader.IP6Tables = e.runtime.IPTables, e.runtime.IP6Tables
	c, err := e.material.manager.bindNetworkPolicyChecks(e.gate, func(context.Context, netidentity.Identity) (BackendInventorySnapshot, error) {
		t.Fatal("association comparison reached inventory")
		return BackendInventorySnapshot{}, ErrNetworkPolicyConsumers
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	inventory := e.inventory
	c.inventory = &inventory
	s := c.nfqReadSources(ctx)
	if s == nil || s.current(ctx) != nil {
		t.Fatal("complete static original tuple refused")
	}
	return c, s, ctx
}

func TestNetworkPolicyNFQReadOriginalAssociations(t *testing.T) {
	for _, mode := range []string{"process", "adapter-execution", "retired", "resource", "binding", "plan", "material", "provider", "source", "both-sources", "review", "inventory", "identity", "closed", "nil-execution-reader", "nil-checks-reader", "nil-checks-inventory"} {
		t.Run(mode, func(t *testing.T) {
			c, s, ctx := networkPolicyNFQReadSourcesFixture(t)
			e := s.execution
			switch mode {
			case "process":
				s.adapter.activeProcess = &nfqws2ActiveOwner{}
			case "adapter-execution":
				s.adapter.activeExecution = &nfqws2ActiveExecution{}
			case "retired":
				e.retired = true
			case "resource":
				e.resource = &NFQWSExecutionResource{}
			case "binding":
				e.binding = &NFQWSScopedBinding{}
			case "plan":
				original := e.resource.plan
				defer func() { s.resource.plan = original }()
				e.resource.plan = &NFQWSScopedPlan{}
			case "material":
				e.material = &NFQWSActiveMaterial{}
			case "provider":
				e.inventory.reader.Provider = netidentity.NewProcProvider()
			case "source":
				e.inventory.reader.Runner = &activeReadDispatchModel{}
			case "both-sources":
				runner := &activeReadDispatchModel{}
				e.inventory.reader.Runner, c.inventory.reader.Runner = runner, runner
			case "review":
				e.inventory.review += "changed"
			case "inventory":
				copy := *c.inventory
				c.inventory = &copy
			case "identity":
				c.identity = &networkPolicyIdentity{}
			case "closed":
				_ = c.Close()
			case "nil-execution-reader":
				e.inventory.reader = backendInventoryReader{}
			case "nil-checks-reader":
				c.inventory.reader = backendInventoryReader{}
			case "nil-checks-inventory":
				c.inventory = nil
			}
			if s.current(ctx) == nil {
				t.Fatal("changed source association accepted", mode)
			}
		})
	}
}

func TestNetworkPolicyNFQReadLateAndConcurrentCallbacks(t *testing.T) {
	for _, mode := range []string{"late-after-empty", "late-after-success", "returned-in-flight", "concurrent"} {
		t.Run(mode, func(t *testing.T) {
			e := &nfqws2ActiveExecution{}
			e.self = e
			ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), nfqws2ActiveExecutionKey{}, e), time.Minute)
			defer cancel()
			fd, err := os.CreateTemp(t.TempDir(), "tentative-")
			if err != nil {
				t.Fatal(err)
			}
			defer fd.Close()
			var reads atomic.Int32
			started, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			var workers sync.WaitGroup
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			t.Cleanup(func() { unblock(); workers.Wait() })
			worker := make(chan error, 1)
			var escaped func(context.Context) error
			read := func(context.Context) ([]networkPolicyNFQObservation, error) {
				reads.Add(1)
				if mode == "returned-in-flight" || mode == "concurrent" {
					close(started)
					<-release
				}
				return []networkPolicyNFQObservation{{receipt: networkPolicyReceiptObservation{document: fd}}}, nil
			}
			observe := func(use func(context.Context) error) error {
				escaped = use
				switch mode {
				case "late-after-empty":
					return nil
				case "late-after-success":
					return use(ctx)
				default:
					workers.Add(1)
					go func() { defer workers.Done(); worker <- use(ctx) }()
					<-started
					if mode == "concurrent" {
						second := use(ctx)
						unblock()
						return errors.Join(second, <-worker)
					}
					return nil
				}
			}
			out, result := networkPolicyNFQReadOnce(ctx, e, observe, func(context.Context) error { return nil }, read)
			if mode == "late-after-success" {
				if result != nil || len(out) != 1 {
					t.Fatal("original completed callback failed", result)
				}
				for _, o := range out {
					o.close()
				}
			} else if result == nil || len(out) != 0 {
				t.Fatal("incomplete/concurrent callback accepted", result)
			}
			if mode == "returned-in-flight" {
				unblock()
				if err := <-worker; err == nil {
					t.Fatal("late completed body published a view")
				}
			}
			before := reads.Load()
			if err := escaped(ctx); err == nil || reads.Load() != before {
				t.Fatal("late callback entered body")
			}
			if mode == "late-after-empty" {
				if before != 0 {
					t.Fatal("empty observer ran body")
				}
			} else {
				if before != 1 {
					t.Fatal("body replay", before)
				}
				if _, err := fd.Read(make([]byte, 1)); !errors.Is(err, os.ErrClosed) {
					t.Fatal("late body descriptor retained", err)
				}
			}
		})
	}
}

func TestNetworkPolicyNFQReadNilReadersRefuse(t *testing.T) {
	for _, mode := range []string{"execution", "checks"} {
		t.Run(mode, func(t *testing.T) {
			c, s, ctx := networkPolicyNFQReadSourcesFixture(t)
			if mode == "execution" {
				s.execution.inventory.reader = backendInventoryReader{}
			} else {
				c.inventory.reader = backendInventoryReader{}
			}
			if c.nfqReadSources(ctx) != nil {
				t.Fatal("nil reader selected")
			}
			if out, err := c.nfqConsumers(ctx, nil); err == nil || len(out) != 0 {
				t.Fatal("nil reader promoted", err)
			}
		})
	}
}
