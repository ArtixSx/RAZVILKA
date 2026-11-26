package dataplane

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type networkPolicyNFQInventoryUnknownAdapter struct{ Adapter }

func (*networkPolicyNFQInventoryUnknownAdapter) ID() string { panic("custom adapter callback entered") }

func TestNetworkPolicyNFQInventoryBodyParity(t *testing.T) {
	data, err := os.ReadFile("network_policy_manager_inventory.go")
	if err != nil {
		t.Fatal(err)
	}
	source := strings.ReplaceAll(string(data), "\r\n", "\n")
	start := strings.Index(source, "func (c *NetworkPolicyChecks) observeInventory(")
	end := strings.Index(source[start:], "\nfunc closeNetworkPolicyXrayObservations") + start
	body := source[start:end]
	opening := "\t\treturn c.observeNFQInventoryRead(held, lan, len(wg) != 0 || xrayScope != nil || prepared != nil, func(held context.Context) error {\n"
	closing := "\t\t\treturn lanPolicyPreflightAt(\"inventory-owner-current\", result)\n\t\t})"
	if strings.Count(body, opening) != 1 || strings.Count(body, closing) != 1 {
		t.Fatal("comparison wrapper layout changed")
	}
	a := strings.Index(body, opening)
	b := strings.Index(body, closing) + len(closing) - len("\t\t})")
	inner := body[a+len(opening) : b]
	lines := strings.Split(inner, "\n")
	for i := range lines {
		lines[i] = strings.TrimPrefix(lines[i], "\t")
	}
	body = body[:a] + strings.Join(lines, "\n") + body[b+len("\t\t})\n"):]
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(body))); got != "0303218de718ef7eb643099b2067afb9966419eb4711f3d4858836a5b52aacf5" {
		t.Fatal("original inventory body/capture/order/error/FD contract changed", got)
	}
}

func TestNetworkPolicyNFQInventoryOriginalSelection(t *testing.T) {
	c, source, ctx := networkPolicyNFQReadSourcesFixture(t)
	c.readSource = &networkPolicyOriginalInventoryReader{inventory: c.inventory}
	// This test compares structural dispatch only, never a native owner. The
	// older registrar fixture seals legacy LAN; compile the direct intent here.
	direct, err := CompileNFQWSDirectLANPolicyRuntime(source.execution.plan.LAN.Generation, source.execution.plan.LAN.Ingress)
	if err != nil {
		t.Fatal(err)
	}
	source.execution.plan.LAN = direct
	ctx = networkPolicyConsumerContext(ctx, source.execution.plan)
	lan := source.execution.plan.LAN
	s := c.nfqInventorySources(ctx, lan, false)
	if s == nil {
		t.Fatalf("original NFQ-only structural tuple refused: mode=%s context=%v adapters=%v shape=%v", lan.Mode, networkPolicyNFQInventoryContext(ctx), networkPolicyNFQInventoryAdapters(c), ValidateNetworkPolicyLAN(lan, source.execution.plan.Routes))
	}
	if err := s.current(ctx); err != nil {
		t.Fatal("original NFQ-only association refused", err)
	}
	if c.nfqInventorySources(ctx, lan, true) != nil {
		t.Fatal("foreign consumer bracket admitted")
	}
	for _, key := range []any{wgOperationOwnerKey{}, wgOperationMaterialKey{}, wgOperationCleanupKey{}, wgInactivityCleanupKey{}, xrayOperationOwnerKey{}, xrayOperationMaterialKey{}, xrayOperationCleanupKey{}, xraySelectedTCPExecutionKey{}, xraySelectedTCPPreResourceKey{}, xraySelectedTCPReplacementKey{}, xraySelectedTCPInventoryScopeKey{}, xraySelectedTCPPreparedInventoryScopeKey{}, nfqwsRetiredInventoryKey{}, nfqwsProbeCleanupKey{}, nfqws2RemovalIntentKey{}, nfqws2RollbackHookContextKey{}} {
		child := context.WithValue(ctx, key, "malformed-or-foreign")
		if c.nfqInventorySources(child, lan, false) != nil || s.current(child) == nil {
			t.Fatalf("foreign context admitted: %T", key)
		}
	}
	original := c.readSource
	c.readSource = networkPolicyInventoryCallback(nil)
	if c.nfqInventorySources(ctx, lan, false) != nil || s.current(ctx) == nil {
		t.Fatal("custom dispatch admitted or late replacement accepted")
	}
	c.readSource = original
	changed := cloneExecutionResourcePlan(source.execution.plan)
	changed.Note += "late-change"
	if s.current(networkPolicyConsumerContext(ctx, changed)) == nil {
		t.Fatal("late same-identity plan replacement accepted")
	}
	c.adapters["custom"] = &networkPolicyNFQInventoryUnknownAdapter{}
	if c.nfqInventorySources(ctx, lan, false) != nil || s.current(ctx) == nil {
		t.Fatal("unknown adapter admitted inside original loan")
	}
	delete(c.adapters, "custom")
	proxy := &ProxyTunnelAdapter{EngineID: "xray"}
	for _, retiring := range [][]string{nil, {"xray"}} {
		p := cloneExecutionResourcePlan(source.execution.plan)
		p.RetiringAdapters = retiring
		if mode, _ := proxy.xrayPlanMode(p); mode == proxyXrayModeNode {
			t.Fatal("NFQ-only original plan could dispatch a live proxy callback")
		}
	}
	// Source association alone must not manufacture a successful observation.
	if err := c.observeNFQInventoryRead(ctx, lan, false, func(context.Context) error { return ErrNetworkPolicyConsumers }); err == nil {
		t.Fatal("source tuple manufactured success")
	}
}

func TestNetworkPolicyNFQInventoryReadOnce(t *testing.T) {
	for _, mode := range []string{"success", "zero", "double", "swallowed-body", "closing-error", "late", "foreign", "cancel", "panic", "recovered-panic"} {
		t.Run(mode, func(t *testing.T) {
			parent, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			e := &nfqws2ActiveExecution{}
			parent = context.WithValue(parent, nfqws2ActiveExecutionKey{}, e)
			calls, closed := 0, false
			sentinel := errors.New("body failure")
			var late func(context.Context) error
			observer := func(request context.Context, read func(context.Context) error) error {
				if mode == "recovered-panic" {
					defer func() { _ = recover() }()
				}
				switch mode {
				case "zero":
					return nil
				case "late":
					late = read
					return nil
				case "foreign":
					return read(context.WithValue(request, nfqws2ActiveExecutionKey{}, &nfqws2ActiveExecution{}))
				}
				err := read(request)
				if mode == "double" {
					return read(request)
				}
				if mode == "swallowed-body" {
					return nil
				}
				if mode == "closing-error" {
					return sentinel
				}
				return err
			}
			var err error
			panicked := false
			func() {
				defer func() { panicked = recover() != nil }()
				err = networkPolicyNFQInventoryReadOnce(parent, e, observer, func(context.Context) error { return nil }, func(context.Context) error {
					calls++
					defer func() { closed = true }()
					if mode == "swallowed-body" {
						return sentinel
					}
					if mode == "cancel" {
						cancel()
					}
					if mode == "panic" || mode == "recovered-panic" {
						panic("body")
					}
					return nil
				})
			}()
			if mode == "success" {
				if err != nil || calls != 1 || !closed || panicked {
					t.Fatal(err, calls, closed, panicked)
				}
			} else if mode == "panic" {
				if !panicked || !closed {
					t.Fatal("panic cleanup lost")
				}
			} else if err == nil || calls > 1 || calls != 0 && !closed {
				t.Fatal("invalid observer accepted", err, calls, closed)
			}
			if mode == "swallowed-body" && !errors.Is(err, sentinel) {
				t.Fatal("body error swallowed", err)
			}
			if late != nil && (late(parent) == nil || calls != 0) {
				t.Fatal("late callback entered body")
			}
		})
	}
}

func TestNetworkPolicyNFQInventoryReadJoinsEnteredBody(t *testing.T) {
	for _, detached := range []bool{false, true} {
		t.Run(fmt.Sprintf("detached-child-%t", detached), func(t *testing.T) {
			parent, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			e := &nfqws2ActiveExecution{}
			parent = context.WithValue(parent, nfqws2ActiveExecutionKey{}, e)
			entered, finished := make(chan struct{}), make(chan struct{})
			var closed atomic.Bool
			file, fileErr := os.CreateTemp(t.TempDir(), "receipt")
			if fileErr != nil {
				t.Fatal(fileErr)
			}
			t.Cleanup(func() { _ = file.Close() })
			err := networkPolicyNFQInventoryReadOnce(parent, e, func(request context.Context, read func(context.Context) error) error {
				child := request
				if detached {
					deadline, _ := request.Deadline()
					var stop context.CancelFunc
					child, stop = context.WithDeadline(context.Background(), deadline)
					t.Cleanup(stop)
					child = context.WithValue(child, nfqws2ActiveExecutionKey{}, e)
				}
				go func() { defer close(finished); _ = read(child) }()
				<-entered
				return nil // Defective observer returns while the original body still owns resources.
			}, func(context.Context) error { return nil }, func(read context.Context) error {
				defer file.Close()
				defer closed.Store(true)
				close(entered)
				<-read.Done()
				return read.Err()
			})
			<-finished
			if err == nil || !closed.Load() {
				t.Fatal("Provider boundary could return before body cleanup", err)
			}
			if _, err := file.Read(make([]byte, 1)); !errors.Is(err, os.ErrClosed) {
				t.Fatal("entered body left its receipt FD open", err)
			}
		})
	}
}

func TestNetworkPolicyNFQInventoryReadNilParent(t *testing.T) {
	called := false
	err := networkPolicyNFQInventoryReadOnce(nil, &nfqws2ActiveExecution{}, func(context.Context, func(context.Context) error) error { called = true; return nil }, func(context.Context) error { return nil }, func(context.Context) error { return nil })
	if err == nil || called {
		t.Fatal("nil parent admitted", err)
	}
}
