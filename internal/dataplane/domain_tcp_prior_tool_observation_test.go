package dataplane

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// These comparisons use real held executable bytes and only modeled tool
// callbacks. They cannot create a native process, tool lease or kernel grant.
func TestDomainPriorToolComparisonClosesNestedFileLoan(t *testing.T) {
	for _, mode := range []string{"clean", "body-error", "closing-error", "swallowed", "zero", "twice", "late", "cancel", "mutation", "extended", "registrar", "panic"} {
		t.Run(mode, func(t *testing.T) {
			p, ctx, cancel := domainPriorFileResourceModel(t)
			defer cancel()
			bodyFailure, closingFailure := errors.New("body refused"), errors.New("tool closing refused")
			var late func(context.Context) error
			var saved context.Context
			var loan *domainTCPSuccessorRead
			calls := 0
			observe := func(parent context.Context, use func(context.Context) error) error {
				if mode == "panic" {
					defer func() { _ = recover() }()
				}
				if mode == "zero" || mode == "late" {
					late = use
					return nil
				}
				observed := context.WithValue(parent, struct{ priorTool bool }{true}, "original tool view")
				if mode == "extended" {
					var release context.CancelFunc
					observed, release = context.WithTimeout(context.WithoutCancel(observed), time.Hour)
					defer release()
				}
				if mode == "registrar" {
					observed = context.WithValue(observed, syntheticExecutionRegistrarKey{}, p.scope)
				}
				err := use(observed)
				if mode == "twice" {
					_ = use(observed)
				}
				if mode == "closing-error" {
					return closingFailure
				}
				if mode == "swallowed" {
					return nil
				}
				return err
			}
			// The real publisher may hold both of these NEW owner locks.
			p.scope.mu.Lock()
			p.mu.Lock()
			err := domainTCPPriorToolComparison(ctx, observe, func(observed context.Context) error {
				calls++
				if observed.Value(syntheticExecutionRegistrarKey{}) != nil {
					t.Fatal("tool comparison manufactured an execution registrar")
				}
				return p.observeOriginalPriorFiles(observed, false, func(readCtx context.Context, files *xrayDomainTCPFileObservation) error {
					saved = readCtx
					if readCtx.Value(struct{ priorTool bool }{true}) != "original tool view" || files.current(readCtx, p) != nil {
						t.Fatal("nested file loan lost its exact outer tool context")
					}
					var err error
					loan, err = p.scope.domainSuccessor.originalSuccessorRead(readCtx)
					if err != nil || loan == nil {
						return errors.Join(ErrPolicyAdditionUnknown, err)
					}
					if p.scope.domainSuccessor.comparePrior(readCtx, false) == nil || p.scope.domainSuccessor.publishFrame(readCtx, nil, nil) == nil || domainTCPDirectForwardContext(readCtx) == nil {
						t.Fatal("readonly nested context acquired journal or DIRECT authority")
					}
					if p.scope.domainSuccessor.listener.Load().currentWithSuccessorRead(readCtx, p, loan) == nil {
						t.Fatal("file comparison fabricated a native listener")
					}
					switch mode {
					case "body-error", "swallowed":
						return bodyFailure
					case "cancel":
						cancel()
					case "mutation":
						return os.WriteFile(p.executable.path, []byte("changed original bytes"), 0700)
					case "panic":
						panic("comparison body panic")
					}
					return nil
				})
			})
			p.mu.Unlock()
			p.scope.mu.Unlock()
			if (err == nil) != (mode == "clean") || calls > 1 {
				t.Fatal("comparison result", mode, calls, err)
			}
			if (mode == "body-error" || mode == "swallowed") && !errors.Is(err, bodyFailure) || mode == "closing-error" && !errors.Is(err, closingFailure) {
				t.Fatal("body or tool closing failure lost", err)
			}
			if saved != nil && (saved.Err() == nil || loan == nil || loan.rootCurrent(saved) == nil || loan.priorRead.open.Load() || !loan.priorRead.bytes.image.lease.closed.Load()) {
				t.Fatal("nested file context survived tool comparison")
			}
			if late != nil && (late(ctx) == nil || calls != 0) {
				t.Fatal("escaped callback entered after journal continuation")
			}
		})
	}
}

func TestDomainPriorToolComparisonJoinsBeforeReturnAndPanic(t *testing.T) {
	for _, panicObserver := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		entered, joined := make(chan struct{}), make(chan struct{})
		returned := make(chan error, 1)
		func() {
			defer func() {
				if recovered := recover(); (recovered != nil) != panicObserver {
					t.Fatal("observer panic changed", recovered)
				}
				select {
				case <-joined:
				default:
					t.Fatal("journal continuation preceded read join")
				}
			}()
			err := domainTCPPriorToolComparison(ctx, func(parent context.Context, use func(context.Context) error) error {
				go func() { returned <- use(parent) }()
				<-entered
				if panicObserver {
					panic("original observer panic")
				}
				return nil
			}, func(observed context.Context) error {
				close(entered)
				<-observed.Done()
				close(joined)
				return observed.Err()
			})
			if err == nil {
				t.Fatal("early observer return admitted")
			}
		}()
		if <-returned == nil {
			t.Fatal("canceled comparison passed")
		}
		cancel()
	}
}

func priorToolSourceModel(t *testing.T) (*domainTCPGlobalSuccessor, *domainTCPPriorToolSource, *baselineCurrentComparisonRunner, context.Context) {
	t.Helper()
	p, ctx, cancel := domainPriorFileResourceModel(t)
	t.Cleanup(cancel)
	c := p.scope.domainSuccessor
	runner, toolRunner := &baselineCurrentComparisonRunner{}, &baselineCurrentComparisonRunner{}
	tools := &SyntheticDNSCommandTools{IP: "/sbin/ip", IPTables: "/sbin/iptables", ReviewSHA256: strings.Repeat("a", 64), Identity: netidentity.Identity{Version: 1, Kind: netidentity.ProcNetInode, BootID: "11111111-2222-3333-4444-555555555555", Inode: 42}, Provider: netidentity.NewProcProvider(), Runner: toolRunner}
	backend := &BackendInventory{review: tools.ReviewSHA256, reader: backendInventoryReader{Provider: tools.Provider, Runner: runner, IPTables: tools.IPTables, IP6Tables: "/sbin/ip6tables"}}
	old := &XrayDomainTCPExecutionResource{}
	capture := &domainTCPCaptureExecutionResource{process: old, tools: tools, backend: backend}
	capture.self = capture
	o := &DomainTCPOriginalScope{closed: true, standbyReady: true, captureResource: capture, process: old, binding: &SyntheticDNSExecutionBinding{scope: &executionResourceScope{}}, backend: backend, tools: *tools, source: runner}
	o.self = o
	d := &DomainTCPDetachedStandby{original: o, owner: &domainTCPStandbyOwner{original: o}}
	d.self = d
	entry := &domainTCPStandbyPoolEntry{detached: d}
	c.pool.entries = []*domainTCPStandbyPoolEntry{entry}
	c.pool.manager.domainPool = c.pool
	s := &domainTCPPriorToolSource{entry: entry, detached: d, owner: o, capture: capture, backend: backend, descriptor: tools, tools: *tools, source: runner, ip6: backend.reader.IP6Tables}
	return c, s, runner, ctx
}

func TestDomainPriorToolSourcesKeepOriginalLeaseAndFallback(t *testing.T) {
	for _, mode := range []string{"original", "source", "descriptor", "tools", "backend", "owner", "owner-open", "new-scope", "ip6", "abi", "custom", "cleanup", "prior"} {
		t.Run(mode, func(t *testing.T) {
			c, s, runner, ctx := priorToolSourceModel(t)
			if s.current(c) != nil {
				t.Fatal("original local associations unavailable")
			}
			switch mode {
			case "source":
				s.backend.reader.Runner = &baselineCurrentComparisonRunner{}
			case "descriptor":
				copy := *s.descriptor
				s.capture.tools = &copy
			case "tools":
				s.descriptor.Identity.Inode++
			case "backend":
				s.capture.backend = &BackendInventory{}
			case "owner":
				s.detached.original = &DomainTCPOriginalScope{}
			case "owner-open":
				s.owner.closed = false
			case "new-scope":
				s.owner.binding.scope = c.scope
			case "ip6":
				s.backend.reader.IP6Tables += "-foreign"
			case "abi":
				s.backend.reader.NFTABI++
			case "custom":
				s.backend.reader.Runner = &baselineCurrentUnobservedRunner{}
			case "cleanup":
				ctx = context.WithValue(ctx, domainTCPFailureCleanupKey{}, true)
			case "prior":
				ctx = context.WithValue(ctx, domainTCPPriorReadKey{}, true)
			}
			if mode != "original" && mode != "cleanup" && mode != "prior" && s.current(c) == nil {
				t.Fatal("captured source association survived replacement", mode)
			}
			// Missing actual process/receipt/kernel owners always refuse. Only
			// the unchanged original source may be asked for a byte observation.
			if c.comparePrior(ctx, false) == nil {
				t.Fatal("local model acquired native standby authority")
			}
			wantCalls := 0
			if mode == "original" || mode == "descriptor" || mode == "ip6" || mode == "abi" {
				wantCalls = 1 // Snapshot is created at the start of this comparison.
			}
			if runner.calls != wantCalls {
				t.Fatal("wrong original source or phase reached observer", mode, runner.calls)
			}
		})
	}
}
