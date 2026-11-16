package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

type baselineCurrentComparisonRunner struct{ calls int }

type baselineCurrentUnobservedRunner struct{}

func (*baselineCurrentUnobservedRunner) Run(context.Context, string, ...string) ([]byte, error) {
	return nil, errors.New("custom source cannot issue a byte loan")
}

func (r *baselineCurrentComparisonRunner) Run(context.Context, string, ...string) ([]byte, error) {
	r.calls++
	return nil, errors.New("comparison fixture cannot run")
}
func (r *baselineCurrentComparisonRunner) RunSyntheticDNS(context.Context, SyntheticDNSCommandAdmission, string, ...string) ([]byte, error) {
	r.calls++
	return nil, errors.New("comparison fixture cannot run")
}
func (r *baselineCurrentComparisonRunner) CheckSyntheticDNS(context.Context, netidentity.Identity) error {
	r.calls++
	return errors.New("comparison fixture cannot check")
}
func (r *baselineCurrentComparisonRunner) ReadDomainTCPBaseline(context.Context, netip.Addr, netip.Addr, string) (DomainTCPBaselineReadImage, error) {
	r.calls++
	return DomainTCPBaselineReadImage{}, errors.New("comparison fixture cannot read")
}
func (r *baselineCurrentComparisonRunner) WithReadOnlyToolObservation(context.Context, netidentity.Identity, string, func(context.Context) error) error {
	r.calls++
	return errors.New("comparison fixture cannot lend bytes")
}

// Real socket plus local associations only; neither a retained child nor an
// original tool source is fabricated. Full Current MUST still refuse.
func baselineCurrentComparison(t *testing.T) (*domainCaptureReadComparisonFixture, *domainTCPBaselineKernelOwner, *baselineCurrentComparisonRunner) {
	f := domainCaptureReadComparison(t)
	runner := &baselineCurrentComparisonRunner{}
	// The real producer has two different wrappers: syntheticDNSRunner for
	// baseline reads and the retained Lease for backend/tool observations.
	reader := &baselineCurrentComparisonRunner{}
	tools := &SyntheticDNSCommandTools{Runner: reader}
	backend := &BackendInventory{reader: backendInventoryReader{Runner: runner}}
	mapping := &dnscontrol.SyntheticDNSMapping{}
	f.material.mapping = mapping
	c := &domainTCPCaptureExecutionResource{capture: f.capture, process: f.process, mapping: mapping, tools: tools, backend: backend}
	c.self = c
	b := &syntheticBaselineExecutionResource{capture: f.capture, mapping: mapping, binding: f.binding, tools: tools, backend: backend}
	b.self = b
	r := &domainTCPBaselineKernelOwner{capture: c, baseline: b, reader: reader}
	r.self = r
	f.owner.kernel, f.owner.captureResource, f.owner.baseline, f.owner.source = r, c, b, runner
	return f, r, runner
}

func TestDomainBaselineCurrentReadContextKeepsOriginalBudget(t *testing.T) {
	for _, mode := range []string{"same", "shorter", "extended", "unbounded", "foreign", "cleanup", "parent-cancel", "child-cancel"} {
		t.Run(mode, func(t *testing.T) {
			parent, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			parent = context.WithValue(parent, syntheticExecutionRegistrarKey{}, &executionResourceScope{})
			child, childCancel := context.WithCancel(parent)
			defer childCancel()
			switch mode {
			case "shorter":
				child, childCancel = context.WithTimeout(parent, time.Second)
				defer childCancel()
			case "extended":
				child, childCancel = context.WithTimeout(context.WithoutCancel(parent), 2*time.Minute)
				defer childCancel()
			case "unbounded":
				child = context.WithoutCancel(parent)
			case "foreign":
				child = context.WithValue(child, syntheticExecutionRegistrarKey{}, &executionResourceScope{})
			case "cleanup":
				child = context.WithValue(child, domainTCPFailureCleanupKey{}, "foreign")
			case "parent-cancel":
				cancel()
			case "child-cancel":
				childCancel()
			}
			if (domainTCPBaselineCurrentReadContext(parent, child) == nil) != (mode == "same" || mode == "shorter") {
				t.Fatal("original callback budget or scope changed", mode)
			}
		})
	}
}

func TestDomainBaselineCurrentSourcesStayOriginal(t *testing.T) {
	for _, mode := range []string{"kernel-copy", "owner-copy", "owner-closed", "owner-kernel", "owner-source", "owner-process", "owner-capture", "owner-baseline", "capture", "process", "material", "material-resource", "binding", "scope", "mapping", "xray", "tools", "backend", "reader"} {
		t.Run(mode, func(t *testing.T) {
			f, r, runner := baselineCurrentComparison(t)
			s, original, err := r.originalCurrentSources(f.ctx)
			if err != nil || !original || s == nil {
				t.Fatal("local comparison unavailable", err)
			}
			switch mode {
			case "kernel-copy":
				r.self = &domainTCPBaselineKernelOwner{}
			case "owner-copy":
				f.owner.self = &DomainTCPOriginalScope{}
			case "owner-closed":
				f.owner.closed = true
			case "owner-kernel":
				f.owner.kernel = &domainTCPBaselineKernelOwner{}
			case "owner-source":
				f.owner.source = &baselineCurrentComparisonRunner{}
			case "owner-process":
				f.owner.process = &XrayDomainTCPExecutionResource{}
			case "owner-capture":
				f.owner.capture = &DomainPolicyTCPCapture{}
			case "owner-baseline":
				f.owner.baseline = &syntheticBaselineExecutionResource{}
			case "capture":
				r.capture.capture = &DomainPolicyTCPCapture{}
			case "process":
				r.capture.process = &XrayDomainTCPExecutionResource{}
			case "material":
				f.process.material = &XrayDomainTCPOperationMaterial{}
			case "material-resource":
				f.material.resource = &XrayDomainTCPExecutionResource{}
			case "binding":
				f.material.binding = &SyntheticDNSExecutionBinding{}
			case "scope":
				// Rebinding both aliases must not evade the original pointer.
				foreign := &executionResourceScope{}
				f.process.scope, f.binding.scope = foreign, foreign
			case "mapping":
				foreign := &dnscontrol.SyntheticDNSMapping{}
				r.capture.mapping, r.baseline.mapping, f.material.mapping = foreign, foreign, foreign
			case "xray":
				copy := *f.xray
				f.capture.xray = &copy
			case "tools":
				copy := *r.capture.tools
				r.capture.tools = &copy
			case "backend":
				copy := *r.capture.backend
				r.capture.backend = &copy
			case "reader":
				r.reader = &baselineCurrentComparisonRunner{}
			}
			if s.current(f.ctx, r) == nil {
				t.Fatal("late original source substitution accepted", mode)
			}
			if runner.calls != 0 {
				t.Fatal("association check invoked external source")
			}
		})
	}
}

func TestDomainBaselineCurrentComparisonCannotMintCurrent(t *testing.T) {
	f, r, runner := baselineCurrentComparison(t)
	if _, original, err := r.originalCurrentSources(f.ctx); err != nil || !original {
		t.Fatal(err)
	}
	if err := r.Current(f.ctx); err == nil {
		t.Fatal("comparison-only handles minted live baseline Current")
	}
	if runner.calls != 0 {
		t.Fatal("unowned opening reached source callback")
	}
	f.cancel()
	if _, _, err := r.originalCurrentSources(f.ctx); err == nil {
		t.Fatal("cancelled original source accepted")
	}
}

func TestDomainBaselineCurrentCleanupAndCustomFallback(t *testing.T) {
	for _, mode := range []string{"baseline-cleanup", "capture-cleanup", "failure-cleanup", "custom-owner", "custom-source"} {
		t.Run(mode, func(t *testing.T) {
			f, r, runner := baselineCurrentComparison(t)
			ctx := f.ctx
			switch mode {
			case "baseline-cleanup":
				ctx = context.WithValue(ctx, domainTCPBaselineCleanupKey{}, "malformed")
			case "capture-cleanup":
				ctx = context.WithValue(ctx, domainTCPCaptureCleanupKey{}, "malformed")
			case "failure-cleanup":
				ctx = context.WithValue(ctx, domainTCPFailureCleanupKey{}, "malformed")
			case "custom-owner":
				f.capture.owner = &syntheticTCPModelOwner{}
			case "custom-source":
				r.capture.backend.reader.Runner = &baselineCurrentUnobservedRunner{}
			}
			if s, original, err := r.originalCurrentSources(ctx); s != nil || original || err != nil {
				t.Fatal("fallback was replaced by private byte source", err)
			}
			before := r.currentWithFiles(ctx, nil)
			after := r.Current(ctx)
			if before == nil || after == nil || before.Error() != after.Error() || runner.calls != 0 {
				t.Fatal("original nil-view refusal changed", before, after)
			}
		})
	}
}
