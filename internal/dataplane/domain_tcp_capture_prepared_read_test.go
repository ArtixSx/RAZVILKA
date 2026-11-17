package dataplane

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestDomainCapturePreparedReadSourceParity(t *testing.T) {
	raw, err := os.ReadFile("domain_tcp_capture_execution_effects.go")
	if err != nil {
		t.Fatal(err)
	}
	source := strings.ReplaceAll(string(raw), "\r\n", "\n")
	function := func(name string) string {
		t.Helper()
		start := strings.Index(source, "func (r *domainTCPCaptureExecutionResource) "+name+"(")
		if start < 0 {
			t.Fatal("missing source function", name)
		}
		end := strings.Index(source[start:], "\n}\n")
		if end < 0 {
			t.Fatal("missing source function end", name)
		}
		return source[start : start+end+2]
	}
	read := function("readWithFiles")
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(read))); got != "2912ce506cb77909adc1cd2aa09514ca20c322ab8ccb35ab016431ad60d15ea7" {
		t.Fatal("9971aa1b generic read body changed", got)
	}
	prepared := function("readOriginalPreparedWithFiles")
	opening := "\tif err := r.currentWithFiles(ctx, files); err != nil {"
	a, b := strings.Index(read, opening), strings.Index(read, "\treturn view, r.currentWithFiles(ctx, files)")
	c, d := strings.Index(prepared, opening), strings.Index(prepared, "\t// Even invalid rows")
	if a < 0 || b < a || c < 0 || d < c {
		t.Fatal("fixed read source bounds changed")
	}
	want := strings.TrimSpace(read[a:b])
	got := strings.TrimSpace(strings.ReplaceAll(prepared[c:d], "return true,", "return backendInventorySnapshot{},"))
	if got != want {
		t.Fatal("prepared opening/backend/coverage/counterfactual differs from original")
	}
	// Source-order contract, not a modeled successful process proof: the pure
	// failure cannot short-circuit the retained full closing or error join.
	tail := "prepared := errors.Join(association(), domainTCPCapturePreparedInventory(view.Rows, plan))\n\tclosing := r.currentWithFiles(ctx, files)\n\treturn true, errors.Join(prepared, closing, association(), ctx.Err())"
	if !strings.Contains(prepared, tail) || strings.Contains(prepared, "receipt.current()") {
		t.Fatal("pure failure/closing/error propagation changed")
	}
	check := function("checkPreparedWithFiles")
	branch := "\tif original, err := r.readOriginalPreparedWithFiles(ctx, files); original {\n\t\tif err != nil {\n\t\t\treturn err\n\t\t}\n\t\treturn errors.Join(receipt.current(), ctx.Err())\n\t}\n"
	if strings.Count(check, branch) != 1 {
		t.Fatal("failed read can reach receipt or lose context closing")
	}
	old := strings.Replace(check, branch, "", 1)
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(old))); got != "2fad517ddf86f7fc0f180f764db8fdec40316f17de863af049817afd1fd1f803" {
		t.Fatal("9971aa1b initial current/receipt/custom/cleanup path changed", got)
	}
}

func TestDomainCapturePreparedReadEligibilityAndFallback(t *testing.T) {
	for _, cut := range []string{"original", "pre-kernel", "custom-source", "custom-owner", "baseline-cleanup", "capture-cleanup", "failure-cleanup", "typed-nil-cleanup", "closed", "owner-copy", "nil-original", "pre-kernel-drift", "kernel-copy", "foreign-resource", "canceled"} {
		t.Run(cut, func(t *testing.T) {
			f, kernel, runner := baselineCurrentComparison(t)
			ctx := f.ctx
			supported, fails := true, false
			switch cut {
			case "pre-kernel":
				f.owner.kernel = nil
				supported = false
			case "custom-source":
				kernel.capture.backend.reader.Runner = &baselineCurrentUnobservedRunner{}
				supported = false
			case "custom-owner":
				f.capture.owner = &syntheticTCPModelOwner{}
				supported = false
			case "baseline-cleanup":
				ctx = context.WithValue(ctx, domainTCPBaselineCleanupKey{}, "malformed")
				supported = false
			case "capture-cleanup":
				ctx = context.WithValue(ctx, domainTCPCaptureCleanupKey{}, "malformed")
				supported = false
			case "failure-cleanup":
				ctx = context.WithValue(ctx, domainTCPFailureCleanupKey{}, "malformed")
				supported = false
			case "typed-nil-cleanup":
				ctx = context.WithValue(ctx, domainTCPCaptureCleanupKey{}, (*domainTCPCaptureExecutionResource)(nil))
				supported = false
			case "closed":
				f.owner.closed = true
				fails = true
			case "owner-copy":
				f.owner.self = &DomainTCPOriginalScope{}
				fails = true
			case "nil-original":
				f.capture.owner = (*DomainTCPOriginalScope)(nil)
				fails = true
			case "pre-kernel-drift":
				f.owner.kernel = nil
				f.owner.captureResource = &domainTCPCaptureExecutionResource{}
				fails = true
			case "kernel-copy":
				kernel.self = &domainTCPBaselineKernelOwner{}
				fails = true
			case "foreign-resource":
				f.owner.kernel = &domainTCPBaselineKernelOwner{}
				fails = true
			case "canceled":
				f.cancel()
				fails = true
			}
			sources, actualKernel, original, err := kernel.capture.originalPreparedReadSources(ctx)
			if original != supported || (err != nil) != fails {
				t.Fatal("wrong eligibility boundary", original, err)
			}
			if supported && !fails && (sources.resource != kernel.capture || actualKernel != kernel) {
				t.Fatal("foreign source selected")
			}
			if runner.calls != 0 {
				t.Fatal("eligibility called external source")
			}
		})
	}
}

func TestDomainCapturePreparedReadFrozenAssociationsAndInputs(t *testing.T) {
	for _, cut := range []string{"source", "owner", "process", "definition", "effect", "digest", "root", "relative", "anchor"} {
		t.Run(cut, func(t *testing.T) {
			f, kernel, runner := baselineCurrentComparison(t)
			r := kernel.capture
			r.definition = ExecutionDomainTCPCaptureDefinition{Schema: 1, Process: xrayDomainExecutionDefinitionFixture(t).Clone()}
			definition := r.definition.Clone()
			plan, err := compileDomainTCPCaptureEffects(definition.Process.Capture, definition.Process.Mapping)
			if err != nil {
				t.Fatal(err)
			}
			r.effects, err = compileDomainTCPCaptureEffects(definition.Process.Capture, definition.Process.Mapping)
			if err != nil {
				t.Fatal(err)
			}
			digest, err := PolicyEffectPlanDigest(plan)
			if err != nil {
				t.Fatal(err)
			}
			r.digest, r.root, r.relative = digest, t.TempDir(), "capture-original"
			anchor, err := os.Stat(r.root)
			if err != nil {
				t.Fatal(err)
			}
			r.anchor = anchor
			root, relative := r.root, r.relative
			sources, actualKernel, original, err := r.originalPreparedReadSources(f.ctx)
			if err != nil || !original || sources.current(f.ctx, actualKernel) != nil || !r.preparedReadInputsMatch(definition, plan, digest, root, relative, anchor) {
				t.Fatal("initial comparisons", err)
			}
			// Models a source callback changing input between bookends; these
			// comparison-only objects never fabricate full Current success.
			switch cut {
			case "source":
				kernel.reader = &baselineCurrentComparisonRunner{}
			case "owner":
				f.owner.closed = true
			case "process":
				r.process = &XrayDomainTCPExecutionResource{}
			case "definition":
				r.definition.Process.Capture.Xray.Generation += "changed"
			case "effect":
				r.effects.Effects[0].Add[0] = "changed"
			case "digest":
				r.digest += "changed"
			case "root":
				r.root += "changed"
			case "relative":
				r.relative += "changed"
			case "anchor":
				r.anchor, err = os.Stat(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
			}
			if sources.current(f.ctx, actualKernel) == nil && r.preparedReadInputsMatch(definition, plan, digest, root, relative, anchor) {
				t.Fatal("late input drift adopted")
			}
			if runner.calls != 0 {
				t.Fatal("local comparisons called runtime source")
			}
		})
	}
}

func TestDomainCapturePreparedReadCannotMintCurrent(t *testing.T) {
	f, kernel, runner := baselineCurrentComparison(t)
	r := kernel.capture
	r.definition = ExecutionDomainTCPCaptureDefinition{Schema: 1, Process: xrayDomainExecutionDefinitionFixture(t).Clone()}
	var err error
	r.effects, err = compileDomainTCPCaptureEffects(r.definition.Process.Capture, r.definition.Process.Mapping)
	if err != nil {
		t.Fatal(err)
	}
	r.digest, err = PolicyEffectPlanDigest(r.effects)
	if err != nil {
		t.Fatal(err)
	}
	r.root, r.relative = t.TempDir(), "original"
	r.anchor, err = os.Stat(r.root)
	if err != nil {
		t.Fatal(err)
	}
	if original, err := r.readOriginalPreparedWithFiles(f.ctx, nil); !original || err == nil {
		t.Fatal("comparison inputs minted process readiness", err)
	}
	if runner.calls != 0 {
		t.Fatal("failed opening reached backend callback")
	}
	if err := r.checkPreparedWithFiles(f.ctx, nil); err == nil {
		t.Fatal("failed initial current reached receipt or readiness")
	}
	if runner.calls != 0 {
		t.Fatal("failed initial current reached callback")
	}
}
