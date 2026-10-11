package app

import (
	"bytes"
	"context"
	"errors"
	"log"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func captureXrayDiagnosticLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var out bytes.Buffer
	writer, flags, prefix := log.Writer(), log.Flags(), log.Prefix()
	log.SetOutput(&out)
	log.SetFlags(0)
	log.SetPrefix("")
	t.Cleanup(func() { log.SetOutput(writer); log.SetFlags(flags); log.SetPrefix(prefix) })
	return &out
}

func TestManagedXrayPrepareFailureLogIsClosedAndPrivate(t *testing.T) {
	out := captureXrayDiagnosticLog(t)
	for _, phase := range []string{"input", "scope-acquire", "source-review", "source-prepare", "shape", "primary-review", "material-review", "plan-build", "closing-current", "private/path/node-id"} {
		out.Reset()
		logManagedXrayPrepareFailure(phase, time.Hour, xrayDiagnosticPrivateError{})
		want := phase
		if strings.HasPrefix(phase, "private") {
			want = "unclassified"
		}
		if out.String() != "Managed Xray prepare refused substage="+want+" elapsed_ms=120000\n" {
			t.Fatal("fixed phase/duration log changed or leaked", out.String())
		}
	}
	out.Reset()
	logManagedXrayPrepareFailure("source-prepare", -time.Second, errors.Join(context.Canceled, context.DeadlineExceeded))
	if out.String() != "Managed Xray prepare refused substage=source-prepare elapsed_ms=0\n" {
		t.Fatal("joined cancellation leaked or negative duration escaped", out.String())
	}
	out.Reset()
	logManagedXrayPrepareFailure("source-prepare", time.Second, nil)
	if out.Len() != 0 {
		t.Fatal("successful preparation logged a refusal")
	}
}

func TestManagedXrayPrepareInputRefusalKeepsOriginalErrorAndCaller(t *testing.T) {
	out := captureXrayDiagnosticLog(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	// The actual private input guard rejects before acquiring any owner. No
	// copied runtime/source or native execution permission is constructed.
	e := &managedXraySelectedTCPListExecution{}
	for _, candidates := range [][]*xrayAutonomyCandidate{{nil}, {nil, nil}} {
		out.Reset()
		compilation, err := e.prepare(ctx, "private-service-id", candidates...)
		currentDeadline, _ := ctx.Deadline()
		if compilation != nil || err != ErrXrayListSource || ctx.Err() != nil || currentDeadline != deadline || e.scope != nil || e.source != nil || e.preparation != nil || e.material != nil {
			t.Fatal("observation changed original refusal, deadline or owner state")
		}
		match := regexp.MustCompile(`^Managed Xray prepare refused substage=input elapsed_ms=([0-9]+)\n$`).FindStringSubmatch(out.String())
		if len(match) != 2 {
			t.Fatal("actual prepare boundary did not log its closed input refusal", out.String())
		}
		elapsed, err := strconv.ParseInt(match[1], 10, 64)
		if err != nil || elapsed < 0 || elapsed > 120000 {
			t.Fatal("actual phase duration escaped bound")
		}
	}
}

func TestManagedXrayReviewTimingLogsExistingOriginalScopeHooks(t *testing.T) {
	out := captureXrayDiagnosticLog(t)
	a, binding, _ := listScopeFixture(t, "mac", false)
	// Actual Store/control/scope/admission; physical and WAN observations are
	// the existing explicit models. This test claims no native/router PASS.
	listScopeOperation(t, a, func(ctx context.Context) {
		measured, finish := beginManagedNFQTimings(ctx)
		if _, err := binding.Observe(measured); err != nil {
			t.Fatal(err)
		}
		finish("xray-review", context.DeadlineExceeded)
	})
	for _, fixed := range []string{"outer=xray-review inner=runtime-operation reason=DEADLINE_EXCEEDED total_ms=", "leaf=physical-verify calls=2 elapsed_ms=", "leaf=wan-profile calls=2 elapsed_ms="} {
		if !strings.Contains(out.String(), fixed) {
			t.Fatal("existing original timing hook did not reach closed Xray log", fixed, out.String())
		}
	}
	if strings.Contains(out.String(), "leaf=physical-acquire") {
		t.Fatal("measurement manufactured another acquisition")
	}
}
