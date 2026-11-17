//go:build linux && (amd64 || arm64) && razvilka_native_fixture

package startuptools

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestDomainBaselineReadTimingFixedLabelsAndEpoch(t *testing.T) {
	stop := StartDomainBaselineReadMeasurement()
	defer stop()
	cases := []struct {
		args   []string
		scoped bool
		prefix string
	}{
		{[]string{"-4", "-j", "rule", "show"}, true, "scoped/rules/"},
		{[]string{"-4", "-j", "route", "show", "table", "all"}, true, "scoped/routes-all/"},
		{[]string{"-j", "-details", "link", "show"}, true, "scoped/links/"},
		{[]string{"-4", "-j", "route", "get", "8.8.8.8", "from", "192.168.1.2", "iif", "lan-test"}, true, "scoped/forwarded-lookup/"},
		{[]string{"-4", "-j", "route", "get", "8.8.8.8", "from", "192.168.1.1"}, false, "standalone/direct-output/"},
	}
	for _, c := range cases {
		if !domainBaselineObservedRead(c.args) {
			t.Fatalf("test form refused: %s", c.prefix)
		}
		m := beginDomainBaselineReadMeasurement(c.args, c.scoped)
		before := DomainBaselineReadTimingSnapshot()
		if before[c.prefix+"incomplete"].Calls != 1 || before[c.prefix+"returned"].Calls != 0 {
			t.Fatalf("expected an incomplete attempt: %+v", before)
		}
		m.finish(false)
		after := DomainBaselineReadTimingSnapshot()
		if after[c.prefix+"returned"].Calls != 1 || after[c.prefix+"unstarted"].Calls != 1 ||
			after[c.prefix+"read-failed"].Calls != 1 || after[c.prefix+"incomplete"].Calls != 0 {
			t.Fatalf("unstarted refusal was not recorded: %+v", after)
		}
	}
	if got := len(DomainBaselineReadTimingSnapshot()); got != len(cases)*4 {
		t.Fatalf("unexpected keys: %+v", DomainBaselineReadTimingSnapshot())
	}
	late := beginDomainBaselineReadMeasurement(cases[0].args, true)
	stop()
	stopNext := StartDomainBaselineReadMeasurement()
	defer stopNext()
	stop() // An old stop must not close the new epoch.
	late.finish(false)
	m := beginDomainBaselineReadMeasurement(cases[0].args, true)
	m.finish(true)
	snapshot := DomainBaselineReadTimingSnapshot()
	if snapshot[cases[0].prefix+"call"].Calls != 1 || snapshot[cases[0].prefix+"returned"].Calls != 1 ||
		snapshot[cases[0].prefix+"read-failed"].Calls != 0 {
		t.Fatalf("different epochs mixed: %+v", snapshot)
	}
	delete(snapshot, cases[0].prefix+"call")
	if DomainBaselineReadTimingSnapshot()[cases[0].prefix+"call"].Calls != 1 {
		t.Fatal("snapshot aliases collector")
	}
}

func TestDomainBaselineReadTimingOriginalStartAndWait(t *testing.T) {
	stop := StartDomainBaselineReadMeasurement()
	defer stop()
	l := syntheticDNSLeaseModel(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rules := []string{"-4", "-j", "rule", "show"}
	command := exec.CommandContext(ctx, filepath.Join(t.TempDir(), "missing"))
	timing := beginDomainBaselineReadMeasurement(rules, false)
	err := l.runObservedReadMeasured(ctx, command, timing)
	timing.finish(err == nil)
	snapshot := DomainBaselineReadTimingSnapshot()
	if !errors.Is(err, os.ErrNotExist) || snapshot["standalone/rules/start-failed"].Calls != 1 ||
		snapshot["standalone/rules/started-to-wait"].Calls != 0 || snapshot["standalone/rules/unstarted"].Calls != 0 {
		t.Fatalf("Start failure reported incorrectly: %v %+v", err, snapshot)
	}

	routes := []string{"-4", "-j", "route", "show", "table", "all"}
	command = exec.CommandContext(ctx, "/bin/sh", "-c", "exit 7")
	timing = beginDomainBaselineReadMeasurement(routes, false)
	err = l.runObservedReadMeasured(ctx, command, timing)
	timing.finish(err == nil)
	var exit *exec.ExitError
	snapshot = DomainBaselineReadTimingSnapshot()
	if !errors.As(err, &exit) || exit.ExitCode() != 7 || snapshot["standalone/routes-all/started"].Calls != 1 ||
		snapshot["standalone/routes-all/started-to-wait"].Calls != 1 || snapshot["standalone/routes-all/wait-error"].Calls != 1 ||
		snapshot["standalone/routes-all/nonzero-exit"].Calls != 1 || snapshot["standalone/routes-all/child-user-cpu"].Calls != 1 ||
		snapshot["standalone/routes-all/child-system-cpu"].Calls != 1 {
		t.Fatalf("Wait result reported incorrectly: %v %+v", err, snapshot)
	}

	file, err := os.Open("/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	l.review.ipEntry.file = file
	deadline, _ := ctx.Deadline()
	o := &toolReadObservation{lease: l, review: l.review, identity: l.identity, digest: l.digest, active: true, deadline: deadline}
	o.self = o
	observed := context.WithValue(ctx, toolReadObservationKey{}, o)
	o.ctx = observed
	command = exec.CommandContext(observed, "/proc/self/fd/3", rules...)
	command.Args[0], command.Env, command.Dir = l.profile.ipAlias, l.profile.environment(), "/"
	command.ExtraFiles = []*os.File{file}
	command.Stdout, command.Stderr = &output{limit: 256, cancel: cancel}, &output{limit: 256, cancel: cancel}
	timing = beginDomainBaselineReadMeasurement(rules, true)
	err = l.runObservedReadMeasured(observed, command, timing)
	timing.finish(err == nil)
	snapshot = DomainBaselineReadTimingSnapshot()
	if err != nil || snapshot["scoped/rules/started-to-wait"].Calls != 1 ||
		snapshot["scoped/rules/child-user-cpu"].Calls != 1 || snapshot["scoped/rules/child-system-cpu"].Calls != 1 ||
		snapshot["scoped/rules/wait-error"].Calls != 0 {
		t.Fatalf("original scoped child did not start and join: %v %+v", err, snapshot)
	}
}

func TestDomainBaselineReadTimingOverflowSeparateFromExit(t *testing.T) {
	stop := StartDomainBaselineReadMeasurement()
	defer stop()
	l := syntheticDNSLeaseModel(t)
	args := []string{"-j", "-details", "link", "show"}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/bin/sh", "-c", "printf 'ab'")
	stdout := &output{limit: 1, cancel: cancel}
	command.Stdout = stdout
	timing := beginDomainBaselineReadMeasurement(args, false)
	err := l.runObservedReadMeasured(ctx, command, timing)
	timing.output(stdout.overflow, false, false)
	timing.finish(err == nil && !stdout.overflow)
	snapshot := DomainBaselineReadTimingSnapshot()
	if !stdout.overflow || snapshot["standalone/links/stdout-overflow"].Calls != 1 ||
		snapshot["standalone/links/started-to-wait"].Calls != 1 || snapshot["standalone/links/read-failed"].Calls != 1 ||
		snapshot["standalone/links/start-failed"].Calls != 0 {
		t.Fatalf("overflow was confused with another state: %v %+v", err, snapshot)
	}
}
