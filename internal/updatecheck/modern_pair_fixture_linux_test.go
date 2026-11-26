//go:build linux && amd64 && razvilka_native_fixture

package updatecheck

import (
	"context"
	"errors"
	"os/exec"
	"reflect"
	"testing"
)

func TestNativeModernPublishedHandoff(t *testing.T) {
	_, u, _ := fileAdapterFixture(t)
	job := u.Snapshot()
	if nativeModernInitialHandoff(job) {
		t.Fatal("ready review is not a launched handoff")
	}
	called := 0
	u.launch = func(ctx context.Context, id string, admission func(func() error) error) (int, error) {
		called++
		published, err := readAdapterRecord(u.Directory, id)
		if err != nil || !nativeModernInitialHandoff(published.Job) {
			t.Fatal("actual Apply did not publish the expected handoff before launcher", err)
		}
		for _, change := range []func(*Job){
			func(j *Job) { j.State = "ready" }, func(j *Job) { j.Stage = "ready" },
			func(j *Job) { j.HelperPID = 23 }, func(j *Job) { j.CanApply = true },
			func(j *Job) { j.CanCancel = true }, func(j *Job) { j.ReviewToken = "retained" },
		} {
			changed := published.Job
			change(&changed)
			if nativeModernInitialHandoff(changed) {
				t.Fatal("changed initial handoff accepted")
			}
		}
		return 345678, admission(func() error { return nil })
	}
	result, err := u.Apply(context.Background(), job.ID, job.ReviewToken, 7, "config-fixture")
	if err != nil || called != 1 || result.HelperPID != 345678 {
		t.Fatal("actual handoff failed", called, result, err)
	}
}

func TestNativeModernAbsentAndInvalidMarker(t *testing.T) {
	for _, marker := range []string{"", "invalid"} {
		t.Run(marker, func(t *testing.T) {
			t.Setenv("RAZVILKA_MODERN_PAIR_NATIVE", marker)
			cmd := exec.Command("/not-a-fixture", "unrelated")
			cmd.Env = []string{"UNCHANGED=1"}
			before := append([]string(nil), cmd.Env...)
			closeSource, err := bindNativeModernInstaller(context.Background(), cmd, "invalid")
			closeSource()
			if (err == nil) != (marker == "") || !reflect.DeepEqual(before, cmd.Env) || len(cmd.ExtraFiles) != 0 {
				t.Fatal("marker changed unrelated command", err)
			}
			if err := nativeModernPairLiveFailure(context.Background(), nil, "invalid", true); err != nil {
				t.Fatal("negative fixture changed successful rollback", err)
			}
		})
	}
}

func TestNativeModernClosedCommandList(t *testing.T) {
	for _, command := range []string{"stop-old-panel", "prepare-private-state", "quiesce-old-runtime", "start-candidate-panel", "stop-candidate-panel", "restore-private-state", "start-rollback-panel"} {
		if !nativeModernCommand(command) {
			t.Fatal(command)
		}
	}
	for _, command := range []string{"", "start", "stop", "restore", "accept-live", "start-candidate-panel\x00", "quiesce-old-runtime extra"} {
		if nativeModernCommand(command) {
			t.Fatal("unexpected command admitted", command)
		}
	}
	for _, ctx := range []context.Context{nil, func() context.Context { ctx, cancel := context.WithCancel(context.Background()); cancel(); return ctx }()} {
		cmd := exec.Command("unused")
		cmd.Env = commandEnvironment()
		closeSource, err := nativeModernAttach(ctx, cmd, "/root/not-issued", false)
		closeSource()
		if !errors.Is(err, ErrFileProtocol) || len(cmd.ExtraFiles) != 0 {
			t.Fatal("invalid lifetime attached descriptor", err)
		}
	}
}
