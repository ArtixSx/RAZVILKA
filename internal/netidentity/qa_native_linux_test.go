//go:build linux && (amd64 || arm64)

package netidentity

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"
)

// Root-only readonly QA. Never print actual errors, metadata, identity or paths.
// Labels are code constants; values are booleans or bounded image indices.
func TestNativeReviewedStockSanitizedStages(t *testing.T) {
	if os.Getenv("RAZVILKA_NETIDENTITY_DIAGNOSTIC") != "1" {
		t.Skip("Root diagnostic opt-in")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	stage := func(label string, ok bool) {
		t.Logf("stage=%s ok=%t", label, ok)
		if !ok {
			t.Fatalf("blocked_stage=%s capability=ungranted", label)
		}
	}
	_, factoryErr := NewReviewedStockNC1812Provider(ctx)
	t.Logf("stage=factory ok=%t capability=ungranted", factoryErr == nil)
	if factoryErr == nil {
		return
	}
	stage("budget-active", ctx.Err() == nil)
	o := captureProc(ctx)
	c := o.Checks
	for _, check := range []struct {
		label string
		ok    bool
	}{
		{"proc.thread-lock", c.ThreadLocked}, {"proc.root", c.ProcRootVerified},
		{"proc.anchored-walk", c.AnchoredWalkVerified}, {"proc.mount", c.SameProcMount},
		{"proc.position", c.FreshPositionZero}, {"proc.dirents", c.RawDirentsValid},
		{"proc.dots", c.DotsPresent}, {"proc.pid-tid", c.SamePIDTID},
		{"proc.task-start", c.SameTaskStart}, {"proc.boot-bracket", c.SameBoot},
		{"proc.uname-bracket", c.SameKernelRelease}, {"proc.mount-bracket", c.SameMountLayout},
		{"proc.self-links", c.SelfLinksMatch}, {"proc.held-fds", c.HeldDescriptorsStable},
		{"proc.reopened-paths", c.ReopenedPathStable}, {"proc.complete", o.DirectoryComplete},
		{"proc.mnt-present", o.MntPresent}, {"proc.observation-valid", o.ObservationValid},
	} {
		stage(check.label, check.ok)
	}
	profile := nc1812Profile()
	opening, err := identityFromObservation(o, &profile)
	stage("proc.typed-identity", err == nil)
	release, machine, ok := kernelTuple()
	stage("build.uname-exact", ok && release == profile.KernelRelease && machine == profile.Machine)
	_, err = os.Lstat("/etc/ld.so.preload")
	stage("build.preload-absent", errors.Is(err, os.ErrNotExist))
	_, preloadNodes, err := protectedPath("/etc")
	stage("build.preload-parent", err == nil)
	_, _, err = protectedPath("/bin/ndmc")
	stage("build.executable-path", err == nil)
	s := &systemImages{seen: map[string]bool{}}
	defer s.close()
	image, err := s.open(ctx, "/bin/ndmc", true)
	stage("build.executable-open-hash", err == nil)
	depsErr := s.dependencies(ctx, image)
	for n, candidate := range s.files {
		known, over := qaNoBitsOverFile(ctx, candidate.file, candidate.info.Size())
		t.Logf("image=%d nobits_probe_known=%t nobits_over_file=%t", n, known, over)
		e, err := boundedELF(ctx, candidate.file, candidate.info.Size())
		t.Logf("image=%d elf_preflight_ok=%t", n, err == nil)
		if err == nil {
			libs, err := e.ImportedLibraries()
			t.Logf("image=%d needed_parse_bounded_ok=%t", n, err == nil && len(libs) <= 32)
			_ = e.Close()
		}
	}
	stage("build.dependencies", depsErr == nil)
	stage("build.images-before", s.unchanged(ctx))
	stdout, stderr := &cappedOutput{limit: 8192}, &cappedOutput{limit: 1024}
	// Same fixed FD, argv, environment and bounds as production readBuild.
	cmd := exec.CommandContext(ctx, "/proc/self/fd/3", "-c", "show version")
	cmd.Args[0] = "/bin/ndmc"
	cmd.ExtraFiles = []*os.File{image.file}
	cmd.Env = []string{"PATH=/bin:/sbin:/usr/bin:/usr/sbin", "LD_LIBRARY_PATH=/lib:/usr/lib", "LANG=C", "LC_ALL=C"}
	cmd.Dir = "/"
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.WaitDelay = 50 * time.Millisecond
	runErr := cmd.Run()
	t.Logf("stage=ndmc.status joined_ok=%t stdout_bounded=%t stderr_bounded=%t stderr_empty=%t budget_active=%t", runErr == nil, !stdout.exceeded, !stderr.exceeded, len(stderr.data) == 0, ctx.Err() == nil)
	stage("ndmc.fixed-command", runErr == nil && !stdout.exceeded && !stderr.exceeded && len(stderr.data) == 0 && ctx.Err() == nil)
	stage("build.images-after", s.unchanged(ctx))
	_, err = os.Lstat("/etc/ld.so.preload")
	stage("build.preload-after", errors.Is(err, os.ErrNotExist) && nodesUnchanged(preloadNodes))
	afterRelease, afterMachine, ok := kernelTuple()
	stage("build.uname-after", ok && release == afterRelease && machine == afterMachine)
	build, err := parseBuild(stdout.data)
	stage("build.tuple-parse", err == nil)
	stage("build.tuple-exact", build == profile.Build)
	closing, err := readObservation(ctx)
	stage("proc.closing-observation", err == nil)
	closed, err := identityFromObservation(closing, &profile)
	stage("proc.closing-identity", err == nil && closed == opening && closing.KernelRelease == o.KernelRelease && closing.Machine == o.Machine)
	stage("budget-closing", ctx.Err() == nil)
	t.Fatal("factory refusal not repeated by one-command stage probe; capability=ungranted")
}
