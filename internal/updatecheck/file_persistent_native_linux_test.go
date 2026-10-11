//go:build linux

package updatecheck_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/app"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

const nativeCrashDirectory = "RAZVILKA_TEST_NATIVE_FILE_CRASH_DIRECTORY"

func nativeContextGuard(ctx context.Context) error { return ctx.Err() }

type crashAfterCommand struct {
	*updatecheck.SelfUpdateFileAdapter
	command string
}

func (a crashAfterCommand) Run(ctx context.Context, id, command string) error {
	if err := a.SelfUpdateFileAdapter.Run(ctx, id, command); err != nil {
		return err
	}
	if command == a.command {
		os.Exit(86) // real worker joined; Execute's checkpoint has not run
	}
	return nil
}

type nativeFileImage struct {
	data []byte
	info os.FileInfo
}

func captureNativeImages(t *testing.T, paths []string) map[string]nativeFileImage {
	t.Helper()
	images := make(map[string]nativeFileImage, len(paths))
	for _, path := range paths {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			images[path] = nativeFileImage{}
			continue
		}
		if err != nil || !info.Mode().IsRegular() {
			t.Fatal("capture regular file", path, err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		images[path] = nativeFileImage{data, info}
	}
	return images
}

func assertNativeImages(t *testing.T, images map[string]nativeFileImage, sameInode bool) {
	t.Helper()
	for path, image := range images {
		info, err := os.Lstat(path)
		if image.info == nil {
			if !errors.Is(err, os.ErrNotExist) {
				t.Fatal("absent image changed", path, err)
			}
			continue
		}
		data, readErr := os.ReadFile(path)
		if err != nil || readErr != nil || !bytes.Equal(data, image.data) || info.Mode() != image.info.Mode() || sameInode && !os.SameFile(info, image.info) {
			t.Fatal("retained image bytes/mode/inode changed", path, err, readErr)
		}
		before, beforeOK := image.info.Sys().(*syscall.Stat_t)
		after, afterOK := info.Sys().(*syscall.Stat_t)
		if !beforeOK || !afterOK || before.Uid != after.Uid || before.Gid != after.Gid {
			t.Fatal("image owner changed", path)
		}
	}
}

func persistentConsumer(t *testing.T, coordinates updatecheck.NativeFileAcceptanceCoordinates) *app.SelfUpdateFiles {
	t.Helper()
	a := updatecheck.NativeFileAcceptanceReopen(t, coordinates.Directory, coordinates.ID)
	return &app.SelfUpdateFiles{Installation: coordinates.Installation, Directory: coordinates.Journal, ControlRoot: coordinates.Control, Adapter: a}
}

// Root executes this exact case natively. All mutations stay in TempDir. The
// consumer is production SelfUpdateFiles.Action; the relocated native adapter
// retains its existing explicit fixture limitations, not production main or
// network/LKG acceptance. Neither unknown commands nor file state are reset.
func TestNativeSelfUpdatePersistentCrashRecovery(t *testing.T) {
	if directory := os.Getenv(nativeCrashDirectory); directory != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		id := os.Getenv("RAZVILKA_TEST_NATIVE_FILE_CRASH_ID")
		a := updatecheck.NativeFileAcceptanceReopen(t, directory, id)
		revision, _, _, err := a.Review(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		installation := os.Getenv("RAZVILKA_TEST_NATIVE_FILE_CRASH_INSTALLATION")
		f := &app.SelfUpdateFiles{Installation: installation, Directory: filepath.Join(installation, "razvilka/state/self-update-files"), ControlRoot: updatecheck.NativeFileAcceptanceControl(t, ctx, a, id), Adapter: a}
		action := os.Getenv("RAZVILKA_TEST_NATIVE_FILE_CRASH_ACTION")
		resume := os.Getenv("RAZVILKA_TEST_NATIVE_FILE_CRASH_RESUME") == "1"
		if effect := os.Getenv("RAZVILKA_TEST_NATIVE_FILE_CRASH_EFFECT"); effect != "" {
			updatecheck.NativeFileAcceptanceCrashAtEffect(a, effect, os.Getenv("RAZVILKA_TEST_NATIVE_FILE_CRASH_AFTER") == "1")
		} else if !resume {
			f.Adapter = crashAfterCommand{a, action}
		}
		if err := f.Action(ctx, id, action, revision, nativeContextGuard); err != nil {
			t.Fatal("native crash action refused before cut", err)
		}
		if resume {
			return
		}
		t.Fatal("native crash cut did not execute")
	}

	a, helper, c, joinPanel := updatecheck.NativeFileAcceptanceFixture(t)
	f := &app.SelfUpdateFiles{Installation: c.Installation, Directory: c.Journal, ControlRoot: c.Control, Adapter: a, Helper: helper}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	started := time.Now()
	alive := func() {
		t.Helper()
		if err := ctx.Err(); err != nil {
			t.Fatal("original persistent fixture context expired", err)
		}
	}
	action := func(name string) {
		t.Helper()
		if err := f.Action(ctx, c.ID, name, c.Revision, nativeContextGuard); err != nil {
			t.Fatal(name, err)
		}
		t.Logf("persistent native action=%s elapsed=%s", name, time.Since(started).Round(time.Millisecond))
	}
	runChild := func(name, effect string, after, resume bool) {
		t.Helper()
		binary, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		child := exec.CommandContext(ctx, binary, "-test.run=^TestNativeSelfUpdatePersistentCrashRecovery$", "-test.v", "-test.timeout=4m")
		child.Env = append(os.Environ(), nativeCrashDirectory+"="+c.Directory,
			"RAZVILKA_TEST_NATIVE_FILE_CRASH_ID="+c.ID, "RAZVILKA_TEST_NATIVE_FILE_CRASH_INSTALLATION="+c.Installation,
			"RAZVILKA_TEST_NATIVE_FILE_CRASH_ACTION="+name, "RAZVILKA_TEST_NATIVE_FILE_CRASH_EFFECT="+effect,
			fmt.Sprintf("RAZVILKA_TEST_NATIVE_FILE_CRASH_AFTER=%d", map[bool]int{false: 0, true: 1}[after]),
			fmt.Sprintf("RAZVILKA_TEST_NATIVE_FILE_CRASH_RESUME=%d", map[bool]int{false: 0, true: 1}[resume]))
		out, err := child.CombinedOutput()
		var exit *exec.ExitError
		if resume && err != nil || !resume && (!errors.As(err, &exit) || exit.ExitCode() != 86) {
			t.Fatalf("child action=%s effect=%s after=%t resume=%t: %v\n%s", name, effect, after, resume, err, out)
		}
		t.Logf("persistent child action=%s effect=%s after=%t resume=%t elapsed=%s", name, effect, after, resume, time.Since(started).Round(time.Millisecond))
		// The crashed process's actual writer/control locks must be reusable.
		f = persistentConsumer(t, c)
	}
	crash := func(name, effect string, after bool) { t.Helper(); runChild(name, effect, after, false) }
	recover := func(name string) { t.Helper(); runChild(name, "", false, true) }
	current := func(phase string) selfupdatejournal.Receipt {
		t.Helper()
		alive()
		r, present, err := f.Current()
		if err != nil || !present || r.ID != c.ID || r.Phase != phase || !r.Pending() {
			t.Fatal("persistent receipt", phase, r, err)
		}
		return r
	}

	control := captureNativeImages(t, []string{filepath.Join(c.Control, ".control.lock"), filepath.Join(c.Control, "current-v1.json")})
	_, _, files, err := a.Review(ctx, c.ID)
	if err != nil || len(files) != 6 {
		t.Fatal("six reviewed files", err)
	}
	paths := make([]string, 0, 6)
	for _, file := range files {
		paths = append(paths, filepath.Join(c.Installation, file.Target))
	}
	old := captureNativeImages(t, paths)
	private := filepath.Join(c.Installation, "etc/razvilka/admin.token")
	if err := os.WriteFile(private, []byte("original private token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	action("prepare")
	action("stop-old-panel")
	joinPanel()
	action("prepare-private-state")
	crash("quiesce-old-runtime", "", false)
	r := current("command-started")
	if r.Command != "quiesce-old-runtime" || !r.BeforeFiles {
		t.Fatal("missing unknown pre-files command", r)
	}
	commandPath := filepath.Join(c.Directory, c.ID, "quiesce-old-runtime.process.json")
	commands := captureNativeImages(t, []string{commandPath, filepath.Join(c.Directory, c.ID, ".quiesce-old-runtime.lock")})
	unknown := captureNativeImages(t, []string{filepath.Join(c.Journal, c.ID, "receipt.json")})
	if err := f.Action(ctx, c.ID, "quiesce-old-runtime", c.Revision, nativeContextGuard); !errors.Is(err, selfupdatejournal.ErrUnknown) {
		t.Fatal("unknown command replay allowed", err)
	}
	alive()
	assertNativeImages(t, unknown, true)
	recover("resolve-unknown")
	assertNativeImages(t, commands, true)
	r = current("prepared")
	if !reflect.DeepEqual(r.Commands, []string{"stop-old-panel", "prepare-private-state", "quiesce-old-runtime"}) {
		t.Fatal("pre-files sequence", r.Commands)
	}
	updatecheck.NativeFileAcceptanceCompletedCommands(t, a, c.ID, r.Commands...)
	retainedPaths := []string{filepath.Join(c.Directory, c.ID, "file-review.json"), filepath.Join(c.Directory, c.ID, "helper.identity.json"), filepath.Join(c.Directory, c.ID, "control.bin"), filepath.Join(c.Journal, ".writer.lock")}
	for i := range files {
		retainedPaths = append(retainedPaths, filepath.Join(c.Journal, c.ID, fmt.Sprintf("new-%d", i)), filepath.Join(c.Journal, c.ID, fmt.Sprintf("old-%d", i)))
	}
	retained := captureNativeImages(t, retainedPaths)
	for _, cut := range []struct {
		effect string
		after  bool
	}{{"install-file-0", false}, {"install-file-0", true}, {"install-file-2", true}, {"install-file-5", true}} {
		crash("install", cut.effect, cut.after)
		r := current("installing")
		index, err := strconv.Atoi(cut.effect[len("install-file-"):])
		if err != nil || r.Index != index {
			t.Fatal("rename cut checkpoint index", r.Index, cut.effect, err)
		}
		if cut.after {
			data, err := os.ReadFile(paths[index])
			if err != nil || fmt.Sprintf("%x", sha256.Sum256(data)) != files[index].SHA256 {
				t.Fatal("actual rename did not precede process crash", cut.effect, err)
			}
		} else {
			assertNativeImages(t, old, true)
			// A third configuration image must fence matching recovery before
			// any file effect. Restore only this test's deliberately edited file.
			configPath := filepath.Join(c.Installation, "etc/razvilka/config.json")
			if err := os.WriteFile(configPath, append(append([]byte(nil), old[configPath].data...), '\n', '\n'), 0600); err != nil {
				t.Fatal(err)
			}
			foreign := captureNativeImages(t, append(append([]string(nil), paths...), filepath.Join(c.Journal, c.ID, "receipt.json")))
			if err := f.Action(ctx, c.ID, "install", c.Revision, nativeContextGuard); err == nil {
				t.Fatal("third config image admitted matching recovery")
			}
			alive()
			assertNativeImages(t, foreign, true)
			if err := os.WriteFile(configPath, old[configPath].data, old[configPath].info.Mode().Perm()); err != nil {
				t.Fatal(err)
			}
		}
		assertNativeImages(t, retained, true)
		assertNativeImages(t, control, true)
	}
	recover("install")
	current("installed")
	for _, file := range files {
		data, err := os.ReadFile(filepath.Join(c.Installation, file.Target))
		if err != nil || fmt.Sprintf("%x", sha256.Sum256(data)) != file.SHA256 {
			t.Fatal("candidate bytes after resumed installation", file.Target, err)
		}
	}
	for _, effect := range []string{"rollback-file-0", "rollback-file-2", "rollback-file-5"} {
		crash("restore", effect, true)
		r := current("restoring")
		index, err := strconv.Atoi(effect[len("rollback-file-"):])
		if err != nil || r.Index != index {
			t.Fatal("rollback cut checkpoint index", r.Index, effect, err)
		}
		assertNativeImages(t, map[string]nativeFileImage{paths[index]: old[paths[index]]}, false)
		assertNativeImages(t, retained, true)
		assertNativeImages(t, control, true)
	}
	recover("restore")
	current("restored")
	assertNativeImages(t, old, false)
	settled := captureNativeImages(t, paths)
	action("restore") // a known restored retry must not replace equal files
	assertNativeImages(t, settled, true)
	if err := os.WriteFile(private, []byte("candidate private token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	crash("restore-private-state", "", false)
	current("command-started")
	privateReceipt := captureNativeImages(t, []string{filepath.Join(c.Directory, c.ID, "restore-private-state.process.json")})
	recover("resolve-unknown")
	assertNativeImages(t, privateReceipt, true)
	updatecheck.NativeFileAcceptanceCompletedCommands(t, a, c.ID, "restore-private-state")
	if data, err := os.ReadFile(private); err != nil || string(data) != "original private token\n" {
		t.Fatal("persistent private rollback", err)
	}
	if err := f.Action(ctx, c.ID, "accept-rollback", c.Revision, nativeContextGuard); err == nil {
		t.Fatal("data-only recovery accepted without actual live runtime")
	}
	current("command-finished")
	if _, err := operationgate.RequestSelfUpdateStop(ctx, c.Control, c.ID, c.Revision); err != nil {
		t.Fatal(err)
	}
	stopped := captureNativeImages(t, []string{filepath.Join(c.Control, ".control.lock"), filepath.Join(c.Control, "current-v1.json"), filepath.Join(c.Control, "stop-"+c.ID+".json")})
	for _, name := range []string{"install", "start-rollback-panel", "accept-rollback"} {
		if err := f.Action(ctx, c.ID, name, c.Revision, nativeContextGuard); err == nil {
			t.Fatal("Stop admitted forward/live action", name)
		}
		alive()
	}
	assertNativeImages(t, stopped, true)
	assertNativeImages(t, settled, true)
	assertNativeImages(t, retained, true)
	if !f.Pending() {
		t.Fatal("data-only recovery opened ordinary startup")
	}
	t.Log("persistent native recovery cuts=9; live_accepted=false; recovery_required=true; Stop preserved")
}
