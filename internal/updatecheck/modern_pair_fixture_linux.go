//go:build linux && amd64 && razvilka_native_fixture

package updatecheck

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"golang.org/x/sys/unix"
)

// Lab inputs identify actual built files and a retained namespace, not a
// release/receipt/Stop/effect grant. Every original production check still runs.
type nativeModernPairSpec struct {
	SourceSHA256      string `json:"source_sha256"`
	CandidateSHA256   string `json:"candidate_sha256"`
	InitSHA256        string `json:"init_sha256"`
	InterpreterSHA256 string `json:"interpreter_sha256"`
	LauncherSHA256    string `json:"launcher_sha256"`
	DaemonSHA256      string `json:"daemon_sha256"`
	NamespaceDevice   uint64 `json:"namespace_device"`
	NamespaceInode    uint64 `json:"namespace_inode"`
}

func nativeModernPairInputs(ctx context.Context) (nativeModernPairSpec, string, error) {
	var spec nativeModernPairSpec
	if ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 || os.Getenv("RAZVILKA_MODERN_PAIR_NATIVE") != "1" || os.Getenv("RAZVILKA_RUNTIME_NATIVE_OUTER_NET_FD") != "3" {
		return spec, "", ErrFileProtocol
	}
	root := os.Getenv("TMPDIR")
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || filepath.Dir(root) != "/root" || !strings.HasPrefix(filepath.Base(root), "razvilka-modern-pair.") || os.Getenv("RAZVILKA_RUNTIME_NATIVE_REVIEW") != filepath.Join(root, "runtime-native-tool-review.json") {
		return spec, "", ErrFileProtocol
	}
	for i, path := range []string{root, filepath.Join(root, "runtime-native-tool-review.json"), filepath.Join(root, "modern-pair-native.json")} {
		info, err := os.Lstat(path)
		if err != nil {
			return spec, "", err
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != 0 || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 || i == 0 && !info.IsDir() || i != 0 && (!info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 4096) {
			return spec, "", ErrFileProtocol
		}
	}
	path := filepath.Join(root, "modern-pair-native.json")
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return spec, "", err
	}
	before, beforeErr := file.Stat()
	decoder := json.NewDecoder(io.LimitReader(file, 4097))
	decoder.DisallowUnknownFields()
	readErr := decoder.Decode(&spec)
	trailing := decoder.Decode(new(any))
	after, afterErr := file.Stat()
	named, namedErr := os.Lstat(path)
	closeErr := file.Close()
	if beforeErr != nil || readErr != nil || trailing != io.EOF || afterErr != nil || namedErr != nil || closeErr != nil || !sameScriptInterpreterGeneration(before, after) || !sameScriptInterpreterGeneration(before, named) {
		return spec, "", ErrFileProtocol
	}
	for _, digest := range []string{spec.SourceSHA256, spec.CandidateSHA256, spec.InitSHA256, spec.InterpreterSHA256, spec.LauncherSHA256, spec.DaemonSHA256} {
		if !validDigest("sha256:" + digest) {
			return spec, "", ErrFileProtocol
		}
	}
	if spec.SourceSHA256 == spec.CandidateSHA256 || spec.NamespaceDevice == 0 || spec.NamespaceInode == 0 {
		return spec, "", ErrFileProtocol
	}
	typeID, err := unix.IoctlRetInt(3, unix.NS_GET_NSTYPE)
	var outer, current syscall.Stat_t
	if err != nil || typeID != unix.CLONE_NEWNET || syscall.Fstat(3, &outer) != nil || syscall.Stat("/proc/self/ns/net", &current) != nil || uint64(outer.Dev) != spec.NamespaceDevice || outer.Ino != spec.NamespaceInode || outer.Dev == current.Dev && outer.Ino == current.Ino {
		return spec, "", ErrFileProtocol
	}
	launcher := filepath.Join(root, "modern-daemon.py")
	if checkRootOwnedPath(launcher) != nil {
		return spec, "", ErrFileProtocol
	}
	digest, err := hashRegularFile(launcher, 64<<10)
	if err != nil || digest != spec.LauncherSHA256 {
		return spec, "", ErrFileProtocol
	}
	return spec, root, ctx.Err()
}

func nativeModernPairHeader(ctx context.Context, a *SelfUpdateFileAdapter, id string, spec nativeModernPairSpec) (updateRecord, fileReview, error) {
	if a == nil || a.installation != "/opt" || a.directory != productionUpdateRoot || a.fileJournal != productionFileJournal {
		return updateRecord{}, fileReview{}, ErrFileProtocol
	}
	record, review, err := a.loadHeader(ctx, id)
	if err != nil || review.Bootstrap != nil || review.OldVersion != "0.20.0" || review.NewVersion != "0.20.1" || review.OldExecutableSHA256 != spec.SourceSHA256 || review.OldInitSHA256 != spec.InitSHA256 || record.Files["scripts/S99razvilka"] != spec.InitSHA256 || record.Job.Release == nil || record.Job.Release.Binary.Digest != "sha256:"+spec.CandidateSHA256 || record.Job.Release.ID <= 0 {
		return record, review, ErrFileProtocol
	}
	return record, review, nil
}

func nativeModernAttach(ctx context.Context, cmd *exec.Cmd, root string, script bool) (func(), error) {
	noop := func() {}
	if ctx == nil || ctx.Err() != nil || cmd == nil || !reflect.DeepEqual(cmd.Env, commandEnvironment()) {
		return noop, ErrFileProtocol
	}
	want := 0
	if script {
		want = 1
	}
	if len(cmd.ExtraFiles) != want {
		return noop, ErrFileProtocol
	}
	fd, err := unix.FcntlInt(3, unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return noop, err
	}
	file := os.NewFile(uintptr(fd), "original modern fixture outer namespace")
	var once sync.Once
	closeSource := func() { once.Do(func() { _ = file.Close() }) }
	cmd.ExtraFiles = append(cmd.ExtraFiles, file)
	childFD := "3"
	if script {
		childFD = "4"
		cmd.Env = append(cmd.Env, "RAZVILKA_START_STOP_DAEMON="+filepath.Join(root, "modern-daemon.py"), "RAZVILKA_MODERN_PAIR_FD_LAYOUT=script4")
	}
	cmd.Env = append(cmd.Env, "TMPDIR="+root, "RAZVILKA_RUNTIME_NATIVE_REVIEW="+filepath.Join(root, "runtime-native-tool-review.json"), "RAZVILKA_RUNTIME_NATIVE_OUTER_NET_FD="+childFD, "RAZVILKA_MODERN_PAIR_NATIVE=1")
	return closeSource, nil
}

func bindNativeModernInstaller(ctx context.Context, cmd *exec.Cmd, id string) (func(), error) {
	noop := func() {}
	if os.Getenv("RAZVILKA_MODERN_PAIR_NATIVE") == "" {
		return noop, nil
	}
	spec, root, err := nativeModernPairInputs(ctx)
	if err != nil || cmd == nil || cmd.Path != "/opt/bin/razvilka" || !reflect.DeepEqual(cmd.Args, []string{cmd.Path, "self-update-helper", id}) {
		return noop, ErrFileProtocol
	}
	record, _, err := nativeModernPairHeader(ctx, NewSelfUpdateFileAdapter(), id, spec)
	self, selfErr := fileProcessAt(os.Getpid())
	if err != nil || selfErr != nil || record.ParentPID != self.PID || self.ExecutableSHA256 != spec.SourceSHA256 || !nativeModernInitialHandoff(record.Job) || checkProductionPID(self.PID, cmd.Path) != nil {
		return noop, ErrFileProtocol
	}
	return nativeModernAttach(ctx, cmd, root, false)
}

// Updater.apply has durably revoked the review token and published handoff
// BEFORE calling its original launcher. This does not change that ordering.
func nativeModernInitialHandoff(job Job) bool {
	return job.State == "installing" && job.Stage == "handoff" && job.HelperPID == 0 && !job.CanApply && !job.CanCancel && job.ReviewToken == ""
}

func nativeModernCommand(command string) bool {
	switch command {
	case "stop-old-panel", "prepare-private-state", "quiesce-old-runtime", "start-candidate-panel", "stop-candidate-panel", "restore-private-state", "start-rollback-panel":
		return true
	}
	return false
}

func bindNativeModernWorker(ctx context.Context, cmd *exec.Cmd, id, command string) (func(), error) {
	noop := func() {}
	spec, root, err := nativeModernPairInputs(ctx)
	if err != nil || !nativeModernCommand(command) || cmd == nil || cmd.Path != filepath.Join(productionUpdateRoot, id, "control.bin") {
		return noop, ErrFileProtocol
	}
	a := NewSelfUpdateFileAdapter()
	_, review, err := nativeModernPairHeader(ctx, a, id, spec)
	if err != nil {
		return noop, err
	}
	worker := reflect.DeepEqual(cmd.Args, []string{cmd.Path, "self-update-command-helper", id, command})
	quiesce := command == "quiesce-old-runtime" && reflect.DeepEqual(cmd.Args, []string{cmd.Path, "self-update-runtime-quiesce", id, strconv.FormatUint(review.Revision, 10), strconv.Itoa(os.Getpid())})
	if !worker && !quiesce {
		return noop, ErrFileProtocol
	}
	identity, identityErr := a.helperIdentity(id, review)
	self, selfErr := fileProcessAt(os.Getpid())
	if identityErr != nil || selfErr != nil {
		return noop, ErrFileProtocol
	}
	if worker {
		if self != identity.Process {
			return noop, ErrFileProtocol
		}
	} else {
		commandRoot, err := a.commandRoot(id)
		if err != nil {
			return noop, err
		}
		armed, readErr := readFileCommand(commandRoot, id, command)
		closeErr := commandRoot.Close()
		if readErr != nil || closeErr != nil || armed.State != "armed" || armed.Supervisor != self || armed.Parent != identity.Process {
			return noop, ErrFileProtocol
		}
	}
	return nativeModernAttach(ctx, cmd, root, false)
}

func bindNativeModernInit(ctx context.Context, a *SelfUpdateFileAdapter, cmd *exec.Cmd, id, command string) (func(), error) {
	noop := func() {}
	if os.Getenv("RAZVILKA_MODERN_PAIR_NATIVE") == "" || command == "quiesce-old-runtime" {
		return noop, nil
	}
	action := "stop"
	switch command {
	case "start-candidate-panel", "start-rollback-panel":
		action = "start"
	case "stop-old-panel", "stop-candidate-panel":
	default:
		return noop, ErrFileProtocol
	}
	spec, root, err := nativeModernPairInputs(ctx)
	if err != nil || cmd == nil || cmd.Path != "/proc/self/fd/3" || !reflect.DeepEqual(cmd.Args, []string{"/bin/sh", "/opt/etc/init.d/S99razvilka", action}) || len(cmd.ExtraFiles) != 1 || cmd.ExtraFiles[0] == nil {
		return noop, ErrFileProtocol
	}
	_, review, err := nativeModernPairHeader(ctx, a, id, spec)
	if err != nil {
		return noop, err
	}
	held, heldErr := cmd.ExtraFiles[0].Stat()
	named, namedErr := os.Stat("/opt/bin/busybox")
	digest, digestErr := hashRegularFile("/opt/bin/busybox", MaximumBinaryBytes)
	if heldErr != nil || namedErr != nil || digestErr != nil || !os.SameFile(held, named) || digest != spec.InterpreterSHA256 {
		return noop, ErrFileProtocol
	}
	commandRoot, err := a.commandRoot(id)
	if err != nil {
		return noop, err
	}
	armed, readErr := readFileCommand(commandRoot, id, command)
	closeErr := commandRoot.Close()
	identity, identityErr := a.helperIdentity(id, review)
	self, selfErr := fileProcessAt(os.Getpid())
	if readErr != nil || closeErr != nil || identityErr != nil || selfErr != nil || armed.State != "armed" || armed.Supervisor != self || armed.Parent != identity.Process {
		return noop, ErrFileProtocol
	}
	return nativeModernAttach(ctx, cmd, root, true)
}

var nativeModernLiveFaultUsed atomic.Bool
var errNativeModernLiveCut = errors.New("native modern pair post-live acceptance cut")

// Called only after the real Live body AND its final Stop check succeeded.
// An injected refusal can exercise known rollback, never grant acceptance.
func nativeModernPairLiveFailure(ctx context.Context, a *SelfUpdateFileAdapter, id string, rollback bool) error {
	if rollback || os.Getenv("RAZVILKA_MODERN_PAIR_NATIVE") == "" {
		return nil
	}
	spec, root, err := nativeModernPairInputs(ctx)
	if err != nil || !reflect.DeepEqual(os.Args[1:], []string{"self-update-helper", id}) {
		return ErrFileProtocol
	}
	_, review, err := nativeModernPairHeader(ctx, a, id, spec)
	if err != nil {
		return err
	}
	identity, identityErr := a.helperIdentity(id, review)
	self, selfErr := fileProcessAt(os.Getpid())
	if identityErr != nil || selfErr != nil || identity.Process != self || self.ExecutableSHA256 != spec.SourceSHA256 {
		return ErrFileProtocol
	}
	store, err := a.OpenFileJournal()
	if err != nil {
		return err
	}
	receipt, present, readErr := store.Current()
	store.Close()
	if readErr != nil || !present || receipt.ID != id || receipt.Phase != "command-finished" || receipt.Command != "start-candidate-panel" || ctx.Err() != nil {
		return ErrFileProtocol
	}
	if nativeModernLiveFaultUsed.CompareAndSwap(false, true) {
		if err := nativeModernRecordLiveCut(ctx, root, id, spec.CandidateSHA256); err != nil {
			return err
		}
		return errNativeModernLiveCut
	}
	return nil
}

// Diagnostic only: no producer/admission reads this file. Its presence cannot
// prove rollback completion; the native consumer separately checks the actual
// original journal and restored live process. Never overwrite an old marker.
func nativeModernRecordLiveCut(ctx context.Context, path, id, digest string) error {
	root, err := ownedfs.Open(path)
	if err != nil {
		return err
	}
	before, beforeErr := root.RootInfo()
	owner, ok := beforeSyscallStat(before)
	if beforeErr != nil || !ok || owner.Uid != 0 || before.Mode().Perm()&0077 != 0 {
		return errors.Join(ErrFileProtocol, root.Close())
	}
	raw, err := json.Marshal(struct {
		ID        string `json:"id"`
		Candidate string `json:"candidate_sha256"`
		Checks    bool   `json:"post_live_and_stop_checks"`
	}{id, digest, true})
	if err != nil {
		return errors.Join(err, root.Close())
	}
	file, err := root.OpenFile("modern-live-cut.json", os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return errors.Join(err, root.Close())
	}
	n, writeErr := file.Write(raw)
	fileErr := file.Close()
	after, afterErr := root.RootInfo()
	named, namedErr := os.Lstat(path)
	closeErr := root.Close()
	if n != len(raw) || afterErr != nil || namedErr != nil || !os.SameFile(before, after) || !os.SameFile(before, named) {
		return errors.Join(ErrFileProtocol, writeErr, fileErr, afterErr, namedErr, closeErr, ctx.Err())
	}
	return errors.Join(writeErr, fileErr, closeErr, ctx.Err())
}

func beforeSyscallStat(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return stat, ok
}
