package updatecheck

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/installpath"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

var ErrExternalBootstrap = errors.New("external old0.19.3 bootstrap requires review; preserve all retained evidence")

type SelfUpdateExternalBootstrapResult struct {
	ID    string `json:"id"`
	State string `json:"state"`
}

// BootstrapExternalOld193 runs the actual verified local-package producer and
// paired file protocol under the calling CLI's original finite owner. The
// running candidate becomes the explicit installer; old0.19.3 stays only the
// physical source/rollback image. No legacy UI helper is adopted. Roots are
// fixed and a nonempty prior helper/file/archive namespace refuses unchanged.
//
// This local package has explicit external-archive provenance (Release.ID=0),
// not fabricated GitHub metadata or attestation. The original archive is pinned
// while copying and verified before extraction or execution. Its extracted
// binary must match the physically running candidate and report version0.20.0.
// Success leaves retirement to the actual new App after this helper has exited.
func (a *SelfUpdateFileAdapter) BootstrapExternalOld193(ctx context.Context, id, archivePath, archiveSHA string, owner SelfUpdateRuntimeObservation, authorityReview func(context.Context, string) (SelfUpdateAuthority, error)) (SelfUpdateExternalBootstrapResult, error) {
	result := SelfUpdateExternalBootstrapResult{ID: id}
	if runtime.GOOS != "linux" || a == nil || ctx == nil || owner == nil || authorityReview == nil || a.admission == nil || a.runtimeInactive == nil || a.filesystem == nil ||
		a.installation != "/opt" || a.directory != productionUpdateRoot || a.fileJournal != productionFileJournal || !jobIDPattern.MatchString(id) ||
		!filepath.IsAbs(archivePath) || filepath.Clean(archivePath) != archivePath || !validDigest("sha256:"+archiveSHA) {
		return result, ErrExternalBootstrap
	}
	if _, finite := ctx.Deadline(); !finite || ctx.Err() != nil || owner(ctx, id) != nil {
		return result, ErrExternalBootstrap
	}
	if a.bootstrapCommandWait != nil {
		return result, ErrExternalBootstrap
	}
	var joins []func(context.Context) error
	a.bootstrapCommandWait = func(_ string, join func(context.Context) error) { joins = append(joins, join) }
	defer func() { a.bootstrapCommandWait = nil }()
	deployment := Deployment{Paths: ProductionPaths(), Executable: "/opt/bin/razvilka", Port: "8787"}
	if a.layout == nil || a.owned == nil || a.layout(deployment) != nil || a.owned(archivePath) != nil {
		return result, ErrExternalBootstrap
	}
	for _, path := range []string{a.directory, a.fileJournal, filepath.Join(a.installation, filepath.FromSlash(pairedPriorArchiveDirectory))} {
		if err := emptyExternalBootstrapNamespace(ctx, path, a.owned); err != nil {
			return result, errors.Join(ErrExternalBootstrap, err)
		}
	}
	if err := externalBootstrapLegacyControllersAbsent(ctx, filepath.Join(a.installation, "razvilka/state/update-backups"), a.owned); err != nil {
		return result, errors.Join(ErrExternalBootstrap, err)
	}
	self, panel, oldSHA, err := externalBootstrapProcesses(ctx, deployment)
	if err != nil || self.ExecutableSHA256 == oldSHA || externalBootstrapEntryMatches(ctx, id, archivePath, archiveSHA, self) != nil || owner(ctx, id) != nil {
		return result, errors.Join(ErrExternalBootstrap, err)
	}
	// Reading a version is the only old-program probe. Never ask the old
	// source for a modern schema/reader flag or infer an ABI from its version.
	oldVersion, err := probeFileCapability(ctx, deployment.Executable, "-version")
	if err != nil || oldVersion != "0.19.3\n" {
		return result, ErrExternalBootstrap
	}
	configRoot, err := ownedfs.Open(installpath.Config)
	if err != nil {
		return result, errors.Join(ErrExternalBootstrap, err)
	}
	oldConfig, err := configRoot.ReadLimited("config.json", 4<<20)
	configRoot.Close()
	cfg, _, inspectErr := config.InspectBytes(oldConfig)
	if err != nil || inspectErr != nil || cfg.Revision == 0 {
		return result, ErrExternalBootstrap
	}
	// The actual caller seals its protected epoch only after these read-only
	// source checks and before the first preparing/header effect.
	authority, err := authorityReview(ctx, id)
	if err != nil || !jobIDPattern.MatchString(authority.InstallationID) || authority.Sequence == 0 || owner(ctx, id) != nil {
		return result, errors.Join(ErrExternalBootstrap, err)
	}
	parent, err := ownedfs.Open(filepath.Dir(a.directory))
	if err != nil {
		return result, errors.Join(ErrExternalBootstrap, err)
	}
	if err = parent.MkdirAll(filepath.Base(a.directory), 0700); err == nil {
		err = syncSelfUpdateDirectory(parent)
	}
	parent.Close()
	if err != nil {
		return result, errors.Join(ErrExternalBootstrap, err)
	}
	root, err := ownedfs.Open(a.directory)
	if err != nil {
		return result, errors.Join(ErrExternalBootstrap, err)
	}
	defer root.Close()
	now := time.Now().UTC()
	record := updateRecord{Owner: updaterOwner, Job: Job{Channel: "stable", ID: id, State: "preparing", Stage: "metadata", ConfigRevision: cfg.Revision, Verification: "verified-external-archive-sha256", StartedAt: now, UpdatedAt: now, CanCancel: true}, CurrentVersion: "0.19.3", ConfigFingerprint: ConfigFingerprint(cfg), ParentPID: panel.PID, Deployment: deployment}
	// The first header is an exclusive claim. Two independent external entries
	// cannot replace each other's preparing owner after seeing an empty root.
	if err := writeInitialExternalBootstrap(root, record); err != nil {
		return result, errors.Join(ErrExternalBootstrap, err)
	}
	fs, err := os.OpenRoot(a.directory)
	if err != nil {
		return result, errors.Join(ErrExternalBootstrap, err)
	}
	err = fs.Mkdir(id, 0700)
	fs.Close()
	if err != nil {
		return result, errors.Join(ErrExternalBootstrap, err)
	}
	if err := syncSelfUpdateDirectory(root); err != nil {
		return result, errors.Join(ErrExternalBootstrap, err)
	}
	job, err := a.commandRoot(id)
	if err != nil {
		return result, errors.Join(ErrExternalBootstrap, err)
	}
	defer job.Close()
	archiveSize, err := copyExternalBootstrapArchive(ctx, archivePath, archiveSHA, job)
	if err != nil || owner(ctx, id) != nil {
		return result, errors.Join(ErrExternalBootstrap, err)
	}
	selfInfo, err := externalBootstrapProgramInfo()
	if err != nil {
		return result, errors.Join(ErrExternalBootstrap, err)
	}
	release := Release{Tag: "v0.20.0", Version: "0.20.0", Architecture: runtime.GOARCH,
		Archive: Asset{Name: "RAZVILKA-0.20.0-entware.tar.gz", Size: archiveSize, Digest: "sha256:" + archiveSHA},
		Binary:  Asset{Name: "razvilka-linux-" + runtime.GOARCH, Size: selfInfo.Size(), Digest: "sha256:" + self.ExecutableSHA256}}
	record.Job.Release, record.Job.Stage = &release, "verifying"
	if err := publishExternalBootstrapHeader(ctx, root, &record, "preparing"); err != nil {
		return result, errors.Join(ErrExternalBootstrap, err)
	}
	files, err := ExtractInstallFiles(ctx, job, "release.tar.gz", release)
	if err != nil || VerifyExtracted(job, files, release) != nil || owner(ctx, id) != nil {
		return result, errors.Join(ErrExternalBootstrap, err)
	}
	record.Job.Stage = "preflight"
	if err := publishExternalBootstrapHeader(ctx, root, &record, "preparing"); err != nil {
		return result, errors.Join(ErrExternalBootstrap, err)
	}
	preparation, err := newExternalBootstrapPreparation(a, ctx, record, files, self, panel, oldSHA, archivePath, archiveSHA, owner)
	if err != nil {
		return result, externalBootstrapFailure("preparation-owner", err)
	}
	if err := preparation.preflight(ctx); err != nil {
		return result, err
	}
	if err := a.filesystem(ctx); err != nil {
		return result, externalBootstrapFailure("filesystem", err)
	}
	if err := preparation.current(ctx); err != nil {
		return result, externalBootstrapFailure("preparation-owner", err)
	}
	record.Files, record.ExecutableHash = files, oldSHA
	mode := "live"
	if cfg.SafeMode || cfg.ServiceControl.Stopped {
		mode = "offline"
	}
	binding := &fileBootstrapBinding{Role: externalOld193InstallerRole, Mode: mode, HelperSHA256: self.ExecutableSHA256, ArchivePath: archivePath, ArchiveSHA256: archiveSHA}
	record.FileReviewSHA256, err = a.stageFileReviewWithBootstrap(ctx, record, authorityReview, binding, preparation)
	if err != nil {
		return result, externalBootstrapFailure("file-review", err)
	}
	if err := owner(ctx, id); err != nil {
		return result, externalBootstrapFailure("review-owner", err)
	}
	currentSelf, currentPanel, currentOldSHA, err := externalBootstrapProcesses(ctx, deployment)
	if err != nil || currentSelf != self || currentPanel != panel || currentOldSHA != oldSHA || !helperConfigMatches(record) {
		return result, errors.Join(ErrExternalBootstrap, err)
	}
	record.Job.State, record.Job.Stage, record.Job.HelperPID = "restarting", "file-protocol", self.PID
	record.Job.CanApply, record.Job.CanCancel = false, false
	if err := publishExternalBootstrapHeader(ctx, root, &record, "preparing"); err != nil {
		return result, errors.Join(ErrExternalBootstrap, err)
	}
	_, review, err := a.load(ctx, id)
	if err != nil || sealFileHelperIdentity(a, id, review) != nil {
		return result, errors.Join(ErrExternalBootstrap, err)
	}
	identity, err := a.helperIdentity(id, review)
	if err != nil || identity.Process != self || identity.OldPanel != panel || owner(ctx, id) != nil {
		return result, errors.Join(ErrExternalBootstrap, err)
	}
	if err := a.runExternalBootstrapFiles(ctx, id, review, owner); err != nil {
		// A failed command is preserved as unknown. Never fabricate join,
		// retire the source, replay files, Start rollback or auto-clear Stop.
		return result, errors.Join(ErrExternalBootstrap, err)
	}
	// start-candidate returns runtime-ready while its real supervisor still
	// owns the handoff. Finish is not its Wait. Retain the original finite
	// owner until every actual exec-created command supervisor has joined.
	wantedJoins := 4
	if mode == "offline" {
		wantedJoins = 3
	}
	if len(joins) != wantedJoins {
		return result, errors.Join(ErrExternalBootstrap, ErrFileCommandUnsettled)
	}
	for _, join := range joins {
		if err := join(ctx); err != nil {
			return result, errors.Join(ErrExternalBootstrap, err)
		}
	}
	if err := owner(ctx, id); err != nil {
		return result, errors.Join(ErrExternalBootstrap, err)
	}
	result.State = "completed-awaiting-owner-retirement"
	if mode == "offline" {
		fresh, frozen, err := a.load(ctx, id)
		if err != nil || fresh.Job.State != "restarting" || fresh.Job.Stage != "file-protocol" || fresh.Job.HelperPID != self.PID || fresh.ParentPID != panel.PID || fresh.FileReviewSHA256 != record.FileReviewSHA256 {
			return result, errors.Join(ErrExternalBootstrap, err)
		}
		if err := a.Authority(ctx, id, frozen.Revision); err != nil {
			return result, errors.Join(ErrExternalBootstrap, err)
		}
		if err := a.Quiescence(ctx, id); err != nil {
			return result, errors.Join(ErrExternalBootstrap, err)
		}
		if err := a.runtimeInactive(ctx, id); err != nil {
			return result, errors.Join(ErrExternalBootstrap, err)
		}
		fresh.Job.State, fresh.Job.Stage, fresh.Job.Code = "requires-review", "installed-offline", "bootstrap-offline-installed"
		fresh.Job.UpdatedAt = time.Now().UTC()
		data, err := json.Marshal(fresh)
		if err != nil {
			return result, err
		}
		if err := writeSelfUpdateRecord(root, data); err != nil {
			return result, err
		}
		result.State = "installed-offline-requires-review"
	}
	return result, nil
}

func emptyExternalBootstrapNamespace(ctx context.Context, path string, owned func(string) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if owned == nil || owned(path) != nil {
		return ErrExternalBootstrap
	}
	entries, err := boundedJobDirectories(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || len(entries) != 0 {
		return ErrExternalBootstrap
	}
	return ctx.Err()
}

func writeInitialExternalBootstrap(root *ownedfs.Root, record updateRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	f, err := root.OpenFile("current.json", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return syncSelfUpdateDirectory(root)
}

func publishExternalBootstrapHeader(ctx context.Context, root *ownedfs.Root, record *updateRecord, previousState string) error {
	if record == nil {
		return ErrExternalBootstrap
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	data, err := root.ReadLimited("current.json", 64<<10)
	var previous updateRecord
	if err != nil || decodeFileProtocol(data, &previous) != nil || previous.Owner != updaterOwner || previous.Job.ID != record.Job.ID || previous.Job.State != previousState ||
		previous.ParentPID != record.ParentPID || previous.ConfigFingerprint != record.ConfigFingerprint || previous.CurrentVersion != record.CurrentVersion || previous.Job.ConfigRevision != record.Job.ConfigRevision ||
		!reflect.DeepEqual(previous.Deployment, record.Deployment) || previous.FileReviewSHA256 != "" || previous.Files != nil || previous.ExecutableHash != "" || previous.Job.HelperPID != 0 ||
		!previous.Job.CanCancel || previous.Job.CanApply || previous.Job.ReviewToken != "" {
		return ErrExternalBootstrap
	}
	record.Job.UpdatedAt = time.Now().UTC()
	data, err = json.Marshal(record)
	if err != nil {
		return err
	}
	return writeSelfUpdateRecord(root, data)
}

func copyExternalBootstrapArchive(ctx context.Context, path, expected string, job *ownedfs.Root) (int64, error) {
	parent, err := ownedfs.Open(filepath.Dir(path))
	if err != nil {
		return 0, err
	}
	defer parent.Close()
	parentInfo, err := parent.RootInfo()
	if err != nil {
		return 0, err
	}
	before, err := parent.Stat(filepath.Base(path))
	if err != nil || !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > MaximumArchiveBytes {
		return 0, ErrExternalBootstrap
	}
	in, err := parent.OpenFile(filepath.Base(path), os.O_RDONLY|externalBootstrapFileFlags(), 0)
	if err != nil {
		return 0, err
	}
	defer in.Close()
	opened, err := in.Stat()
	if err != nil || !sameExternalBootstrapFile(before, opened) {
		return 0, ErrExternalBootstrap
	}
	out, err := job.OpenFile("release.tar.gz", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return 0, err
	}
	defer out.Close() // Partial evidence survives every failure.
	hash := sha256.New()
	buffer := make([]byte, 64<<10)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		n, readErr := in.Read(buffer)
		if n > 0 {
			total += int64(n)
			if total > before.Size() {
				return total, ErrExternalBootstrap
			}
			if _, err := io.MultiWriter(out, hash).Write(buffer[:n]); err != nil {
				return total, err
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return total, readErr
		}
	}
	after, statErr := in.Stat()
	current, currentErr := parent.Stat(filepath.Base(path))
	currentParent, parentErr := os.Lstat(filepath.Dir(path))
	if statErr != nil || currentErr != nil || parentErr != nil || !os.SameFile(parentInfo, currentParent) || parentInfo.Mode() != currentParent.Mode() ||
		!sameExternalBootstrapFile(before, after) || !sameExternalBootstrapFile(before, current) || total != before.Size() || hex.EncodeToString(hash.Sum(nil)) != expected {
		return total, ErrExternalBootstrap
	}
	if err := out.Sync(); err != nil {
		return total, err
	}
	if err := out.Close(); err != nil {
		return total, err
	}
	if err := syncSelfUpdateDirectory(job); err != nil {
		return total, err
	}
	copyFile, err := job.OpenFile("release.tar.gz", os.O_RDONLY|externalBootstrapFileFlags(), 0)
	if err != nil {
		return total, err
	}
	defer copyFile.Close()
	copyInfo, err := copyFile.Stat()
	if err != nil || !copyInfo.Mode().IsRegular() || copyInfo.Size() != total {
		return total, ErrExternalBootstrap
	}
	readback := sha256.New()
	n, err := io.Copy(readback, io.LimitReader(copyFile, MaximumArchiveBytes+1))
	if err != nil || n != total || hex.EncodeToString(readback.Sum(nil)) != expected {
		return total, ErrExternalBootstrap
	}
	return total, ctx.Err()
}

func sameExternalBootstrapFile(before, after os.FileInfo) bool {
	return before != nil && after != nil && os.SameFile(before, after) && before.Mode() == after.Mode() && before.Size() == after.Size() && before.ModTime().Equal(after.ModTime())
}

func (a *SelfUpdateFileAdapter) runExternalBootstrapFiles(ctx context.Context, id string, review fileReview, owner SelfUpdateRuntimeObservation) error {
	check := func(c context.Context) error {
		if c != ctx || owner(c, id) != nil {
			return ErrExternalBootstrap
		}
		return a.Authority(c, id, review.Revision)
	}
	parent, err := ownedfs.Open(filepath.Dir(a.fileJournal))
	if err != nil {
		return err
	}
	if err = parent.MkdirAll(filepath.Base(a.fileJournal), 0700); err == nil {
		err = syncSelfUpdateDirectory(parent)
	}
	parent.Close()
	if err != nil {
		return err
	}
	store, err := a.OpenFileJournal()
	if err != nil {
		return err
	}
	err = store.Prepare(ctx, id, review.Files, check, func(c context.Context) error { return a.Quiescence(c, id) })
	store.Close()
	if err != nil {
		return err
	}
	for _, command := range []string{"stop-old-panel", "prepare-private-state", "quiesce-old-runtime"} {
		store, err := a.OpenFileJournal()
		if err != nil {
			return err
		}
		err = store.Execute(ctx, id, command, check, func(c context.Context) error { return a.Run(c, id, command) })
		store.Close()
		if err != nil {
			return err
		}
	}
	if err := check(ctx); err != nil {
		return err
	}
	if err := externalBootstrapLegacyControllersAbsent(ctx, filepath.Join(a.installation, "razvilka/state/update-backups"), a.owned); err != nil {
		return err
	}
	if err := a.SealPairedPriorState(ctx, id); err != nil {
		return err
	}
	store, err = a.OpenFileJournal()
	if err != nil {
		return err
	}
	err = store.InstallAdmitted(ctx, id, check, func(c context.Context) error { return a.Quiescence(c, id) }, func(c context.Context, effect string, begin func() error) error {
		return a.EffectAdmission(c, id, fileInstallAuthority(review), effect, begin)
	})
	store.Close()
	if err != nil {
		return err
	}
	if review.Bootstrap.Mode == "offline" {
		if err := check(ctx); err != nil {
			return err
		}
		if err := a.Quiescence(ctx, id); err != nil {
			return err
		}
		return a.runtimeInactive(ctx, id)
	}
	store, err = a.OpenFileJournal()
	if err != nil {
		return err
	}
	err = store.Execute(ctx, id, "start-candidate-panel", check, func(c context.Context) error { return a.Run(c, id, "start-candidate-panel") })
	store.Close()
	if err != nil {
		return err
	}
	store, err = a.OpenFileJournal()
	if err != nil {
		return err
	}
	err = store.Accept(ctx, id, false, check, func(c context.Context) error { return a.Live(c, id, false) })
	store.Close()
	if err != nil {
		return err
	}
	if err := check(ctx); err != nil {
		return err
	}
	return a.Finish(ctx, id, false)
}

// Fresh raw install backups may have no prior executable. They remain opaque
// artifacts. A retained legacy executable is an additional controller owner;
// this first-bootstrap path cannot invent its reader ABI or retire it by copy.
func externalBootstrapLegacyControllersAbsent(ctx context.Context, path string, owned func(string) error) error {
	if owned == nil || owned(path) != nil {
		return ErrExternalBootstrap
	}
	entries, err := boundedJobDirectories(path)
	if errors.Is(err, os.ErrNotExist) {
		return ctx.Err()
	}
	if err != nil {
		return err
	}
	root, err := ownedfs.Open(path)
	if err != nil {
		return err
	}
	defer root.Close()
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return ErrExternalBootstrap
		}
		if _, err := root.Stat(filepath.Join(entry.Name(), "razvilka.bin")); !errors.Is(err, os.ErrNotExist) {
			return ErrExternalBootstrap
		}
	}
	return ctx.Err()
}

func externalBootstrapPID(data []byte) (int, error) {
	value := strings.TrimSuffix(string(data), "\n")
	pid, err := strconv.Atoi(value)
	if err != nil || pid <= 1 || value != strconv.Itoa(pid) || string(data) != value+"\n" {
		return 0, ErrExternalBootstrap
	}
	return pid, nil
}
