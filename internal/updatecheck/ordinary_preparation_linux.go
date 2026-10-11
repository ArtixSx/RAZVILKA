//go:build linux

package updatecheck

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/installpath"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

func newOrdinaryPreparation(ctx context.Context, u *Updater, files map[string]string, done chan struct{}) (*ordinaryPreparation, error) {
	if u == nil || ctx == nil || u.Directory != productionUpdateRoot || u.FileAuthorityReview == nil || u.FileEffectAdmission == nil || CheckDeployment(u.Deployment) != nil {
		return nil, errOrdinaryPreparation
	}
	u.mu.Lock()
	record := u.record
	u.mu.Unlock()
	if record.Job.Release == nil || !ordinaryFutureVersions(record.CurrentVersion, record.Job.Release.Version) || record.Owner != updaterOwner || !jobIDPattern.MatchString(record.Job.ID) ||
		record.Job.State != "preparing" || record.Job.Stage != "preflight" || record.Job.Verification != "github-release-sha256" || record.ParentPID != os.Getpid() || record.Job.HelperPID != 0 ||
		record.Files != nil || record.ExecutableHash != "" || record.FileReviewSHA256 != "" || record.Job.CanApply || !record.Job.CanCancel || record.Job.ReviewToken != "" || !ValidChannel(record.Job.Channel) ||
		!validDigest("sha256:"+record.ConfigFingerprint) || !reflect.DeepEqual(record.Deployment, u.Deployment) || record.CurrentVersion != u.Current {
		return nil, errOrdinaryPreparation
	}
	p := &ordinaryPreparation{updater: u, adapter: NewSelfUpdateFileAdapterWithAuthority(nil, u.FileEffectAdmission), original: ctx, done: done, record: record, files: make(map[string]string, len(files))}
	for name, sha := range files {
		p.files[name] = sha
	}
	root, err := ownedfs.Open(u.Directory)
	if err != nil {
		return nil, err
	}
	p.header, err = root.ReadLimited("current.json", 64<<10)
	root.Close()
	var persisted updateRecord
	if err != nil || decodeFileProtocol(p.header, &persisted) != nil || !reflect.DeepEqual(persisted, record) {
		return nil, errOrdinaryPreparation
	}
	p.record = persisted // Detach all maps/pointers from Updater's mutable record.
	entries, err := boundedJobDirectories(filepath.Join(u.Directory, record.Job.ID))
	if err != nil || len(entries) != 2 {
		return nil, errOrdinaryPreparation
	}
	for _, entry := range entries {
		if entry.Name() != "bundle" && entry.Name() != "release.tar.gz" {
			return nil, errOrdinaryPreparation
		}
	}
	p.producer, err = fileProcessOf(os.Getpid())
	if err != nil || !validFileProcess(p.producer) {
		return nil, errOrdinaryPreparation
	}
	p.authority, err = u.FileAuthorityReview(ctx, record.Job.ID)
	if err != nil || p.authority.Sequence == 0 || !jobIDPattern.MatchString(p.authority.InstallationID) {
		return nil, errOrdinaryPreparation
	}
	p.helperInfo, err = os.Lstat(u.Directory)
	if err != nil {
		return nil, err
	}
	p.jobInfo, err = os.Lstat(filepath.Join(u.Directory, record.Job.ID))
	if err != nil {
		return nil, err
	}
	p.self = p
	p.adapter.ordinaryPreparation = p
	p.active.Store(true)
	if err := p.current(ctx); err != nil {
		p.active.Store(false)
		return nil, err
	}
	return p, nil
}

func ordinaryAuthorityCurrent(ctx context.Context, wanted SelfUpdateAuthority) error {
	control, present, err := operationgate.ReadSelfUpdateStop(ctx, installpath.State+"/self-update-stop")
	if err != nil || !present || control.Stopped || control.InstallationID != wanted.InstallationID || control.Sequence != wanted.Sequence {
		return errors.Join(errOrdinaryPreparation, err)
	}
	return ctx.Err()
}

func (a *SelfUpdateFileAdapter) ordinaryNoPendingFiles(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := os.Lstat(a.fileJournal); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	store, err := a.OpenFileJournal()
	if err != nil {
		return err
	}
	defer store.Close()
	current, present, err := store.Current()
	if err != nil || present && current.Pending() {
		return errors.Join(errOrdinaryPreparation, err)
	}
	_, err = store.RequiredReadVersion(ctx)
	return err
}

func (p *ordinaryPreparation) quickCurrent(ctx context.Context) error {
	if err := p.lifetime(ctx); err != nil {
		return err
	}
	if fileProcessMatches(p.producer) != nil || checkProductionPID(p.producer.PID, p.record.Deployment.Executable) != nil {
		return errOrdinaryPreparation
	}
	if err := ordinaryAuthorityCurrent(ctx, p.authority); err != nil {
		return err
	}
	fresh, err := p.updater.FileAuthorityReview(ctx, p.record.Job.ID)
	if err != nil || fresh != p.authority || !helperConfigMatches(p.record) {
		return errors.Join(errOrdinaryPreparation, err)
	}
	return p.adapter.ordinaryNoPendingFiles(ctx)
}

func (p *ordinaryPreparation) current(ctx context.Context) error {
	if err := p.quickCurrent(ctx); err != nil {
		return err
	}
	if !productionOrdinaryRoleAdapter(p.adapter) || CheckDeployment(p.record.Deployment) != nil {
		return errOrdinaryPreparation
	}
	actual, err := fileProcessOf(os.Getpid())
	if err != nil || actual != p.producer {
		return errOrdinaryPreparation
	}
	sha, err := hashRegularFile(p.record.Deployment.Executable, MaximumBinaryBytes)
	if err != nil || sha != p.producer.ExecutableSHA256 {
		return errOrdinaryPreparation
	}
	cfg, _, err := config.Inspect(p.record.Deployment.Paths["config"])
	if err != nil || cfg.SafeMode || cfg.ServiceControl.Stopped || cfg.Revision != p.record.Job.ConfigRevision || ConfigFingerprint(cfg) != p.record.ConfigFingerprint {
		return errOrdinaryPreparation
	}
	helperInfo, helperErr := os.Lstat(p.adapter.directory)
	jobPath := filepath.Join(p.adapter.directory, p.record.Job.ID)
	jobInfo, jobErr := os.Lstat(jobPath)
	if helperErr != nil || jobErr != nil || !os.SameFile(p.helperInfo, helperInfo) || !os.SameFile(p.jobInfo, jobInfo) || checkRootOwnedPath(jobPath) != nil {
		return errOrdinaryPreparation
	}
	root, err := ownedfs.Open(p.adapter.directory)
	if err != nil {
		return err
	}
	data, err := root.ReadLimited("current.json", 64<<10)
	root.Close()
	if err != nil || !bytes.Equal(data, p.header) {
		return errOrdinaryPreparation
	}
	job, err := p.adapter.commandRoot(p.record.Job.ID)
	if err != nil {
		return err
	}
	defer job.Close()
	if err := VerifyExtracted(job, p.files, *p.record.Job.Release); err != nil {
		return err
	}
	archiveSHA, err := hashRegularFile(filepath.Join(jobPath, "release.tar.gz"), MaximumArchiveBytes)
	if err != nil || "sha256:"+archiveSHA != p.record.Job.Release.Archive.Digest {
		return errOrdinaryPreparation
	}
	entries, err := boundedJobDirectories(jobPath)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if checkRootOwnedPath(filepath.Join(jobPath, entry.Name())) != nil {
			return errOrdinaryPreparation
		}
		switch entry.Name() {
		case "bundle", "staged":
			if !entry.IsDir() {
				return errOrdinaryPreparation
			}
		case "release.tar.gz":
			if !entry.Type().IsRegular() {
				return errOrdinaryPreparation
			}
		case "control.bin":
			sha, err := hashRegularFile(filepath.Join(jobPath, entry.Name()), MaximumBinaryBytes)
			if err != nil || sha != p.producer.ExecutableSHA256 {
				return errOrdinaryPreparation
			}
		case "file-review.json":
			data, err := job.ReadLimited(entry.Name(), 256<<10)
			if err != nil || p.reviewSHA == "" || digestBytes(data) != p.reviewSHA {
				return errOrdinaryPreparation
			}
		default:
			return errOrdinaryPreparation
		}
	}
	if err := ordinaryStagedTree(jobPath); err != nil {
		return err
	}
	if err := p.adapter.ordinaryNoPendingFiles(ctx); err != nil {
		return err
	}
	return p.quickCurrent(ctx)
}

// A verified candidate can create recovery metadata only below this private
// staged root. Existing material, links, special files and unbounded trees
// never become implicit migration inputs.
func ordinaryStagedTree(jobPath string) error {
	count, size := 0, int64(0)
	return filepath.WalkDir(filepath.Join(jobPath, "staged"), func(path string, entry os.DirEntry, err error) error {
		if errors.Is(err, os.ErrNotExist) && path == filepath.Join(jobPath, "staged") {
			return nil
		}
		if err != nil {
			return err
		}
		count++
		if count > 256 || entry.Type()&os.ModeSymlink != 0 || checkRootOwnedPath(path) != nil {
			return errOrdinaryPreparation
		}
		info, err := entry.Info()
		if err != nil || !info.IsDir() && !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return errOrdinaryPreparation
		}
		if !info.IsDir() {
			size += info.Size()
			if size > 8<<20 {
				return errOrdinaryPreparation
			}
		}
		return nil
	})
}

// Execute the held, digest-checked image. Only Start is under admission; the
// actual Wait belongs to this caller and is joined even after revocation.
func ordinaryImageCommand(ctx context.Context, path, sha string, args []string, effect string, admission func(context.Context, string, func() error) error, before, tick, after func() error) (string, error) {
	if ctx == nil || ctx.Err() != nil || admission == nil || before == nil || tick == nil || after == nil || !validDigest("sha256:"+sha) || checkRootOwnedPath(path) != nil {
		return "", errOrdinaryPreparation
	}
	if err := before(); err != nil {
		return "", err
	}
	root, err := ownedfs.Open(filepath.Dir(path))
	if err != nil {
		return "", err
	}
	program, err := root.OpenFile(filepath.Base(path), os.O_RDONLY, 0)
	root.Close()
	if err != nil {
		return "", err
	}
	defer program.Close()
	info, err := program.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > MaximumBinaryBytes || info.Mode().Perm()&0100 == 0 {
		return "", errOrdinaryPreparation
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(program, MaximumBinaryBytes+1))
	if err != nil || n > MaximumBinaryBytes || hex.EncodeToString(hash.Sum(nil)) != sha {
		return "", errOrdinaryPreparation
	}
	if _, err := program.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	commandTimeout := 30 * time.Second
	if len(args) == 1 || effect == "ordinary-prepare-syntax" {
		commandTimeout = 3 * time.Second
	}
	commandCtx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	command := exec.CommandContext(commandCtx, "/proc/self/fd/3", args...)
	command.Args[0] = path
	if effect == "ordinary-prepare-syntax" {
		command.Args[0] = "/bin/sh"
	} // BusyBox selects its shell applet from argv[0].
	command.ExtraFiles = []*os.File{program}
	command.Env = commandEnvironment()
	output, diagnostic := &cappedOutput{maximum: 64 << 10}, &cappedOutput{maximum: 8192}
	command.Stdout, command.Stderr = output, diagnostic
	configureBoundedCommand(command)
	_, done, startErr := startInstallerHelperCommand(commandCtx, command, func(begin func() error) error {
		if err := before(); err != nil {
			return err
		}
		current, err := os.Lstat(path)
		if err != nil || !os.SameFile(current, info) || checkRootOwnedPath(path) != nil {
			return errOrdinaryPreparation
		}
		return admission(commandCtx, effect, begin)
	})
	if done == nil {
		return "", startErr
	}
	if startErr != nil {
		cancel()
		cleanupCommand(command)
	}
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case waitErr := <-done:
			if startErr != nil || waitErr != nil || commandCtx.Err() != nil || diagnostic.Len() != 0 || output.Len() == output.maximum {
				return "", errors.Join(errOrdinaryPreparation, startErr, waitErr, commandCtx.Err())
			}
			current, err := os.Lstat(path)
			if err != nil || !os.SameFile(current, info) {
				return "", errOrdinaryPreparation
			}
			if err := after(); err != nil {
				return "", err
			}
			return output.String(), nil
		case <-ticker.C:
			if err := tick(); err != nil {
				cancel()
				cleanupCommand(command)
				<-done
				return "", err
			}
		case <-commandCtx.Done():
			cleanupCommand(command)
			<-done
			return "", commandCtx.Err()
		}
	}
}

func (p *ordinaryPreparation) run(ctx context.Context, path string, args []string, effect string) (string, error) {
	if !p.commandMatches(path, args, effect) {
		return "", errOrdinaryPreparation
	}
	sha := p.producer.ExecutableSHA256
	candidate := filepath.Join(p.adapter.directory, p.record.Job.ID, "bundle/dist", p.record.Job.Release.Binary.Name)
	if path == candidate {
		sha = p.files["dist/"+p.record.Job.Release.Binary.Name]
	} else if path != p.record.Deployment.Executable {
		return "", errOrdinaryPreparation
	}
	return ordinaryImageCommand(ctx, path, sha, args, effect, func(c context.Context, e string, begin func() error) error {
		return p.updater.FileEffectAdmission(c, p.record.Job.ID, p.authority.InstallationID, p.authority.Sequence, "start/live", e, begin)
	}, func() error { return p.current(ctx) }, func() error { return p.quickCurrent(ctx) }, func() error { return p.current(ctx) })
}

func (p *ordinaryPreparation) capabilities(ctx context.Context, path string, nodes, component int) error {
	return checkOrdinaryPreparationCapabilities(ctx, path, nodes, component, func(c context.Context, path, flag string) (string, error) {
		return p.run(c, path, []string{flag}, "ordinary-prepare-metadata")
	})
}

func (p *ordinaryPreparation) preflight(ctx context.Context) (err error) {
	stage := "owner"
	defer func() { err = ordinaryPreparationFailed(stage, err) }()
	if err := p.current(ctx); err != nil {
		return err
	}
	jobPath := filepath.Join(p.adapter.directory, p.record.Job.ID)
	job, err := p.adapter.commandRoot(p.record.Job.ID)
	if err != nil {
		return err
	}
	defer job.Close()
	program, err := job.OpenFile("bundle/dist/"+p.record.Job.Release.Binary.Name, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	err = program.Chmod(0700)
	closeErr := program.Close()
	if err != nil || closeErr != nil {
		return errors.Join(err, closeErr)
	}
	binary := filepath.Join(jobPath, "bundle/dist", p.record.Job.Release.Binary.Name)
	stage = "version"
	for _, image := range []struct{ path, version string }{{p.record.Deployment.Executable, p.record.CurrentVersion}, {binary, p.record.Job.Release.Version}} {
		version, err := p.run(ctx, image.path, []string{"-version"}, "ordinary-prepare-metadata")
		if err != nil || version != image.version+"\n" {
			return errOrdinaryPreparation
		}
	}
	stage = "histories"
	nodes, err := RequiredRetainedNodeHistoryReadVersion(ctx, installpath.Config, installpath.State, validatedNodeHistoryRead)
	if err != nil {
		return err
	}
	component, err := components.RequiredRetainedManagedUpdateReadVersion(ctx, installpath.State+"/components")
	if err != nil {
		return err
	}
	stage = "capabilities"
	for _, image := range []string{p.record.Deployment.Executable, binary} {
		if err := p.capabilities(ctx, image, nodes, component); err != nil {
			return err
		}
	}
	stage = "journals"
	if _, err := p.adapter.requiredJournalReadVersion(ctx); err != nil {
		return err
	}
	// Parse the genuine candidate's config/catalog report without mutation.
	stage = "candidate-check"
	output, err := p.run(ctx, binary, ordinaryPreparationArguments(jobPath, "-check", p.record.Deployment.Paths["config"]), "ordinary-prepare-check")
	if err != nil || !ordinaryPreparationReport(output, p.record.Job.Release.Version, false) {
		return errOrdinaryPreparation
	}
	// Syntax parsing is read-only. Execute the actual owned interpreter, with
	// no installer replacement workflow or schema2/raw-apply permission.
	stage = "script-syntax"
	shell, err := filepath.EvalSymlinks("/bin/sh")
	if err != nil {
		return err
	}
	shellSHA, err := hashRegularFile(shell, MaximumBinaryBytes)
	if err != nil {
		return err
	}
	for _, name := range []string{"upgrade-entware.sh", "rollback-entware.sh", "S99razvilka"} {
		_, err := ordinaryImageCommand(ctx, shell, shellSHA, []string{"-n", filepath.Join(jobPath, "bundle/scripts", name)}, "ordinary-prepare-syntax", func(c context.Context, e string, begin func() error) error {
			return p.updater.FileEffectAdmission(c, p.record.Job.ID, p.authority.InstallationID, p.authority.Sequence, "start/live", e, begin)
		}, func() error { return p.current(ctx) }, func() error { return p.quickCurrent(ctx) }, func() error { return p.current(ctx) })
		if err != nil {
			return err
		}
	}
	stage = "owner"
	return p.current(ctx)
}

func (p *ordinaryPreparation) migrate(ctx context.Context, job *ownedfs.Root) (err error) {
	defer func() { err = ordinaryPreparationFailed("migration", err) }()
	if err := p.current(ctx); err != nil {
		return err
	}
	if job == nil {
		return errOrdinaryPreparation
	}
	info, err := job.RootInfo()
	if err != nil || !os.SameFile(info, p.jobInfo) {
		return errOrdinaryPreparation
	}
	jobPath := filepath.Join(p.adapter.directory, p.record.Job.ID)
	entries, err := boundedJobDirectories(filepath.Join(jobPath, "staged"))
	if err != nil || len(entries) != 1 || entries[0].Name() != "config.json" || !entries[0].Type().IsRegular() {
		return errOrdinaryPreparation
	}
	stagedParent, err := job.Stat("staged")
	if err != nil {
		return err
	}
	output, err := p.run(ctx, filepath.Join(jobPath, "bundle/dist", p.record.Job.Release.Binary.Name), ordinaryPreparationArguments(jobPath, "-migrate-config", filepath.Join(jobPath, "staged/config.json")), "ordinary-prepare-migration")
	if err != nil || !ordinaryPreparationReport(output, p.record.Job.Release.Version, true) {
		return errors.Join(errOrdinaryPreparation, err)
	}
	current, err := job.Stat("staged")
	if err != nil || !os.SameFile(stagedParent, current) {
		return errOrdinaryPreparation
	}
	return p.current(ctx)
}

func (a *SelfUpdateFileAdapter) ordinaryFutureReady(ctx context.Context, id string, record updateRecord, review fileReview) (err error) {
	defer func() { err = ordinaryPreparationFailed("ready", err) }()
	if ctx == nil {
		return errOrdinaryPreparation
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if !productionOrdinaryRoleAdapter(a) || !ordinaryFutureReview(record, review) || record.Job.HelperPID != 0 || record.ParentPID != os.Getpid() || record.Job.State != "ready" || !record.Job.CanApply || record.Job.CanCancel || CheckDeployment(record.Deployment) != nil {
		return errOrdinaryPreparation
	}
	parent, err := fileProcessOf(os.Getpid())
	if err != nil || !ordinaryReadyParentMatches(record, review, parent) {
		return errOrdinaryPreparation
	}
	wanted := SelfUpdateAuthority{review.AuthorityInstallationID, review.AuthoritySequence}
	check := func() error {
		if ctx.Err() != nil || fileProcessMatches(parent) != nil || CheckDeployment(record.Deployment) != nil {
			return errOrdinaryPreparation
		}
		if err := ordinaryAuthorityCurrent(ctx, wanted); err != nil {
			return err
		}
		if err := a.Authority(ctx, id, review.Revision); err != nil {
			return err
		}
		freshRecord, freshReview, err := a.load(ctx, id)
		if err != nil || !reflect.DeepEqual(record, freshRecord) || !reflect.DeepEqual(review, freshReview) {
			return errOrdinaryPreparation
		}
		job, err := a.commandRoot(id)
		if err != nil {
			return err
		}
		_, identityErr := job.Stat("helper.identity.json")
		job.Close()
		if !errors.Is(identityErr, os.ErrNotExist) {
			return errOrdinaryPreparation
		}
		if err := ordinaryStagedTree(filepath.Join(a.directory, id)); err != nil {
			return err
		}
		return a.ordinaryNoPendingFiles(ctx)
	}
	if err := check(); err != nil {
		return err
	}
	nodes, err := RequiredRetainedNodeHistoryReadVersion(ctx, installpath.Config, installpath.State, validatedNodeHistoryRead)
	if err != nil {
		return err
	}
	component, seal, err := components.InspectRetainedManagedUpdateReadVersion(ctx, installpath.State+"/components")
	if err != nil {
		return err
	}
	for _, image := range []struct{ path, sha string }{{record.Deployment.Executable, record.ExecutableHash}, {filepath.Join(a.directory, id, "bundle/dist", record.Job.Release.Binary.Name), strings.TrimPrefix(record.Job.Release.Binary.Digest, "sha256:")}} {
		if err := checkOrdinaryPreparationCapabilities(ctx, image.path, nodes, component, func(c context.Context, path, flag string) (string, error) {
			return ordinaryImageCommand(c, path, image.sha, []string{flag}, "ordinary-ready-metadata", func(c context.Context, e string, begin func() error) error {
				return a.admission(c, id, wanted.InstallationID, wanted.Sequence, "start/live", e, begin)
			}, check, check, check)
		}); err != nil {
			return err
		}
	}
	if err := a.CheckRetainedJournalReaders(ctx, id, 4); err != nil {
		return err
	}
	freshNodes, err := RequiredRetainedNodeHistoryReadVersion(ctx, installpath.Config, installpath.State, validatedNodeHistoryRead)
	if err != nil || freshNodes != nodes {
		return errOrdinaryPreparation
	}
	freshComponent, freshSeal, err := components.InspectRetainedManagedUpdateReadVersion(ctx, installpath.State+"/components")
	if err != nil || freshComponent != component || freshSeal != seal {
		return errOrdinaryPreparation
	}
	freshParent, err := fileProcessOf(os.Getpid())
	if err != nil || freshParent != parent {
		return errOrdinaryPreparation
	}
	return check()
}
