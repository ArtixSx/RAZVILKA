package updatecheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/community"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/sources"
)

// This capability exists only inside the actual executing external producer.
// It cannot enable ordinary migration, raw replacement or schema2 effects.
type externalBootstrapPreparation struct {
	self       *externalBootstrapPreparation
	adapter    *SelfUpdateFileAdapter
	original   context.Context
	owner      SelfUpdateRuntimeObservation
	header     []byte
	record     updateRecord
	files      map[string]string
	producer   fileProcess
	panel      fileProcess
	oldSHA     string
	archive    string
	archiveSHA string
	helperInfo os.FileInfo
	jobInfo    os.FileInfo
}

func newExternalBootstrapPreparation(a *SelfUpdateFileAdapter, ctx context.Context, record updateRecord, files map[string]string, producer, panel fileProcess, oldSHA, archive, archiveSHA string, owner SelfUpdateRuntimeObservation) (*externalBootstrapPreparation, error) {
	if a == nil || ctx == nil || owner == nil || ctx.Err() != nil || a.installation != "/opt" || a.directory != productionUpdateRoot || a.fileJournal != productionFileJournal {
		return nil, ErrExternalBootstrap
	}
	if _, finite := ctx.Deadline(); !finite {
		return nil, ErrExternalBootstrap
	}
	header, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	p := &externalBootstrapPreparation{adapter: a, original: ctx, owner: owner, header: header, record: record, producer: producer, panel: panel, oldSHA: oldSHA, archive: archive, archiveSHA: archiveSHA, files: make(map[string]string, len(files))}
	for name, sha := range files {
		p.files[name] = sha
	}
	p.helperInfo, err = os.Lstat(a.directory)
	if err != nil {
		return nil, err
	}
	p.jobInfo, err = os.Lstat(filepath.Join(a.directory, record.Job.ID))
	if err != nil {
		return nil, err
	}
	p.self = p
	if err := p.current(ctx); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *externalBootstrapPreparation) current(ctx context.Context) error {
	if p == nil || p.self != p || p.adapter == nil || p.original == nil || p.owner == nil || ctx == nil || ctx != p.original || runtime.GOOS != "linux" ||
		p.original.Err() != nil || ctx.Err() != nil || p.adapter.installation != "/opt" || p.adapter.directory != productionUpdateRoot || p.adapter.fileJournal != productionFileJournal {
		return ErrExternalBootstrap
	}
	deadline, finite := p.original.Deadline()
	if !finite || !deadline.After(time.Now()) || p.record.Owner != updaterOwner || p.record.Job.State != "preparing" || p.record.Job.Stage != "preflight" ||
		p.record.CurrentVersion != "0.19.3" || p.record.Job.Release == nil || p.record.Job.Release.Version != "0.20.0" ||
		p.record.Job.Verification != "verified-external-archive-sha256" || p.record.FileReviewSHA256 != "" || p.record.Job.HelperPID != 0 || p.record.ParentPID != p.panel.PID ||
		p.record.Job.Release.Binary.Digest != "sha256:"+p.producer.ExecutableSHA256 || p.record.Job.Release.Archive.Digest != "sha256:"+p.archiveSHA {
		return ErrExternalBootstrap
	}
	id, a := p.record.Job.ID, p.adapter
	helperInfo, helperErr := os.Lstat(a.directory)
	jobInfo, jobErr := os.Lstat(filepath.Join(a.directory, id))
	if helperErr != nil || jobErr != nil || p.helperInfo == nil || p.jobInfo == nil || !os.SameFile(helperInfo, p.helperInfo) || !os.SameFile(jobInfo, p.jobInfo) ||
		a.owned == nil || a.owned(a.directory) != nil || a.owned(filepath.Join(a.directory, id)) != nil {
		return errors.Join(ErrExternalBootstrap, helperErr, jobErr)
	}
	if err := p.owner(ctx, id); err != nil {
		return err
	}
	self, panel, oldSHA, err := externalBootstrapProcesses(ctx, p.record.Deployment)
	if err != nil || self != p.producer || panel != p.panel || oldSHA != p.oldSHA || externalBootstrapEntryMatches(ctx, id, p.archive, p.archiveSHA, self) != nil || !helperConfigMatches(p.record) {
		return errors.Join(ErrExternalBootstrap, err)
	}
	root, err := ownedfs.Open(a.directory)
	if err != nil {
		return err
	}
	data, err := root.ReadLimited("current.json", 64<<10)
	root.Close()
	if err != nil || !bytes.Equal(data, p.header) {
		return errors.Join(ErrExternalBootstrap, err)
	}
	entries, err := boundedJobDirectories(a.directory)
	if err != nil || len(entries) != 2 {
		return errors.Join(ErrExternalBootstrap, err)
	}
	for _, entry := range entries {
		if entry.Name() != "current.json" && (entry.Name() != id || !entry.IsDir() || entry.Type()&os.ModeSymlink != 0) {
			return ErrExternalBootstrap
		}
	}
	for _, path := range []string{a.fileJournal, filepath.Join(a.installation, filepath.FromSlash(pairedPriorArchiveDirectory))} {
		if err := emptyExternalBootstrapNamespace(ctx, path, a.owned); err != nil {
			return err
		}
	}
	job, err := a.commandRoot(id)
	if err != nil {
		return err
	}
	err = VerifyExtracted(job, p.files, *p.record.Job.Release)
	job.Close()
	if err != nil {
		return err
	}
	archiveSHA, err := hashRegularFile(filepath.Join(a.directory, id, "release.tar.gz"), MaximumArchiveBytes)
	if err != nil || archiveSHA != p.archiveSHA {
		return errors.Join(ErrExternalBootstrap, err)
	}
	return p.owner(ctx, id)
}

func (p *externalBootstrapPreparation) matches(ctx context.Context, a *SelfUpdateFileAdapter, record updateRecord, binding *fileBootstrapBinding) error {
	if p == nil || p.adapter != a || binding == nil || binding.Role != externalOld193InstallerRole || binding.HelperSHA256 != p.producer.ExecutableSHA256 ||
		binding.ArchivePath != p.archive || binding.ArchiveSHA256 != p.archiveSHA || record.Job.ID != p.record.Job.ID || record.Job.ConfigRevision != p.record.Job.ConfigRevision ||
		record.ConfigFingerprint != p.record.ConfigFingerprint || record.ExecutableHash != p.oldSHA || !reflect.DeepEqual(record.Files, p.files) || !reflect.DeepEqual(record.Job.Release, p.record.Job.Release) {
		return ErrExternalBootstrap
	}
	cfg, _, err := config.Inspect(record.Deployment.Paths["config"])
	if err != nil {
		return err
	}
	mode := "live"
	if cfg.SafeMode || cfg.ServiceControl.Stopped {
		mode = "offline"
	}
	if binding.Mode != mode {
		return ErrExternalBootstrap
	}
	return p.current(ctx)
}

func (p *externalBootstrapPreparation) preflight(ctx context.Context) error {
	if err := p.current(ctx); err != nil {
		return externalBootstrapFailure("preparation-owner", err)
	}
	bundle := filepath.Join(p.adapter.directory, p.record.Job.ID, "bundle")
	binary := filepath.Join(bundle, "dist", p.record.Job.Release.Binary.Name)
	root, err := ownedfs.Open(bundle)
	if err != nil {
		return externalBootstrapFailure("candidate-version", err)
	}
	program, err := root.OpenFile("dist/"+p.record.Job.Release.Binary.Name, os.O_RDONLY, 0)
	root.Close()
	if err != nil {
		return externalBootstrapFailure("candidate-version", err)
	}
	err = program.Chmod(0755)
	closeErr := program.Close()
	if err != nil || closeErr != nil {
		return externalBootstrapFailure("candidate-version", errors.Join(err, closeErr))
	}
	version, err := probeFileCapability(ctx, binary, "-version")
	if err != nil || version != "0.20.0\n" {
		return externalBootstrapFailure("candidate-version", err)
	}
	if _, _, err := config.Inspect(p.record.Deployment.Paths["config"]); err != nil {
		return externalBootstrapFailure("source-config", err)
	}
	if err := inspectExternalBootstrapCatalogs(bundle); err != nil {
		return externalBootstrapFailure("release-catalogs", err)
	}
	// Only parse the verified scripts. The legacy raw replacement workflow
	// requires schema2 and is deliberately unavailable to this schema0 owner.
	for _, name := range []string{"upgrade-entware.sh", "rollback-entware.sh", "S99razvilka"} {
		if err := p.current(ctx); err != nil {
			return externalBootstrapFailure("preparation-owner", err)
		}
		checkCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		command := exec.CommandContext(checkCtx, "/bin/sh", "-n", filepath.Join(bundle, "scripts", name))
		configureBoundedCommand(command)
		command.Env = commandEnvironment()
		command.Stdout, command.Stderr = nil, nil
		err := runBoundedCommand(command)
		cancel()
		if err != nil {
			return externalBootstrapFailure("release-script-syntax", err)
		}
	}
	if err := p.current(ctx); err != nil {
		return externalBootstrapFailure("preparation-owner", err)
	}
	return nil
}

func inspectExternalBootstrapCatalogs(bundle string) error {
	if _, err := catalog.Load(filepath.Join(bundle, "configs/service-catalog.json")); err != nil {
		return err
	}
	if _, err := sources.LoadRegistry(filepath.Join(bundle, "configs/sources.json")); err != nil {
		return err
	}
	_, err := community.Load(filepath.Join(bundle, "configs/community-catalog.json"))
	return err
}

func (p *externalBootstrapPreparation) capabilities(ctx context.Context, binary string, nodeRequired, componentRequired int) error {
	if err := p.current(ctx); err != nil {
		return err
	}
	if binary != filepath.Join(p.adapter.directory, p.record.Job.ID, "bundle/dist", p.record.Job.Release.Binary.Name) {
		return ErrExternalBootstrap
	}
	if err := checkExternalBootstrapCapabilities(ctx, binary, nodeRequired, componentRequired, probeFileCapability); err != nil {
		return err
	}
	return p.current(ctx)
}

// This is metadata validation, not an effect capability. Its sole production
// caller above retains the actual original producer and both bookends.
func checkExternalBootstrapCapabilities(ctx context.Context, binary string, nodeRequired, componentRequired int, probe func(context.Context, string, string) (string, error)) error {
	if ctx == nil || !knownNodeHistoryReadVersion(nodeRequired) || !knownComponentReadVersion(componentRequired) || probe == nil {
		return ErrFileProtocol
	}
	for _, capability := range []struct{ flag, wanted string }{
		{"-self-update-schema", "0"}, {"-self-update-read-version", "4"}, {"-component-update-schema", ""},
		{"-node-history-read-version", ""}, {"-native-enrollment-schema", "1"}, {"-subscription-schema", "1"},
	} {
		if err := ctx.Err(); err != nil {
			return err
		}
		output, err := probe(ctx, binary, capability.flag)
		if err != nil {
			return err
		}
		switch capability.flag {
		case "-component-update-schema":
			version, err := parseComponentReadVersion(output)
			if err != nil || version < max(components.ComponentUpdateSchema, componentRequired) {
				return ErrComponentHistoryAdmission
			}
		case "-node-history-read-version":
			version, err := parseNodeHistoryReadVersion(output)
			if err != nil || version < max(2, nodeRequired) {
				return ErrNodeHistoryAdmission
			}
		default:
			if strings.TrimSpace(output) != capability.wanted {
				return ErrFileProtocol
			}
		}
	}
	return ctx.Err()
}

func (p *externalBootstrapPreparation) migrate(ctx context.Context, job *ownedfs.Root) error {
	if err := p.current(ctx); err != nil {
		return err
	}
	if job == nil {
		return ErrExternalBootstrap
	}
	jobInfo, err := job.RootInfo()
	if err != nil || !os.SameFile(jobInfo, p.jobInfo) {
		return errors.Join(ErrExternalBootstrap, err)
	}
	// This process is itself the digest-verified candidate. Use its genuine
	// config migration implementation on the exact private staged file; do
	// not grant ordinary Main a startup/migration bypass under a pending header.
	path := filepath.Join(p.adapter.directory, p.record.Job.ID, "staged/config.json")
	held, err := job.Stat("staged/config.json")
	if err != nil {
		return err
	}
	parent, err := job.Stat("staged")
	if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 {
		return errors.Join(ErrExternalBootstrap, err)
	}
	if _, err := config.Migrate(path); err != nil {
		return err
	}
	current, err := os.Lstat(filepath.Dir(path))
	closingParent, parentErr := job.Stat("staged")
	if err != nil || parentErr != nil || !os.SameFile(current, parent) || !os.SameFile(parent, closingParent) || !held.Mode().IsRegular() {
		return errors.Join(ErrExternalBootstrap, err, parentErr)
	}
	return p.current(ctx)
}

type externalBootstrapFailureError struct {
	stage string
	err   error
}

func (e *externalBootstrapFailureError) Error() string { return ExternalBootstrapFailureCategory(e) }
func (e *externalBootstrapFailureError) Unwrap() error { return e.err }

func externalBootstrapFailure(stage string, err error) error {
	var previous *externalBootstrapFailureError
	if errors.As(err, &previous) {
		return errors.Join(ErrExternalBootstrap, err)
	}
	return &externalBootstrapFailureError{stage, errors.Join(ErrExternalBootstrap, err)}
}

// Public diagnostics are a closed vocabulary. Original errors remain in the
// chain for trusted callers, but no raw command output/path can enter this code.
func ExternalBootstrapFailureCategory(err error) string {
	var failure *externalBootstrapFailureError
	if errors.As(err, &failure) {
		switch failure.stage {
		case "preparation-owner", "candidate-version", "source-config", "release-catalogs", "release-script-syntax", "filesystem", "review-capabilities", "staged-migration", "file-review", "review-owner":
			return failure.stage
		}
	}
	return "external-bootstrap-refused"
}
