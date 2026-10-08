package updatecheck

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

const productionFileJournal = "/opt/var/lib/razvilka/self-update-files"

var ErrFileAuthorityStopped = errors.New("self update authority was durably revoked")

// StopCheck is wired by CORE to its single operationgate Stop journal. An
// active request returns stopped=true, nil. Unavailable/corrupt evidence must
// return an error. A missing consumer never authorizes production effects.
type SelfUpdateStopCheck func(context.Context, string) (stopped bool, err error)

// CORE binds this to its short interprocess epoch admission, shared with
// RequestSelfUpdateStop. begin performs only the exact bounded start/rename
// syscall; it must not wait a process, fsync, or acquire a live Store.
type SelfUpdateEffectAdmission func(ctx context.Context, id, installationID string, sequence uint64, action, effectID string, begin func() error) error

// This immutable authority is read by trusted CORE review, then sealed with
// the candidate. The consumer compares both values under the Stop lock.
type SelfUpdateAuthority struct {
	InstallationID string
	Sequence       uint64
}

type SelfUpdateRuntimeObservation func(context.Context, string) error

type fileReview struct {
	Schema                  int                      `json:"schema"`
	ID                      string                   `json:"id"`
	Revision                uint64                   `json:"revision"`
	AuthorityInstallationID string                   `json:"authority_installation_id"`
	AuthoritySequence       uint64                   `json:"authority_sequence"`
	OldConfigSHA256         string                   `json:"old_config_sha256"`
	MigratedConfigSHA256    string                   `json:"migrated_config_sha256"`
	OldExecutableSHA256     string                   `json:"old_executable_sha256"`
	OldInitSHA256           string                   `json:"old_init_sha256"`
	OldVersion              string                   `json:"old_version"`
	NewVersion              string                   `json:"new_version"`
	ReleaseID               int64                    `json:"release_id"`
	Files                   []selfupdatejournal.File `json:"files"`
	JournalReaders          *journalReaderProof      `json:"journal_readers,omitempty"`
}

// Concrete neutral provider: this package does not import app. Production
// paths are fixed; private overrides below exist only for isolated fixtures.
type SelfUpdateFileAdapter struct {
	directory       string
	installation    string
	fileJournal     string
	owned           func(string) error
	layout          func(Deployment) error
	capabilities    func(context.Context, string) error
	filesystem      func(context.Context) error
	stopCheck       SelfUpdateStopCheck
	admission       SelfUpdateEffectAdmission
	runtimeInactive SelfUpdateRuntimeObservation
	// Private process observer override is used only by isolated model tests.
	processInactive func(context.Context, fileProcess) error
}

func NewSelfUpdateFileAdapterWithAuthority(stop SelfUpdateStopCheck, admission SelfUpdateEffectAdmission, runtime ...SelfUpdateRuntimeObservation) *SelfUpdateFileAdapter {
	a := NewSelfUpdateFileAdapter(stop)
	a.admission = admission
	if len(runtime) == 1 {
		a.runtimeInactive = runtime[0]
	}
	return a
}

func NewSelfUpdateFileAdapter(stop ...SelfUpdateStopCheck) *SelfUpdateFileAdapter {
	a := &SelfUpdateFileAdapter{directory: productionUpdateRoot, installation: "/opt", fileJournal: productionFileJournal, owned: checkRootOwnedPath, layout: checkDeploymentLayout, capabilities: checkFileCapabilities}
	a.filesystem = func(ctx context.Context) error { return probePrivateFilesystems(ctx, a.installation) }
	if len(stop) == 1 {
		a.stopCheck = stop[0]
	}
	return a
}

func readAdapterRecord(directory, id string) (updateRecord, error) {
	var record updateRecord
	if !jobIDPattern.MatchString(id) {
		return record, ErrFileProtocol
	}
	root, err := ownedfs.Open(directory)
	if err != nil {
		return record, err
	}
	defer root.Close()
	data, err := root.ReadLimited("current.json", 64<<10)
	if err != nil {
		return record, err
	}
	// Existing helper receipt fields remain backwards readable, but a file
	// protocol record must include the separately sealed immutable review.
	if decodeFileProtocol(data, &record) != nil || record.Owner != updaterOwner || record.Job.ID != id || record.Job.Release == nil || !validDigest("sha256:"+record.FileReviewSHA256) {
		return record, ErrFileProtocol
	}
	switch record.Job.State {
	case "ready", "installing", "restarting", "requires-review", "completed", "rolled-back", stoppedRollbackState:
	default:
		return record, ErrFileProtocol
	}
	return record, nil
}

func (a *SelfUpdateFileAdapter) load(ctx context.Context, id string) (updateRecord, fileReview, error) {
	return a.loadReview(ctx, id, true)
}
func (a *SelfUpdateFileAdapter) loadHeader(ctx context.Context, id string) (updateRecord, fileReview, error) {
	return a.loadReview(ctx, id, false)
}
func (a *SelfUpdateFileAdapter) loadReview(ctx context.Context, id string, verifyArtifacts bool) (updateRecord, fileReview, error) {
	return a.loadBoundReview(ctx, id, verifyArtifacts, false)
}

func (a *SelfUpdateFileAdapter) loadBoundReview(ctx context.Context, id string, verifyArtifacts, retained bool) (updateRecord, fileReview, error) {
	var review fileReview
	if err := ctx.Err(); err != nil {
		return updateRecord{}, review, err
	}
	if a == nil || a.owned == nil || a.layout == nil {
		return updateRecord{}, review, ErrFileProtocol
	}
	if err := a.owned(a.directory); err != nil {
		return updateRecord{}, review, err
	}
	var record updateRecord
	var err error
	if retained {
		record, err = readRetainedHelperRecord(a.directory, id)
	} else {
		record, err = readAdapterRecord(a.directory, id)
	}
	if err != nil {
		return record, review, err
	}
	if err := a.layout(record.Deployment); err != nil {
		return record, review, err
	}
	jobPath := filepath.Join(a.directory, id)
	if err := a.owned(jobPath); err != nil {
		return record, review, err
	}
	root, err := ownedfs.Open(jobPath)
	if err != nil {
		return record, review, err
	}
	defer root.Close()
	data, err := root.ReadLimited("file-review.json", 256<<10)
	if err != nil || digestBytes(data) != record.FileReviewSHA256 || decodeFileProtocol(data, &review) != nil {
		return record, review, ErrFileProtocol
	}
	if review.Schema != selfUpdateProtocolSchema || review.ID != id || !jobIDPattern.MatchString(review.AuthorityInstallationID) || review.AuthoritySequence == 0 || review.Revision != record.Job.ConfigRevision || review.ReleaseID != record.Job.Release.ID || review.OldVersion != record.CurrentVersion || review.NewVersion != record.Job.Release.Version || review.OldExecutableSHA256 != record.ExecutableHash || !validDigest("sha256:"+review.OldExecutableSHA256) || !validDigest("sha256:"+review.OldInitSHA256) || !validDigest("sha256:"+review.OldConfigSHA256) || !validDigest("sha256:"+review.MigratedConfigSHA256) {
		return record, review, ErrFileProtocol
	}
	if verifyArtifacts {
		if err := VerifyExtracted(root, record.Files, *record.Job.Release); err != nil {
			return record, review, err
		}
	}
	expected := reviewedFileList(jobPath, *record.Job.Release, record.Files, review.MigratedConfigSHA256)
	if !reflect.DeepEqual(expected, review.Files) {
		return record, review, ErrFileProtocol
	}
	for _, file := range review.Files {
		if !verifyArtifacts || file.Target != "etc/razvilka/config.json" {
			continue
		}
		hash, err := hashRegularFile(file.Candidate, MaximumBinaryBytes)
		if err != nil || hash != file.SHA256 {
			return record, review, ErrFileProtocol
		}
	}
	return record, review, ctx.Err()
}

func archiveHelperRecord(directory string, record updateRecord) error {
	if !jobIDPattern.MatchString(record.Job.ID) || !validDigest("sha256:"+record.FileReviewSHA256) || !terminalHelperState(record.Job.State) {
		return ErrFileProtocol
	}
	root, err := ownedfs.Open(filepath.Join(directory, record.Job.ID))
	if err != nil {
		return err
	}
	defer root.Close()
	if existing, err := root.ReadLimited("retained-helper.json", 64<<10); err == nil {
		var previous updateRecord
		if decodeFileProtocol(existing, &previous) != nil || previous.Job.ID != record.Job.ID || previous.FileReviewSHA256 != record.FileReviewSHA256 || previous.Job.State != record.Job.State {
			return ErrFileProtocol
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if err := root.WriteAtomic("retained-helper.json", data, 0600); err != nil {
		return err
	}
	return syncSelfUpdateDirectory(root)
}

func readRetainedHelperRecord(directory, id string) (updateRecord, error) {
	var record updateRecord
	if !jobIDPattern.MatchString(id) {
		return record, ErrFileProtocol
	}
	root, err := ownedfs.Open(filepath.Join(directory, id))
	if err != nil {
		return record, err
	}
	defer root.Close()
	data, err := root.ReadLimited("retained-helper.json", 64<<10)
	if err != nil {
		return record, err
	}
	if decodeFileProtocol(data, &record) != nil || record.Owner != updaterOwner || record.Job.ID != id || record.Job.Release == nil || !validDigest("sha256:"+record.FileReviewSHA256) || !terminalHelperState(record.Job.State) {
		return record, ErrFileProtocol
	}
	return record, nil
}

func (a *SelfUpdateFileAdapter) Inspect(ctx context.Context, id string) error {
	if err := a.checkStop(ctx, id, "read/observe"); err != nil {
		return err
	}
	record, review, err := a.loadBoundReview(ctx, id, true, true)
	if err != nil {
		return err
	}
	store, err := a.OpenFileJournal()
	if err != nil {
		return err
	}
	defer store.Close()
	receipt, present, err := store.Current()
	if err != nil || !present || receipt.ID != id || receipt.Pending() {
		return errors.Join(ErrFileProtocol, err)
	}
	wanted := "accepted"
	if record.Job.State == "rolled-back" {
		wanted = "rolled-back"
	}
	if record.Job.State == stoppedRollbackState {
		wanted = stoppedRollbackState
	}
	if receipt.Rollback != (record.Job.State != "completed") || (receipt.Phase != wanted && !(wanted == "accepted" && receipt.Phase == "archived")) {
		return ErrFileProtocol
	}
	if wanted == stoppedRollbackState && (receipt.Stopped == nil || receipt.Stopped.InstallationID != review.AuthorityInstallationID || receipt.Stopped.PreStopSequence != review.AuthoritySequence || receipt.Stopped.Revision != review.Revision || !validJournalReaderProof(review.JournalReaders)) {
		return ErrFileProtocol
	}
	if err := store.VerifyTerminalArtifacts(ctx, id, receipt.Rollback); err != nil {
		return err
	}
	root, err := ownedfs.Open(filepath.Dir(record.Deployment.Paths["config"]))
	if err != nil {
		return err
	}
	defer root.Close()
	data, err := root.ReadLimited(filepath.Base(record.Deployment.Paths["config"]), 4<<20)
	if err != nil {
		return err
	}
	cfg, _, err := config.InspectBytes(data)
	if err != nil || cfg.Revision < review.Revision {
		return errors.Join(ErrFileProtocol, err)
	}
	return a.checkStop(ctx, id, "read/observe")
}

func reviewedFileList(jobPath string, release Release, hashes map[string]string, configSHA string) []selfupdatejournal.File {
	var files []selfupdatejournal.File
	for _, mapping := range []struct{ target, source string }{
		{"bin/razvilka", "dist/" + release.Binary.Name},
		{"etc/init.d/S99razvilka", "scripts/S99razvilka"},
		{"etc/razvilka/service-catalog.json", "configs/service-catalog.json"},
		{"etc/razvilka/community-catalog.json", "configs/community-catalog.json"},
		{"etc/razvilka/sources.json", "configs/sources.json"},
	} {
		files = append(files, selfupdatejournal.File{Target: mapping.target, Candidate: filepath.Join(jobPath, "bundle", filepath.FromSlash(mapping.source)), SHA256: hashes[mapping.source]})
	}
	files = append(files, selfupdatejournal.File{Target: "etc/razvilka/config.json", Candidate: filepath.Join(jobPath, "staged", "config.json"), SHA256: configSHA})
	return files
}

func stageFileReview(ctx context.Context, directory string, record updateRecord, authorityReview func(context.Context, string) (SelfUpdateAuthority, error), admission SelfUpdateEffectAdmission) (string, error) {
	if record.Job.Release == nil || !helperConfigMatches(record) {
		return "", ErrReviewChanged
	}
	if authorityReview == nil {
		return "", ErrFileProtocol
	}
	authority, err := authorityReview(ctx, record.Job.ID)
	if err != nil || authority.Sequence == 0 || !jobIDPattern.MatchString(authority.InstallationID) {
		return "", errors.Join(ErrFileProtocol, err)
	}
	root, err := ownedfs.Open(filepath.Join(directory, record.Job.ID))
	if err != nil {
		return "", err
	}
	defer root.Close()
	if err := VerifyExtracted(root, record.Files, *record.Job.Release); err != nil {
		return "", err
	}
	jobPath := filepath.Join(directory, record.Job.ID)
	binary := filepath.Join(jobPath, "bundle", "dist", record.Job.Release.Binary.Name)
	requiredNodeReader, err := RequiredRetainedNodeHistoryReadVersion(ctx, "/opt/etc/razvilka", "/opt/var/lib/razvilka", validatedNodeHistoryRead)
	if err != nil {
		return "", err
	}
	requiredComponentReader, componentSeal, err := components.InspectRetainedManagedUpdateReadVersion(ctx, "/opt/var/lib/razvilka/components")
	if err != nil {
		return "", err
	}
	if err := checkFileCapabilitiesForHistories(ctx, binary, requiredNodeReader, requiredComponentReader, probeFileCapability); err != nil {
		return "", err
	}
	if err := checkFileCapabilitiesForHistories(ctx, record.Deployment.Executable, requiredNodeReader, requiredComponentReader, probeFileCapability); err != nil {
		return "", errors.New("current-file-controller-capability-refused")
	}
	if err := root.MkdirAll("staged", 0700); err != nil {
		return "", err
	}
	configRoot, err := ownedfs.Open(filepath.Dir(record.Deployment.Paths["config"]))
	if err != nil {
		return "", err
	}
	defer configRoot.Close()
	old, err := configRoot.ReadLimited(filepath.Base(record.Deployment.Paths["config"]), 4<<20)
	if err != nil {
		return "", err
	}
	if err := root.WriteAtomic("staged/config.json", old, 0600); err != nil {
		return "", err
	}
	// Migration touches only the staged configuration and isolated empty
	// private roots. Its final bytes are sealed before file Prepare.
	args := []string{"-migrate-config", "-config", filepath.Join(jobPath, "staged", "config.json")}
	for flag, name := range map[string]string{"-custom-services": "custom.json", "-devices": "devices.json", "-node-state": "nodes", "-stage": "engines", "-warp-state": "warp", "-cloudflare-state": "cloudflare"} {
		args = append(args, flag, filepath.Join(jobPath, "staged", name))
	}
	for flag, name := range map[string]string{"-catalog": "service-catalog.json", "-sources": "sources.json", "-community-catalog": "community-catalog.json"} {
		args = append(args, flag, filepath.Join(jobPath, "bundle", "configs", name))
	}
	command := exec.CommandContext(ctx, binary, args...)
	command.Env = commandEnvironment()
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := runBoundedCommand(command); err != nil {
		return "", errors.New("staged-config-migration-refused")
	}
	staged, err := root.ReadLimited("staged/config.json", 4<<20)
	if err != nil {
		return "", err
	}
	if _, err := inspectFileMigration(old, staged, record.Job.ConfigRevision); err != nil {
		return "", err
	}
	review := fileReview{Schema: selfUpdateProtocolSchema, ID: record.Job.ID, Revision: record.Job.ConfigRevision, OldConfigSHA256: digestBytes(old), MigratedConfigSHA256: digestBytes(staged), OldExecutableSHA256: record.ExecutableHash, OldVersion: record.CurrentVersion, NewVersion: record.Job.Release.Version, ReleaseID: record.Job.Release.ID}
	review.AuthoritySequence = authority.Sequence
	review.AuthorityInstallationID = authority.InstallationID
	review.OldInitSHA256, err = hashRegularFile("/opt/etc/init.d/S99razvilka", 256<<10)
	if err != nil {
		return "", err
	}
	if err := copyFileController(root, record.Deployment.Executable, record.ExecutableHash); err != nil {
		return "", err
	}
	review.Files = reviewedFileList(jobPath, *record.Job.Release, record.Files, review.MigratedConfigSHA256)
	readerAdapter := NewSelfUpdateFileAdapterWithAuthority(nil, admission)
	readerAdapter.directory = directory
	// Nil proof is an explicit ineligible outcome for stopped settlement.
	// Keeping the schema2 encoding unchanged lets the existing reader2 helper
	// perform an ordinary live upgrade; it cannot write the new terminal3.
	review.JournalReaders, err = readerAdapter.sealOptionalJournalReadersWithProbe(ctx, review, authorityReview, readerAdapter.probeJournalReader)
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(review)
	if err != nil {
		return "", err
	}
	if len(data) > 256<<10 {
		return "", ErrFileProtocol
	}
	file, err := root.OpenFile("file-review.json", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", err
	}
	defer file.Close()
	if _, err = file.Write(data); err != nil {
		return "", err
	}
	if err = file.Sync(); err != nil {
		return "", err
	}
	if err = file.Close(); err != nil {
		return "", err
	}
	if err := syncSelfUpdateDirectory(root); err != nil {
		return "", err
	}
	if !helperConfigMatches(record) {
		return "", ErrReviewChanged
	}
	freshNodeReader, err := RequiredRetainedNodeHistoryReadVersion(ctx, "/opt/etc/razvilka", "/opt/var/lib/razvilka", validatedNodeHistoryRead)
	if err != nil || freshNodeReader != requiredNodeReader {
		return "", errors.Join(ErrReviewChanged, err)
	}
	freshComponentReader, freshComponentSeal, err := components.InspectRetainedManagedUpdateReadVersion(ctx, "/opt/var/lib/razvilka/components")
	if err != nil || freshComponentReader != requiredComponentReader || freshComponentSeal != componentSeal {
		return "", errors.Join(ErrReviewChanged, err)
	}
	freshAuthority, err := authorityReview(ctx, record.Job.ID)
	if err != nil || freshAuthority != authority {
		return "", errors.Join(ErrFileProtocol, err)
	}
	return digestBytes(data), nil
}

func copyFileController(root *ownedfs.Root, path, expected string) error {
	in, err := os.Open(path)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := root.OpenFile("control.bin", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	if err != nil {
		return err
	}
	defer out.Close()
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, hash), io.LimitReader(in, MaximumBinaryBytes+1))
	if err != nil || n > MaximumBinaryBytes || hex.EncodeToString(hash.Sum(nil)) != expected {
		return ErrReviewChanged
	}
	if err := out.Sync(); err != nil {
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return syncSelfUpdateDirectory(root)
}

func checkFileCapabilities(ctx context.Context, binary string) error {
	required, err := RequiredRetainedNodeHistoryReadVersion(ctx, "/opt/etc/razvilka", "/opt/var/lib/razvilka", validatedNodeHistoryRead)
	if err != nil {
		return err
	}
	componentRequired, err := components.RequiredRetainedManagedUpdateReadVersion(ctx, "/opt/var/lib/razvilka/components")
	if err != nil {
		return err
	}
	return checkFileCapabilitiesForHistories(ctx, binary, required, componentRequired, probeFileCapability)
}

func checkFileCapabilitiesForNodeHistory(ctx context.Context, binary string, required int, probe func(context.Context, string, string) (string, error)) error {
	return checkFileCapabilitiesForHistories(ctx, binary, required, components.ComponentUpdateSchema, probe)
}

func checkFileCapabilitiesForHistories(ctx context.Context, binary string, required, componentRequired int, probe func(context.Context, string, string) (string, error)) error {
	if !knownNodeHistoryReadVersion(required) || !knownComponentReadVersion(componentRequired) || probe == nil {
		return ErrFileProtocol
	}
	// Keep the existing reader2 floor for ordinary file-protocol2 controllers.
	// Reader3 is additionally admitted only with the actual typed library;
	// retained XHTTP material requires 3 without changing any journal schema.
	if required < 2 {
		required = 2
	}
	for _, capability := range []struct{ flag, wanted string }{
		{"-self-update-schema", "2"}, {"-component-update-schema", "2"},
		{"-node-history-read-version", ""}, {"-native-enrollment-schema", "1"}, {"-subscription-schema", "1"},
	} {
		if err := ctx.Err(); err != nil {
			return err
		}
		output, err := probe(ctx, binary, capability.flag)
		if err != nil {
			return errors.New("candidate-recovery-capability-refused")
		}
		if capability.flag == "-component-update-schema" {
			version, err := parseComponentReadVersion(output)
			if err != nil || version < max(components.ComponentUpdateSchema, componentRequired) {
				return ErrComponentHistoryAdmission
			}
		} else if capability.flag == "-node-history-read-version" {
			version, err := parseNodeHistoryReadVersion(output)
			if err != nil || version < required {
				return ErrNodeHistoryAdmission
			}
		} else if strings.TrimSpace(output) != capability.wanted {
			return errors.New("candidate-recovery-capability-refused")
		}
	}
	return ctx.Err()
}

func probeFileCapability(ctx context.Context, binary, flag string) (string, error) {
	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	command := exec.CommandContext(probeCtx, binary, flag)
	command.Env = commandEnvironment()
	out := &cappedOutput{maximum: 32}
	stderr := &cappedOutput{maximum: 1024}
	command.Stdout = out
	command.Stderr = stderr
	if err := runBoundedCommand(command); err != nil || stderr.Len() != 0 {
		return "", errors.New("candidate-recovery-capability-refused")
	}
	return out.String(), ctx.Err()
}

func (a *SelfUpdateFileAdapter) Ready(ctx context.Context, id string) error {
	if a == nil || a.admission == nil || a.runtimeInactive == nil || a.filesystem == nil {
		return ErrFileProtocol
	}
	record, _, err := a.load(ctx, id)
	if err != nil {
		return err
	}
	if record.Job.State != "ready" || !record.Job.CanApply || record.ParentPID != os.Getpid() || record.Job.ReviewToken == "" || time.Since(record.Job.UpdatedAt) > 15*time.Minute {
		return ErrReviewChanged
	}
	if err := a.Authority(ctx, id, record.Job.ConfigRevision); err != nil {
		return err
	}
	if err := a.filesystem(ctx); err != nil {
		return err
	}
	if err := a.capabilities(ctx, filepath.Join(a.directory, id, "bundle", "dist", record.Job.Release.Binary.Name)); err != nil {
		return err
	}
	return a.Authority(ctx, id, record.Job.ConfigRevision)
}

func (a *SelfUpdateFileAdapter) EffectAdmission(ctx context.Context, id, action, effectID string, begin func() error) error {
	_, review, err := a.loadHeader(ctx, id)
	if err != nil {
		return err
	}
	if err := a.AuthorityAction(ctx, id, review.Revision, action); err != nil {
		return err
	}
	if a.admission == nil || begin == nil || !validFileEffect(effectID) || !validFileEffectAction(effectID, action) {
		return ErrFileProtocol
	}
	return a.admission(ctx, id, review.AuthorityInstallationID, review.AuthoritySequence, action, effectID, begin)
}

func validFileEffectAction(effect, action string) bool {
	if effect == installerHelperEffect || effect == journalReaderProbeEffect || pairedFileEffect(effect) || fileLiveProbeEffect(effect) {
		return action == "start/live"
	}
	for _, prefix := range []string{"command-worker-", "command-child-"} {
		if strings.HasPrefix(effect, prefix) {
			return fileCommandAuthority(strings.TrimPrefix(effect, prefix)) == action
		}
	}
	if strings.HasPrefix(effect, "install-file-") {
		return action == "start/live"
	}
	if strings.HasPrefix(effect, "rollback-file-") {
		return action == "replace-to-rollback"
	}
	if strings.HasPrefix(effect, "rollback-private-") {
		return action == "replace-to-rollback"
	}
	return false
}

func validFileEffect(effect string) bool {
	if effect == installerHelperEffect || effect == journalReaderProbeEffect || pairedFileEffect(effect) || fileLiveProbeEffect(effect) {
		return true
	}
	if strings.HasPrefix(effect, "rollback-private-") {
		name := strings.TrimPrefix(effect, "rollback-private-")
		_, directory := fileMutablePrivateDirectories[name]
		_, file := filePrivateFiles[name]
		return directory || file
	}
	for _, prefix := range []string{"command-worker-", "command-child-"} {
		if strings.HasPrefix(effect, prefix) {
			return validFileCommand(strings.TrimPrefix(effect, prefix))
		}
	}
	for _, prefix := range []string{"install-file-", "rollback-file-"} {
		if strings.HasPrefix(effect, prefix) {
			value := strings.TrimPrefix(effect, prefix)
			n, err := strconv.Atoi(value)
			return err == nil && n >= 0 && n < 6 && strconv.Itoa(n) == value
		}
	}
	return false
}

func (a *SelfUpdateFileAdapter) Review(ctx context.Context, id string) (uint64, string, []selfupdatejournal.File, error) {
	_, review, err := a.load(ctx, id)
	if err != nil {
		return 0, "", nil, err
	}
	return review.Revision, review.MigratedConfigSHA256, append([]selfupdatejournal.File(nil), review.Files...), nil
}

func (a *SelfUpdateFileAdapter) Authority(ctx context.Context, id string, revision uint64) error {
	return a.AuthorityAction(ctx, id, revision, "start/live")
}

// Action-sensitive authority does not clear Stop. CORE retains independent
// matching admission and quiescence checks for rollback and owned cleanup.
func (a *SelfUpdateFileAdapter) AuthorityAction(ctx context.Context, id string, revision uint64, action string) error {
	if err := a.checkStop(ctx, id, action); err != nil {
		return err
	}
	record, review, err := a.loadHeader(ctx, id)
	if err != nil {
		return err
	}
	if revision != review.Revision {
		return ErrReviewChanged
	}
	root, err := ownedfs.Open(filepath.Dir(record.Deployment.Paths["config"]))
	if err != nil {
		return err
	}
	defer root.Close()
	data, err := root.ReadLimited(filepath.Base(record.Deployment.Paths["config"]), 4<<20)
	if err != nil {
		return err
	}
	hash := digestBytes(data)
	if hash != review.OldConfigSHA256 && hash != review.MigratedConfigSHA256 {
		return ErrReviewChanged
	}
	cfg, _, err := config.InspectBytes(data)
	if err != nil || cfg.Revision != revision || cfg.SafeMode || cfg.ServiceControl.Stopped {
		return ErrReviewChanged
	}
	if err := a.configExclusionsCurrent(ctx, review, data); err != nil {
		return err
	}
	if action == "start/live" && (cfg.InactiveResourceExclusions != nil || config.ValidateListNetworkPolicy(cfg.NetworkPolicy) != nil || config.ValidateListNetworkPolicy(cfg.AppliedNetworkPolicy) != nil || !filePolicyExclusionsEqual(cfg.NetworkPolicy, cfg.AppliedNetworkPolicy)) {
		return ErrReviewChanged
	}
	return a.checkStop(ctx, id, action)
}

func (a *SelfUpdateFileAdapter) checkStop(ctx context.Context, id, action string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if a == nil || a.stopCheck == nil || !jobIDPattern.MatchString(id) {
		return ErrFileProtocol
	}
	switch action {
	case "read/observe", "replace-to-rollback", "stop-owned", "start/live":
	default:
		return ErrFileProtocol
	}
	stopped, err := a.stopCheck(ctx, id)
	if err != nil {
		return err
	}
	if stopped && action == "start/live" {
		return ErrFileAuthorityStopped
	}
	return ctx.Err()
}

func fileCommandAuthority(command string) string {
	switch command {
	case "stop-old-panel", "stop-candidate-panel", "quiesce-old-runtime":
		return "stop-owned"
	case "restore-private-state":
		return "replace-to-rollback"
	default:
		return "start/live"
	}
}

func (a *SelfUpdateFileAdapter) Finish(ctx context.Context, id string, rollback bool) error {
	record, review, err := a.load(ctx, id)
	if err != nil {
		return err
	}
	if err := a.Authority(ctx, id, review.Revision); err != nil {
		return err
	}
	store, err := a.OpenFileJournal()
	if err != nil {
		return err
	}
	defer store.Close()
	r, present, err := store.Current()
	if err != nil || !present || r.ID != id || r.Rollback != rollback || (!rollback && r.Phase != "accepted") || (rollback && r.Phase != "rolled-back") {
		return ErrFileProtocol
	}
	if err := store.VerifyInstallation(ctx, id, rollback); err != nil {
		return err
	}
	if err := a.Live(ctx, id, rollback); err != nil {
		return err
	}
	if err := a.Authority(ctx, id, review.Revision); err != nil {
		return err
	}
	if err := store.VerifyInstallation(ctx, id, rollback); err != nil {
		return err
	}
	root, err := ownedfs.Open(a.directory)
	if err != nil {
		return err
	}
	defer root.Close()
	fresh, err := readAdapterRecord(a.directory, id)
	if err != nil {
		return err
	}
	if fresh.FileReviewSHA256 != record.FileReviewSHA256 {
		return ErrReviewChanged
	}
	wanted := "completed"
	if rollback {
		wanted = "rolled-back"
	}
	if fresh.Job.State == wanted {
		return nil
	}
	if terminalHelperState(fresh.Job.State) {
		return ErrFileProtocol
	}
	fresh.Job.State = wanted
	fresh.Job.Stage = wanted
	fresh.Job.Code = ""
	fresh.Job.Message = ""
	fresh.Job.CanApply = false
	fresh.Job.CanCancel = false
	fresh.Job.UpdatedAt = time.Now().UTC()
	if err := archiveHelperRecord(a.directory, fresh); err != nil {
		return err
	}
	data, err := json.Marshal(fresh)
	if err != nil {
		return err
	}
	return writeSelfUpdateRecord(root, data)
}

// Adapter methods below use the separate command supervision ledger.
func (a *SelfUpdateFileAdapter) Run(ctx context.Context, id, command string) error {
	return a.runFileCommand(ctx, id, command)
}
func (a *SelfUpdateFileAdapter) Quiescence(ctx context.Context, id string) error {
	return a.fileQuiescence(ctx, id)
}
func (a *SelfUpdateFileAdapter) Observe(ctx context.Context, id, command string) error {
	return a.observeFileCommand(ctx, id, command)
}
func (a *SelfUpdateFileAdapter) Live(ctx context.Context, id string, rollback bool) error {
	if err := a.checkStop(ctx, id, "start/live"); err != nil {
		return err
	}
	if err := a.liveFileRuntime(ctx, id, rollback); err != nil {
		return err
	}
	return a.checkStop(ctx, id, "start/live")
}
func (a *SelfUpdateFileAdapter) Startup(ctx context.Context, id string, pid int) error {
	if pid <= 1 {
		return ErrFileProtocol
	}
	if err := a.checkStop(ctx, id, "start/live"); err != nil {
		return err
	}
	if err := a.fileStartup(ctx, id, strconv.Itoa(pid)); err != nil {
		return err
	}
	return a.checkStop(ctx, id, "start/live")
}
