package components

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/installpath"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// managedUpdateComponents may be updated while their routes are in use: the
// update is checked by the caller and rolled back to a cached copy on failure.
var managedUpdateComponents = map[string]bool{"nfqws2": true, "sing-box": true, "xray": true, "usque": true, "warp-wg": true, "wireguard": true}

// ManagedUpdateSupported reports whether id uses the checked in-use update.
func ManagedUpdateSupported(id string) bool { return managedUpdateComponents[id] }

var ErrRollbackPackageMissing = errors.New("no cached copy of the installed version for rollback")

const (
	maxRollbackPackageBytes = 64 << 20
	maxConffileBytes        = 4 << 20
	maxConffiles            = 32
)

// dirRunner runs a command in a working directory (opkg download writes to
// the current directory).
type dirRunner interface {
	RunIn(ctx context.Context, dir, name string, args ...string) ([]byte, error)
}

func (execRunner) RunIn(ctx context.Context, dir, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	return cmd.CombinedOutput()
}

func (m *Manager) rollbackDir() string {
	return filepath.Join(defaultValue(m.StateDir, installpath.State+"/components"), "rollback-packages")
}

func (m *Manager) infoDir() string { return defaultValue(m.InfoDir, "/opt/lib/opkg/info") }

// RollbackCached reports whether a copy of this version of a managed-update
// component is kept for rollback.
func (m *Manager) RollbackCached(id, version string) bool {
	spec, ok := lookup(id)
	return ok && managedUpdateComponents[id] && m.rollbackPackage(spec, version) != ""
}

// rollbackPackage returns the cached package file of exactly this version.
func (m *Manager) rollbackPackage(spec Spec, version string) string {
	if version == "" || strings.ContainsAny(version, "/\\") {
		return ""
	}
	matches, _ := filepath.Glob(filepath.Join(m.rollbackDir(), spec.Package+"_"+version+"_*.ipk"))
	for _, match := range matches {
		if info, err := os.Lstat(match); err == nil && info.Mode().IsRegular() && info.Size() > 0 {
			return match
		}
	}
	return ""
}

// CacheRollbackPackage keeps one downloaded copy of the installed version of a
// managed-update component while its package source still offers it.
func (m *Manager) CacheRollbackPackage(ctx context.Context, id string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cacheRollbackLocked(ctx, id)
}

func (m *Manager) cacheRollbackLocked(ctx context.Context, id string) (string, error) {
	spec, ok := lookup(id)
	if !ok || !managedUpdateComponents[id] || spec.Provider != "opkg" || m.Opkg == "" {
		return "", fmt.Errorf("component %s has no managed package cache", id)
	}
	installed, err := m.installedPackageVersions(ctx)
	if err != nil {
		return "", err
	}
	version := installed[spec.Package]
	if version == "" {
		return "", fmt.Errorf("%s is not installed", spec.Package)
	}
	if path := m.rollbackPackage(spec, version); path != "" {
		return path, nil
	}
	if m.lastAvailable[spec.Package] != version {
		return "", fmt.Errorf("installed %s %s is no longer offered by its source", spec.Package, version)
	}
	runner, ok := m.Runner.(dirRunner)
	if !ok {
		return "", errors.New("package download runner is unavailable")
	}
	if err := os.MkdirAll(m.rollbackDir(), 0o700); err != nil {
		return "", err
	}
	work, err := os.MkdirTemp(m.rollbackDir(), "download-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(work)
	runCtx, cancel := context.WithTimeout(ctx, defaultDuration(m.Timeout, 90*time.Second))
	defer cancel()
	if out, err := runner.RunIn(runCtx, work, m.Opkg, "download", spec.Package); err != nil {
		return "", fmt.Errorf("opkg download %s: %s", spec.Package, boundedOutput(out))
	}
	matches, _ := filepath.Glob(filepath.Join(work, spec.Package+"_"+version+"_*.ipk"))
	if len(matches) != 1 {
		return "", fmt.Errorf("downloaded package does not match installed %s %s", spec.Package, version)
	}
	info, err := os.Lstat(matches[0])
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > maxRollbackPackageBytes {
		return "", errors.New("downloaded rollback package is invalid")
	}
	target := filepath.Join(m.rollbackDir(), filepath.Base(matches[0]))
	if err := os.Rename(matches[0], target); err != nil {
		return "", err
	}
	// A download is not live acceptance. Keep older packages, including the
	// previous LKG, until a separately reviewed retention operation is added.
	return target, nil
}

type conffileImage struct {
	path   string
	data   []byte
	mode   os.FileMode
	exists bool
}

// snapshotConffiles records the package's configuration files. Packages may
// migrate (replace) a configuration during an upgrade; a rollback restores it.
func (m *Manager) snapshotConffiles(spec Spec) ([]conffileImage, error) {
	list, err := os.ReadFile(filepath.Join(m.infoDir(), spec.Package+".conffiles"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var images []conffileImage
	seen := map[string]bool{}
	total := 0
	scanner := bufio.NewScanner(bytes.NewReader(list))
	for scanner.Scan() {
		path := strings.TrimSpace(scanner.Text())
		if path == "" {
			continue
		}
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || seen[path] || len(images) >= maxConffiles {
			return nil, errors.New("package configuration list is unsafe")
		}
		seen[path] = true
		image := conffileImage{path: path}
		info, err := os.Lstat(path)
		switch {
		case errors.Is(err, os.ErrNotExist):
		case err != nil:
			return nil, err
		case !info.Mode().IsRegular():
			return nil, fmt.Errorf("package configuration %s is not a regular file", path)
		default:
			if image.data, err = os.ReadFile(path); err != nil {
				return nil, err
			}
			image.mode, image.exists = info.Mode().Perm(), true
			total += len(image.data)
		}
		if total > maxConffileBytes {
			return nil, errors.New("package configuration exceeds the rollback snapshot bound")
		}
		images = append(images, image)
	}
	return images, scanner.Err()
}

func restoreConffiles(images []conffileImage) error {
	var failures []error
	for _, image := range images {
		root, err := ownedfs.Open(filepath.Dir(image.path))
		if err != nil {
			failures = append(failures, err)
			continue
		}
		name := filepath.Base(image.path)
		if !image.exists {
			if err := root.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
				failures = append(failures, err)
			}
			failures = append(failures, syncUpdateDirectory(root))
			_ = root.Close()
			continue
		}
		if err := root.WriteAtomic(name, image.data, image.mode); err != nil {
			failures = append(failures, err)
		}
		failures = append(failures, syncUpdateDirectory(root))
		_ = root.Close()
	}
	return errors.Join(failures...)
}

// ManagedUpdate updates a component whose routes are in use. The caller's
// check runs after the package changed (for NFQWS2: configuration kept, init
// adopted, service and routes healthy). If the upgrade or the check fails,
// the package configuration is restored and the cached previous version is
// reinstalled. Candidate evidence is never reused as rollback acceptance;
// the default path remains pending until matching independent recovery.
func (m *Manager) ManagedUpdate(ctx context.Context, id string, check func(context.Context) error) (Result, error) {
	return m.ManagedUpdateGuarded(ctx, id, check, nil)
}

// ManagedUpdateGuarded repeats the caller's current SafeMode/Stop/revision
// admission before each package or configuration mutation. A successful check
// stages the update; RecoverManagedUpdate("accept-live") accepts actual live
// runtime later. Until then the old package/configuration snapshot is retained.
func (m *Manager) ManagedUpdateGuarded(ctx context.Context, id string, check, guard func(context.Context) error) (Result, error) {
	return m.ManagedUpdateGuardedWithRollback(ctx, id, check, guard, nil)
}

// ManagedUpdateGuardedWithRollback optionally supplies separate trusted live
// or inactive evidence for the old runtime. It must not be a candidate probe.
// Without it, known file/package rollback stops at awaiting-rollback-acceptance.
func (m *Manager) ManagedUpdateGuardedWithRollback(ctx context.Context, id string, check, guard, rollbackAcceptance func(context.Context) error) (Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.nfqwsPackageMutationGuard(id); err != nil {
		return Result{Component: id, Action: "update"}, NoMutation(err)
	}
	spec, ok := lookup(id)
	if !ok || !managedUpdateComponents[id] || check == nil {
		return Result{}, NoMutation(fmt.Errorf("component %s has no managed update", id))
	}
	if err := m.usquePackageNetworkPreflight(id); err != nil {
		return Result{Component: id, Action: "update"}, NoMutation(err)
	}
	tx, err := m.lockUpdateJournal()
	if err != nil {
		return Result{}, NoMutation(err)
	}
	defer tx.close()
	if err := tx.requireIdle(); err != nil {
		return Result{}, NoMutation(err)
	}
	if err := tx.authority(ctx, guard); err != nil {
		return Result{}, NoMutation(err)
	}
	installed, err := m.installedPackageVersions(ctx)
	if err != nil {
		return Result{Component: id, Action: "update"}, NoMutation(err)
	}
	before := installed[spec.Package]
	rollback := m.rollbackPackage(spec, before)
	if before == "" || rollback == "" {
		return Result{Component: id, Action: "update"}, NoMutation(ErrRollbackPackageMissing)
	}
	// A managed transaction snapshots one package. Installing a missing
	// dependency here would add an unjournaled package/script side effect.
	for _, dependency := range spec.Dependencies {
		dep, known := lookup(dependency)
		if !known || (dep.Provider == "opkg" && installed[dep.Package] == "") || (dep.Provider == "github-release" && externalReceiptVersion(filepath.Join(defaultValue(m.BinDir, "/opt/bin"), dep.Binary)) == "") {
			return Result{}, NoMutation(fmt.Errorf("managed update dependency %s must already be installed", dependency))
		}
	}
	conffiles, err := m.snapshotConffiles(spec)
	if err != nil {
		return Result{Component: id, Action: "update"}, NoMutation(fmt.Errorf("snapshot package configuration: %w", err))
	}
	if err := tx.prepare(spec, before, rollback, conffiles); err != nil {
		return Result{}, NoMutation(err)
	}
	result, updateErr := m.applyJournalLocked(ctx, id, map[string]bool{}, tx, guard)
	// Even a non-advancing version may follow package/configuration changes.
	// It must use the same verified rollback as any other failed upgrade.
	var checkErr error
	if updateErr == nil {
		checkErr = tx.authority(ctx, guard)
		if checkErr == nil {
			checkErr = check(ctx)
		}
		if checkErr == nil {
			versions, err := m.installedPackageVersions(ctx)
			if err != nil {
				return result, &UpdateFailure{Outcome: ErrRollbackUnconfirmed, Version: before, Cause: err}
			}
			if versions[spec.Package] != tx.doc.AfterVersion {
				return result, &UpdateFailure{Outcome: ErrRollbackUnconfirmed, Version: before, Cause: errors.New("package version changed during candidate check")}
			}
			if err := tx.captureCandidateConfig(spec); err != nil {
				return result, &UpdateFailure{Outcome: ErrRollbackUnconfirmed, Version: before, Cause: err}
			}
			if err := tx.phase(UpdateAwaitingLive); err != nil {
				return result, &UpdateFailure{Outcome: ErrRollbackUnconfirmed, Version: before, Cause: err}
			}
			result.TransactionID, result.PendingLiveAcceptance = tx.doc.TransactionID, true
			if _, cacheErr := m.cacheRollbackLocked(ctx, id); cacheErr != nil {
				result.Output += "\nnew version is not cached for a later rollback yet: " + boundedMessage(cacheErr.Error())
			}
			return result, nil
		}
	}
	cause := errors.Join(updateErr, checkErr)
	// An intent with no durably recorded command completion is unknown. It
	// must remain fenced, even if version readback happens to look unchanged.
	persisted, _, readErr := readUpdateJournal(tx.root)
	if readErr != nil || persisted.Phase != UpdateInstalled {
		return Result{Component: id, Action: "update"}, &UpdateFailure{Outcome: ErrRollbackUnconfirmed, Version: before, Cause: errors.Join(cause, readErr, ErrUpdatePending)}
	}
	rollbackResult, rollbackErr := tx.rollback(ctx, guard, rollbackAcceptance)
	if rollbackErr != nil {
		return rollbackResult, &UpdateFailure{Outcome: ErrRollbackUnconfirmed, Version: before, Cause: errors.Join(cause, rollbackErr)}
	}
	rollbackResult.OK = false
	return rollbackResult, &UpdateFailure{Outcome: ErrRollbackVerified, Version: before, Cause: cause}
}

func defaultDuration(value, fallback time.Duration) time.Duration {
	if value <= 0 {
		return fallback
	}
	return value
}
