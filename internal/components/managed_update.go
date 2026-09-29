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
	return filepath.Join(defaultValue(m.StateDir, "/opt/var/lib/razvilka/components"), "rollback-packages")
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
	// Keep exactly one cached version per package.
	others, _ := filepath.Glob(filepath.Join(m.rollbackDir(), spec.Package+"_*.ipk"))
	for _, other := range others {
		if other != target {
			_ = os.Remove(other)
		}
	}
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
	total := 0
	scanner := bufio.NewScanner(bytes.NewReader(list))
	for scanner.Scan() {
		path := strings.TrimSpace(scanner.Text())
		if path == "" {
			continue
		}
		if !filepath.IsAbs(path) || len(images) >= maxConffiles {
			return nil, errors.New("package configuration list is unsafe")
		}
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
		if !image.exists {
			if err := os.Remove(image.path); err != nil && !errors.Is(err, os.ErrNotExist) {
				failures = append(failures, err)
			}
			continue
		}
		temporary := image.path + ".razvilka-restore"
		if err := os.WriteFile(temporary, image.data, image.mode); err != nil {
			failures = append(failures, err)
			continue
		}
		if err := os.Rename(temporary, image.path); err != nil {
			_ = os.Remove(temporary)
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

// ManagedUpdate updates a component whose routes are in use. The caller's
// check runs after the package changed (for NFQWS2: configuration kept, init
// adopted, service and routes healthy). If the upgrade or the check fails,
// the package configuration is restored and the cached previous version is
// reinstalled, then the check runs again for the restored state.
func (m *Manager) ManagedUpdate(ctx context.Context, id string, check func(context.Context) error) (Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	spec, ok := lookup(id)
	if !ok || !managedUpdateComponents[id] || check == nil {
		return Result{}, fmt.Errorf("component %s has no managed update", id)
	}
	installed, err := m.installedPackageVersions(ctx)
	if err != nil {
		return Result{Component: id, Action: "update"}, err
	}
	before := installed[spec.Package]
	rollback := m.rollbackPackage(spec, before)
	if before == "" || rollback == "" {
		return Result{Component: id, Action: "update"}, ErrRollbackPackageMissing
	}
	conffiles, err := m.snapshotConffiles(spec)
	if err != nil {
		return Result{Component: id, Action: "update"}, fmt.Errorf("snapshot package configuration: %w", err)
	}
	result, updateErr := m.applyLocked(ctx, id, map[string]bool{})
	if updateErr != nil && errors.Is(updateErr, errUpdateNotAdvanced) {
		return result, updateErr
	}
	var checkErr error
	if updateErr == nil {
		checkErr = check(ctx)
		if checkErr == nil {
			if _, cacheErr := m.cacheRollbackLocked(ctx, id); cacheErr != nil {
				result.Output += "\nnew version is not cached for a later rollback yet: " + boundedMessage(cacheErr.Error())
			}
			return result, nil
		}
	}
	cause := errors.Join(updateErr, checkErr)
	// Restore the configuration first, so the previous version's install
	// scripts see the reviewed configuration and do not migrate it.
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*defaultDuration(m.Timeout, 90*time.Second))
	defer cancel()
	restoreErr := restoreConffiles(conffiles)
	out, installErr := m.run(rollbackCtx, "install", "--force-downgrade", "--force-reinstall", rollback)
	after, verifyErr := m.installedPackageVersions(rollbackCtx)
	if verifyErr == nil && after[spec.Package] != before {
		verifyErr = fmt.Errorf("rollback left %s at %q, expected %s", spec.Package, after[spec.Package], before)
	}
	// The previous version's install scripts may have rewritten defaults.
	restoreErr = errors.Join(restoreErr, restoreConffiles(conffiles))
	var postErr error
	if installErr == nil && verifyErr == nil {
		postErr = check(rollbackCtx)
	}
	rollbackErr := errors.Join(restoreErr, installErr, verifyErr, postErr)
	receipt := lifecycleReceipt{SchemaVersion: 1, Component: id, Package: spec.Package, Provider: spec.Provider, Action: "rollback", BeforeVersion: before, AfterVersion: after[spec.Package], CompletedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if rollbackErr == nil {
		_ = m.writeLifecycleReceipt(receipt)
		result.OK = false
		result.Output += "\n" + boundedOutput(out)
		return result, fmt.Errorf("update was rolled back to %s: %w", before, cause)
	}
	return Result{Component: id, Action: "update", Output: boundedOutput(out)}, fmt.Errorf("update failed and rollback is not confirmed: %w", errors.Join(cause, rollbackErr))
}

func defaultDuration(value, fallback time.Duration) time.Duration {
	if value <= 0 {
		return fallback
	}
	return value
}
