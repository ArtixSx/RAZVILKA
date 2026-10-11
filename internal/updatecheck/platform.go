package updatecheck

import (
	"bytes"
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
	"runtime"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/installpath"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

var errInstallerTimeout = errors.New("installer-timeout")

func runBoundedCommand(command *exec.Cmd) error {
	configureBoundedCommand(command)
	err := command.Run()
	if err != nil {
		cleanupCommand(command)
	}
	return err
}

// ConfigFingerprint binds the reviewed update to the complete configuration.
func ConfigFingerprint(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func ProductionPaths() map[string]string {
	return map[string]string{
		"config": installpath.Config + "/config.json", "catalog": installpath.Config + "/service-catalog.json", "sources": installpath.Config + "/sources.json", "community": installpath.Config + "/community-catalog.json",
		"token": installpath.Config + "/admin.token", "credentials": installpath.Config + "/admin.credentials.json", "custom": installpath.Config + "/custom-services.json", "devices": installpath.Config + "/devices.json",
		"cloudflare": installpath.Config + "/cloudflare-private", "nodes": installpath.Config + "/nodes-private", "stage": installpath.State + "/staging", "backups": installpath.State + "/backups", "warp": installpath.State + "/warp", "dataplane": installpath.State + "/dataplane",
		"dns": installpath.State + "/dns/state.json",
	}
}

func CheckDeployment(deployment Deployment) error {
	if err := checkDeploymentLayout(deployment); err != nil {
		return err
	}
	return checkProductionPID(os.Getpid(), deployment.Executable)
}

func checkDeploymentLayout(deployment Deployment) error {
	if runtime.GOOS != "linux" {
		return errors.New("unsupported-platform")
	}
	if os.Geteuid() != 0 {
		return errors.New("root-required")
	}
	if deployment.Executable != "/opt/bin/razvilka" || deployment.Port != "8787" || !reflect.DeepEqual(deployment.Paths, ProductionPaths()) {
		return errors.New("production-layout-required")
	}
	if err := checkInstallerWritePaths("/opt", checkRootOwnedPath); err != nil {
		return errors.New("production-path-ownership-refused")
	}
	for _, path := range append([]string{"/opt/bin/razvilka", "/opt/etc/init.d/S99razvilka", "/opt/sbin/start-stop-daemon", installpath.Run + "/razvilka.pid", productionUpdateRoot}, mapValues(deployment.Paths)...) {
		if err := checkRootOwnedPath(path); err != nil {
			return errors.New("production-path-ownership-refused")
		}
	}
	for _, path := range []string{deployment.Executable, "/opt/etc/init.d/S99razvilka", "/opt/sbin/start-stop-daemon"} {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0100 == 0 {
			return errors.New("production-service-unavailable")
		}
	}
	return nil
}

// These destinations are written by the verified installer and supervisor,
// in addition to the daemon's configured files. In particular current-backup
// is redirected by the shell, so a pre-existing symlink must fail preflight.
func checkInstallerWritePaths(base string, check func(string) error) error {
	for _, rel := range []string{"razvilka/state/update-backups", "razvilka/state/current-backup", "razvilka/state/start-failures", "razvilka/state/boot-disabled", "razvilka/log/server.log", "razvilka/cache", "razvilka/run/razvilka.pid", "etc/razvilka/source-state.json", "etc/init.d/S99artem-flow", "etc/init.d/S99artem-flow.razvilka-disabled"} {
		if err := check(filepath.Join(base, filepath.FromSlash(rel))); err != nil {
			return err
		}
	}
	return nil
}

func mapValues(values map[string]string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	return out
}

func hashRegularFile(path string, maximum int64) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > maximum {
		return "", errors.New("file-identity-refused")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	current, err := f.Stat()
	if err != nil || !os.SameFile(info, current) {
		return "", errors.New("file-identity-changed")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, maximum+1))
	if err != nil || n > maximum {
		return "", errors.New("file-read-refused")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

type cappedOutput struct {
	bytes.Buffer
	maximum int
}

func (b *cappedOutput) Write(p []byte) (int, error) {
	n := len(p)
	if remaining := b.maximum - b.Len(); remaining > 0 {
		_, _ = b.Buffer.Write(p[:min(remaining, n)])
	}
	return n, nil
}

func commandEnvironment() []string {
	return []string{"PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/opt/root", "LANG=C", "LC_ALL=C", "RAZVILKA_BASE=/opt", "RAZVILKA_PORT=8787"}
}

func preflightInstaller(ctx context.Context, bundle string, release Release) error {
	root, err := ownedfs.Open(bundle)
	if err != nil {
		return err
	}
	defer root.Close()
	bin, err := root.OpenFile("dist/"+release.Binary.Name, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	err = bin.Chmod(0755)
	bin.Close()
	if err != nil {
		return err
	}
	checkCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	version := exec.CommandContext(checkCtx, filepath.Join(bundle, "dist", release.Binary.Name), "-version")
	configureBoundedCommand(version)
	version.Env = commandEnvironment()
	output := &cappedOutput{maximum: 1024}
	version.Stdout = output
	version.Stderr = io.Discard
	if err := runBoundedCommand(version); err != nil || strings.TrimSpace(output.String()) != release.Version {
		return errors.New("candidate-version-or-architecture-refused")
	}
	command := exec.CommandContext(checkCtx, "/bin/sh", filepath.Join(bundle, "scripts/upgrade-entware.sh"), "--dry-run", "--without-components")
	configureBoundedCommand(command)
	command.Env = commandEnvironment()
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := runBoundedCommand(command); err != nil {
		return errors.New("installer-preflight-refused")
	}
	return checkCtx.Err()
}
