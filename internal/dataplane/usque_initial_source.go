package dataplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/installpath"
	"github.com/ArtixSx/razvilka/internal/usquediag"
)

var ErrUSQUEInitialSource = errors.New("original USQUE core or its managed sidecar is unavailable")

// USQUEInitialSource reviews the actual adapter registered with this Manager.
// It provides no installation permission, process start or route authority.
type USQUEInitialSource struct {
	manager      *Manager
	adapter      *ProxyTunnelAdapter
	configs      *engineconfig.Manager
	core         usqueInitialExecutable
	sidecar      usqueInitialExecutable
	engineSHA256 string
	backend      string
}

type usqueInitialExecutable struct {
	path string
	info os.FileInfo
}

func usqueInitialExecutableAt(path string) (usqueInitialExecutable, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return usqueInitialExecutable{}, ErrUSQUEInitialSource
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path || !usqueInitialProtectedPath(path) {
		return usqueInitialExecutable{}, ErrUSQUEInitialSource
	}
	info, err := os.Lstat(path)
	maxSize := int64(64 << 20)
	if path == installpath.ManagedMASQUESingBox {
		maxSize, _ = components.MASQUESidecarBinaryIdentity()
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maxSize || info.Mode().Perm()&0o111 == 0 || info.Mode().Perm()&0o022 != 0 {
		return usqueInitialExecutable{}, ErrUSQUEInitialSource
	}
	return usqueInitialExecutable{path: path, info: info}, nil
}

func (x usqueInitialExecutable) same(info os.FileInfo) bool {
	return info != nil && os.SameFile(x.info, info) && x.info.Mode() == info.Mode() &&
		x.info.Size() == info.Size() && x.info.ModTime().Equal(info.ModTime()) && usqueInitialSameOwner(x.info, info)
}

func (x usqueInitialExecutable) current() bool {
	current, err := usqueInitialExecutableAt(x.path)
	return err == nil && x.same(current.info)
}

func (x usqueInitialExecutable) digest(ctx context.Context) (string, error) {
	file, err := os.Open(x.path)
	if err != nil {
		return "", ErrUSQUEInitialSource
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !x.same(info) {
		return "", ErrUSQUEInitialSource
	}
	hash := sha256.New()
	buf := make([]byte, 64<<10)
	reader := io.LimitReader(file, x.info.Size()+1)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		n, err := reader.Read(buf)
		total += int64(n)
		_, _ = hash.Write(buf[:n])
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", ErrUSQUEInitialSource
		}
	}
	if info, err := file.Stat(); err != nil || total != x.info.Size() || !x.same(info) || !x.current() {
		return "", ErrUSQUEInitialSource
	}
	return hex.EncodeToString(hash.Sum(nil)), ctx.Err()
}

func (m *Manager) ReviewUSQUEInitialSource(ctx context.Context, configs *engineconfig.Manager) (*USQUEInitialSource, error) {
	if runtime.GOOS != "linux" || m == nil || ctx == nil || ctx.Err() != nil || configs == nil {
		return nil, ErrUSQUEInitialSource
	}
	adapter, _ := m.adapter("usque")
	a, ok := adapter.(*ProxyTunnelAdapter)
	if !ok || a == nil || a.ID() != "usque" || a.Configs != configs || a.valid() != nil || !a.usqueInitialOwnsRuntime() {
		return nil, ErrUSQUEInitialSource
	}
	core, err := usqueInitialExecutableAt(a.engineBinary())
	if err != nil {
		return nil, err
	}
	digest, err := core.digest(ctx)
	if err != nil || !usquediag.OwnedUSQUENativeBinaryAudited(digest, runtime.GOARCH) {
		return nil, ErrUSQUEInitialSource
	}
	sidecar, err := usqueInitialExecutableAt(a.sidecarBinary())
	if err != nil {
		return nil, err
	}
	budget := 3 * time.Second
	if sidecar.path == installpath.ManagedMASQUESingBox {
		budget = a.timeout()
	}
	check, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	backend := a.effectiveSidecar()
	if backend == "hev" {
		if a.hevInstalledCheck == nil || a.preflightHEVRuntime(check) != nil {
			return nil, ErrUSQUEInitialSource
		}
	} else if _, err := a.detectSidecarSchema(check); err != nil {
		return nil, ErrUSQUEInitialSource
	}
	result := &USQUEInitialSource{manager: m, adapter: a, configs: configs, core: core, sidecar: sidecar, engineSHA256: digest, backend: backend}
	return result, result.Current(ctx, m, configs)
}

func privateMASQUESidecarPresent() bool {
	_, err := os.Lstat(installpath.ManagedMASQUESingBox)
	return !errors.Is(err, os.ErrNotExist)
}

func (a *ProxyTunnelAdapter) verifyPrivateMASQUESidecar(ctx context.Context, path string) error {
	if path != installpath.ManagedMASQUESingBox {
		return nil
	}
	if a.ID() != "usque" || a.effectiveSidecar() != "sing-box" {
		return ErrUSQUEInitialSource
	}
	size, expected := components.MASQUESidecarBinaryIdentity()
	source, err := usqueInitialExecutableAt(path)
	if err != nil || source.info.Size() != size {
		return errors.Join(components.ErrMASQUESidecarIntegrity, err)
	}
	if err := components.CheckInitialMASQUESidecarPublication(ctx); err != nil {
		return err
	}
	hash, err := source.digest(ctx)
	if err != nil || hash != expected {
		return errors.Join(components.ErrMASQUESidecarIntegrity, err)
	}
	return ctx.Err()
}

// USQUEMissingManagedSidecar inspects the real adapter. In particular, an
// explicit TUN executor or a vendor-managed USQUE never grants private setup.
func (m *Manager) USQUEMissingManagedSidecar(configs *engineconfig.Manager) bool {
	if m == nil || configs == nil {
		return false
	}
	adapter, _ := m.adapter("usque")
	a, ok := adapter.(*ProxyTunnelAdapter)
	return ok && a != nil && a.Configs == configs && a.ID() == "usque" && a.effectiveSidecar() == "sing-box" &&
		a.SidecarBin == "" && a.valid() == nil && a.usqueInitialOwnsRuntime() && a.sidecarBinary() == ""
}

// PublishInitialUSQUECompanion preserves an existing runtime's executable
// identity. Hold the dataplane operation gate only for the final publication.
func (m *Manager) PublishInitialUSQUECompanion(ctx context.Context, configs *engineconfig.Manager, publish func() error) error {
	if m == nil || ctx == nil || publish == nil || ctx.Err() != nil || !m.tryBeginOperation() {
		return ErrReviewChanged
	}
	defer m.endOperation()
	if !m.USQUEMissingManagedSidecar(configs) {
		return ErrReviewChanged
	}
	if err := m.CheckExecutionRecovery(ctx); err != nil {
		return err
	}
	adapter, _ := m.adapter("usque")
	a, ok := adapter.(*ProxyTunnelAdapter)
	if !ok || a.Configs != configs {
		return ErrReviewChanged
	}
	if err := a.VerifyRuntimeInactive(ctx); err != nil {
		return err
	}
	if ctx.Err() != nil || !m.USQUEMissingManagedSidecar(configs) {
		return ErrReviewChanged
	}
	return publish()
}

func (a *ProxyTunnelAdapter) usqueInitialOwnsRuntime() bool {
	// A vendor init may start a competing persistent network owner. An Auto
	// first activation may not execute it, even to stop a previous service.
	if a.PackageInit != "" {
		return false
	}
	_, err := os.Lstat("/opt/etc/init.d/S51usque")
	return errors.Is(err, os.ErrNotExist)
}

func (x *USQUEInitialSource) RegistrationBinary() (path, sha256 string) {
	return x.core.path, x.engineSHA256
}

func (x *USQUEInitialSource) Current(ctx context.Context, manager *Manager, configs *engineconfig.Manager) error {
	if x == nil || x.manager != manager || x.configs != configs || ctx == nil || ctx.Err() != nil {
		return ErrUSQUEInitialSource
	}
	adapter, _ := manager.adapter("usque")
	a := x.adapter
	if adapter != a || a.Configs != configs || a.engineBinary() != x.core.path || a.sidecarBinary() != x.sidecar.path ||
		a.effectiveSidecar() != x.backend || !a.usqueInitialOwnsRuntime() || !x.core.current() || !x.sidecar.current() {
		return ErrUSQUEInitialSource
	}
	return ctx.Err()
}
