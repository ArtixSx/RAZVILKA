package dataplane

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// Stage/Activate publish only these generated images and retain the actual
// authored inodes. Equal-byte path replacement cannot supply cleanup custody.
func (r *mihomoLiveResource) publishCompiled(ctx context.Context, path string, data []byte) error {
	if r == nil || r.self != r || r.scope == nil || r.proxy == nil || r.records == nil {
		return errMihomoLiveMaterial
	}
	adapterRoot := filepath.Join(r.scope.root, "mihomo")
	want := ""
	switch path {
	case filepath.Join(adapterRoot, "engine.staged.json"), r.proxy.engineConfigPath():
		want = r.definition.Profile.ConfigSHA256
	case filepath.Join(adapterRoot, "sidecar.staged.json"), r.proxy.sidecarConfigPath():
		want = r.definition.Sidecar.ConfigSHA256
	default:
		return errMihomoLiveMaterial
	}
	if len(data) == 0 || len(data) > 1<<20 || nodeDefaultSourceMaterialHash(data) != want {
		return errMihomoLiveMaterial
	}
	if err := r.currentBeforeStart(ctx); err != nil {
		return err
	}
	r.filesMu.Lock()
	defer r.filesMu.Unlock()
	if r.compiledRoot == nil {
		root, err := ownedfs.Open(r.scope.managerRoot)
		if err != nil {
			return err
		}
		info, err := root.RootInfo()
		if err != nil || !os.SameFile(info, r.records.anchor) {
			_ = root.Close()
			return errMihomoLiveMaterial
		}
		r.compiledRoot = root
		r.compiledFiles = map[string]*mihomoLiveSidecarIdentityFile{}
	}
	name, err := filepath.Rel(r.scope.managerRoot, path)
	if err != nil || !filepath.IsLocal(name) || name == "." {
		return errMihomoLiveMaterial
	}
	if d := r.compiledFiles[name]; d != nil {
		if !d.published || !bytes.Equal(d.data, data) {
			return errMihomoLiveMaterial
		}
		return mihomoLiveFileCurrent(r.compiledRoot, d, name)
	}
	if err := r.compiledRoot.MkdirAll(filepath.Dir(name), 0700); err != nil {
		return err
	}
	d := &mihomoLiveSidecarIdentityFile{name: name, temporary: name + ".pending", data: bytes.Clone(data)}
	r.compiledFiles[name] = d
	return publishMihomoLiveFile(ctx, r.compiledRoot, r, d)
}

func (r *mihomoLiveResource) compiledCurrent(runtime bool) error {
	r.filesMu.Lock()
	defer r.filesMu.Unlock()
	if r.compiledRoot == nil {
		return errMihomoLiveMaterial
	}
	paths := []string{r.proxy.engineConfigPath(), r.proxy.sidecarConfigPath()}
	if !runtime {
		paths = []string{filepath.Join(r.scope.root, "mihomo", "engine.staged.json"), filepath.Join(r.scope.root, "mihomo", "sidecar.staged.json")}
	}
	for _, path := range paths {
		name, err := filepath.Rel(r.scope.managerRoot, path)
		if err != nil {
			return err
		}
		d := r.compiledFiles[name]
		if d == nil || !d.published {
			return errMihomoLiveMaterial
		}
		if err := mihomoLiveFileCurrent(r.compiledRoot, d, name); err != nil {
			return err
		}
	}
	return nil
}

func (r *mihomoLiveResource) removeRuntimeImages(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview) error {
	r.filesMu.Lock()
	defer r.filesMu.Unlock()
	if r.compiledRoot == nil {
		return nil
	}
	for _, path := range []string{r.proxy.engineConfigPath(), r.proxy.sidecarConfigPath()} {
		name, err := filepath.Rel(r.scope.managerRoot, path)
		if err != nil {
			return err
		}
		d := r.compiledFiles[name]
		if d == nil {
			continue
		}
		if err := removeMihomoLiveFile(ctx, r.compiledRoot, d, func(remove func() error) error { return r.control.WithCleanupRemove(ctx, cleanup, remove) }); err != nil {
			return err
		}
		delete(r.compiledFiles, name)
	}
	return nil
}

func (r *mihomoLiveResource) closeCompiledFiles() error {
	r.filesMu.Lock()
	defer r.filesMu.Unlock()
	var result error
	for name, d := range r.compiledFiles {
		if d == nil {
			continue
		}
		if !d.published {
			return errors.Join(errMihomoLiveMaterial, result)
		}
		if d.file != nil {
			result = errors.Join(result, d.file.Close())
			if result == nil {
				d.file = nil
			}
		}
		if result != nil {
			return result
		}
		clear(d.data)
		delete(r.compiledFiles, name)
	}
	if r.compiledRoot != nil {
		result = errors.Join(result, r.compiledRoot.Close())
		if result == nil {
			r.compiledRoot = nil
		}
	}
	return result
}
