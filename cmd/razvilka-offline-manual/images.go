package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

type imageSpec struct {
	name     string
	limit    int64
	required bool
	pin      string
}

type observedImage struct {
	spec   imageSpec
	exists bool
	info   os.FileInfo
	digest string
}

type preservedImages struct {
	root     *ownedfs.Root
	path     string
	rootInfo os.FileInfo
	images   []observedImage
}

func captureImages(ctx context.Context, p paths, pins incident) (*preservedImages, error) {
	root, err := ownedfs.Open(p.installation)
	if err != nil {
		return nil, err
	}
	info, err := root.RootInfo()
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	result := &preservedImages{root: root, path: p.installation, rootInfo: info}
	dp := filepath.Join(p.state, "dataplane")
	tx := filepath.Join(dp, "transactions", pins.failedID)
	var specs []imageSpec
	add := func(path string, limit int64, required bool, pin string) {
		rel, err := filepath.Rel(p.installation, path)
		if err != nil || !filepath.IsLocal(rel) {
			rel = ""
		}
		specs = append(specs, imageSpec{rel, limit, required, pin})
	}
	add(p.executable, 64<<20, true, pins.binarySHA)
	add(p.init, 128<<10, true, pins.initSHA)
	add(filepath.Join(dp, "latest-plan.json"), 4<<20, true, pins.failedPlanSHA)
	add(filepath.Join(dp, "latest-committed-plan.json"), 4<<20, true, pins.priorPlanSHA)
	add(filepath.Join(dp, "latest-execution.json"), 4<<20, true, "")
	add(filepath.Join(tx, "execution.json"), 4<<20, true, "")
	add(filepath.Join(tx, "nfqws2/snapshot.json"), 8<<20, true, pins.snapshotSHA)
	add(filepath.Join(dp, "runtime/nfqws2/ownership.json"), 16<<10, true, "")
	add(filepath.Join(p.configDir, "admin.token"), 4096, true, "")
	add(filepath.Join(p.configDir, "admin.credentials.json"), 64<<10, true, "")
	add(filepath.Join(p.configDir, "config.json.automation.json"), 4<<20, false, "")
	add(filepath.Join(p.configDir, "config.json.automation.json.autonomy.json"), 4<<20, true, "")
	for _, name := range []string{"nfqws2.conf", "nfqws2.conf.run", "lists/user.list", "lists/ipset.list", "lists/exclude.list", "lists/ipset_exclude.list"} {
		add(filepath.Join(p.installation, "etc/nfqws2", name), 8<<20, name == "nfqws2.conf", "")
	}
	add(filepath.Join(p.installation, "etc/init.d/S51nfqws2"), 128<<10, true, "")
	for _, spec := range specs {
		image, err := result.read(ctx, spec)
		if err != nil {
			_ = root.Close()
			return nil, err
		}
		result.images = append(result.images, image)
	}
	if err := result.check(ctx); err != nil {
		_ = root.Close()
		return nil, err
	}
	return result, nil
}

func (p *preservedImages) currentRoot() error {
	held, err := p.root.RootInfo()
	if err != nil {
		return err
	}
	now, err := os.Lstat(p.path)
	if err != nil || !os.SameFile(held, now) || !os.SameFile(p.rootInfo, held) || now.Mode() != p.rootInfo.Mode() || !ownerOK(now) {
		return errRefused
	}
	return nil
}

func (p *preservedImages) read(ctx context.Context, spec imageSpec) (observedImage, error) {
	out := observedImage{spec: spec}
	if ctx.Err() != nil || spec.name == "" || p.currentRoot() != nil {
		return out, errRefused
	}
	info, err := p.root.Stat(spec.name)
	if errors.Is(err, os.ErrNotExist) && !spec.required {
		return out, nil
	}
	if err != nil || !info.Mode().IsRegular() || !ownerOK(info) || info.Size() > spec.limit {
		return out, errRefused
	}
	f, err := p.root.OpenFile(spec.name, readOnlyFileFlags(), 0)
	if err != nil {
		return out, err
	}
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() {
		_ = f.Close()
		return out, errRefused
	}
	h := sha256.New()
	n, readErr := io.Copy(h, io.LimitReader(f, spec.limit+1))
	end, endErr := f.Stat()
	closeErr := f.Close()
	current, currentErr := p.root.Stat(spec.name)
	if readErr != nil || endErr != nil || closeErr != nil || currentErr != nil || n > spec.limit || !sameFileImage(info, end) || !sameFileImage(info, current) || ctx.Err() != nil {
		return out, errRefused
	}
	out.exists, out.info, out.digest = true, current, hex.EncodeToString(h.Sum(nil))
	if spec.pin != "" && spec.pin != out.digest {
		return out, errRefused
	}
	return out, nil
}

func sameFileImage(a, b os.FileInfo) bool {
	return a != nil && b != nil && os.SameFile(a, b) && a.Mode() == b.Mode() && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime()) && ownerOK(b)
}

func (p *preservedImages) check(ctx context.Context) error {
	if err := p.currentRoot(); err != nil {
		return err
	}
	for _, old := range p.images {
		now, err := p.read(ctx, old.spec)
		if err != nil {
			return err
		}
		if now.exists != old.exists || now.digest != old.digest || now.exists && !sameFileImage(old.info, now.info) {
			return errRefused
		}
	}
	return ctx.Err()
}

func (p *preservedImages) close() error { return errors.Join(p.currentRoot(), p.root.Close()) }
