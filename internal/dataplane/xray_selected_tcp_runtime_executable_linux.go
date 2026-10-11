//go:build linux

package dataplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

const xraySelectedTCPExecutableLimit = 128 << 20

// Only the actual original material's resolved dispatcher binary is opened.
// This retained descriptor cannot launch anything by itself: the original
// issued resource, journal, control and native version checks remain required.
func holdXraySelectedTCPExecutable(ctx context.Context, material *XrayOperationMaterial) (*xraySelectedTCPExecutable, error) {
	if material == nil || material.self != material || xraySelectedTCPFinite(ctx) != nil {
		return nil, errXraySelectedTCPRuntime
	}
	material.barrier.RLock()
	defer material.barrier.RUnlock()
	return holdXraySelectedTCPExecutableLocked(ctx, material)
}

// The original issuer already holds material.barrier through its file
// publication; avoid recursively taking an RWMutex while Close is waiting.
func holdXraySelectedTCPExecutableLocked(ctx context.Context, material *XrayOperationMaterial) (*xraySelectedTCPExecutable, error) {
	if material == nil || material.self != material || xraySelectedTCPFinite(ctx) != nil {
		return nil, errXraySelectedTCPRuntime
	}
	if material.current(ctx, false) != nil {
		return nil, errXraySelectedTCPRuntime
	}
	named, err := os.Lstat(material.binary)
	if err != nil || !named.Mode().IsRegular() || named.Mode().Perm()&0022 != 0 || named.Mode().Perm()&0111 == 0 || named.Size() <= 0 || named.Size() > xraySelectedTCPExecutableLimit {
		return nil, errXraySelectedTCPRuntime
	}
	f, err := os.Open(material.binary)
	if err != nil {
		return nil, errXraySelectedTCPRuntime
	}
	keep := false
	defer func() {
		if !keep {
			_ = f.Close()
		}
	}()
	info, err := f.Stat()
	if err != nil || !os.SameFile(named, info) {
		return nil, errXraySelectedTCPRuntime
	}
	if xraySelectedTCPELFHeader(f, info.Size()) != nil {
		return nil, errXraySelectedTCPRuntime
	}
	p := &xraySelectedTCPExecutable{material: material, file: f, info: info, path: material.binary}
	p.self = p
	p.sha256, err = p.hash(ctx)
	if err != nil || p.current(ctx) != nil || material.current(ctx, false) != nil {
		return nil, errXraySelectedTCPRuntime
	}
	keep = true
	return p, nil
}

func (p *xraySelectedTCPExecutable) hash(ctx context.Context) (string, error) {
	if xraySelectedTCPFinite(ctx) != nil || p == nil || p.file == nil || p.info == nil || p.info.Size() <= 0 || p.info.Size() > xraySelectedTCPExecutableLimit {
		return "", errXraySelectedTCPRuntime
	}
	hash := sha256.New()
	var block [32 << 10]byte
	var offset int64
	for offset < p.info.Size() {
		if ctx.Err() != nil {
			return "", errXraySelectedTCPRuntime
		}
		want := min(int64(len(block)), p.info.Size()-offset)
		n, err := p.file.ReadAt(block[:want], offset)
		if err != nil && err != io.EOF || int64(n) != want {
			return "", errXraySelectedTCPRuntime
		}
		_, _ = hash.Write(block[:n])
		offset += int64(n)
	}
	return hex.EncodeToString(hash.Sum(nil)), ctx.Err()
}

// current is a readback comparison under the upper original issuer. It never
// calls the old request's forward guard or silently extends that lifetime.
func (p *xraySelectedTCPExecutable) current(ctx context.Context) error {
	if p == nil || p.self != p || xraySelectedTCPFinite(ctx) != nil {
		return errXraySelectedTCPRuntime
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed || p.material == nil || p.material.self != p.material || p.material.binary != p.path || p.material.adapter == nil || p.material.adapter.engineBinary() != p.path || p.file == nil || p.info == nil {
		return errXraySelectedTCPRuntime
	}
	named, err := os.Lstat(p.path)
	held, heldErr := p.file.Stat()
	if err != nil || heldErr != nil || !named.Mode().IsRegular() || !os.SameFile(p.info, named) || !os.SameFile(p.info, held) || named.Mode() != p.info.Mode() || held.Mode() != p.info.Mode() ||
		named.Size() != p.info.Size() || held.Size() != p.info.Size() || !named.ModTime().Equal(p.info.ModTime()) || !held.ModTime().Equal(p.info.ModTime()) {
		return errXraySelectedTCPRuntime
	}
	hash, err := p.hash(ctx)
	after, statErr := os.Lstat(p.path)
	if err != nil || statErr != nil || hash != p.sha256 || !os.SameFile(named, after) || after.Mode() != p.info.Mode() || after.Size() != p.info.Size() || !after.ModTime().Equal(p.info.ModTime()) {
		return errXraySelectedTCPRuntime
	}
	return ctx.Err()
}

func (p *xraySelectedTCPExecutable) close() error {
	if p == nil || p.self != p {
		return errXraySelectedTCPRuntime
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	return p.file.Close()
}
