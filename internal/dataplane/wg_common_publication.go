package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"slices"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// Only the actual WG producer installs this carrier, around its original
// COMMON writer. A receipt read, reference or path cannot mint a publication.
type wgCommonWriterKey struct{}
type wgCommonWriter struct {
	adapter *WARPWireGuardAdapter
	ref     warpWGPolicyReference
	effects wgNetworkEffects
	roots   []string
}

type wgCommonPublication struct {
	owner                *wgOperationOwner
	path                 string
	root                 *ownedfs.Root
	anchor               os.FileInfo
	document, marker     *os.File
	fileInfo, markerInfo os.FileInfo
	canonical            []byte
	states               []string
	checksum             string
	status               PolicyAdditionStatus
	effects              PolicyEffectPlan
	ref                  warpWGPolicyReference
	ack                  bool
}

func wgCommonWriterContext(ctx context.Context, a *WARPWireGuardAdapter, ref warpWGPolicyReference, effects wgNetworkEffects, roots ...string) context.Context {
	return context.WithValue(ctx, wgCommonWriterKey{}, wgCommonWriter{a, ref, effects, slices.Clone(roots)})
}

func captureWGCommonPublication(ctx context.Context, s *policyAdditionSession, file *os.File) (result error) {
	raw := ctx.Value(wgCommonWriterKey{})
	if raw == nil || ctx.Value(wgOperationOwnerKey{}) == nil {
		return nil // Existing legacy producers retain their own contracts.
	}
	writer, present := raw.(wgCommonWriter)
	if !present {
		return ErrWGOperationOwner
	}
	o, ok := ctx.Value(wgOperationOwnerKey{}).(*wgOperationOwner)
	if !ok || o == nil || o.self != o || o.scope == nil || o.scope.wgOwner != o || writer.adapter != o.adapter || ctx.Value(wgOperationMaterialKey{}) != o.material ||
		s == nil || s.root == nil || file == nil || !slices.Contains(writer.roots, s.path) || !reflect.DeepEqual(writer.ref.FrozenLAN, o.material.lan) {
		return ErrWGOperationOwner
	}
	// This is the original writer's pure post-rename handoff. Cancellation
	// cannot erase its own inode; no command or forward context is issued.
	if _, bounded := ctx.Deadline(); !bounded {
		return ErrWGOperationOwner
	}
	expected, err := o.adapter.compileWGNetworkEffects(writer.ref)
	digest, digestErr := PolicyEffectPlanDigest(expected.plan)
	if err != nil || digestErr != nil || !reflect.DeepEqual(expected, writer.effects) || s.doc.Schema != 2 || s.doc.Generation != expected.plan.Generation || s.doc.EffectsHash != digest {
		return errors.Join(ErrPolicyAdditionReceipt, err)
	}
	canonical, err := json.Marshal(s.doc)
	if err != nil || len(canonical) == 0 || len(canonical) > policyAdditionMaxBytes {
		return ErrPolicyAdditionReceipt
	}
	root, anchor, err := openNetworkPolicyObservationRoot(s.path)
	if err != nil {
		return err
	}
	p := &wgCommonPublication{owner: o, path: s.path, root: root, anchor: anchor, canonical: canonical, checksum: s.doc.Checksum, status: s.status(), effects: expected.plan, ref: writer.ref}
	transferred := false
	defer func() {
		if !transferred {
			_ = p.close()
		}
	}()
	p.fileInfo, err = file.Stat()
	sourceAnchor, sourceErr := s.root.RootInfo()
	if err != nil || sourceErr != nil || !os.SameFile(anchor, sourceAnchor) {
		return ErrPolicyAdditionReceipt
	}
	p.document, err = root.OpenFile(policyAdditionFile, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	p.marker, err = root.OpenFile(policyAdditionLock, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	p.markerInfo, err = s.lock.Stat()
	if err != nil {
		return err
	}
	for _, step := range s.doc.Steps {
		p.states = append(p.states, step.State)
	}
	if err := p.currentFiles(); err != nil {
		return err
	}
	o.commonMu.Lock()
	defer o.commonMu.Unlock()
	if old := o.common[s.path]; old != nil {
		// The actual writer may replace its own receipt inode. The permanent
		// lock and original directory must survive every publication.
		if old.heldFilesCurrent() != nil || !os.SameFile(old.anchor, p.anchor) || !os.SameFile(old.markerInfo, p.markerInfo) || old.status.ID != p.status.ID {
			return ErrPolicyAdditionReceipt
		}
		o.common[s.path] = p
		transferred = true
		return old.close()
	}
	o.common[s.path] = p
	transferred = true
	return nil
}

func saveWGCommonOriginal(ctx context.Context, s *policyAdditionSession, file *os.File, prior error) error {
	captureErr := captureWGCommonPublication(ctx, s, file)
	if prior != nil || captureErr != nil {
		return errors.Join(prior, captureErr)
	}
	// The fault models a directory-sync failure after the real retained rename.
	if err := s.fault("wg-directory-sync", -1); err != nil {
		return err
	}
	if err := syncDataplaneJournalDirectory(s.root); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	o := ctx.Value(wgOperationOwnerKey{}).(*wgOperationOwner)
	o.commonMu.Lock()
	defer o.commonMu.Unlock()
	p := o.common[s.path]
	info, err := file.Stat()
	if p == nil || err != nil || !os.SameFile(p.fileInfo, info) || p.currentFiles() != nil {
		return ErrPolicyAdditionReceipt
	}
	p.ack = true
	return nil
}

func checkWGCommonBeforePublication(ctx context.Context, s *policyAdditionSession) error {
	if ctx.Value(wgCommonWriterKey{}) == nil || ctx.Value(wgOperationOwnerKey{}) == nil {
		return nil
	}
	o, ok := ctx.Value(wgOperationOwnerKey{}).(*wgOperationOwner)
	if !ok || o == nil || o.self != o || o.scope == nil || o.scope.wgOwner != o || s == nil {
		return ErrWGOperationOwner
	}
	o.commonMu.Lock()
	defer o.commonMu.Unlock()
	if p := o.common[s.path]; p != nil {
		return p.current(ctx)
	}
	return nil
}

func (p *wgCommonPublication) heldCurrent(ctx context.Context) error {
	if wgFiniteContext(ctx) != nil {
		return ErrPolicyAdditionReceipt
	}
	return p.heldFilesCurrent()
}

func (p *wgCommonPublication) heldFilesCurrent() error {
	if p == nil || p.owner == nil || p.document == nil || p.marker == nil || p.fileInfo == nil || p.markerInfo == nil || p.fileInfo.Size() <= 0 || p.fileInfo.Size() > policyAdditionMaxBytes {
		return ErrPolicyAdditionReceipt
	}
	check := func() bool {
		f, e := p.document.Stat()
		m, me := p.marker.Stat()
		return e == nil && me == nil && validNetworkPolicyReceiptFile(f) && validNetworkPolicyReceiptFile(m) && os.SameFile(p.fileInfo, f) && os.SameFile(p.markerInfo, m) &&
			f.Size() == p.fileInfo.Size() && f.Mode() == p.fileInfo.Mode() && f.ModTime().Equal(p.fileInfo.ModTime())
	}
	if !check() {
		return ErrPolicyAdditionReceipt
	}
	data := make([]byte, int(p.fileInfo.Size()))
	defer clear(data)
	n, err := p.document.ReadAt(data, 0)
	var compact bytes.Buffer
	if err != nil || n != len(data) || json.Compact(&compact, data) != nil || !bytes.Equal(compact.Bytes(), p.canonical) || !check() {
		return ErrPolicyAdditionReceipt
	}
	return nil
}

func (p *wgCommonPublication) current(ctx context.Context) error {
	if err := p.heldCurrent(ctx); err != nil {
		return err
	}
	if !p.ack && !p.owner.material.IsCleanupContext(ctx) {
		return ErrPolicyAdditionReceipt
	}
	return p.currentFiles()
}

func (p *wgCommonPublication) currentFiles() error {
	if err := p.heldFilesCurrent(); err != nil {
		return err
	}
	directory, err := os.Lstat(p.path)
	root, re := p.root.RootInfo()
	f, fe := p.root.Stat(policyAdditionFile)
	m, me := p.root.Stat(policyAdditionLock)
	if err != nil || re != nil || fe != nil || me != nil || !networkPolicyPrivateDirectory(directory) || !os.SameFile(p.anchor, directory) || !os.SameFile(p.anchor, root) || !os.SameFile(p.fileInfo, f) || !os.SameFile(p.markerInfo, m) {
		return ErrPolicyAdditionReceipt
	}
	return p.heldFilesCurrent()
}

func checkWGOriginalLoadedReceipt(ctx context.Context, b *policyEffectReceiptBorrow) error {
	if ctx.Value(wgCommonWriterKey{}) == nil || ctx.Value(wgOperationOwnerKey{}) == nil {
		return nil
	}
	o, ok := ctx.Value(wgOperationOwnerKey{}).(*wgOperationOwner)
	if !ok || o == nil || o.self != o || o.scope == nil || o.scope.wgOwner != o || !o.material.IsCleanupContext(ctx) || b == nil || b.self != b {
		return ErrWGOperationOwner
	}
	o.commonMu.Lock()
	defer o.commonMu.Unlock()
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.session == nil || b.currentOwner() != nil {
		return ErrPolicyAdditionReceipt
	}
	p := o.common[b.session.path]
	if p == nil || p.current(ctx) != nil || b.publishedInfo == nil || !os.SameFile(p.fileInfo, b.publishedInfo) || !bytes.Equal(p.canonical, b.publishedBytes) || !reflect.DeepEqual(p.effects, b.session.plan) {
		return ErrPolicyAdditionReceipt
	}
	return nil
}

func (p *wgCommonPublication) close() error {
	if p == nil {
		return nil
	}
	var err error
	if p.document != nil {
		err = p.document.Close()
	}
	if p.marker != nil {
		err = errors.Join(err, p.marker.Close())
	}
	if p.root != nil {
		err = errors.Join(err, p.root.Close())
	}
	return err
}
func (o *wgOperationOwner) closeCommon() error {
	o.commonMu.Lock()
	defer o.commonMu.Unlock()
	var err error
	for path, p := range o.common {
		err = errors.Join(err, p.close())
		delete(o.common, path)
	}
	return err
}
