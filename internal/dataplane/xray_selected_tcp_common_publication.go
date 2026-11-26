package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"slices"
)

// Issued only at the original COMMON writer's actual successful save. These
// independent held file descriptors survive its in-call borrow; a later reader
// cannot reconstruct this producer from a receipt path, status or checksum.
type xraySelectedTCPCommonPublication struct {
	resource             *XraySelectedTCPExecutionResource
	session              *policyEffectSession
	document, marker     *os.File
	fileInfo, markerInfo os.FileInfo
	canonical            []byte
	states               []string
	checksum             string
	status               PolicyAdditionStatus
}

// CORE calls this only after b.saved() has ACKed the actual publication, outside
// b.mu. No public callback or generic receipt constructor supplies this owner.
func captureXraySelectedTCPPolicyPublication(ctx context.Context, b *policyEffectReceiptBorrow) error {
	if ctx == nil {
		return ErrPolicyAdditionReceipt
	}
	value := ctx.Value(xrayOperationOwnerKey{})
	if value == nil {
		return nil
	}
	o, ok := value.(*xrayOperationOwner)
	if !ok || o == nil || o.self != o || o.scope == nil || b == nil || b.self != b || ctx.Value(policyEffectReceiptBorrowKey{}) != b ||
		ctx.Value(xrayOperationMaterialKey{}) != o.material || xraySelectedTCPFinite(ctx) != nil {
		return ErrPolicyAdditionReceipt
	}
	o.scope.mu.Lock()
	var r *XraySelectedTCPExecutionResource
	if len(o.scope.xraySelectedTCP) == 1 {
		for _, owned := range o.scope.xraySelectedTCP {
			r = owned
		}
	}
	if r == nil || r.self != r || r.owner != o || !r.startACK {
		o.scope.mu.Unlock()
		return ErrPolicyAdditionReceipt
	}
	_, err := r.matching()
	o.scope.mu.Unlock()
	if err != nil {
		return err
	}
	r.commonMu.Lock()
	defer r.commonMu.Unlock()
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.session == nil || b.session.path != r.rootPath || !reflect.DeepEqual(b.session.plan, r.effects) || b.currentOwner() != nil ||
		b.absent || b.published == nil || b.publishedInfo == nil || b.markerInfo == nil || len(b.publishedBytes) == 0 {
		return ErrPolicyAdditionReceipt
	}
	p := &xraySelectedTCPCommonPublication{resource: r, session: b.session, canonical: slices.Clone(b.publishedBytes), fileInfo: b.publishedInfo, markerInfo: b.markerInfo,
		checksum: b.session.doc.Checksum, status: b.session.status()}
	for _, step := range b.session.doc.Steps {
		p.states = append(p.states, step.State)
	}
	keep := false
	defer func() {
		if !keep {
			p.close()
		}
	}()
	p.document, err = r.root.OpenFile(policyAdditionFile, os.O_RDONLY, 0)
	if err != nil {
		return ErrPolicyAdditionReceipt
	}
	p.marker, err = r.root.OpenFile(policyAdditionLock, os.O_RDONLY, 0)
	if err != nil {
		return ErrPolicyAdditionReceipt
	}
	if p.current(ctx) != nil || b.currentOwner() != nil {
		return ErrPolicyAdditionReceipt
	}
	if r.common != nil {
		if err := r.common.heldCurrent(ctx); err != nil {
			return err
		}
		if r.common.status.ID != p.status.ID {
			return ErrPolicyAdditionReceipt
		}
		if err := r.common.close(); err != nil {
			return err
		}
	}
	r.common = p
	keep = true
	return nil
}

func (p *xraySelectedTCPCommonPublication) heldCurrent(ctx context.Context) error {
	if p == nil || p.resource == nil || p.resource.self != p.resource || p.document == nil || p.marker == nil || xraySelectedTCPFinite(ctx) != nil ||
		len(p.canonical) == 0 || len(p.canonical) > policyAdditionMaxBytes {
		return ErrPolicyAdditionReceipt
	}
	bookend := func() bool {
		file, err := p.document.Stat()
		marker, markerErr := p.marker.Stat()
		return err == nil && markerErr == nil && validNetworkPolicyReceiptFile(file) && validNetworkPolicyReceiptFile(marker) &&
			os.SameFile(p.fileInfo, file) && os.SameFile(p.markerInfo, marker) && file.Mode() == p.fileInfo.Mode() && file.Size() == p.fileInfo.Size() && file.ModTime().Equal(p.fileInfo.ModTime())
	}
	if !bookend() || p.fileInfo.Size() <= 0 || p.fileInfo.Size() > policyAdditionMaxBytes {
		return ErrPolicyAdditionReceipt
	}
	image := make([]byte, int(p.fileInfo.Size()))
	defer clear(image)
	n, err := p.document.ReadAt(image, 0)
	var canonical bytes.Buffer
	if err != nil || n != len(image) || json.Compact(&canonical, image) != nil || !bytes.Equal(canonical.Bytes(), p.canonical) || !bookend() {
		return ErrPolicyAdditionReceipt
	}
	return ctx.Err()
}

func (p *xraySelectedTCPCommonPublication) current(ctx context.Context) error {
	if err := p.heldCurrent(ctx); err != nil {
		return err
	}
	r := p.resource
	directory, err := os.Lstat(r.rootPath)
	root, rootErr := r.root.RootInfo()
	file, fileErr := r.root.Stat(policyAdditionFile)
	marker, markerErr := r.root.Stat(policyAdditionLock)
	if err != nil || rootErr != nil || fileErr != nil || markerErr != nil || !networkPolicyPrivateDirectory(directory) ||
		!os.SameFile(r.anchor, directory) || !os.SameFile(r.anchor, root) || !os.SameFile(p.fileInfo, file) || !os.SameFile(p.markerInfo, marker) {
		return ErrPolicyAdditionReceipt
	}
	return p.heldCurrent(ctx)
}

func (p *xraySelectedTCPCommonPublication) close() error {
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
	return err
}
