package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
)

// Private original COMMON writer sink. The FD was opened on its actual staged
// inode before rename; ownership transfers only after exact publication ACK.
func (b *policyEffectReceiptBorrow) savedOriginal(file *os.File) error {
	if b == nil || file == nil {
		return ErrPolicyAdditionReceipt
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.currentOwner(); err != nil {
		return err
	}
	expected, err := json.Marshal(b.session.doc)
	if err != nil {
		return err
	}
	before, err := file.Stat()
	named, namedErr := b.session.root.Stat(policyAdditionFile)
	if err != nil || namedErr != nil || !validNetworkPolicyReceiptFile(before) || !os.SameFile(before, named) || before.Size() <= 0 || before.Size() > policyAdditionMaxBytes {
		return ErrPolicyAdditionReceipt
	}
	data := make([]byte, int(before.Size()))
	defer clear(data)
	n, readErr := file.ReadAt(data, 0)
	var compact bytes.Buffer
	closing, closeErr := b.session.root.Stat(policyAdditionFile)
	if readErr != nil || n != len(data) || closeErr != nil || !os.SameFile(before, closing) || json.Compact(&compact, data) != nil || !bytes.Equal(compact.Bytes(), expected) || b.currentOwner() != nil {
		return ErrPolicyAdditionReceipt
	}
	if b.published != nil {
		if err := b.published.Close(); err != nil {
			return err
		}
	}
	b.published, b.publishedInfo, b.publishedBytes = file, before, expected
	return nil
}

// A newly loaded Remove session must match the original retained publication
// before it can issue its first cleanup command. Matching bytes are insufficient.
func checkXraySelectedTCPOriginalLoadedReceipt(ctx context.Context, b *policyEffectReceiptBorrow) error {
	if ctx == nil {
		return ErrPolicyAdditionReceipt
	}
	raw := ctx.Value(xrayOperationOwnerKey{})
	if raw == nil {
		return nil
	}
	o, ok := raw.(*xrayOperationOwner)
	if !ok || o == nil || o.self != o || o.scope == nil || b == nil {
		return ErrPolicyAdditionReceipt
	}
	o.scope.mu.Lock()
	var r *XraySelectedTCPExecutionResource
	for _, candidate := range o.scope.xraySelectedTCP {
		if r != nil {
			o.scope.mu.Unlock()
			return ErrPolicyAdditionReceipt
		}
		r = candidate
	}
	o.scope.mu.Unlock()
	if r == nil || r.self != r || r.owner != o || !o.material.IsCleanupContext(ctx) {
		return ErrPolicyAdditionReceipt
	}
	r.commonMu.Lock()
	defer r.commonMu.Unlock()
	b.mu.Lock()
	defer b.mu.Unlock()
	p := r.common
	if p == nil || p.current(ctx) != nil || b.currentOwner() != nil || b.publishedInfo == nil || !os.SameFile(p.fileInfo, b.publishedInfo) ||
		!bytes.Equal(p.canonical, b.publishedBytes) || b.session.path != r.rootPath {
		return ErrPolicyAdditionReceipt
	}
	return nil
}
