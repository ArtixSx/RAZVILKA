package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"sync"
)

// Only the actual COMMON Apply installs this private in-call reader. It
// borrows the original locked session, not a status DTO or another journal.
// Reads use a separate parser view and never race with the writer's s.doc.
type policyEffectReceiptBorrow struct {
	self           *policyEffectReceiptBorrow
	mu             sync.Mutex
	session        *policyEffectSession
	anchor         os.FileInfo
	marker         *os.File
	markerInfo     os.FileInfo
	open, absent   bool
	published      *os.File
	publishedInfo  os.FileInfo
	publishedBytes []byte
}

type policyEffectReceiptBorrowKey struct{}

type policyEffectBorrowObservation struct {
	borrow    *policyEffectReceiptBorrow
	status    PolicyAdditionStatus
	states    []string
	checksum  string
	document  *os.File
	fileInfo  os.FileInfo
	canonical []byte
	absent    bool
}

func newPolicyEffectReceiptBorrow(s *policyEffectSession) (*policyEffectReceiptBorrow, error) {
	if s == nil || s.root == nil || s.unlocked == nil || s.lock == nil {
		return nil, ErrPolicyAdditionReceipt
	}
	anchor, err := s.root.RootInfo()
	if err != nil || !networkPolicyPrivateDirectory(anchor) {
		return nil, errors.Join(ErrPolicyAdditionReceipt, err)
	}
	marker := s.lock
	info, err := marker.Stat()
	if err != nil || !validNetworkPolicyReceiptFile(info) || info.Size() != int64(len(policyAdditionMarker)) {
		return nil, ErrPolicyAdditionReceipt
	}
	b := &policyEffectReceiptBorrow{session: s, anchor: anchor, marker: marker, markerInfo: info, open: true, absent: true}
	b.self = b
	if err := b.currentOwner(); err != nil {
		b.close()
		return nil, err
	}
	return b, nil
}

// Called with b.mu held, or during construction before publication. No Gate,
// Store, source, runtime or receipt callback is reachable from this bookend.
func (b *policyEffectReceiptBorrow) currentOwner() error {
	if b == nil || b.self != b || !b.open || b.session == nil || b.session.root == nil || b.marker == nil {
		return ErrPolicyAdditionReceipt
	}
	s := b.session
	info, err := os.Lstat(s.path)
	if err != nil || !networkPolicyPrivateDirectory(info) || !os.SameFile(b.anchor, info) {
		return ErrPolicyAdditionReceipt
	}
	info, err = s.root.RootInfo()
	if err != nil || !os.SameFile(b.anchor, info) {
		return ErrPolicyAdditionReceipt
	}
	info, err = s.root.Stat(policyAdditionLock)
	if err != nil || !validNetworkPolicyReceiptFile(info) || !os.SameFile(b.markerInfo, info) {
		return ErrPolicyAdditionReceipt
	}
	data := make([]byte, len(policyAdditionMarker)+1)
	n, err := b.marker.ReadAt(data, 0)
	if err != io.EOF || n != len(policyAdditionMarker) || string(data[:n]) != policyAdditionMarker {
		return ErrPolicyAdditionReceipt
	}
	return nil
}

func (b *policyEffectReceiptBorrow) requireDocument() {
	b.mu.Lock()
	b.absent = false // Set before the first write attempt, including failure.
	b.mu.Unlock()
}

func (b *policyEffectReceiptBorrow) close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.open {
		b.open = false // Revoke before releasing the actual COMMON writer.
		if b.published != nil {
			b.published.Close()
		}
	}
}

// This hook runs only after the original writer's real successful atomic save.
// It retains that published inode/image, so a forged exact-plan receipt cannot
// manufacture added steps for the in-call reader. It never reads writer s.doc
// concurrently: the writer alone invokes this method between callbacks.
func (b *policyEffectReceiptBorrow) saved() (result error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.currentOwner(); err != nil {
		return err
	}
	canonical, err := json.Marshal(b.session.doc)
	if err != nil {
		return ErrPolicyAdditionReceipt
	}
	f, err := b.session.root.OpenFile(policyAdditionFile, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer func() {
		if result != nil {
			f.Close()
		}
	}()
	info, err := f.Stat()
	data, readErr := io.ReadAll(io.LimitReader(f, policyAdditionMaxBytes+1))
	var compact bytes.Buffer
	if err != nil || readErr != nil || !validNetworkPolicyReceiptFile(info) || len(data) > policyAdditionMaxBytes || json.Compact(&compact, data) != nil || !bytes.Equal(compact.Bytes(), canonical) {
		return ErrPolicyAdditionReceipt
	}
	current, err := b.session.root.Stat(policyAdditionFile)
	if err != nil || !os.SameFile(info, current) {
		return ErrPolicyAdditionReceipt
	}
	if err := b.currentOwner(); err != nil {
		return err
	}
	if b.published != nil {
		b.published.Close()
	}
	b.published, b.publishedInfo, b.publishedBytes = f, info, canonical
	return nil
}

func observeBorrowedPolicyEffects(ctx context.Context, plan PolicyEffectPlan, path string) (o policyEffectBorrowObservation, present bool, result error) {
	if ctx == nil || ctx.Err() != nil {
		return o, false, errors.Join(ErrPolicyAdditionReceipt, networkPolicyChecksContextError(ctx))
	}
	raw := ctx.Value(policyEffectReceiptBorrowKey{})
	if raw == nil {
		return o, false, nil
	}
	b, ok := raw.(*policyEffectReceiptBorrow)
	if !ok || b == nil || b.self != b {
		return o, true, ErrPolicyAdditionReceipt
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.currentOwner(); err != nil {
		return o, true, err
	}
	s := b.session
	if path != s.path || !reflect.DeepEqual(plan, s.plan) {
		return o, true, ErrPolicyAdditionReceipt
	}
	view := policyEffectSession{policyAdditionSession: &policyAdditionSession{root: s.root, path: s.path, options: s.options}, plan: s.plan, hash: s.hash}
	err := view.load(ctx)
	if errors.Is(err, os.ErrNotExist) && b.absent {
		return policyEffectBorrowObservation{borrow: b, absent: true}, true, b.currentOwner()
	}
	if err != nil || b.absent || view.doc.Phase != "active" {
		return o, true, errors.Join(ErrPolicyAdditionReceipt, err)
	}
	document, err := s.root.OpenFile(policyAdditionFile, os.O_RDONLY, 0)
	if err != nil {
		return o, true, err
	}
	defer func() {
		if result != nil {
			document.Close()
		}
	}()
	info, err := document.Stat()
	canonical, marshalErr := json.Marshal(view.doc)
	if err != nil || marshalErr != nil || !validNetworkPolicyReceiptFile(info) || b.published == nil || !os.SameFile(b.publishedInfo, info) || !bytes.Equal(canonical, b.publishedBytes) {
		return o, true, ErrPolicyAdditionReceipt
	}
	o = policyEffectBorrowObservation{borrow: b, status: view.status(), checksum: view.doc.Checksum, document: document, fileInfo: info, canonical: canonical}
	for _, step := range view.doc.Steps {
		o.states = append(o.states, step.State)
	}
	return o, true, o.currentLocked(ctx)
}

func (o policyEffectBorrowObservation) close() {
	if o.document != nil {
		o.document.Close()
	}
}

func (o policyEffectBorrowObservation) current(ctx context.Context) error {
	if o.borrow == nil {
		return ErrPolicyAdditionReceipt
	}
	o.borrow.mu.Lock()
	defer o.borrow.mu.Unlock()
	return o.currentLocked(ctx)
}

func (o policyEffectBorrowObservation) currentLocked(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrPolicyAdditionReceipt
	}
	b := o.borrow
	if err := b.currentOwner(); err != nil {
		return err
	}
	if o.absent {
		if !b.absent {
			return ErrPolicyAdditionReceipt
		}
		_, err := b.session.root.Stat(policyAdditionFile)
		if !errors.Is(err, os.ErrNotExist) {
			return ErrPolicyAdditionReceipt
		}
		return b.currentOwner()
	}
	if o.document == nil || o.fileInfo == nil || len(o.canonical) == 0 {
		return ErrPolicyAdditionReceipt
	}
	info, err := b.session.root.Stat(policyAdditionFile)
	if err != nil || !validNetworkPolicyReceiptFile(info) || !os.SameFile(o.fileInfo, info) {
		return ErrPolicyAdditionReceipt
	}
	data, err := b.session.root.ReadLimited(policyAdditionFile, policyAdditionMaxBytes)
	var compact bytes.Buffer
	if err != nil || json.Compact(&compact, data) != nil || !bytes.Equal(compact.Bytes(), o.canonical) {
		return ErrPolicyAdditionReceipt
	}
	info, err = b.session.root.Stat(policyAdditionFile)
	if err != nil || !os.SameFile(o.fileInfo, info) {
		return ErrPolicyAdditionReceipt
	}
	return b.currentOwner()
}
