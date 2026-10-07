package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// Inspection must NEVER recreate a missing permanent receipt lock. Reuse the
// common canonical validator, with the original existing nonblocking lock.
// No save, migration, repair or effect method is reachable from this reader.
type networkPolicyReceiptObservation struct {
	path      string
	anchor    os.FileInfo
	owner     *ownedfs.Root
	status    PolicyAdditionStatus
	checksum  string
	document  *os.File
	fileInfo  os.FileInfo
	lock      *os.File
	lockInfo  os.FileInfo
	canonical []byte
}

func (o networkPolicyReceiptObservation) close() {
	if o.document != nil {
		o.document.Close()
	}
	if o.lock != nil {
		o.lock.Close()
	}
	if o.owner != nil {
		o.owner.Close()
	}
}

// Pure anchored file validation AFTER the final complete collector. No owner
// callback, runtime read or effect runs here. Retained document/lock descriptors
// prevent inode reuse from hiding replacement, including identical bytes.
func (o networkPolicyReceiptObservation) current() error {
	if o.owner == nil || o.document == nil || o.lock == nil || len(o.canonical) == 0 {
		return ErrPolicyAdditionReceipt
	}
	unlock, lock, err := lockNetworkPolicyReceiptExisting(o.owner)
	if err != nil {
		return err
	}
	defer lock.Close()
	defer unlock()
	info, err := lock.Stat()
	if err != nil || !os.SameFile(o.lockInfo, info) {
		return ErrPolicyAdditionReceipt
	}
	info, err = o.owner.Stat(policyAdditionFile)
	if err != nil || !validNetworkPolicyReceiptFile(info) || !os.SameFile(o.fileInfo, info) {
		return ErrPolicyAdditionReceipt
	}
	data, err := o.owner.ReadLimited(policyAdditionFile, policyAdditionMaxBytes)
	var compact bytes.Buffer
	if err != nil || json.Compact(&compact, data) != nil || !bytes.Equal(compact.Bytes(), o.canonical) {
		return ErrPolicyAdditionReceipt
	}
	after, err := o.owner.Stat(policyAdditionFile)
	if err != nil || !validNetworkPolicyReceiptFile(after) || !os.SameFile(o.fileInfo, after) {
		return ErrPolicyAdditionReceipt
	}
	return nil
}

func validNetworkPolicyReceiptFile(info os.FileInfo) bool {
	return info != nil && validCloudflareScanLockFile(info) && info.Size() <= policyAdditionMaxBytes
}

func observeNetworkPolicyProxyAddition(ctx context.Context, state PolicyState, path string, options policyAdditionOptions) (observation networkPolicyReceiptObservation, result error) {
	if ctx == nil || ctx.Err() != nil {
		return observation, errors.Join(ErrNetworkPolicyConsumers, networkPolicyChecksContextError(ctx))
	}
	if _, err := policyAdditionExpected(state); err != nil {
		return observation, err
	}
	root, anchor, err := openNetworkPolicyObservationRoot(path)
	if err != nil {
		return observation, err
	}
	defer func() {
		if result != nil {
			root.Close()
		}
	}()
	unlock, lock, err := lockNetworkPolicyReceiptExisting(root)
	if err != nil {
		return observation, err
	}
	defer func() {
		if result != nil {
			lock.Close()
		}
	}()
	defer unlock()
	if options.boot == nil {
		options.boot = (&ProxyTunnelAdapter{}).currentBootIdentity
	}
	session := policyAdditionSession{root: root, path: path, state: state, options: options}
	if err := session.load(ctx); err != nil {
		return observation, err
	}
	document, err := root.OpenFile(policyAdditionFile, os.O_RDONLY, 0)
	if err != nil {
		return observation, err
	}
	defer func() {
		if result != nil {
			document.Close()
		}
	}()
	fileInfo, err := document.Stat()
	if err != nil || !validNetworkPolicyReceiptFile(fileInfo) {
		return observation, ErrPolicyAdditionReceipt
	}
	data, err := io.ReadAll(io.LimitReader(document, policyAdditionMaxBytes+1))
	canonical, marshalErr := json.Marshal(session.doc)
	var compact bytes.Buffer
	if err != nil || marshalErr != nil || len(data) > policyAdditionMaxBytes || json.Compact(&compact, data) != nil || !bytes.Equal(compact.Bytes(), canonical) {
		return observation, ErrPolicyAdditionReceipt
	}
	current, err := root.Stat(policyAdditionFile)
	if err != nil || !os.SameFile(fileInfo, current) {
		return observation, ErrPolicyAdditionReceipt
	}
	lockInfo, err := lock.Stat()
	if err != nil {
		return observation, err
	}
	observation = networkPolicyReceiptObservation{path: path, anchor: anchor, owner: root, status: session.status(), checksum: session.doc.Checksum, document: document, fileInfo: fileInfo, lock: lock, lockInfo: lockInfo, canonical: canonical}
	return observation, ctx.Err()
}

func lockNetworkPolicyReceiptExisting(root *ownedfs.Root) (func(), *os.File, error) {
	file, err := openNFQWS2LockFile(root, policyAdditionLock, false)
	if err != nil {
		return nil, nil, ErrPolicyAdditionReceipt
	}
	keep := false
	defer func() {
		if !keep {
			file.Close()
		}
	}()
	info, err := file.Stat()
	if err != nil || !validCloudflareScanLockFile(info) || info.Size() != int64(len(policyAdditionMarker)) {
		return nil, nil, ErrPolicyAdditionReceipt
	}
	if err := lockCloudflareScanFile(file); err != nil {
		return nil, nil, ErrPolicyAdditionBusy
	}
	defer func() {
		if !keep {
			unlockCloudflareScanFile(file)
		}
	}()
	data, err := io.ReadAll(io.LimitReader(file, int64(len(policyAdditionMarker)+1)))
	current, statErr := root.Stat(policyAdditionLock)
	if err != nil || statErr != nil || string(data) != policyAdditionMarker || !os.SameFile(info, current) {
		return nil, nil, ErrPolicyAdditionReceipt
	}
	keep = true
	return func() { unlockCloudflareScanFile(file) }, file, nil
}
