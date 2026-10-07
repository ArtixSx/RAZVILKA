package dataplane

import (
	"context"
	"errors"
	"io"
	"os"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// Inspection must NEVER recreate a missing permanent receipt lock. Reuse the
// common canonical validator, with the original existing nonblocking lock.
// No save, migration, repair or effect method is reachable from this reader.
type networkPolicyReceiptObservation struct {
	path     string
	anchor   os.FileInfo
	owner    *ownedfs.Root
	status   PolicyAdditionStatus
	checksum string
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
	unlock, err := lockNetworkPolicyReceiptExisting(root)
	if err != nil {
		return observation, err
	}
	defer unlock()
	if options.boot == nil {
		options.boot = (&ProxyTunnelAdapter{}).currentBootIdentity
	}
	session := policyAdditionSession{root: root, path: path, state: state, options: options}
	if err := session.load(ctx); err != nil {
		return observation, err
	}
	observation = networkPolicyReceiptObservation{path: path, anchor: anchor, owner: root, status: session.status(), checksum: session.doc.Checksum}
	return observation, ctx.Err()
}

func lockNetworkPolicyReceiptExisting(root *ownedfs.Root) (func(), error) {
	file, err := openNFQWS2LockFile(root, policyAdditionLock, false)
	if err != nil {
		return nil, ErrPolicyAdditionReceipt
	}
	keep := false
	defer func() {
		if !keep {
			file.Close()
		}
	}()
	info, err := file.Stat()
	if err != nil || !validCloudflareScanLockFile(info) || info.Size() != int64(len(policyAdditionMarker)) {
		return nil, ErrPolicyAdditionReceipt
	}
	if err := lockCloudflareScanFile(file); err != nil {
		return nil, ErrPolicyAdditionBusy
	}
	defer func() {
		if !keep {
			unlockCloudflareScanFile(file)
		}
	}()
	data, err := io.ReadAll(io.LimitReader(file, int64(len(policyAdditionMarker)+1)))
	current, statErr := root.Stat(policyAdditionLock)
	if err != nil || statErr != nil || string(data) != policyAdditionMarker || !os.SameFile(info, current) {
		return nil, ErrPolicyAdditionReceipt
	}
	keep = true
	return func() { unlockCloudflareScanFile(file); file.Close() }, nil
}
