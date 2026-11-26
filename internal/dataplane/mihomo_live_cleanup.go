package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

func (r *mihomoLiveResource) originalSidecarImage(ctx context.Context) (components.MihomoRuntimeImage, error) {
	if r == nil || r.self != r || r.source == nil || r.adapter == nil || r.scope == nil || !r.source.OwnedBy(r.adapter.components) || !r.adapter.RegisteredWith(r.scope.manager) || r.source.Reference() != r.definition.Source {
		return components.MihomoRuntimeImage{}, errMihomoLiveMaterial
	}
	if err := r.source.Current(ctx); err != nil {
		return components.MihomoRuntimeImage{}, err
	}
	r.mu.Lock()
	sidecar := r.sidecar
	r.mu.Unlock()
	if sidecar == nil {
		return components.MihomoRuntimeImage{}, nil
	}
	sidecar.mu.Lock()
	defer sidecar.mu.Unlock()
	if sidecar.self != sidecar || sidecar.owner != r {
		return components.MihomoRuntimeImage{}, errMihomoLiveMaterial
	}
	if !sidecar.started {
		return components.MihomoRuntimeImage{}, nil
	}
	if sidecar.witnessedSHA != r.definition.Sidecar.BinarySHA256 || sidecar.witnessedSize != r.definition.Sidecar.BinarySize {
		return components.MihomoRuntimeImage{}, errMihomoLiveMaterial
	}
	return components.MihomoRuntimeImage{SHA256: sidecar.witnessedSHA, Size: sidecar.witnessedSize}, nil
}

// Actual process and kernel absence, independent of Running(false) or metadata
// outcome. Called before settling the resource and again before terminal ACK.
func (r *mihomoLiveResource) observeLiveInactive(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview) error {
	if r == nil || r.self != r || r.proxy == nil || r.adapter == nil || r.scope == nil || r.control == nil || r.source == nil {
		return errMihomoLiveMaterial
	}
	if actual, err := r.adapter.originalLiveProxy(r.scope.manager); err != nil || actual != r.proxy {
		return errMihomoLiveMaterial
	}
	if err := errors.Join(r.control.CurrentForCleanupOperation(ctx, cleanup), r.source.Current(ctx)); err != nil {
		return err
	}
	if err := observeMihomoInactiveOriginal(ctx, r.adapter.provider, nil, r); err != nil {
		return err
	}
	if err := r.proxy.VerifyRuntimeInactive(ctx); err != nil {
		return err
	}
	return errors.Join(r.control.CurrentForCleanupOperation(ctx, cleanup), r.source.Current(ctx))
}

func (r *mihomoLiveResource) removeCompiledMetadata(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview) error {
	if err := r.removeRuntimeImages(ctx, cleanup); err != nil {
		return err
	}
	for _, entry := range []struct {
		path  string
		check func([]byte) bool
	}{
		{r.proxy.policyPath(), func(data []byte) bool {
			canonical, err := json.Marshal(proxyPolicyJournal{PolicyState: r.definition.Policy, AdditionReceiptVersion: 1})
			var compact bytes.Buffer
			return err == nil && json.Compact(&compact, data) == nil && bytes.Equal(compact.Bytes(), canonical)
		}},
		{r.proxy.policyBindingPath(), func(data []byte) bool {
			binding, exists, err := r.proxy.readPolicyBinding(r.definition.Policy)
			if err != nil || !exists || binding.Phase != "removed" {
				return false
			}
			canonical, err := json.Marshal(binding)
			return err == nil && string(canonical) == string(data)
		}},
	} {
		root, err := ownedfs.Open(filepath.Dir(entry.path))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		name := filepath.Base(entry.path)
		file, err := root.OpenFile(name, os.O_RDONLY, 0)
		if errors.Is(err, os.ErrNotExist) {
			if err := root.Close(); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			_ = root.Close()
			return err
		}
		info, err := file.Stat()
		if err != nil || !validNetworkPolicyReceiptFile(info) || info.Size() < 1 || info.Size() > 1<<20 {
			_ = file.Close()
			_ = root.Close()
			return errMihomoLiveMaterial
		}
		data := make([]byte, int(info.Size()))
		count, err := file.ReadAt(data, 0)
		valid := err == nil && count == len(data) && entry.check(data)
		clear(data)
		if !valid {
			_ = file.Close()
			_ = root.Close()
			return errMihomoLiveMaterial
		}
		err = r.control.WithCleanupRemove(ctx, cleanup, func() error {
			actual, err := root.Stat(name)
			if err != nil || !sameMihomoLiveFile(actual, info) {
				return errMihomoLiveMaterial
			}
			return root.Remove(name)
		})
		if err == nil {
			err = root.Sync()
		}
		err = errors.Join(err, file.Close(), root.Close())
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *mihomoLiveResource) cleanupLive(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview) error {
	ctx = context.WithValue(ctx, mihomoLiveCleanupCommandKey{}, cleanup)
	if r == nil || r.self != r || r.proxy == nil || r.control == nil || r.records == nil {
		return errMihomoLiveMaterial
	}
	if err := r.control.CurrentForCleanupOperation(ctx, cleanup); err != nil {
		return err
	}
	// Partial publication may have two different, but genuinely authored,
	// images. It is not permission to overwrite a foreign inode or skip join.
	custodyErr := r.records.current(ctx, false)
	if custodyErr != nil && !r.validationUsed && !r.startUsed {
		custodyErr = r.records.beforePublication()
	}
	var journalErr error
	if custodyErr == nil {
		journalErr = r.recordPhase(ctx, "closed", nil)
	} else {
		journalErr = custodyErr
	}
	transitErr := r.cleanupHealthTransits(ctx)
	// Original temporary cleanup still needs this exact live TUN/source and
	// active policy for its independent readback. Retain those prerequisites
	// across partial settlement ACKs; destroying them would strand the SAME
	// strict retry owner. No Stop/absence acknowledgment is issued here.
	if transitErr != nil {
		return errors.Join(mihomoLiveStopAt("close-row", journalErr), mihomoLiveStopAt("transit-settlement", transitErr))
	}
	var policyErr error
	// Remove only actual owned selectors/forwarding before joining children.
	if custodyErr == nil {
		if _, exists, err := r.proxy.loadPolicy(); err != nil {
			policyErr = err
		} else if exists {
			policyErr = r.proxy.deactivateLivePolicy(ctx, r.control, cleanup)
		} else {
			policyErr = r.proxy.removeCandidatePolicy(ctx, filepath.Join(r.scope.root, "mihomo"))
			policyErr = errors.Join(policyErr, r.proxy.removeForwarding(ctx))
		}
	}
	// Each independently held native owner gets its own actual fresh cleanup,
	// even when a journal publication or another original cleanup failed.
	nativeErr := errors.Join(mihomoLiveStopAt("sidecar-native", r.cleanupSidecarNative(ctx, cleanup)), mihomoLiveStopAt("engine-native", r.cleanupNative(ctx, cleanup)))
	if err := errors.Join(mihomoLiveStopAt("close-row", journalErr), transitErr, mihomoLiveStopAt("persistent-policy", policyErr), nativeErr); err != nil {
		return err
	}
	if err := observeMihomoInactiveOriginal(ctx, r.adapter.provider, nil, r); err != nil {
		return mihomoLiveStopAt("process-absence", err)
	}
	if err := r.removeCompiledMetadata(ctx, cleanup); err != nil {
		return mihomoLiveStopAt("compiled-remove", err)
	}
	if err := r.observeLiveInactive(ctx, cleanup); err != nil {
		return mihomoLiveStopAt("full-absence", err)
	}
	return mihomoLiveStopAt("removed-row", r.recordPhase(ctx, "removed", nil))
}

// Terminal publication owns these leases after native retirement. No caller
// may close them early merely because a process is absent.
func (r *mihomoLiveResource) closeNativeLeases() error {
	if r == nil || r.self != r {
		return errMihomoLiveMaterial
	}
	r.mu.Lock()
	sidecar := r.sidecar
	r.mu.Unlock()
	var sidecarErr error
	if sidecar != nil {
		sidecarErr = sidecar.closeJoined()
	}
	return errors.Join(sidecarErr, r.closeCompiledFiles())
}
