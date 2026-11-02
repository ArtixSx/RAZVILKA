package dataplane

import (
	"context"
	"os"
	"os/exec"
	"sync"

	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// This owner comes only from the actual retained Cmd. Historical receipt/PID
// data cannot construct it. The sidecar has no asserted parent-death promise.
type mihomoLiveSidecar struct {
	mu                   sync.Mutex
	self                 *mihomoLiveSidecar
	owner                *mihomoLiveResource
	spec                 ProcessSpec
	root                 *ownedfs.Root
	rootInfo             os.FileInfo
	binary, profile      *os.File
	command              *exec.Cmd
	done                 chan struct{}
	state                *os.ProcessState
	waitErr              error
	started              bool
	joined               bool
	closed               bool
	closeErr             error
	checkUsed            bool
	pidRaw, receiptRaw   []byte
	pidInfo, receiptInfo os.FileInfo
	identities           [2]*mihomoLiveSidecarIdentityFile
	witnessedSHA         string
	witnessedSize        int64
}

type mihomoLiveSidecarIdentityFile struct {
	name, temporary string
	file            *os.File
	info            os.FileInfo
	data            []byte
	published       bool
}

func (r *mihomoLiveResource) startSidecarNative(ctx context.Context) error {
	if r == nil || r.self != r || r.proxy == nil || r.proxy.ID() != "mihomo" {
		return errMihomoLiveMaterial
	}
	if err := r.currentBeforeStart(ctx); err != nil {
		return err
	}
	if err := r.nativeCurrent(ctx); err != nil {
		return err
	}
	if err := r.compiledCurrent(true); err != nil {
		return err
	}
	r.mu.Lock()
	if r.sidecarAttempted || r.sidecar != nil || r.closed || r.closeErr != nil {
		r.mu.Unlock()
		return errMihomoLiveMaterial
	}
	r.sidecarAttempted = true
	r.mu.Unlock()
	native, err := newMihomoLiveSidecar(ctx, r, r.proxy.sidecarProcess())
	r.mu.Lock()
	r.sidecar = native
	if err != nil && native == nil {
		r.sidecarUnused = true
	}
	r.mu.Unlock()
	if err != nil {
		return err
	}
	if err := native.validate(ctx); err != nil {
		return err
	}
	if err := r.recordPhase(ctx, "sidecar-pending", nil); err != nil {
		return err
	}
	if err := native.start(ctx); err != nil {
		return err
	}
	if err := r.captureTUN(ctx); err != nil {
		return err
	}
	observation, err := native.observation(ctx)
	if err != nil {
		return err
	}
	return r.recordPhase(ctx, "sidecar-bound", &observation)
}

func (r *mihomoLiveResource) cleanupSidecarNative(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview) error {
	if r == nil || r.self != r {
		return errMihomoLiveMaterial
	}
	r.mu.Lock()
	sidecar, attempted, unused := r.sidecar, r.sidecarAttempted, r.sidecarUnused
	r.mu.Unlock()
	if sidecar == nil {
		if attempted && !unused {
			return errMihomoLiveMaterial
		}
		return nil
	}
	return sidecar.cleanup(ctx, cleanup)
}
