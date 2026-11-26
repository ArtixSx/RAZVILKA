package dataplane

import (
	"errors"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// No native Start is possible before transfer to issueLive. A failed actual
// Close retains this same original holder and fences further preparation.
type mihomoLivePreparation struct {
	source                *components.MihomoLiveSource
	control, childControl *operationgate.ControlEpochReview
	closeErr              error
}

func (p *mihomoLivePreparation) close() error {
	if p.closeErr != nil {
		return p.closeErr
	}
	if p.source != nil {
		if err := p.source.Close(); err != nil {
			p.closeErr = err
			return err
		}
		p.source = nil
	}
	if p.childControl != nil {
		if err := p.childControl.Close(); err != nil {
			p.closeErr = err
			return err
		}
		p.childControl = nil
	}
	if p.control != nil {
		if err := p.control.Close(); err != nil {
			p.closeErr = err
			return err
		}
		p.control = nil
	}
	return nil
}
func (a *MihomoProbeAdapter) HasPendingLive() bool {
	if a == nil || a.self != a {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.livePreparing != nil || a.livePending != nil || a.liveActive != nil
}
func (a *MihomoProbeAdapter) closeLivePreparation(p *mihomoLivePreparation) error {
	err := p.close()
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.livePreparing != p {
		return errors.Join(errMihomoLiveMaterial, err)
	}
	if err != nil {
		if a.liveOptions != nil {
			a.liveOptions.Gate.FenceJournal()
		}
		return err
	}
	a.livePreparing = nil
	return nil
}
