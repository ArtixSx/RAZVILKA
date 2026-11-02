package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"time"
)

func (a *MihomoProbeAdapter) phaseResource(ctx context.Context, plan Plan, root string) (*mihomoLiveResource, error) {
	r, err := a.liveResource(ctx)
	if err != nil {
		return nil, err
	}
	if root != filepath.Join(r.scope.root, "mihomo") || !reflect.DeepEqual(plan, r.definition.Plan) || r.proxy == nil {
		return nil, errMihomoLiveMaterial
	}
	return r, nil
}
func (a *MihomoProbeAdapter) liveSnapshot(ctx context.Context, plan Plan, root string) error {
	a.mu.Lock()
	proxy, options := a.liveProxy, a.liveOptions
	busy := a.busy || a.pending != nil || a.liveActive != nil || a.livePending != nil || a.livePreparing != nil
	a.mu.Unlock()
	if proxy == nil || options == nil || busy || !a.RegisteredWith(options.Manager) {
		return ErrMihomoProbe
	}
	if _, err := mihomoLiveIntentNode(plan); err != nil {
		return err
	}
	// Full actual configured kernel/process absence precedes the first live
	// resource publication. Running(false) and a missing PID file are no proof.
	if err := a.VerifyRuntimeInactive(ctx); err != nil {
		return err
	}
	r, err := a.prepareLive(ctx, plan, root)
	if err != nil {
		return err
	}
	if err := r.currentBeforeStart(ctx); err != nil {
		return fmt.Errorf("mihomo snapshot closing original source: %w", err)
	}
	return nil
}
func (r *mihomoLiveResource) sidecarImage() ([]byte, error) {
	var data []byte
	var err error
	if r.proxy.effectiveSidecar() == "hev" {
		data, err = r.proxy.hevConfig()
	} else {
		data, err = buildSOCKSTunnelConfigForSchema(r.proxy.Interface, r.proxy.TunnelCIDR, r.proxy.SOCKSPort, singBoxSidecarSchema{modernAddress: true, dnsMode: true})
	}
	if err != nil || nodeDefaultSourceMaterialHash(data) != r.definition.Sidecar.ConfigSHA256 {
		return nil, errors.Join(errMihomoLiveMaterial, err)
	}
	return data, nil
}
func (a *MihomoProbeAdapter) liveStage(ctx context.Context, p Plan, root string) error {
	r, err := a.phaseResource(ctx, p, root)
	if err != nil {
		return err
	}
	ctx = r.resourceContext(ctx)
	engine, err := r.engineImage(ctx)
	if err != nil {
		return err
	}
	defer clear(engine)
	sidecar, err := r.sidecarImage()
	if err != nil {
		return err
	}
	defer clear(sidecar)
	if err = r.publishCompiled(ctx, filepath.Join(root, "engine.staged.json"), engine); err != nil {
		return err
	}
	if err = r.publishCompiled(ctx, filepath.Join(root, "sidecar.staged.json"), sidecar); err != nil {
		return err
	}
	if err = r.currentBeforeStart(ctx); err != nil {
		return err
	}
	data, err := json.Marshal(r.definition.Policy)
	if err != nil {
		return err
	}
	if err = writeAtomic(filepath.Join(root, "policy.staged.json"), data, 0600); err != nil {
		return err
	}
	if err = r.proxy.prepareCandidatePolicy(root, r.definition.Policy); err != nil {
		return err
	}
	return r.currentBeforeStart(ctx)
}
func (a *MihomoProbeAdapter) liveValidate(ctx context.Context, p Plan, root string) error {
	r, err := a.phaseResource(ctx, p, root)
	if err != nil {
		return err
	}
	ctx = r.resourceContext(ctx)
	if err = r.compiledCurrent(false); err != nil {
		return err
	}
	if err = r.proxy.preflightForwarding(ctx, r.definition.Policy); err != nil {
		return err
	}
	cleanup, err := r.cleanupReview(ctx)
	if err != nil {
		return err
	}
	if err = r.startNative(ctx, cleanup); err != nil {
		return err
	}
	// The original child owns its listener; poll actual birth/FD/socket proof,
	// rather than a successful TCP connect or a serialized PID.
	ready, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for {
		err = r.nativeCurrent(ready)
		if err == nil {
			break
		}
		select {
		case <-ready.Done():
			return errors.Join(err, ready.Err())
		case <-time.After(25 * time.Millisecond):
		}
	}
	return r.recordPhase(ctx, "listener-bound", nil)
}
func (a *MihomoProbeAdapter) Canary(ctx context.Context, p RoutePlan, root string) error {
	r, err := a.liveResource(ctx)
	if err != nil {
		return err
	}
	if root != filepath.Join(r.scope.root, "mihomo") || !reflect.DeepEqual(p, r.definition.Plan.RoutePlanFor("mihomo")) {
		return errMihomoLiveMaterial
	}
	return r.canaryLive(r.resourceContext(ctx))
}
func (a *MihomoProbeAdapter) liveActivate(ctx context.Context, p Plan, root string) error {
	r, err := a.phaseResource(ctx, p, root)
	if err != nil {
		return err
	}
	ctx = r.resourceContext(ctx)
	if err = errors.Join(r.currentBeforeStart(ctx), r.nativeCurrent(ctx), r.compiledCurrent(false)); err != nil {
		return err
	}
	if err = r.proxy.preflightForwarding(ctx, r.definition.Policy); err != nil {
		return err
	}
	if err = r.proxy.beginCandidatePolicy(root, r.definition.Policy); err != nil {
		return err
	}
	engine, err := r.engineImage(ctx)
	if err != nil {
		return err
	}
	defer clear(engine)
	sidecar, err := r.sidecarImage()
	if err != nil {
		return err
	}
	defer clear(sidecar)
	if err = r.publishCompiled(ctx, r.proxy.engineConfigPath(), engine); err != nil {
		return err
	}
	if err = r.publishCompiled(ctx, r.proxy.sidecarConfigPath(), sidecar); err != nil {
		return err
	}
	if err = r.startSidecarNative(ctx); err != nil {
		return err
	}
	if err = r.recordPhase(ctx, "policy-pending", r.definition.Observation); err != nil {
		return err
	}
	if err = r.proxy.applyCandidatePolicy(ctx, r.definition.Policy, root); err != nil {
		return err
	}
	return r.currentBeforeStart(ctx)
}
func (a *MihomoProbeAdapter) liveCommit(ctx context.Context, p Plan, root string) error {
	r, err := a.phaseResource(ctx, p, root)
	if err != nil {
		return err
	}
	ctx = r.resourceContext(ctx)
	if err = r.verifyHealthHandoff(ctx); err != nil {
		return err
	}
	if err = r.proxy.verifyCandidateReceipt(ctx, root, r.definition.Policy, true); err != nil {
		return err
	}
	if err = r.proxy.promoteCandidatePolicy(ctx, r.definition.Policy, root); err != nil {
		return err
	}
	if err = r.proxy.savePolicyJournal(r.definition.Policy, true); err != nil {
		return err
	}
	// The original Manager still performs mandatory TUN HTTPS in
	// prepareActiveMihomo AFTER config CAS and before ACTIVE/publication.
	// Do not issue or reuse service evidence across that callback.
	return r.currentPromotedStructure(ctx)
}
func (a *MihomoProbeAdapter) liveRollback(ctx context.Context, p Plan, root string) error {
	r, err := a.phaseResource(ctx, p, root)
	if err != nil {
		return err
	}
	cleanup, err := r.cleanupReview(ctx)
	if err != nil {
		return err
	}
	return r.cleanupLive(ctx, cleanup)
}
