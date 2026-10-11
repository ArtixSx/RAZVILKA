package app

import (
	"context"
	"errors"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/installpath"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/strategylab"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

const (
	ManagedComponentReadVersion   = components.ManagedNFQWSJournalSchema
	managedComponentsState        = installpath.State + "/components"
	managedNFQBundlePlanPath      = "/api/v1/components/nfqws2/managed-bundle/plan"
	managedNFQBundleInstallPath   = "/api/v1/components/nfqws2/managed-bundle/install"
	managedNFQBundleInstalledPath = "/api/v1/components/nfqws2/managed-bundle/installed"
)

type managedNFQBundleState struct {
	mu      sync.Mutex
	control *operationgate.ControlEpochReview
}

// ConfigureManagedNFQCompatibility retains the actual configured owner for
// subsequent source inactivity reviews. The caller already owns the original
// finite exclusive operation. No process, source or consent is created here.
func (a *App) ConfigureManagedNFQCompatibility(ctx context.Context) (*operationgate.ControlEpochReview, error) {
	control, err := a.managedNFQControl(ctx)
	defer a.closeUnretainedManagedNFQControl(control)
	if err != nil {
		return nil, err
	}
	if err := a.configureManagedNFQCompatibility(ctx, control, nil); err != nil {
		return nil, err
	}
	return control, nil
}

func (a *App) managedNFQControl(ctx context.Context) (*operationgate.ControlEpochReview, error) {
	if a == nil || a.StrategyLab == nil || a.Components == nil || a.SelfUpdateFiles == nil {
		return nil, components.ErrRecoveryAuthority
	}
	if err := a.Operations.WithExclusiveContext(ctx, func() error { return nil }); err != nil {
		return nil, err
	}
	a.managedNFQBundle.mu.Lock()
	defer a.managedNFQBundle.mu.Unlock()
	control := a.managedNFQBundle.control
	if control == nil {
		var err error
		control, err = a.Operations.ReviewControlEpoch(ctx, a.SelfUpdateFiles.ControlRoot)
		if err != nil {
			return nil, err
		}
	}
	if !control.MatchesControlRoot(a.SelfUpdateFiles.ControlRoot) {
		return nil, components.ErrRecoveryAuthority
	}
	return control, control.Current(ctx)
}

// Only an installed provider needs this exact descriptor across operations.
// Failed initial construction/installation must not pin an unused epoch.
func (a *App) retainManagedNFQControl(control *operationgate.ControlEpochReview) {
	a.managedNFQBundle.mu.Lock()
	defer a.managedNFQBundle.mu.Unlock()
	a.managedNFQBundle.control = control
}

func (a *App) closeUnretainedManagedNFQControl(control *operationgate.ControlEpochReview) {
	if control == nil {
		return
	}
	a.managedNFQBundle.mu.Lock()
	defer a.managedNFQBundle.mu.Unlock()
	if a.managedNFQBundle.control != control {
		_ = control.Close()
	}
}

func (a *App) managedNFQRetainedControlCurrent(ctx context.Context) error {
	a.managedNFQBundle.mu.Lock()
	defer a.managedNFQBundle.mu.Unlock()
	if a.managedNFQBundle.control == nil {
		return nil
	}
	return a.managedNFQBundle.control.Current(ctx)
}

func (a *App) configureManagedNFQCompatibility(ctx context.Context, control *operationgate.ControlEpochReview, inactive *strategylab.ManagedCompatibilityInactiveReview) error {
	lease, err := a.Components.AcquireCurrentManagedNFQWSRuntime(ctx)
	if err != nil {
		return err
	}
	provider, validator, buildErr := strategylab.NewManagedSupervisedCompatibilityProvider(ctx, a.StrategyLab, lease, control, a.SelfUpdateFiles.ControlRoot)
	if buildErr != nil || provider == nil || validator.Provider != provider {
		return errors.Join(strategylab.ErrSelectedCandidateChanged, buildErr, lease.Close())
	}
	if inactive != nil {
		// Hot handover keeps this genuine runtime writer lease through the
		// source owner's locked setter, carrying its SAME original review.
		setErr := a.StrategyLab.InstallManagedCompatibilityValidator(ctx, control, provider, validator, inactive)
		if setErr == nil {
			a.retainManagedNFQControl(control)
		}
		return errors.Join(setErr, lease.Close())
	}
	if err := lease.Close(); err != nil {
		return err
	}
	// Only ordinary main startup calls with nil, before workers or HTTP.
	a.StrategyLab.Validator = validator
	a.retainManagedNFQControl(control)
	return nil
}

// Main closes this retained descriptor only after HTTP/worker cleanup joins.
func (a *App) CloseManagedNFQControl() error {
	if a.strategyCompatibilityPending() || a.managedNFQListPending() {
		return strategylab.ErrCompatibilityQuiescenceUnknown
	}
	a.managedNFQBundle.mu.Lock()
	defer a.managedNFQBundle.mu.Unlock()
	if a.managedNFQBundle.control == nil {
		return nil
	}
	return a.managedNFQBundle.control.Close()
}

func (a *App) managedNFQBundleConfigured() error {
	if a.Store == nil || a.Components == nil || a.StrategyLab == nil || a.ComponentHistory == nil || a.SelfUpdateFiles == nil || a.strategyCompatibilityPending() {
		return components.ErrRecoveryAuthority
	}
	// The retained fleet scanner covers this fixed deployment. A caller may
	// inspect another configured state directory but cannot write outside it.
	if a.Components.StateDir != managedComponentsState {
		return components.ErrRecoveryAuthority
	}
	return nil
}

func (a *App) managedNFQConfigCurrent(ctx context.Context, expected config.Config) error {
	return a.Store.WithResourceExclusionObservation(ctx, expected, func(config.EffectiveExclusionSet) error { return nil })
}

func (a *App) managedNFQHistoryCurrent(ctx context.Context) error {
	before, digest, err := components.InspectRetainedManagedUpdateReadVersion(ctx, a.Components.StateDir)
	if err != nil || before > ManagedComponentReadVersion {
		return errors.Join(components.ErrRecoveryAuthority, err)
	}
	if err := a.ComponentHistory.CheckWrite(ctx, ManagedComponentReadVersion); err != nil {
		return err
	}
	after, fresh, err := components.InspectRetainedManagedUpdateReadVersion(ctx, a.Components.StateDir)
	if err != nil || before != after || digest != fresh {
		return errors.Join(components.ErrRecoveryAuthority, err)
	}
	return nil
}

func (a *App) managedNFQAuthority(cfg config.Config, control *operationgate.ControlEpochReview, inactive *strategylab.ManagedCompatibilityInactiveReview) components.ManagedNFQWSBundleAuthority {
	ref := control.Reference()
	check := func(c context.Context, installation string, sequence, revision uint64, reader int) error {
		if installation != ref.InstallationID || sequence != ref.Sequence || revision != cfg.Revision || reader != ManagedComponentReadVersion {
			return components.ErrRecoveryAuthority
		}
		if err := a.Operations.WithExclusiveContext(c, func() error { return nil }); err != nil {
			return err
		}
		if err := errors.Join(a.managedNFQBundleConfigured(), control.Current(c), a.managedNFQConfigCurrent(c, cfg)); err != nil {
			return err
		}
		if err := a.managedNFQHistoryCurrent(c); err != nil {
			return err
		}
		if err := inactive.Current(c); err != nil {
			return err
		}
		return errors.Join(a.managedNFQConfigCurrent(c, cfg), control.Current(c))
	}
	return components.ManagedNFQWSBundleAuthority{
		InstallationID: ref.InstallationID, Sequence: ref.Sequence, ReaderVersion: ManagedComponentReadVersion,
		Check: check, Inactive: inactive.Current,
		Admit: func(c context.Context, transaction, installation string, sequence, revision uint64, effect string, begin func() error) error {
			if len(transaction) != 32 || begin == nil {
				return components.ErrRecoveryAuthority
			}
			if err := check(c, installation, sequence, revision, ManagedComponentReadVersion); err != nil {
				return err
			}
			var err error
			switch effect {
			case "nfqws-publish-generation", "nfqws-publish-receipt", "nfqws-rollback-receipt":
				err = control.WithRename(c, begin)
			case "nfqws-remove-receipt":
				err = control.WithRemove(c, begin)
			default:
				return components.ErrRecoveryAuthority
			}
			return errors.Join(err, check(c, installation, sequence, revision, ManagedComponentReadVersion))
		},
	}
}

func managedNFQRecoveryActions(state components.ManagedUpdateState, pending bool) []string {
	if !pending {
		return []string{}
	}
	switch state.Phase {
	case components.UpdatePrepared, components.UpdateStarted, components.UpdateInstalled, components.UpdateAwaitingLive:
		return []string{"resume", "rollback"}
	case components.UpdateRollbackStarted:
		return []string{"rollback"}
	default:
		return []string{}
	}
}

func (a *App) managedNFQBundlePlan(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if a.Security == nil || !a.Security.Authenticated(r) {
		http.Error(w, "administrator login is required", http.StatusUnauthorized)
		return
	}
	var revision uint64
	if a.Store != nil {
		revision = a.Store.Get().Revision
	}
	plan := map[string]any{"revision": revision, "ready": false, "code": "MANAGED_NFQWS_INSTALL_UNAVAILABLE", "reason": "Установка управляемого NFQWS2 сейчас недоступна.", "installed_idle": false, "compatibility_ready": false, "working_routes_changed": false}
	manifest, err := components.ReviewedManagedNFQWSManifest(runtime.GOARCH)
	if err == nil {
		digest, _ := manifest.Digest()
		plan["bundle"] = map[string]any{"provider_id": manifest.ProviderID, "flavor": manifest.Flavor, "architecture": manifest.Architecture, "manifest_sha256": digest}
	}
	if err != nil || runtime.GOOS != "linux" || os.Geteuid() != 0 || a.managedNFQBundleConfigured() != nil {
		if err != nil || runtime.GOOS != "linux" {
			plan["code"] = "MANAGED_NFQWS_PLATFORM_UNREVIEWED"
			plan["reason"] = "Для этой платформы ещё нет проверенного пакета управляемого NFQWS2."
		}
		writeJSON(w, http.StatusOK, plan)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	// A plan only reads. It never initializes the source or the control owner.
	control, err := a.Operations.ReviewControlEpoch(ctx, a.SelfUpdateFiles.ControlRoot)
	if err != nil {
		writeJSON(w, http.StatusOK, plan)
		return
	}
	defer control.Close()
	cfg := a.Store.Get()
	if cfg.Revision != revision {
		writeJSON(w, http.StatusOK, plan)
		return
	}
	if err := errors.Join(a.managedNFQRetainedControlCurrent(ctx), a.managedNFQConfigCurrent(ctx, cfg), a.managedNFQHistoryCurrent(ctx), control.Current(ctx)); err != nil {
		plan["code"], plan["reason"] = managedNFQBundleFailureDetails(err)
		writeJSON(w, http.StatusOK, plan)
		return
	}
	plan["ready"], plan["code"], plan["reason"] = true, "MANAGED_NFQWS_INSTALL_READY", "Можно запросить установку. Исходная операция и неактивность управляемой проверки будут проверены повторно."
	if descriptor, readErr := a.managedNFQInstalled(ctx); readErr == nil {
		plan["installed_idle"] = true
		plan["installed"] = descriptor
	}
	if errors.Join(a.managedNFQConfigCurrent(ctx, cfg), control.Current(ctx)) != nil {
		plan["ready"] = false
		plan["code"] = "MANAGED_NFQWS_AUTHORITY_CHANGED"
	}
	writeJSON(w, http.StatusOK, plan)
}

func (a *App) managedNFQInstalled(ctx context.Context) (map[string]any, error) {
	if a.Components == nil {
		return nil, components.ErrManagedNFQWSBundle
	}
	lease, err := a.Components.AcquireCurrentManagedNFQWSRuntime(ctx)
	if err != nil {
		return nil, err
	}
	d := lease.Descriptor()
	err = lease.Close()
	if err != nil {
		return nil, err
	}
	return map[string]any{"installed_idle": true, "provider_id": components.ManagedNFQWSProvider, "flavor": d.Flavor, "manifest_sha256": d.ManifestSHA256, "receipt_id": d.ReceiptID, "working_routes_changed": false}, nil
}

func (a *App) managedNFQBundleInstalled(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if a.Security == nil || !a.Security.Authenticated(r) {
		http.Error(w, "administrator login is required", http.StatusUnauthorized)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	installed, err := a.managedNFQInstalled(ctx)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"installed_idle": false, "code": "MANAGED_NFQWS_SOURCE_UNAVAILABLE", "working_routes_changed": false})
		return
	}
	writeJSON(w, http.StatusOK, installed)
}

func (a *App) managedNFQBundleInstall(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if a.Security == nil || !a.Security.Authenticated(r) {
		http.Error(w, "administrator login is required", http.StatusUnauthorized)
		return
	}
	var in struct {
		ExpectedRevision *uint64 `json:"expected_revision"`
	}
	if !decodeServiceControl(w, r, &in) {
		return
	}
	if in.ExpectedRevision == nil {
		http.Error(w, "expected_revision is required", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Minute)
	defer cancel()
	ctx, release, err := a.privateExclusiveOperation(ctx)
	if err != nil {
		a.writeOperationFailure(w, err)
		return
	}
	defer release()
	manifest, err := components.ReviewedManagedNFQWSManifest(runtime.GOARCH)
	if err != nil || runtime.GOOS != "linux" || os.Geteuid() != 0 {
		a.writeManagedNFQBundleFailure(w, err, "platform")
		return
	}
	if err := a.managedNFQBundleConfigured(); err != nil {
		a.writeManagedNFQBundleFailure(w, err, "configuration")
		return
	}
	cfg := a.Store.Get()
	if cfg.Revision != *in.ExpectedRevision {
		a.writeManagedNFQBundleFailure(w, components.ErrRecoveryAuthority, "config")
		return
	}
	control, err := a.managedNFQControl(ctx)
	defer a.closeUnretainedManagedNFQControl(control)
	if err != nil {
		a.writeManagedNFQBundleFailure(w, err, "control")
		return
	}
	if err := a.managedNFQConfigCurrent(ctx, cfg); err != nil {
		a.writeManagedNFQBundleFailure(w, err, "config")
		return
	}
	if err := a.managedNFQHistoryCurrent(ctx); err != nil {
		a.writeManagedNFQBundleFailure(w, err, "history")
		return
	}
	if err := a.StrategyLab.InitializeManagedCompatibilitySource(ctx, control); err != nil {
		a.writeManagedNFQBundleFailure(w, err, "source_initialize")
		return
	}
	inactive, err := a.StrategyLab.ReviewManagedCompatibilityInactive(ctx, control)
	if err != nil {
		a.writeManagedNFQBundleFailure(w, err, "source_inactive")
		return
	}
	defer inactive.Close()
	// This independent read identifies filesystem refusal without exposing raw
	// paths or errors. The installer repeats it under its actual writer lease.
	if err := a.Components.PreflightManagedNFQWS(ctx); err != nil {
		a.writeManagedNFQBundleFailure(w, err, "bundle_preflight")
		return
	}
	receipt, err := a.Components.InstallManagedBundle(ctx, manifest, cfg.Revision, a.managedNFQAuthority(cfg, control, inactive))
	if err != nil {
		a.writeManagedNFQBundleFailure(w, err, "bundle_install")
		return
	}
	a.writeManagedNFQBundleSuccess(w, ctx, cfg, control, inactive, receipt)
}

// stage is an internal literal naming the caller's last failed check, not an
// error string or a producer capability. No request data enters this field.
func (a *App) writeManagedNFQBundleFailure(w http.ResponseWriter, err error, stage string) {
	pending := a.PendingComponentRecovery()
	status, code := http.StatusConflict, "MANAGED_NFQWS_INSTALL_REFUSED"
	if pending {
		status, code = http.StatusServiceUnavailable, "MANAGED_NFQWS_RECOVERY_REQUIRED"
	}
	reasonCode, reason := managedNFQBundleFailureDetails(err)
	writeJSON(w, status, map[string]any{"ok": false, "code": code, "reason_code": reasonCode, "stage": stage, "error": reason, "recovery_required": pending, "installed_idle": false, "working_routes_changed": false})
}

func managedNFQBundleFailureDetails(err error) (string, string) {
	if errors.Is(err, updatecheck.ErrComponentHistoryAdmission) || errors.Is(err, components.ErrRetainedManagedUpdate) {
		return "MANAGED_NFQWS_RETAINED_CONTROLLER_BLOCKED", "Состояние компонента или сохранённые контроллеры не допускают формат установки NFQWS2. Сохраните журналы и версии контроллеров для проверки."
	} else if errors.Is(err, strategylab.ErrCompatibilityQuiescenceUnknown) {
		return "MANAGED_NFQWS_SOURCE_NOT_INACTIVE", "Исходное состояние управляемой проверки NFQWS2 не подтверждает её завершение. Повторная установка не запускается."
	}
	return "MANAGED_NFQWS_AUTHORITY_UNAVAILABLE", "Установка управляемого NFQWS2 не завершена. Проверьте доступность исходного состояния и совместимость сохранённых контроллеров."
}

func (a *App) writeManagedNFQBundleSuccess(w http.ResponseWriter, ctx context.Context, cfg config.Config, control *operationgate.ControlEpochReview, inactive *strategylab.ManagedCompatibilityInactiveReview, receipt components.ManagedNFQWSBundleReceipt) {
	installed, err := a.managedNFQInstalled(ctx)
	if err != nil || installed["receipt_id"] != receipt.TransactionID || installed["manifest_sha256"] != receipt.ManifestSHA256 || installed["flavor"] != receipt.Flavor || installed["provider_id"] != receipt.ProviderID {
		a.writeManagedNFQBundleFailure(w, err, "installed_readback")
		return
	}
	ready := a.configureManagedNFQCompatibility(ctx, control, inactive) == nil
	if err := errors.Join(a.managedNFQConfigCurrent(ctx, cfg), a.managedNFQHistoryCurrent(ctx), control.Current(ctx)); err != nil {
		a.writeManagedNFQBundleFailure(w, err, "final_bookend")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "receipt": receipt, "installed_idle": installed["installed_idle"], "compatibility_ready": ready, "working_routes_changed": false})
}

func (a *App) recoverManagedNFQBundle(w http.ResponseWriter, ctx context.Context, observed components.ManagedUpdateState, action string, revision uint64) {
	if a.managedNFQBundleConfigured() != nil {
		a.writeManagedNFQBundleFailure(w, components.ErrRecoveryAuthority, "configuration")
		return
	}
	cfg := a.Store.Get()
	if cfg.Revision != revision {
		a.writeManagedNFQBundleFailure(w, components.ErrRecoveryAuthority, "config")
		return
	}
	control, err := a.managedNFQControl(ctx)
	defer a.closeUnretainedManagedNFQControl(control)
	if err != nil {
		a.writeManagedNFQBundleFailure(w, err, "control")
		return
	}
	// Recovery never initializes a missing source or changes the saved epoch.
	inactive, err := a.StrategyLab.ReviewManagedCompatibilityInactive(ctx, control)
	if err != nil {
		a.writeManagedNFQBundleFailure(w, err, "source_inactive")
		return
	}
	defer inactive.Close()
	authority := a.managedNFQAuthority(cfg, control, inactive)
	receipt, err := a.Components.RecoverManagedBundle(ctx, observed.TransactionID, action, authority)
	if err != nil {
		a.writeManagedNFQBundleFailure(w, err, "bundle_recovery")
		return
	}
	if receipt.TransactionID == "" {
		if err := errors.Join(a.managedNFQConfigCurrent(ctx, cfg), a.managedNFQHistoryCurrent(ctx), control.Current(ctx)); err != nil {
			a.writeManagedNFQBundleFailure(w, err, "final_bookend")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "installed_idle": false, "compatibility_ready": false, "recovery_required": false, "working_routes_changed": false})
		return
	}
	a.writeManagedNFQBundleSuccess(w, ctx, cfg, control, inactive, receipt)
}
