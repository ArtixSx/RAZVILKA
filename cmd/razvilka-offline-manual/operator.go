package main

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"slices"

	"github.com/ArtixSx/razvilka/internal/app"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/installpath"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/privaterestore"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

type paths struct {
	installation, configDir, state, executable, init, pid, proc string
}

func productionPaths() paths {
	return paths{"/opt", installpath.Config, installpath.State, "/opt/bin/razvilka", "/opt/etc/init.d/S99razvilka", installpath.Run + "/razvilka.pid", "/proc"}
}

type incident struct {
	source, binarySHA, initSHA, failedID, failedDigest, failedPlanSHA string
	priorID, priorDigest, priorPlanSHA, snapshotSHA                   string
}

func productionIncident() incident {
	return incident{
		source:    "079e8b338d3adc4397614423956f0a86322537f2",
		binarySHA: "030c9b185c1c313be609c9fb15d27c5c11ae9a96c724ac06285de0d669dd58ba",
		initSHA:   "8278cf7be9fe9772d6976fd090960afae163024062814bfcdd0e522693ad91b2",
		failedID:  "dp-b6535e11d748d4da", failedDigest: "b6535e11d748d4da59f88405f56171bc3e60bcf6d88f538824153a4e9bdfc80e",
		failedPlanSHA: "b3b9fdad006ea15a912597b1dd0e75f7c4e5bd0841b3198c42102931d8828923",
		priorID:       "dp-8a922548e1a21fb9", priorDigest: "8a922548e1a21fb9f308daf294de1fe53bab280953bae2a456ffc5f419f16c02",
		priorPlanSHA: "e5d9bcff29bf2779ea21c4796dc7ea33f8119a27a5d19daaa9c1e4ac64edbc29",
		snapshotSHA:  "91588c3e445b93e0b1273c63b626e78db8dbba6253ba2685786c791c1bac3983",
	}
}

type result struct {
	Kind              string `json:"kind"`
	Schema            int    `json:"schema"`
	ToolSource        string `json:"tool_source"`
	InstalledSource   string `json:"installed_source"`
	Outcome           string `json:"outcome"`
	Stage             string `json:"stage"`
	PanelState        string `json:"panel_state"`
	BeforeRevision    uint64 `json:"before_revision,omitempty"`
	AfterRevision     uint64 `json:"after_revision,omitempty"`
	ConfigSHA256      string `json:"config_sha256,omitempty"`
	ManualSaved       bool   `json:"automatic_service_apply_paused"`
	PreservedEvidence bool   `json:"preserved_evidence"`
	Note              string `json:"note"`
}

func newResult() result {
	return result{Kind: "razvilka-offline-manual", Schema: 1, ToolSource: sourceCommit,
		InstalledSource: productionIncident().source, Outcome: "refused-before-write", PanelState: "not-observed",
		Note: "This tool never starts the panel. Manual mode pauses automatic service Apply, not all maintenance. Service reachability is not checked."}
}

var errRefused = errors.New("offline manual transition refused; retain current state")

// Paths, pins and the private crash seam are supplied only by compiled code or
// package tests. The CLI accepts no path, environment or incident overrides.
func runOperator(ctx context.Context, p paths, pins incident, beforeWrite func()) (out result, resultErr error) {
	out = newResult()
	out.InstalledSource = pins.source
	out.Stage = "context"
	if ctx == nil || ctx.Err() != nil {
		return out, errRefused
	}
	if _, finite := ctx.Deadline(); !finite {
		return out, errRefused
	}
	wrote := false
	defer func() {
		if resultErr != nil {
			out.ManualSaved, out.PreservedEvidence = false, false
			out.ConfigSHA256 = ""
			if wrote {
				out.Outcome = "write-uncertain"
			}
		}
	}()
	out.Stage = "panel-and-paths"
	if err := checkOperatorPaths(p); err != nil {
		return out, err
	}
	if err := panelAbsent(ctx, p); err != nil {
		return out, err
	}
	out.PanelState = "stopped-confirmed-before-write"
	out.Stage = "independent-recovery"
	if err := independentFences(ctx, p); err != nil {
		return out, err
	}
	out.Stage = "private-lifetime-leases"
	leases, err := openLeases(ctx, p)
	if err != nil {
		return out, err
	}
	defer func() {
		for i := len(leases) - 1; i >= 0; i-- {
			if err := leases[i].Close(); err != nil {
				out.Stage = "private-lifetime-close"
				resultErr = errors.Join(resultErr, err)
			}
		}
	}()
	out.Stage = "preserved-images"
	images, err := captureImages(ctx, p, pins)
	if err != nil {
		return out, err
	}
	defer func() {
		if err := images.close(); err != nil {
			out.Stage = "image-close"
			resultErr = errors.Join(resultErr, err)
		}
	}()
	configPath := filepath.Join(p.configDir, "config.json")
	// Each generation is revalidated under its ORIGINAL lifetime lease. The
	// innermost callback never acquires a competing Store-file lease around Save.
	var underLeases func(int) error
	underLeases = func(i int) error {
		if i < len(leases) {
			return leases[i].WithOfflineServiceControl(ctx, configPath, func(c context.Context) error {
				if c != ctx {
					return errRefused
				}
				return underLeases(i + 1)
			})
		}
		out.Stage = "strict-existing-config"
		store, err := config.LoadExistingStrict(ctx, configPath)
		if err != nil {
			return err
		}
		binding, err := store.OwnerBinding(ctx)
		wanted, wantedErr := config.RestoreBinding(configPath)
		if err != nil || wantedErr != nil || binding != wanted {
			return errRefused
		}
		before := store.Get()
		out.BeforeRevision = before.Revision
		out.Stage = "exact-recovered-incident"
		if err := checkIncident(ctx, p, pins, before); err != nil {
			return err
		}
		out.Stage = "source-closing-before-write"
		if beforeWrite != nil {
			beforeWrite()
		}
		if err := independentFences(ctx, p); err != nil {
			return err
		}
		if err := images.check(ctx); err != nil {
			return err
		}
		if err := panelAbsent(ctx, p); err != nil {
			return err
		}
		if err := store.CheckStrictImage(); err != nil {
			return err
		}
		if before.ServiceControl.Mode != "manual" {
			out.Stage = "save-manual"
			manual := "manual"
			wrote = true // Any unproved failure from this point remains uncertain.
			if err := store.UpdateServiceControl(&manual, nil, before.Revision); err != nil {
				return err
			}
		}
		after := store.Get()
		wantedConfig := before
		if wrote {
			wantedConfig.ServiceControl.Mode = "manual"
			wantedConfig.Revision++
		}
		out.Stage = "complete-config-readback"
		if !reflect.DeepEqual(after, wantedConfig) || after.ServiceControl.Mode != "manual" {
			return errRefused
		}
		if err := store.CheckStrictImage(); err != nil {
			return err
		}
		out.Stage = "preservation-readback"
		if err := images.check(ctx); err != nil {
			return err
		}
		if err := independentFences(ctx, p); err != nil {
			return err
		}
		if err := checkIncident(ctx, p, pins, after); err != nil {
			return err
		}
		if err := panelAbsent(ctx, p); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		out.ConfigSHA256, err = store.StrictImageSHA256()
		if err != nil {
			return err
		}
		out.AfterRevision = after.Revision
		out.ManualSaved, out.PreservedEvidence = true, true
		out.PanelState = "stopped-confirmed-after-write"
		out.Outcome = "already-manual-panel-left-stopped"
		if wrote {
			out.Outcome = "saved-manual-panel-left-stopped"
		}
		out.Stage = "completed"
		return nil
	}
	resultErr = underLeases(0)
	return out, resultErr
}

func layouts(p paths) []privaterestore.Layout {
	base := privaterestore.Layout{Config: filepath.Join(p.configDir, "config.json"), CustomServices: filepath.Join(p.configDir, "custom-services.json"), Devices: filepath.Join(p.configDir, "devices.json"), StageRoot: filepath.Join(p.state, "staging"), ProviderRoot: filepath.Join(p.configDir, "cloudflare-private")}
	var result []privaterestore.Layout
	for i, name := range []string{"private-restore", "private-restore-nodes-v1", "private-restore-native-v1", "private-restore-feeds-v1"} {
		base.JournalRoot = filepath.Join(p.configDir, name)
		if i >= 1 {
			base.NodeRoot = filepath.Join(p.configDir, "nodes-private")
		}
		if i >= 2 {
			base.WarpRoot = filepath.Join(p.state, "warp")
		}
		if i >= 3 {
			base.FeedRoot = filepath.Join(p.configDir, "subscriptions-private")
		}
		result = append(result, base)
	}
	return result
}

func openLeases(ctx context.Context, p paths) ([]*privaterestore.Coordinator, error) {
	var result []*privaterestore.Coordinator
	for _, layout := range layouts(p) {
		c, err := privaterestore.OpenForOfflineServiceControl(ctx, layout)
		if err != nil {
			for i := len(result) - 1; i >= 0; i-- {
				err = errors.Join(err, result[i].Close())
			}
			return nil, err
		}
		result = append(result, c)
	}
	return result, nil
}

func independentFences(ctx context.Context, p paths) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	dp := filepath.Join(p.state, "dataplane")
	if err := app.CheckOfflineNFQWS2Stop(dp); err != nil {
		return err
	}
	if err := app.CheckNFQWS2HookRecovery(dp); err != nil {
		return err
	}
	m := dataplane.New(dp)
	if err := m.CheckNFQWS2BootHookRecovery(); err != nil {
		return err
	}
	if err := m.CheckExecutionRecovery(ctx); err != nil {
		return err
	}
	helperDir, filesDir := filepath.Join(p.state, "self-update"), filepath.Join(p.state, "self-update-files")
	required, err := updatecheck.RequiredSelfUpdateJournalReadVersion(ctx, p.installation, helperDir, filesDir)
	if err != nil || required < 1 || required > updatecheck.SelfUpdateReadVersion {
		return errRefused
	}
	helper := updatecheck.NewUpdater("0.20.0-rc.106", p.state, updatecheck.Deployment{})
	f := &app.SelfUpdateFiles{Installation: p.installation, Directory: filesDir, ControlRoot: filepath.Join(p.state, "self-update-stop"), Helper: helper}
	if p == productionPaths() {
		f.Adapter = updatecheck.NewSelfUpdateFileAdapter(func(c context.Context, id string) (bool, error) {
			r, present, err := operationgate.ReadSelfUpdateStop(c, f.ControlRoot)
			if err != nil {
				return false, err
			}
			if !present {
				return false, operationgate.ErrSelfUpdateStopJournal
			}
			if r.Stopped && r.TransactionID != id {
				return false, operationgate.ErrSelfUpdateStopChanged
			}
			return r.Stopped, nil
		})
	}
	if f.Pending() {
		return errRefused
	}
	cm := &components.Manager{StateDir: filepath.Join(p.state, "components")}
	if _, pending, err := cm.PendingManagedUpdate(); err != nil || pending {
		return errRefused
	}
	return ctx.Err()
}

func checkIncident(ctx context.Context, p paths, pins incident, cfg config.Config) error {
	m := dataplane.New(filepath.Join(p.state, "dataplane"))
	if err := m.CheckExecutionRecovery(ctx); err != nil {
		return err
	}
	s, err := m.Status()
	if err != nil || s.Plan == nil || s.CommittedPlan == nil || s.Execution == nil {
		return errRefused
	}
	e, prior := s.Execution, s.CommittedPlan
	if s.Plan.PlanID != pins.failedID || s.Plan.Digest != pins.failedDigest || e.PlanID != pins.failedID || e.Digest != pins.failedDigest || e.State != "rolled-back" || !e.RollbackVerified || len(e.Steps) != 9 {
		return errRefused
	}
	for i, phase := range []string{"retry-rollback", "retry-verify-rollback"} {
		step := e.Steps[7+i]
		if step.Adapter != "nfqws2" || step.Phase != phase || step.State != "passed" || step.FinishedAt == "" {
			return errRefused
		}
	}
	if prior.PlanID != pins.priorID || prior.Digest != pins.priorDigest || prior.State != "committed" || prior.Revision != 11 || !slices.Equal(prior.Adapters, []string{"nfqws2"}) || len(prior.RetiringAdapters) != 0 || prior.LAN != nil || prior.DNS != nil || prior.DomainPolicy != nil || prior.SyntheticDNS != nil || prior.SuspendDNS || prior.DiscardDNS || prior.RouteCount != 3 || len(prior.Routes) != 3 {
		return errRefused
	}
	if cfg.SafeMode || cfg.ServiceControl.Stopped || cfg.AppliedRevision != 11 || cfg.Revision < 12 || cfg.Revision == ^uint64(0) || len(cfg.AppliedServices) != 3 || cfg.AppliedNFQWSFirstStartRecipe != prior.NFQWSFirstStartRecipe {
		return errRefused
	}
	expected := map[string]bool{"nfqws2-common": true, "roblox": true, "youtube": true}
	for _, route := range prior.Routes {
		state, found := cfg.AppliedServices[route.ServiceID]
		if !expected[route.ServiceID] || !found || !state.Enabled || route.Resolved != "nfqws2" || state.Route != "nfqws2" || state.Mode != "nfqws2" || state.WireGuardProfileRevision != "" || !slices.Equal(state.Sources, route.Sources) {
			return errRefused
		}
		delete(expected, route.ServiceID)
	}
	if len(expected) != 0 {
		return errRefused
	}
	a := dataplane.NewNFQWS2Adapter()
	a.StateRoot = filepath.Join(m.StateRoot, "runtime", "nfqws2")
	a.ConfigPath = filepath.Join(p.installation, "etc/nfqws2/nfqws2.conf")
	a.InitPath = filepath.Join(p.installation, "etc/init.d/S51nfqws2")
	a.UserListPath = filepath.Join(p.installation, "etc/nfqws2/lists/user.list")
	a.IPSetListPath = filepath.Join(p.installation, "etc/nfqws2/lists/ipset.list")
	if err := a.CheckOfflineServiceControl(ctx, *prior); err != nil {
		return err
	}
	return ctx.Err()
}
