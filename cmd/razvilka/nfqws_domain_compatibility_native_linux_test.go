//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/strategylab"
)

// No queue, scope, App/dataplane, installation, network probe or owner callback.
// TestMain dispatches the actual production compatibility supervisor. An
// explicit opt-in runs genuine no-intercept payloads from an accepted bundle.
func TestManagedNFQDomainCompatibilityInstalled(t *testing.T) {
	if os.Getenv("RAZVILKA_NATIVE_NFQ_DOMAIN_COMPAT") != "1" {
		t.Skip("set RAZVILKA_NATIVE_NFQ_DOMAIN_COMPAT=1 only in coordinator-owned root ARM64 environment with an accepted installed bundle")
	}
	if os.Geteuid() != 0 || runtime.GOARCH != "arm64" {
		t.Fatal("stage=preflight code=root_arm64_required")
	}
	root, stateRoot := os.Getenv("RAZVILKA_NATIVE_NFQ_DOMAIN_ROOT"), os.Getenv("RAZVILKA_COMPONENT_STATE")
	for _, path := range []string{root, stateRoot} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			t.Fatal("stage=preflight code=explicit_canonical_roots_required")
		}
	}
	if root == stateRoot || strings.HasPrefix(root, stateRoot+"/") || strings.HasPrefix(stateRoot, root+"/") {
		t.Fatal("stage=preflight code=independent_roots_required")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&077 != 0 {
		t.Fatal("stage=preflight code=private_real_root_required")
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatal("stage=preflight code=new_empty_root_required")
	}
	body, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	gate := &operationgate.Gate{}
	ctx, release, err := gate.ExclusiveContext(body)
	if err != nil {
		t.Fatal("stage=admission code=exclusive_admission_refused")
	}
	defer release()
	files, err := productionSelfUpdateFiles()
	if err != nil {
		t.Fatal("stage=control code=production_configuration_required")
	}
	// Existing production writer only. This fixture does not initialize/restart
	// control and cannot manufacture an unstopped installation epoch.
	control, err := gate.ReviewControlEpoch(ctx, files.ControlRoot)
	if err != nil {
		t.Fatal("stage=control code=existing_unstopped_control_required")
	}
	defer control.Close()
	owner := components.New()
	owner.StateDir = stateRoot
	bootstrap, err := owner.AcquireCurrentManagedNFQWSRuntime(ctx)
	if err != nil {
		t.Fatal("stage=source code=genuine_installer_receipt_required")
	}
	var completion *strategylab.ManagedCompatibilityCompletion
	var material *strategylab.NFQWSDomainMaterial
	var source *strategylab.SelectedCandidateReview
	var sourceRuntime, validationRuntime *components.ManagedNFQWSRuntimeLease
	// Original owner stays alive indefinitely if its native Join is unknown.
	// Never use go test -timeout or an external timeout to force this test out.
	defer retainManagedListRetirement(func(cleanup context.Context) error {
		if completion != nil {
			if err := completion.RetireKnown(cleanup); err != nil {
				return err
			}
			completion = nil
		}
		if material != nil {
			if err := material.Close(); errors.Is(err, strategylab.ErrCompatibilityQuiescenceUnknown) {
				if err := material.RetireCompatibility(cleanup); err != nil {
					return err
				}
				if err := material.Close(); err != nil {
					return err
				}
			} else if err != nil {
				return err
			}
			material = nil
		}
		if source != nil {
			if err := source.Close(); err != nil {
				return err
			}
			source = nil
		}
		for _, lease := range []*components.ManagedNFQWSRuntimeLease{validationRuntime, sourceRuntime, bootstrap} {
			if lease != nil {
				if err := lease.Close(); err != nil {
					return err
				}
			}
		}
		return nil
	})
	manager, err := strategylab.New(filepath.Join(root, "strategy.json"))
	if err != nil {
		t.Fatal("stage=source code=manager_unavailable")
	}
	_, validator, err := strategylab.NewManagedSupervisedCompatibilityProvider(ctx, manager, bootstrap, control, files.ControlRoot)
	if err != nil {
		t.Fatal("stage=source code=managed_provider_refused")
	}
	manager.Validator, manager.Executor = validator, nil
	candidate, err := manager.AddCandidate("tcp-tls", "native domain compatibility source", "--filter-tcp=443 --lua-desync=fake:blob=tls_clienthello", "expert")
	if err != nil {
		t.Fatal("stage=source code=candidate_refused")
	}
	checked, completed, validationErr := manager.ValidateManagedCandidate(ctx, candidate.ID, bootstrap)
	completion = completed
	if completion == nil {
		t.Fatal("stage=source code=original_completion_missing")
	}
	if err := completion.RetireKnown(ctx); err != nil {
		t.Fatal("stage=source code=original_completion_retained_unknown")
	}
	completion = nil
	bootstrap = nil // RetireKnown closed precisely this original lease.
	if validationErr != nil || !checked.Validation.OK || !checked.Validation.Native || !checked.Validation.LuaChecked || checked.Validation.QuiescenceUnknown {
		t.Fatal("stage=source code=genuine_native_compatibility_refused")
	}
	sourceRuntime, err = owner.AcquireCurrentManagedNFQWSRuntime(ctx)
	if err != nil {
		t.Fatal("stage=source code=retained_runtime_required")
	}
	const service = "native-domain-compatibility"
	if _, err := manager.SelectManual(ctx, service, "tcp", "ipv4", candidate.ID, sourceRuntime); err != nil {
		t.Fatal("stage=source code=actual_manual_selection_refused")
	}
	source, err = manager.RetainSelectedCandidateReview(ctx, service, "tcp", "ipv4", sourceRuntime)
	if err != nil {
		t.Fatal("stage=source code=original_selected_review_refused")
	}
	before, err := os.ReadFile(manager.Path)
	if err != nil {
		t.Fatal("stage=source code=source_image_unavailable")
	}
	defer func() {
		after, err := os.ReadFile(manager.Path)
		if err != nil || !bytes.Equal(before, after) {
			t.Error("stage=source code=domain_validation_changed_original_source")
		}
	}()
	// A second independent acquisition must remain excluded by the original
	// writer. A supported owner-issued validation branch is required instead.
	second, secondErr := owner.AcquireCurrentManagedNFQWSRuntime(ctx)
	if secondErr == nil || second != nil {
		if second != nil {
			_ = second.Close()
		}
		t.Fatal("stage=domain_lease code=second_independent_writer_acquisition_must_refuse")
	}
	if err := source.ManagedOwnersCurrent(ctx, sourceRuntime, control); err != nil {
		t.Fatal("stage=domain_lease code=failed_second_acquire_changed_original_source")
	}
	if bad, err := strategylab.ReviewManagedNFQWSDomainMaterial(ctx, source, sourceRuntime, control, []string{"video.example"}, nil); err == nil || bad != nil {
		material = bad // Even a regression must not abandon a returned owner.
		t.Fatal("stage=domain_lease code=source_lease_cannot_be_validation_lease")
	}
	validationRuntime, err = sourceRuntime.ForkValidation(ctx)
	if err != nil {
		t.Fatal("stage=domain_lease code=original_owner_validation_branch_required")
	}
	if !errors.Is(sourceRuntime.Close(), components.ErrManagedNFQWSValidationPending) || source.ManagedOwnersCurrent(ctx, sourceRuntime, control) != nil || validationRuntime.Check(ctx) != nil {
		t.Fatal("stage=domain_lease code=live_child_must_retain_unchanged_original_owner")
	}
	if bad, err := strategylab.ReviewManagedNFQWSDomainMaterial(ctx, source, validationRuntime, control, nil, nil); err == nil || bad != nil {
		material = bad
		t.Fatal("stage=domain_constructor code=empty_include_must_refuse_before_native_start")
	}
	material, err = strategylab.ReviewManagedNFQWSDomainMaterial(ctx, source, validationRuntime, control, []string{"video.example"}, []string{"private.video.example"})
	if err != nil {
		t.Fatal("stage=domain_constructor code=genuine_domain_compatibility_refused; original cleanup remains retained")
	}
	if material == nil || material.Current(ctx) != nil || source.ManagedOwnersCurrent(ctx, sourceRuntime, control) != nil {
		t.Fatal("stage=domain_constructor code=original_material_or_source_not_current")
	}
	_, command, err := material.Command(ctx)
	if err != nil {
		t.Fatal("stage=domain_command code=final_command_unavailable")
	}
	var include, exclude string
	for _, arg := range command {
		if path, ok := strings.CutPrefix(arg, "--hostlist="); ok {
			include = path
		}
		if path, ok := strings.CutPrefix(arg, "--hostlist-exclude="); ok {
			exclude = path
		}
	}
	if include == "" || exclude == "" || filepath.Dir(include) != filepath.Dir(exclude) {
		t.Fatal("stage=domain_command code=both_original_lists_required")
	}
	childPath := filepath.Dir(include) + "-compat/strategy.json"
	child, err := os.ReadFile(childPath)
	if err != nil {
		t.Fatal("stage=domain_receipt code=actual_child_receipt_required")
	}
	assertNFQDomainNativeReceipt(t, child, command)
	// Same-byte replacement must revoke the retained receipt's authority.
	if err := os.Rename(childPath, childPath+".original"); err != nil {
		t.Fatal("stage=domain_receipt code=receipt_replacement_unavailable")
	}
	if err := os.WriteFile(childPath, child, 0600); err != nil {
		t.Fatal("stage=domain_receipt code=receipt_replacement_write_failed")
	}
	if material.Current(ctx) == nil || source.ManagedOwnersCurrent(ctx, sourceRuntime, control) != nil {
		t.Fatal("stage=domain_receipt code=receipt_replacement_adopted_or_original_source_lost")
	}
	t.Log("genuine domain dry-run/Lua final argv, original source preservation and same-byte receipt substitution refusal passed; compatibility only, no domain Apply or packet claim")
}

func assertNFQDomainNativeReceipt(t *testing.T, data []byte, command []string) {
	t.Helper()
	type phase struct {
		Command struct {
			Args []string `json:"args"`
		} `json:"command"`
		Receipt struct {
			Started      bool `json:"started"`
			WaitECHILD   bool `json:"wait_echild"`
			DirectReaped bool `json:"direct_reaped"`
			ExitCode     int  `json:"exit_code"`
			Cancelled    bool `json:"cancelled"`
		} `json:"receipt"`
		Acknowledged bool `json:"acknowledged"`
	}
	var state struct {
		Session struct {
			DryRun  *phase `json:"dry_run"`
			LuaInit *phase `json:"lua_init"`
			Unknown bool   `json:"unknown"`
		} `json:"compatibility_session"`
	}
	if json.Unmarshal(data, &state) != nil || state.Session.Unknown {
		t.Fatal("stage=domain_receipt code=invalid_actual_session")
	}
	for i, p := range []*phase{state.Session.DryRun, state.Session.LuaInit} {
		if p == nil || !p.Acknowledged || !p.Receipt.Started || !p.Receipt.WaitECHILD || !p.Receipt.DirectReaped || p.Receipt.ExitCode != 0 || p.Receipt.Cancelled {
			t.Fatal("stage=domain_receipt code=actual_terminal_ack_required")
		}
		args := p.Command.Args
		if i == 0 {
			if len(args) < 2 || args[0] != "--dry-run" || args[1] != "--intercept=0" || !slices.Equal(args[2:], command) {
				t.Fatal("stage=domain_receipt code=dry_run_final_argv_differs")
			}
		} else if len(args) < 2 || args[0] != "--intercept=0" || !strings.HasPrefix(args[len(args)-1], "--lua-init=") || !slices.Equal(args[1:len(args)-1], command) {
			t.Fatal("stage=domain_receipt code=lua_final_argv_differs")
		}
	}
}
