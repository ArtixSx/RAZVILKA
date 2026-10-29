package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

var errVerifiedRollbackBoot = errors.New("verified rollback boot review is unavailable or changed")
var retryBootPlanID = regexp.MustCompile(`^dp-[a-f0-9]{16}$`)
var retryBootDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)

type verifiedRollbackBootImage struct {
	files    map[string][]byte
	previous dataplane.Plan
}

// Recovery Safe Mode may be left by an earlier failed boot. A verified explicit
// rollback leaves that flag in place; requiring it OFF before restoring the
// committed runtime would deadlock every later boot. This path only reviews the
// same applied intent behind a complete unchanged successful retry certificate.
// It does not clear the flag. The actual Manager recovery/health must still pass
// before settleRecoverySafeMode retires it.
func bootRecoveryGuardForManager(cfgPath string, store *config.Store, manager *dataplane.Manager) (func(dataplane.Plan) error, error) {
	if store == nil {
		return nil, errVerifiedRollbackBoot
	}
	if !store.Get().SafeMode {
		return bootRecoveryGuard(cfgPath, store)
	}
	if manager == nil {
		return nil, errVerifiedRollbackBoot
	}
	original := store.Get()
	baseline, err := os.ReadFile(cfgPath)
	if err != nil {
		return nil, err
	}
	image, err := readVerifiedRollbackBootImage(manager.StateRoot)
	if err != nil {
		return nil, err
	}
	return func(committed dataplane.Plan) error {
		cfg := store.Get()
		if !reflect.DeepEqual(cfg, original) || !cfg.SafeMode || len(cfg.ServiceControl.SuspendedServices) != 0 || len(cfg.ServiceControl.SuspendedRoutes) != 0 || !reflect.DeepEqual(committed, image.previous) ||
			!closeRollbackSettingsMatch(cfg, committed) || !dataplane.PlanHonoursLegacyExclusions(cfg, committed) {
			return errVerifiedRollbackBoot
		}
		observation, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		return store.WithResourceExclusionObservation(observation, cfg, func(config.EffectiveExclusionSet) error {
			current, err := os.ReadFile(cfgPath)
			if err != nil || !bytes.Equal(current, baseline) {
				return errVerifiedRollbackBoot
			}
			closing, err := readVerifiedRollbackBootImage(manager.StateRoot)
			if err != nil || !reflect.DeepEqual(image, closing) {
				return errVerifiedRollbackBoot
			}
			return nil
		})
	}, nil
}

func readVerifiedRollbackBootImage(root string) (verifiedRollbackBootImage, error) {
	fail := func() (verifiedRollbackBootImage, error) { return verifiedRollbackBootImage{}, errVerifiedRollbackBoot }
	owned, err := ownedfs.Open(root)
	if err != nil {
		return fail()
	}
	defer owned.Close()
	image := verifiedRollbackBootImage{files: map[string][]byte{}}
	read := func(name string, target any) bool {
		raw, err := owned.ReadLimited(name, 4<<20)
		if err != nil || json.Unmarshal(raw, target) != nil {
			return false
		}
		image.files[name] = raw
		return true
	}
	var latest, previous dataplane.Plan
	var execution, transaction dataplane.Execution
	if !read("latest-plan.json", &latest) || !read("latest-committed-plan.json", &previous) || !read("latest-execution.json", &execution) {
		return fail()
	}
	if !retryBootPlanID.MatchString(latest.PlanID) || !retryBootDigest.MatchString(latest.Digest) || latest.PlanID != "dp-"+latest.Digest[:16] ||
		latest.SchemaVersion != dataplane.SchemaVersion || latest.State != "rolled-back" || latest.SafeMode || latest.Noop ||
		execution.PlanID != latest.PlanID || execution.Digest != latest.Digest || execution.State != "rolled-back" || !execution.RollbackVerified ||
		previous.SchemaVersion != dataplane.SchemaVersion || previous.State != "committed" || !previous.Ready || previous.SafeMode || previous.Noop ||
		previous.PlanID == latest.PlanID || !retryBootPlanID.MatchString(previous.PlanID) || !retryBootDigest.MatchString(previous.Digest) || previous.PlanID != "dp-"+previous.Digest[:16] {
		return fail()
	}
	name := filepath.ToSlash(filepath.Join("transactions", latest.PlanID, "execution.json"))
	if !read(name, &transaction) || !reflect.DeepEqual(execution, transaction) || !bytes.Equal(image.files["latest-execution.json"], image.files[name]) {
		return fail()
	}
	// Require the complete successful LAST explicit retry batch; rolled-back
	// alone and a historical retry hidden before a later failure are no grant.
	n := len(latest.Adapters)
	if n == 0 || n > 4 || len(execution.Steps) < 2*n {
		return fail()
	}
	seen := map[string]bool{}
	tail := execution.Steps[len(execution.Steps)-2*n:]
	finished, err := time.Parse(time.RFC3339Nano, execution.FinishedAt)
	if err != nil {
		return fail()
	}
	for i, adapter := range latest.Adapters {
		if seen[adapter] || adapter != "nfqws2" && adapter != "sing-box" && adapter != "xray" {
			return fail()
		}
		seen[adapter] = true
		pairs := []struct {
			step  dataplane.ExecutionStep
			phase string
		}{{tail[n-1-i], "retry-rollback"}, {tail[n+i], "retry-verify-rollback"}}
		for _, pair := range pairs {
			start, e1 := time.Parse(time.RFC3339Nano, pair.step.StartedAt)
			end, e2 := time.Parse(time.RFC3339Nano, pair.step.FinishedAt)
			if pair.step.Adapter != adapter || pair.step.Phase != pair.phase || pair.step.State != "passed" || e1 != nil || e2 != nil || end.Before(start) || end.After(finished) {
				return fail()
			}
		}
	}
	image.previous = previous
	return image, nil
}
