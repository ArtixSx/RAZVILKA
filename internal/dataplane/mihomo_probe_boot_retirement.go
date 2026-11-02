package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

var ErrMihomoProbeRetirement = errors.New("offline Mihomo probe retirement requires intact old-boot intent and fresh absence")

const mihomoRetirementDetail = "Finite probe interrupted; old-boot process is gone and the private listener is absent. Service and original cleanup remain unverified."

type mihomoProbeRetirement struct {
	Schema   int                  `json:"schema"`
	Before   []byte               `json:"before"`
	After    []byte               `json:"after"`
	Observed netidentity.Identity `json:"observed"`
	SameBoot bool                 `json:"same_boot,omitempty"`
}

// RetireMihomoProbeAfterBoot is file-only, explicit offline maintenance. The
// caller must continuously hold every existing private-restore lifetime lease
// before opening workers/API. It never adopts, signals or restarts a process.
// The old intent is archived verbatim; a failed probe never becomes evidence.
func (m *Manager) RetireMihomoProbeAfterBoot(ctx context.Context, planID, digest string, offlineCurrent func(context.Context) error) (Execution, error) {
	provider := netidentity.NewProcProvider()
	return m.retireMihomoProbeAfterBoot(ctx, planID, digest, offlineCurrent, func(c context.Context, old netidentity.Identity, port int) (netidentity.Identity, error) {
		current, err := provider.Observe(c)
		if err != nil || current.BootID == old.BootID {
			return netidentity.Identity{}, ErrMihomoProbeRetirement
		}
		return current, observeMihomoProbeListenerAbsent(c, provider, current, port)
	}, nil)
}

func decodeMihomoRetirementExecution(raw []byte) (Execution, error) {
	var e Execution
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if len(raw) > 4<<20 || d.Decode(&e) != nil || d.Decode(new(any)) != io.EOF || nfqws2ManagedUniqueJSON(raw) != nil {
		return e, ErrMihomoProbeRetirement
	}
	canonical, err := json.Marshal(e)
	if err != nil || !bytes.Equal(raw, canonical) || validateExecutionResources(e, false) != nil || len(e.Resources) != 1 || e.Resources[0].MihomoProbe == nil || len(e.Steps) != 1 || e.Steps[0].Adapter != "mihomo" || e.Steps[0].Phase != "health" || e.RollbackVerified || !strings.HasPrefix(e.PlanID, "dp-check-") || !validExecutionPlanID(e.PlanID) {
		return e, ErrMihomoProbeRetirement
	}
	definition := e.Resources[0].MihomoProbe
	plan := mihomoProbePlan(*definition)
	if e.ResourcePlanID != plan.PlanID || e.Digest != plan.Digest || definition.PlanID != plan.PlanID || definition.PlanDigest != plan.Digest {
		return e, ErrMihomoProbeRetirement
	}
	if _, err := time.Parse(time.RFC3339Nano, e.StartedAt); err != nil {
		return e, ErrMihomoProbeRetirement
	}
	return e, nil
}

func mihomoRetirementTerminal(before Execution, finished string) (Execution, error) {
	return mihomoRetirementTerminalDetail(before, finished, mihomoRetirementDetail)
}

func mihomoRetirementTerminalDetail(before Execution, finished, detail string) (Execution, error) {
	if before.State != "checking" && before.State != "resource-failed" && before.State != "journal-failed" && before.State != "cancelled" {
		return Execution{}, ErrMihomoProbeRetirement
	}
	if _, err := time.Parse(time.RFC3339Nano, finished); err != nil {
		return Execution{}, ErrMihomoProbeRetirement
	}
	after := before
	after.Resources = cloneExecutionResources(before.Resources)
	after.Resources[0].State, after.Resources[0].Phase = "removed", "removed"
	after.Steps = append([]ExecutionStep(nil), before.Steps...)
	after.Steps[0].State, after.Steps[0].FinishedAt, after.Steps[0].Detail = "failed", finished, detail
	after.State, after.FinishedAt, after.Error = "temporary-complete", finished, detail
	return after, validateExecutionResources(after, true)
}

func (m *Manager) retireMihomoProbeAfterBoot(ctx context.Context, id, digest string, offlineCurrent func(context.Context) error,
	absent func(context.Context, netidentity.Identity, int) (netidentity.Identity, error), fault func(string) error) (result Execution, resultErr error) {
	if absent == nil {
		return result, ErrMihomoProbeRetirement
	}
	return m.retireMihomoProbeMetadata(ctx, id, digest, offlineCurrent, func(c context.Context, d ExecutionMihomoProbeDefinition) (netidentity.Identity, error) {
		return absent(c, d.NetworkIdentity, d.Source.SOCKSPort)
	}, false, fault)
}

func (m *Manager) retireMihomoProbeMetadata(ctx context.Context, id, digest string, offlineCurrent func(context.Context) error, absent func(context.Context, ExecutionMihomoProbeDefinition) (netidentity.Identity, error), sameBoot bool, fault func(string) error) (result Execution, resultErr error) {
	if m == nil || xraySelectedTCPFinite(ctx) != nil || !validExecutionPlanID(id) || !strings.HasPrefix(id, "dp-check-") || !validPlanDigest(digest) || offlineCurrent == nil || absent == nil {
		return result, ErrMihomoProbeRetirement
	}
	if err := m.beginOperation(ctx); err != nil {
		return result, err
	}
	defer m.endOperation()
	if m.retainedNFQOwner() != nil || m.retainedXrayOwner() != nil || m.retainedWGOwner() != nil || m.HasPendingManagedNFQWS() {
		return result, ErrMihomoProbeRetirement
	}
	if a, ok := m.adapter("mihomo"); ok {
		if probe, valid := a.(*MihomoProbeAdapter); !valid || probe.Pending() {
			return result, ErrMihomoProbeRetirement
		}
	}
	state, err := openBootRetirementRoot(m.StateRoot)
	if err != nil {
		return result, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, state.Close())
		if resultErr != nil {
			result = Execution{}
		}
	}()
	transactions, err := openRetirementChild(state, "transactions")
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, transactions.Close()) }()
	transaction, err := openRetirementChild(transactions, id)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, transaction.Close()) }()
	archive := filepath.Join("mihomo-probe-retirements", id)
	manifestName := filepath.Join(archive, "retirement.json")
	var manifest mihomoProbeRetirement
	raw, readErr := bootRetirementRead(state, manifestName)
	exists := !errors.Is(readErr, os.ErrNotExist)
	if exists {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if readErr != nil || len(raw) > 12<<20 || decoder.Decode(&manifest) != nil || decoder.Decode(new(any)) != io.EOF {
			return result, ErrMihomoProbeRetirement
		}
		canonical, _ := json.Marshal(manifest)
		if !bytes.Equal(canonical, raw) || manifest.Schema != 1 || manifest.Observed.Validate() != nil {
			return result, ErrMihomoProbeRetirement
		}
	} else {
		manifest.Before, err = bootRetirementRead(state, "latest-execution.json")
		if err != nil {
			return result, err
		}
		other, err := bootRetirementRead(transaction, "execution.json")
		if err != nil || !bytes.Equal(manifest.Before, other) {
			return result, ErrMihomoProbeRetirement
		}
		manifest.Schema = 1
		manifest.SameBoot = sameBoot
	}
	before, err := decodeMihomoRetirementExecution(manifest.Before)
	if err != nil || before.PlanID != id || before.Digest != digest {
		return result, ErrMihomoProbeRetirement
	}
	definition := before.Resources[0].MihomoProbe
	if (sameBoot || manifest.SameBoot) && definition.Source.ParentOrigin.Validate() != nil {
		return result, ErrMihomoProbeRetirement
	}
	finished := time.Now().UTC().Format(time.RFC3339Nano)
	if exists {
		parsed, err := decodeMihomoRetirementExecution(manifest.After)
		if err != nil {
			return result, err
		}
		finished = parsed.FinishedAt
	}
	detail := mihomoRetirementDetail
	if manifest.SameBoot {
		detail = mihomoColdRetirementDetail
	}
	after, err := mihomoRetirementTerminalDetail(before, finished, detail)
	if err != nil {
		return result, err
	}
	expectedAfter, _ := json.Marshal(after)
	if exists && !bytes.Equal(manifest.After, expectedAfter) {
		return result, ErrMihomoProbeRetirement
	}
	manifest.After = expectedAfter
	rootCurrent := func() error {
		path, err := os.Lstat(m.StateRoot)
		held, heldErr := state.Stat(".")
		if err != nil || heldErr != nil || !os.SameFile(path, held) || !path.IsDir() || path.Mode()&os.ModeSymlink != 0 {
			return ErrMihomoProbeRetirement
		}
		return errors.Join(checkRetirementChild(state, "transactions", transactions), checkRetirementChild(transactions, id, transaction), offlineCurrent(ctx), ctx.Err())
	}
	var runIdentity netidentity.Identity
	observe := func() error {
		if err := rootCurrent(); err != nil {
			return err
		}
		current, err := absent(ctx, *definition)
		if err != nil || current.Validate() != nil || (current.BootID == definition.NetworkIdentity.BootID) != sameBoot {
			return ErrMihomoProbeRetirement
		}
		if runIdentity.Validate() == nil && current != runIdentity {
			return ErrMihomoProbeRetirement
		}
		runIdentity = current
		if !exists {
			manifest.Observed = current
		}
		return rootCurrent()
	}
	// Every resumed operation binds a fresh identity and repeats actual absence.
	// A second reboot does not replay the earlier observation as authority.
	if err := observe(); err != nil {
		return result, err
	}
	if !exists {
		if err := mkdirBootRetirement(state, archive); err != nil {
			return result, err
		}
		raw, _ = json.Marshal(manifest)
		if err := writeBootRetirementAtomic(state, manifestName, raw, rootCurrent); err != nil {
			return result, err
		}
		exists = true
		if fault != nil {
			if err := fault("manifest"); err != nil {
				return result, err
			}
		}
	}
	checkManifest, closeManifest, err := pinBootRetirementFile(state, manifestName, raw)
	if err != nil {
		return result, err
	}
	defer closeManifest()
	paths := []struct {
		root *os.Root
		name string
	}{{transaction, "execution.json"}, {state, "latest-execution.json"}}
	checks := make([]func() error, 2)
	closes := make([]func(), 2)
	images := make([][]byte, 2)
	defer func() {
		for _, close := range closes {
			if close != nil {
				close()
			}
		}
	}()
	for i, path := range paths {
		images[i], err = bootRetirementRead(path.root, path.name)
		if err != nil || !bytes.Equal(images[i], manifest.Before) && !bytes.Equal(images[i], manifest.After) {
			return result, ErrMihomoProbeRetirement
		}
		checks[i], closes[i], err = pinBootRetirementFile(path.root, path.name, images[i])
		if err != nil {
			return result, err
		}
	}
	current := func() error {
		if err := rootCurrent(); err != nil {
			return err
		}
		return errors.Join(checkManifest(), checks[0](), checks[1](), ctx.Err())
	}
	for i, path := range paths {
		if bytes.Equal(images[i], manifest.After) {
			continue
		}
		if err := errors.Join(current(), observe()); err != nil {
			return result, err
		}
		if err := writeBootRetirementAtomic(path.root, path.name, manifest.After, current); err != nil {
			return result, err
		}
		closes[i]()
		closes[i] = nil
		checks[i], closes[i], err = pinBootRetirementFile(path.root, path.name, manifest.After)
		if err != nil {
			return result, err
		}
		images[i] = manifest.After
		if fault != nil {
			if err := fault(path.name); err != nil {
				return result, err
			}
		}
	}
	if err := errors.Join(observe(), current()); err != nil {
		return result, err
	}
	beforeDefinition, _ := json.Marshal(definition)
	afterDefinition, _ := json.Marshal(after.Resources[0].MihomoProbe)
	if !bytes.Equal(beforeDefinition, afterDefinition) {
		return result, ErrMihomoProbeRetirement
	}
	return after, nil
}
