package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

type mihomoColdManifest struct {
	Schema   int                      `json:"schema"`
	Before   []byte                   `json:"before"`
	After    []byte                   `json:"after"`
	Plans    map[string][]byte        `json:"plans"`
	Runtime  mihomoColdRuntimeArchive `json:"runtime"`
	Observed netidentity.Identity     `json:"observed"`
}

// This is explicit offline maintenance, before workers or HTTP startup. The
// caller continuously holds the existing private-restore application lifetime
// leases. This lane performs no process or packet mutation and never restores
// an old owner from a journal. Same-boot teardown has a separate native issuer.
func (m *Manager) RetireMihomoLiveAfterBoot(ctx context.Context, id, digest string, offlineCurrent func(context.Context) error) (Execution, error) {
	if m == nil {
		return Execution{}, ErrMihomoLiveRetirement
	}
	registered, ok := m.adapter("mihomo")
	a, typed := registered.(*MihomoProbeAdapter)
	if !ok || !typed || a == nil {
		return Execution{}, ErrMihomoLiveRetirement
	}
	proxy, err := a.originalLiveProxy(m)
	if err != nil {
		return Execution{}, err
	}
	proof, err := proxyInactivePlatformProof()
	if err != nil {
		return Execution{}, err
	}
	return m.retireMihomoLiveMetadata(ctx, id, digest, proxy, offlineCurrent, func(c context.Context, d ExecutionMihomoLiveDefinition) (netidentity.Identity, error) {
		identity, err := observeMihomoLiveColdProcesses(c, a.provider, d, m.StateRoot)
		if err != nil || identity.BootID == d.NetworkIdentity.BootID {
			return netidentity.Identity{}, errors.Join(ErrMihomoLiveRetirement, err)
		}
		if err := observeBootRetirement(c, proxy, proof); err != nil {
			return netidentity.Identity{}, err
		}
		closing, err := observeMihomoLiveColdProcesses(c, a.provider, d, m.StateRoot)
		if err != nil || closing != identity {
			return netidentity.Identity{}, errors.Join(ErrMihomoLiveRetirement, err)
		}
		return identity, nil
	}, nil)
}

// Private fixture seam supplies negative observations only. Production above
// always uses the actual original provider and complete native inventories.
func (m *Manager) retireMihomoLiveMetadata(ctx context.Context, id, digest string, a *ProxyTunnelAdapter, offlineCurrent func(context.Context) error, absent func(context.Context, ExecutionMihomoLiveDefinition) (netidentity.Identity, error), fault func(string) error) (result Execution, resultErr error) {
	if m == nil || a == nil || a.ID() != "mihomo" || a.StateRoot != filepath.Join(m.StateRoot, "mihomo") || !validPlanID(id) || !validPlanDigest(digest) || offlineCurrent == nil || absent == nil || xraySelectedTCPFinite(ctx) != nil {
		return result, ErrMihomoLiveRetirement
	}
	if err := m.beginOperation(ctx); err != nil {
		return result, err
	}
	defer m.endOperation()
	if m.retainedNFQOwner() != nil || m.retainedXrayOwner() != nil || m.retainedWGOwner() != nil || m.HasPendingManagedNFQWS() || m.HasPendingMihomoLive() || m.originalMihomoLive() != nil {
		return result, ErrMihomoLiveRetirement
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
	archiveName := filepath.Join("mihomo-live-retirements", id)
	manifestPath := filepath.Join(archiveName, "retirement.json")
	raw, readErr := readMihomoColdFile(state, manifestPath)
	exists := !errors.Is(readErr, os.ErrNotExist)
	var manifest mihomoColdManifest
	if exists {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if readErr != nil || nfqws2ManagedUniqueJSON(raw) != nil || decoder.Decode(&manifest) != nil || decoder.Decode(new(any)) != io.EOF || manifest.Schema != 1 || manifest.Observed.Validate() != nil {
			return result, ErrMihomoLiveRetirement
		}
	} else {
		manifest.Schema = 1
		manifest.Before, err = readMihomoColdFile(state, "latest-execution.json")
		if err != nil {
			return result, err
		}
		other, err := readMihomoColdFile(transaction, "execution.json")
		if err != nil || !bytes.Equal(manifest.Before, other) {
			return result, ErrMihomoLiveRetirement
		}
		manifest.Plans = map[string][]byte{}
		for _, name := range mihomoStoppedPlanNames {
			data, err := readMihomoColdFile(state, name)
			if errors.Is(err, os.ErrNotExist) && name == "latest-committed-plan.json" {
				continue
			}
			if err != nil {
				return result, err
			}
			manifest.Plans[name] = data
		}
		manifest.Runtime, err = readMihomoColdRuntime(state, "mihomo", a)
		if err != nil {
			return result, err
		}
	}
	before, d, err := decodeMihomoLiveRetirementIntent(manifest.Before)
	if err != nil || before.PlanID != id || before.Digest != digest {
		return result, ErrMihomoLiveRetirement
	}
	if err := validateMihomoColdRuntime(a, d, manifest.Runtime); err != nil {
		return result, err
	}
	if err := validateMihomoColdPlans(d.Plan, manifest.Plans); err != nil {
		return result, err
	}
	finished := time.Now().UTC().Format(time.RFC3339Nano)
	if exists {
		var saved Execution
		if json.Unmarshal(manifest.After, &saved) != nil {
			return result, ErrMihomoLiveRetirement
		}
		finished = saved.FinishedAt
	}
	after, err := mihomoLiveRetirementTerminal(before, finished)
	if err != nil {
		return result, err
	}
	afterRaw, err := json.Marshal(after)
	if err != nil {
		return result, err
	}
	if exists && !bytes.Equal(afterRaw, manifest.After) {
		return result, ErrMihomoLiveRetirement
	}
	manifest.After = afterRaw
	rootCurrent := func() error {
		info, e1 := os.Lstat(m.StateRoot)
		held, e2 := state.Stat(".")
		if e1 != nil || e2 != nil || !networkPolicyPrivateDirectory(info) || !executionHistoryOwner(info, true) || !os.SameFile(info, held) {
			return ErrMihomoLiveRetirement
		}
		return errors.Join(checkMihomoColdDirectory(state, "transactions", transactions), checkMihomoColdDirectory(transactions, id, transaction), offlineCurrent(ctx), ctx.Err())
	}
	var runIdentity netidentity.Identity
	observe := func() error {
		if err := rootCurrent(); err != nil {
			return err
		}
		identity, err := absent(ctx, d)
		if err != nil || identity.Validate() != nil || identity.BootID == d.NetworkIdentity.BootID || runIdentity.Validate() == nil && identity != runIdentity {
			return errors.Join(ErrMihomoLiveRetirement, err)
		}
		runIdentity = identity
		if !exists {
			manifest.Observed = identity
		}
		return rootCurrent()
	}
	if err := observe(); err != nil {
		return result, err
	}
	if err := mkdirBootRetirement(state, archiveName); err != nil {
		return result, err
	}
	archive, err := openRetirementChild(state, archiveName)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, archive.Close()) }()
	records := []*mihomoColdRecord{}
	defer func() {
		for _, r := range records {
			resultErr = errors.Join(resultErr, r.file.Close())
		}
	}()
	for _, item := range []struct {
		root *os.Root
		name string
	}{{transaction, "execution.json"}, {state, "latest-execution.json"}} {
		data, err := readMihomoColdFile(item.root, item.name)
		if err != nil || !bytes.Equal(data, manifest.Before) && !bytes.Equal(data, manifest.After) {
			return result, ErrMihomoLiveRetirement
		}
		r, err := openMihomoColdRecord(item.root, item.name, data)
		if err != nil {
			return result, err
		}
		records = append(records, r)
	}
	for _, name := range mihomoStoppedPlanNames {
		data, found := manifest.Plans[name]
		if !found {
			if _, err := state.Lstat(name); !errors.Is(err, os.ErrNotExist) {
				return result, ErrMihomoLiveRetirement
			}
			continue
		}
		r, err := openMihomoColdRecord(state, name, data)
		if err != nil {
			return result, err
		}
		records = append(records, r)
	}
	current := func() error {
		if err := errors.Join(rootCurrent(), checkMihomoColdDirectory(state, archiveName, archive)); err != nil {
			return err
		}
		for _, r := range records {
			if err := r.current(); err != nil {
				return err
			}
		}
		if err := checkMihomoColdRuntimePair(state, archive, a, manifest.Runtime); err != nil {
			return err
		}
		if _, found := manifest.Plans["latest-committed-plan.json"]; !found {
			if _, err := state.Lstat("latest-committed-plan.json"); !errors.Is(err, os.ErrNotExist) {
				return ErrMihomoLiveRetirement
			}
		}
		return nil
	}
	if !exists {
		dir, err := archive.Open(".")
		if err != nil {
			return result, err
		}
		entries, readErr := dir.ReadDir(2)
		closeErr := dir.Close()
		if readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil || len(entries) != 0 {
			return result, ErrMihomoLiveRetirement
		}
		raw, err = json.Marshal(manifest)
		if err != nil || len(raw) > bootRetirementLimit {
			return result, ErrMihomoLiveRetirement
		}
		file, err := writeMihomoColdRetained(archive, "retirement.json", raw, current)
		if file != nil {
			err = errors.Join(err, file.Close(), syncBootRetirementDirectory(archive, "."))
		}
		if err != nil {
			return result, err
		}
		exists = true
		if fault != nil {
			if err := fault("manifest"); err != nil {
				return result, err
			}
		}
	}
	witness, err := openMihomoColdRecord(archive, "retirement.json", raw)
	if err != nil {
		return result, err
	}
	records = append(records, witness)
	if err := errors.Join(current(), observe()); err != nil {
		return result, err
	}
	if err := moveMihomoColdRuntime(state, archive, a, manifest.Runtime, current, fault); err != nil {
		return result, err
	}
	for i := range 2 {
		if bytes.Equal(records[i].data, manifest.After) {
			continue
		}
		if err := errors.Join(current(), observe()); err != nil {
			return result, err
		}
		if err := records[i].publish(manifest.After, current); err != nil {
			return result, err
		}
		if fault != nil {
			if err := fault(records[i].name); err != nil {
				return result, err
			}
		}
	}
	if err := errors.Join(current(), observe()); err != nil {
		return result, err
	}
	completed := mihomoColdCompletion(raw)
	completedRaw, readErr := readMihomoColdFile(archive, "completed.json")
	if errors.Is(readErr, os.ErrNotExist) {
		file, err := writeMihomoColdRetained(archive, "completed.json", completed, current)
		if file != nil {
			err = errors.Join(err, file.Close(), syncBootRetirementDirectory(archive, "."))
		}
		if err != nil {
			return result, err
		}
	} else if readErr != nil || !bytes.Equal(completedRaw, completed) {
		return result, ErrMihomoLiveRetirement
	}
	if fault != nil {
		if err := fault("completed"); err != nil {
			return result, err
		}
	}
	if err := errors.Join(current(), observe()); err != nil {
		return result, err
	}
	return after, nil
}

func checkMihomoColdDirectory(parent *os.Root, name string, child *os.Root) error {
	if err := checkRetirementChild(parent, name, child); err != nil {
		return err
	}
	named, err := parent.Lstat(name)
	held, heldErr := child.Stat(".")
	if err != nil || heldErr != nil || !networkPolicyPrivateDirectory(named) || !networkPolicyPrivateDirectory(held) || !executionHistoryOwner(named, true) || !executionHistoryOwner(held, true) {
		return ErrMihomoLiveRetirement
	}
	return nil
}

func validateMihomoColdPlans(expected Plan, plans map[string][]byte) error {
	if len(plans) < 1 || len(plans) > 2 || len(plans["latest-plan.json"]) == 0 {
		return ErrMihomoLiveRetirement
	}
	for name, raw := range plans {
		if name != "latest-plan.json" && name != "latest-committed-plan.json" {
			return ErrMihomoLiveRetirement
		}
		var p Plan
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if nfqws2ManagedUniqueJSON(raw) != nil || decoder.Decode(&p) != nil || decoder.Decode(new(any)) != io.EOF {
			return ErrMihomoLiveRetirement
		}
		if name == "latest-committed-plan.json" && p.Noop && len(p.Routes) == 0 && p.State == "committed" {
			continue
		}
		p.State, p.ObservedEvidence, p.Note, p.EvidenceNote = expected.State, expected.ObservedEvidence, expected.Note, expected.EvidenceNote
		if len(p.RouteEvidence) != len(expected.RouteEvidence) {
			return ErrMihomoLiveRetirement
		}
		for i := range p.RouteEvidence {
			p.RouteEvidence[i].Observed, p.RouteEvidence[i].Source, p.RouteEvidence[i].Note = expected.RouteEvidence[i].Observed, expected.RouteEvidence[i].Source, expected.RouteEvidence[i].Note
		}
		left, e1 := json.Marshal(p)
		right, e2 := json.Marshal(expected)
		if e1 != nil || e2 != nil || !bytes.Equal(left, right) {
			return ErrMihomoLiveRetirement
		}
	}
	return nil
}
