package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// NFQWS2OfflineStopEvidence is comparison data retained by the explicit Stop
// journal, never absence or permission to mutate a process. Only the original
// startup source can produce a current observation of it.
type NFQWS2OfflineStopEvidence struct {
	Binding      string                 `json:"binding"`
	RuntimeRoot  string                 `json:"runtime_root"`
	RuntimeOwner string                 `json:"runtime_owner"`
	Network      netidentity.Identity   `json:"network"`
	Instance     string                 `json:"instance"`
	Lease        []byte                 `json:"lease"`
	StoppedLease []byte                 `json:"stopped_lease"`
	Files        []restorejournal.Image `json:"files"`
	FileOwners   []string               `json:"file_owners"`
}

// NFQWS2OfflineStopPlanScope is a closed legacy first-start scope. It does not
// grant authority over a lease, process, settings or kernel objects.
func NFQWS2OfflineStopPlanScope(p Plan) bool {
	if p.SchemaVersion != SchemaVersion || !validPlanID(p.PlanID) || !validPlanDigest(p.Digest) || p.State != "committed" || !p.Ready || p.SafeMode || p.Noop ||
		!slices.Equal(p.Adapters, []string{"nfqws2"}) || len(p.RetiringAdapters) != 0 || p.LAN != nil || p.DNS != nil || p.DomainPolicy != nil || p.SyntheticDNS != nil ||
		p.SuspendDNS || p.DiscardDNS || p.NetworkProfileID != "" || len(p.Routes) == 0 || p.RouteCount != len(p.Routes) {
		return false
	}
	for _, route := range p.Routes {
		if route.Resolved != "nfqws2" || route.NetworkPolicyGeneration != "" || route.NetworkPolicyRole != "" || route.WireGuardProfileRevision != "" || len(route.Sources) != 0 || len(route.CIDRs) != 0 || len(route.Domains) == 0 {
			return false
		}
	}
	return true
}

// InspectNFQWS2OfflineStop binds the FULL retained plan to the actual original
// first-start lease and tool/layout source. It deliberately does not certify
// that the daemon stopped; VerifyNFQWS2Inactive is required after Deactivate.
func (r *RuntimeInactivitySourceReview) InspectNFQWS2OfflineStop(ctx context.Context, plan Plan) (NFQWS2OfflineStopEvidence, error) {
	return r.inspectNFQWS2OfflineStop(ctx, plan, r.CheckCurrent)
}

func (r *RuntimeInactivitySourceReview) inspectNFQWS2OfflineStop(ctx context.Context, plan Plan, current func(context.Context) error) (NFQWS2OfflineStopEvidence, error) {
	fail := func(err error) (NFQWS2OfflineStopEvidence, error) {
		return NFQWS2OfflineStopEvidence{}, errors.Join(ErrRuntimeInactivity, err)
	}
	if r == nil || current == nil || !NFQWS2OfflineStopPlanScope(plan) {
		return fail(nil)
	}
	if err := current(ctx); err != nil {
		return fail(err)
	}
	a := r.nfq
	transaction, ok := a.firstStartTransaction(plan)
	if !ok {
		return fail(nil)
	}
	before, err := a.firstStartHookFiles(transaction)
	if err != nil {
		return fail(err)
	}
	fileOwners, err := r.offlineStopFileOwners(transaction)
	if err != nil {
		return fail(err)
	}
	lease, err := a.verifyOwnedLists(false)
	if err != nil || lease == nil || lease.FirstStart == nil || lease.FirstStart.Process == nil || lease.Transaction != transaction ||
		lease.FirstStart.Phase != nfqws2FirstRunning && lease.FirstStart.Phase != nfqws2FirstStopped {
		return fail(err)
	}
	config, exists, err := nfqws2Read(a.ConfigPath)
	if err != nil || !exists {
		return fail(err)
	}
	expected, err := a.firstStartConfig(plan, config)
	if err != nil || !bytes.Equal(expected, config) {
		return fail(err)
	}
	// The staged transaction remains a second binding to the full frozen plan.
	staged, exists, err := nfqws2Read(filepath.Join(transaction, "nfqws2.conf.staged"))
	if err != nil || !exists || !bytes.Equal(staged, config) {
		return fail(err)
	}
	init, exists, err := nfqws2Read(filepath.Join(transaction, "S51nfqws2.staged"))
	if err != nil || !exists || nfqws2Hash(init) != lease.InitHash {
		return fail(err)
	}
	info, err := os.Lstat(a.StateRoot)
	if err != nil {
		return fail(err)
	}
	owner, err := offlineStopDirectoryIdentity(info)
	if err != nil {
		return fail(err)
	}
	raw, exists, err := nfqws2Read(filepath.Join(a.StateRoot, nfqws2LeaseFile))
	canonical, marshalErr := json.Marshal(lease)
	if err != nil || marshalErr != nil || !exists || !bytes.Equal(raw, canonical) {
		return fail(errors.Join(err, marshalErr))
	}
	stopped := *lease
	first := *lease.FirstStart
	first.Phase = nfqws2FirstStopped
	stopped.FirstStart = &first
	stoppedRaw, err := json.Marshal(stopped)
	if err != nil {
		return fail(err)
	}
	binding, err := json.Marshal(struct {
		Root, Settings, State, Config, Init, IPTables, IP6Tables, ToolReview string
		Lists                                                                [4]string
		Kind                                                                 netidentity.Kind
		Platform                                                             string
	}{r.root, r.settings, a.StateRoot, a.ConfigPath, a.InitPath, r.source.frozen.reader.IPTables, r.source.frozen.reader.IP6Tables, r.source.frozen.review, a.ownedListPaths(), r.source.identity.Kind, r.source.identity.PlatformReviewSHA256})
	if err != nil {
		return fail(err)
	}
	after, err := a.firstStartHookFiles(transaction)
	closingOwners, ownersErr := r.offlineStopFileOwners(transaction)
	closing, statErr := os.Lstat(a.StateRoot)
	if err != nil || statErr != nil || ownersErr != nil || !slices.Equal(fileOwners, closingOwners) || !os.SameFile(info, closing) || !reflect.DeepEqual(before, after) {
		return fail(errors.Join(err, statErr))
	}
	if err := current(ctx); err != nil {
		return fail(err)
	}
	files := make([]restorejournal.Image, len(after))
	for i, file := range after {
		files[i] = restorejournal.Image{Exists: file.exists, Data: slices.Clone(file.data)}
	}
	return NFQWS2OfflineStopEvidence{Binding: nfqws2Hash(binding), RuntimeRoot: a.StateRoot, RuntimeOwner: owner, Network: r.source.identity, Instance: nfqws2HookInstance(lease), Lease: raw, StoppedLease: stoppedRaw, Files: files, FileOwners: fileOwners}, nil
}

// Matches compares identities and exact lease images. A fresh, originally
// bound source in a later boot may observe the same stopped generation; no
// previous-boot absence result is reused. The caller still performs the full
// fresh absence check before publishing any metadata.
func (e NFQWS2OfflineStopEvidence) Matches(original NFQWS2OfflineStopEvidence, stopped bool) bool {
	if e.Binding == "" || e.Binding != original.Binding || e.RuntimeRoot != original.RuntimeRoot || e.RuntimeOwner != original.RuntimeOwner || e.Instance == "" || e.Instance != original.Instance ||
		e.Network.Validate() != nil || original.Network.Validate() != nil || e.Network.Kind != original.Network.Kind || e.Network.PlatformReviewSHA256 != original.Network.PlatformReviewSHA256 ||
		e.Network.BootID == original.Network.BootID && e.Network != original.Network || !bytes.Equal(e.StoppedLease, original.StoppedLease) || len(e.Files) != 11 || len(original.Files) != 11 || len(e.FileOwners) != 11 || len(original.FileOwners) != 11 {
		return false
	}
	for i, image := range e.Files {
		if i == 0 { // The only lease mutation is the recorded stopped phase.
			if !image.Exists || !bytes.Equal(image.Data, e.Lease) || e.FileOwners[i] == "" || bytes.Equal(e.Lease, original.Lease) && e.FileOwners[i] != original.FileOwners[i] {
				return false
			}
			continue
		}
		if i == 2 || i == 4 { // Original .run and PID may disappear during Stop.
			if !image.Exists && len(image.Data) == 0 && e.FileOwners[i] == "" {
				continue
			}
			if stopped {
				return false
			}
		}
		if !emptyStopImageEqual(image, original.Files[i]) || e.FileOwners[i] != original.FileOwners[i] || image.Exists && e.FileOwners[i] == "" {
			return false
		}
	}
	if stopped {
		return bytes.Equal(e.Lease, original.StoppedLease)
	}
	return bytes.Equal(e.Lease, original.Lease) || bytes.Equal(e.Lease, original.StoppedLease)
}

func (r *RuntimeInactivitySourceReview) offlineStopFileOwners(transaction string) ([]string, error) {
	a := r.nfq
	lists := a.ownedListPaths()
	paths := []string{filepath.Join(a.StateRoot, nfqws2LeaseFile), a.ConfigPath, a.ConfigPath + ".run", a.InitPath, a.firstStartPIDPath(),
		filepath.Join(transaction, "nfqws2.conf.staged"), filepath.Join(transaction, "S51nfqws2.staged"), lists[0], lists[1], lists[2], lists[3]}
	owners := make([]string, len(paths))
	for i, path := range paths {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		protected := r.source.platform.protected != nil && r.source.platform.protected(info, false, i == 0)
		if i >= 7 && r.source.platform.foreignList != nil {
			protected = r.source.platform.foreignList(info)
		}
		if !protected {
			return nil, ErrReviewChanged
		}
		owners[i], err = offlineStopNativeFileIdentity(info)
		if err != nil {
			return nil, err
		}
	}
	return owners, nil
}

// VerifyNFQWS2OfflineStopRetry reads the actual original command's pending WAL.
// It is only a retry admission for the original Deactivate, never settlement.
// A killed owned_stop may already have removed its .run/PID while the lease is
// still running, or have written stopped before removing those files. Only
// that exact recorded generation and disappearance of its files are accepted.
// Every process, queue and kernel source is read anew before admission.
func (r *RuntimeInactivitySourceReview) VerifyNFQWS2OfflineStopRetry(ctx context.Context) error {
	return r.verifyNFQWS2OfflineStopRetry(ctx, r.CheckCurrent)
}

func (r *RuntimeInactivitySourceReview) verifyNFQWS2OfflineStopRetry(ctx context.Context, checkCurrent func(context.Context) error) error {
	if r == nil || checkCurrent == nil || !nfqws2InactiveFinite(ctx) {
		return ErrRuntimeInactivity
	}
	if err := checkCurrent(ctx); err != nil {
		return err
	}
	guard, _ := ctx.Value(reviewGuardKey{}).(func(context.Context) error)
	if guard == nil {
		return ErrReviewChanged
	}
	root, err := ownedfs.Open(r.root)
	if err != nil {
		return err
	}
	defer root.Close()
	info, err := root.RootInfo()
	if err != nil {
		return err
	}
	owner, err := offlineStopDirectoryIdentity(info)
	if err != nil {
		return err
	}
	raw, err := readOfflineNFQWS2StopIntent(root)
	intent, parseErr := DecodeNFQWS2OfflineStopIntent(raw)
	if err != nil || parseErr != nil || intent.State != "pending" || intent.StateRoot != r.root || intent.DNSPath != r.settings || intent.StateOwner != owner {
		return errors.Join(ErrReviewChanged, err, parseErr)
	}
	if err := guard(ctx); err != nil {
		return err
	}
	current, err := r.inspectNFQWS2OfflineStop(ctx, intent.Plan, checkCurrent)
	if err != nil || !current.Matches(intent.Source, false) {
		return errors.Join(ErrReviewChanged, err)
	}
	plan, found, err := r.manager.Committed()
	if err != nil || !found || !reflect.DeepEqual(plan, intent.Plan) {
		return ErrReviewChanged
	}
	if err := r.nfq.firstStartRuntimeAbsent(ctx); err != nil {
		return err
	}
	closing, err := r.inspectNFQWS2OfflineStop(ctx, intent.Plan, checkCurrent)
	after, readErr := readOfflineNFQWS2StopIntent(root)
	pathInfo, statErr := os.Lstat(r.root)
	if err != nil || readErr != nil || statErr != nil || !reflect.DeepEqual(current, closing) || !bytes.Equal(raw, after) || !os.SameFile(info, pathInfo) {
		return ErrReviewChanged
	}
	if err := guard(ctx); err != nil {
		return err
	}
	return checkCurrent(ctx)
}

func readOfflineNFQWS2StopIntent(root *ownedfs.Root) ([]byte, error) {
	file, err := offlineStopOpenFile(root, NFQWS2OfflineStopJournalName)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !offlineStopPrivateFile(info) {
		return nil, ErrReviewChanged
	}
	raw, err := io.ReadAll(io.LimitReader(file, NFQWS2OfflineStopJournalLimit+1))
	if err != nil || len(raw) > NFQWS2OfflineStopJournalLimit {
		return nil, ErrReviewChanged
	}
	return raw, nil
}
