package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/privaterestore"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

var ErrOfflineNFQWS2Stop = errors.New("explicit NFQWS2 Stop is unfinished or changed: keep the panel stopped and repeat the installed CLI -stop-owned-routes with the original paths; preserve all journals on refusal")

type OfflineNFQWS2StopResult struct {
	Stopped  bool   `json:"stopped"`
	PlanID   string `json:"plan_id,omitempty"`
	Revision uint64 `json:"revision,omitempty"`
}

// Private model seams replace native observations only in package tests. The
// exported installed-command path always constructs these from the actual
// Manager's original opaque source association and existing Hook Stop review.
type offlineNFQStopNative struct {
	inspect     func(context.Context, dataplane.Plan) (dataplane.NFQWS2OfflineStopEvidence, error)
	inactive    func(context.Context) error
	retry       func(context.Context) error
	hooks       func(context.Context, time.Time) (func() error, func() error, func(), error)
	publication func(context.Context, dataplane.Plan, dataplane.Plan, map[string]restorejournal.Image) (dataplane.OfflineNFQWS2StopPublication, error)
	complete    func(context.Context, dataplane.Plan, dataplane.Plan, map[string]restorejournal.Image, dataplane.OfflineNFQWS2StopPublication) error
	checkpoint  func(string) error
	syncRoot    func(*ownedfs.Root) error
}

// StopOwnedNFQWS2Routes is separate from updater/uninstall quiescence. It must
// retain an actual offline private-recovery lifetime lease; HTTP/runtime
// handover revokes admission to this entry point. No automatic Resume occurs.
func StopOwnedNFQWS2Routes(ctx context.Context, lease *privaterestore.Coordinator, m *dataplane.Manager, store *config.Store, configPath, dnsPath string) (OfflineNFQWS2StopResult, error) {
	var result OfflineNFQWS2StopResult
	if lease == nil || m == nil || store == nil {
		return result, ErrOfflineNFQWS2Stop
	}
	err := lease.WithOfflineNFQWS2Stop(ctx, configPath, func(c context.Context) error {
		source, err := m.ReviewRuntimeInactivitySources(c, dnsPath)
		if err != nil {
			return err
		}
		native := offlineNFQStopNative{
			inspect: source.InspectNFQWS2OfflineStop, inactive: source.VerifyNFQWS2Inactive, retry: source.VerifyNFQWS2OfflineStopRetry,
			hooks: func(c context.Context, at time.Time) (func() error, func() error, func(), error) {
				boot, closeBoot, err := m.ReviewNFQWS2BootHookStop(c, dnsPath)
				if err != nil {
					return nil, nil, nil, err
				}
				application, closeApp, err := reviewNFQWS2AppHookStopAt(c, m, dnsPath, at)
				if err != nil {
					closeBoot()
					return nil, nil, nil, err
				}
				return application, boot, func() { closeApp(); closeBoot() }, nil
			},
			publication: func(c context.Context, prior, target dataplane.Plan, original map[string]restorejournal.Image) (dataplane.OfflineNFQWS2StopPublication, error) {
				return m.ReviewNFQWS2EmptyStopPublication(c, source, prior, target, original)
			},
			complete: func(c context.Context, prior, target dataplane.Plan, original map[string]restorejournal.Image, publication dataplane.OfflineNFQWS2StopPublication) error {
				return m.CompleteNFQWS2EmptyStopPublication(c, source, prior, target, original, publication)
			},
		}
		result, err = runOfflineNFQWS2Stop(c, m, store, configPath, dnsPath, native)
		return err
	})
	if err != nil {
		return OfflineNFQWS2StopResult{}, errors.Join(ErrOfflineNFQWS2Stop, err)
	}
	return result, nil
}

// CheckOfflineNFQWS2Stop is bounded/read-only. A pending or malformed document
// blocks normal startup and every existing mutation/update dispatch. The only
// recovery is another explicit offline invocation holding its lifetime leases.
func CheckOfflineNFQWS2Stop(path string) error {
	root, err := openNFQWS2HookJournal(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.Join(ErrOfflineNFQWS2Stop, err)
	}
	defer root.Close()
	image, err := readOfflineNFQImage(root, dataplane.NFQWS2OfflineStopJournalName, dataplane.NFQWS2OfflineStopJournalLimit)
	if err != nil {
		return errors.Join(ErrOfflineNFQWS2Stop, err)
	}
	if !image.Exists {
		return nil
	}
	intent, err := dataplane.DecodeNFQWS2OfflineStopIntent(image.Data)
	if err != nil || intent.State != "complete" || intent.StateRoot != path {
		return errors.Join(ErrOfflineNFQWS2Stop, err)
	}
	info, err := root.RootInfo()
	if err != nil {
		return errors.Join(ErrOfflineNFQWS2Stop, err)
	}
	owner, err := offlineNFQDirectoryIdentity(info, true)
	if err != nil || owner != intent.StateOwner {
		return ErrOfflineNFQWS2Stop
	}
	return nil
}

type offlineNFQStopOwner struct {
	root, configRoot *ownedfs.Root
	path, configPath string
	image            restorejournal.Image
	intent           dataplane.NFQWS2OfflineStopIntent
	store            *config.Store
	manager          *dataplane.Manager
	native           offlineNFQStopNative
}

func readOfflineNFQImage(root *ownedfs.Root, name string, limit int64) (restorejournal.Image, error) {
	file, err := offlineNFQOpenFile(root, name)
	if errors.Is(err, os.ErrNotExist) {
		return restorejournal.Image{}, nil
	}
	if err != nil {
		return restorejournal.Image{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || nfqws2HookPrivateOwner(info) != nil {
		return restorejournal.Image{}, ErrOfflineNFQWS2Stop
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return restorejournal.Image{}, ErrOfflineNFQWS2Stop
	}
	return restorejournal.Image{Exists: true, Data: raw}, nil
}

func offlineNFQImageEqual(a, b restorejournal.Image) bool {
	return a.Exists == b.Exists && bytes.Equal(a.Data, b.Data)
}

func offlineNFQConfigEqual(a, b config.Config) bool {
	left, leftErr := json.Marshal(a)
	right, rightErr := json.Marshal(b)
	return leftErr == nil && rightErr == nil && bytes.Equal(left, right)
}

func (o *offlineNFQStopOwner) current(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || o.manager.StateRoot != o.path {
		return dataplane.ErrReviewChanged
	}
	for _, item := range []struct {
		root        *ownedfs.Root
		path, owner string
		private     bool
	}{
		{o.root, o.path, o.intent.StateOwner, true}, {o.configRoot, filepath.Dir(o.configPath), o.intent.ConfigOwner, false},
	} {
		info, err := item.root.RootInfo()
		pathInfo, statErr := os.Lstat(item.path)
		if err != nil || statErr != nil || !os.SameFile(info, pathInfo) {
			return dataplane.ErrReviewChanged
		}
		owner, err := offlineNFQDirectoryIdentity(info, item.private)
		if err != nil || owner != item.owner {
			return dataplane.ErrReviewChanged
		}
	}
	actual, err := readOfflineNFQImage(o.root, dataplane.NFQWS2OfflineStopJournalName, dataplane.NFQWS2OfflineStopJournalLimit)
	if err != nil || !offlineNFQImageEqual(actual, o.image) {
		return dataplane.ErrReviewChanged
	}
	return nil
}

func (o *offlineNFQStopOwner) save(ctx context.Context) error {
	if err := o.current(ctx); err != nil {
		return err
	}
	if err := dataplane.ValidateNFQWS2OfflineStopIntent(o.intent); err != nil {
		return err
	}
	raw, err := json.Marshal(o.intent) // Typed network identity requires compact JSON.
	if err != nil || len(raw) > dataplane.NFQWS2OfflineStopJournalLimit {
		return ErrOfflineNFQWS2Stop
	}
	if err := o.root.WriteAtomic(dataplane.NFQWS2OfflineStopJournalName, raw, 0600); err != nil {
		return err
	}
	if err := o.syncRoot(); err != nil {
		return err
	}
	o.image = restorejournal.Image{Exists: true, Data: raw}
	return o.current(ctx)
}

func (o *offlineNFQStopOwner) syncRoot() error {
	if o.native.syncRoot != nil {
		return o.native.syncRoot(o.root)
	}
	return o.root.Sync()
}

// Reopened pending WAL may be the result of rename followed by a reported
// fsync failure. Re-establish durability of the exact retained image before
// another native/metadata effect, rather than assuming visibility is durable.
func (o *offlineNFQStopOwner) durable(ctx context.Context) error {
	if err := o.current(ctx); err != nil {
		return err
	}
	file, err := offlineNFQOpenFile(o.root, dataplane.NFQWS2OfflineStopJournalName)
	if err != nil {
		return err
	}
	err = errors.Join(file.Sync(), file.Close())
	if err != nil {
		return err
	}
	if err := o.syncRoot(); err != nil {
		return err
	}
	return o.current(ctx)
}

func (o *offlineNFQStopOwner) checkpoint(stage string) error {
	if o.native.checkpoint != nil {
		return o.native.checkpoint(stage)
	}
	return nil
}

func (o *offlineNFQStopOwner) guard(ctx context.Context, inactive, allowStoppedConfig bool) error {
	if err := o.current(ctx); err != nil {
		return err
	}
	if err := o.guardMetadata(ctx, allowStoppedConfig); err != nil {
		return err
	}
	in := o.intent
	observed, err := o.native.inspect(ctx, in.Plan)
	if err != nil || !observed.Matches(in.Source, inactive) {
		return errors.Join(dataplane.ErrReviewChanged, err)
	}
	if inactive {
		if err := o.native.inactive(ctx); err != nil {
			return err
		}
	}
	// Fresh process/kernel reads can take time. Close their observation with
	// the same exact config and metadata images before any subsequent effect
	// or already-completed success is allowed.
	if err := o.guardMetadata(ctx, allowStoppedConfig); err != nil {
		return err
	}
	return o.current(ctx)
}

func (o *offlineNFQStopOwner) guardMetadata(ctx context.Context, allowStoppedConfig bool) error {
	in := o.intent
	cfg := o.store.Get()
	expectedImage := in.BeforeImage
	if !offlineNFQConfigEqual(cfg, in.ConfigBefore) {
		if !allowStoppedConfig || !offlineNFQConfigEqual(cfg, in.ConfigAfter) {
			return config.ErrRevisionChanged
		}
		expectedImage = in.AfterImage
	}
	if err := o.store.WithResourceExclusionObservation(ctx, cfg, func(config.EffectiveExclusionSet) error {
		actual, err := readOfflineNFQImage(o.configRoot, filepath.Base(o.configPath), 1<<20)
		if err != nil || !offlineNFQImageEqual(actual, expectedImage) {
			return config.ErrRevisionChanged
		}
		return nil
	}); err != nil {
		return err
	}
	for name, expected := range in.Original {
		if name == "nfqws2-hooks-recovery.json" || name == "nfqws2-boot-hooks.json" {
			actual, err := readOfflineNFQImage(o.root, name, 1<<20)
			if err != nil || !offlineNFQImageEqual(actual, in.HooksAfter[name]) && (in.State != "pending" || !offlineNFQImageEqual(actual, expected)) {
				return dataplane.ErrReviewChanged
			}
			continue
		}
		if in.State == "applying" || in.State == "complete" {
			if name == "latest-plan.json" || name == "latest-committed-plan.json" || name == "latest-execution.json" {
				continue
			}
		}
		actual, err := readOfflineNFQImage(o.root, name, 1<<20)
		if err != nil || !offlineNFQImageEqual(actual, expected) {
			return dataplane.ErrReviewChanged
		}
	}
	if in.State == "applying" || in.State == "complete" {
		if err := o.manager.ObserveNFQWS2EmptyStopPublication(ctx, in.Plan, in.Target, in.Original, in.Publication); err != nil {
			return err
		}
	}
	return nil
}

func offlineNFQHookTargets(in dataplane.NFQWS2OfflineStopIntent) (map[string]restorejournal.Image, bool, error) {
	after := map[string]restorejournal.Image{}
	pending := false
	application := in.Original[nfqws2HookJournalName]
	after[nfqws2HookJournalName] = application
	if application.Exists {
		var record nfqws2HookJournal
		d := json.NewDecoder(bytes.NewReader(application.Data))
		d.DisallowUnknownFields()
		if d.Decode(&record) != nil || d.Decode(new(any)) != io.EOF {
			return nil, false, ErrNFQWS2HookRecovery
		}
		canonical, _ := json.Marshal(record)
		if !bytes.Equal(canonical, application.Data) || record.Version != 1 || record.Started.IsZero() || record.State != "pending" && record.State != "settled" {
			return nil, false, ErrNFQWS2HookRecovery
		}
		if record.State == "pending" {
			if !reflect.DeepEqual(record.Plan, in.Plan) || record.Instance != in.Source.Instance || in.AppliedAt.Before(record.Started) {
				return nil, false, dataplane.ErrReviewChanged
			}
			record.State, record.Reason, record.Finished = "settled", "verified-settlement", in.AppliedAt
			raw, _ := json.Marshal(record)
			after[nfqws2HookJournalName] = restorejournal.Image{Exists: true, Data: raw}
			pending = true
		}
	}
	boot := in.Original["nfqws2-boot-hooks.json"]
	raw, bootPending, err := dataplane.ReviewedNFQWS2BootHookStopImage(boot.Data, in.Plan, in.Source.Instance)
	if err != nil {
		return nil, false, err
	}
	after["nfqws2-boot-hooks.json"] = restorejournal.Image{Exists: boot.Exists, Data: raw}
	return after, pending || bootPending, nil
}

func (o *offlineNFQStopOwner) begin(ctx context.Context, dnsPath string) error {
	before := o.store.Get()
	status, err := o.manager.Status()
	if err != nil || status.CommittedPlan == nil || status.Execution == nil || status.Execution.State != "committed" || status.Execution.PlanID != status.CommittedPlan.PlanID || status.Execution.Digest != status.CommittedPlan.Digest || o.manager.CheckExecutionRecovery(ctx) != nil {
		return dataplane.ErrExecutionJournal
	}
	plan := *status.CommittedPlan
	if !dataplane.NFQWS2OfflineStopPlanScope(plan) || plan.Revision != before.AppliedRevision || before.ServiceControl.Stopped {
		return dataplane.ErrReviewChanged
	}
	source, err := o.native.inspect(ctx, plan)
	if err != nil {
		return err
	}
	resolved := map[string]string{}
	for _, route := range plan.Routes {
		if _, duplicate := resolved[route.ServiceID]; duplicate {
			return dataplane.ErrReviewChanged
		}
		resolved[route.ServiceID] = route.Resolved
	}
	at := time.Now().UTC()
	after, err := config.ReviewedNFQWS2StopImage(before, resolved, at)
	if err != nil {
		return err
	}
	exclusions, err := dataplane.LegacySiteExclusions(before)
	if err != nil {
		return err
	}
	target, err := dataplane.BuildAt(dataplane.Input{Revision: after.Revision, SiteExclusions: exclusions}, at)
	if err != nil {
		return err
	}
	// A content-derived target ID must not inherit another attempt's files.
	if _, err := o.root.Stat(filepath.Join("transactions", target.PlanID)); !errors.Is(err, os.ErrNotExist) {
		return dataplane.ErrReviewChanged
	}
	configImage, err := readOfflineNFQImage(o.configRoot, filepath.Base(o.configPath), 1<<20)
	if err != nil || !configImage.Exists {
		return config.ErrRevisionChanged
	}
	afterRaw, _ := json.MarshalIndent(after, "", "  ")
	rootInfo, err := o.root.RootInfo()
	if err != nil {
		return err
	}
	configInfo, err := o.configRoot.RootInfo()
	if err != nil {
		return err
	}
	rootOwner, err := offlineNFQDirectoryIdentity(rootInfo, true)
	if err != nil {
		return err
	}
	configOwner, err := offlineNFQDirectoryIdentity(configInfo, false)
	if err != nil {
		return err
	}
	in := dataplane.NFQWS2OfflineStopIntent{Version: 1, State: "pending", StateRoot: o.path, StateOwner: rootOwner, ConfigPath: o.configPath, ConfigOwner: configOwner, DNSPath: dnsPath,
		AppliedAt: at, Plan: plan, Target: target, ConfigBefore: before, ConfigAfter: after, BeforeImage: configImage, AfterImage: restorejournal.Image{Exists: true, Data: afterRaw}, Resolved: resolved, Source: source, Original: map[string]restorejournal.Image{}}
	for _, name := range []string{"latest-plan.json", "latest-committed-plan.json", "latest-execution.json", "latest-recovery.json", nfqws2HookJournalName, "nfqws2-boot-hooks.json", filepath.Join("transactions", plan.PlanID, "execution.json")} {
		image, err := readOfflineNFQImage(o.root, name, 1<<20)
		if err != nil {
			return err
		}
		in.Original[name] = image
	}
	for _, name := range []string{"latest-plan.json", "latest-committed-plan.json"} {
		var actual dataplane.Plan
		if !in.Original[name].Exists || json.Unmarshal(in.Original[name].Data, &actual) != nil || !reflect.DeepEqual(actual, plan) {
			return dataplane.ErrReviewChanged
		}
	}
	in.HooksAfter, _, err = offlineNFQHookTargets(in)
	_, pending, hookErr := offlineNFQHookTargets(in)
	if err != nil || hookErr != nil || !pending {
		return errors.Join(ErrOfflineNFQWS2Stop, err, hookErr)
	}
	// Original admission MUST precede the durable intent. A new request cannot
	// create itself a retry waiver for an already unknown same-boot graph.
	_, _, closeReview, err := o.native.hooks(ctx, at)
	if err != nil {
		return err
	}
	closeReview()
	o.intent = in
	if err := o.guard(ctx, false, false); err != nil {
		return err
	}
	if o.image.Exists {
		// Retain a completed earlier Stop before recording a different explicit
		// generation. Unknown/pending history never reaches this branch.
		sum := sha256.Sum256(o.image.Data)
		if err := o.root.MkdirAll("offline-nfqws2-stop-history", 0700); err != nil {
			return err
		}
		history, err := ownedfs.Open(filepath.Join(o.path, "offline-nfqws2-stop-history"))
		if err != nil {
			return err
		}
		defer history.Close()
		historyInfo, err := history.RootInfo()
		if err != nil {
			return err
		}
		if _, err := offlineNFQDirectoryIdentity(historyInfo, true); err != nil {
			return err
		}
		name := filepath.Join("offline-nfqws2-stop-history", hex.EncodeToString(sum[:])+".json")
		if err := o.root.Link(dataplane.NFQWS2OfflineStopJournalName, name); err != nil {
			if !errors.Is(err, os.ErrExist) {
				return err
			}
		}
		checkHistory := func() error {
			current, statErr := o.root.Stat("offline-nfqws2-stop-history")
			archived, readErr := readOfflineNFQImage(history, filepath.Base(name), dataplane.NFQWS2OfflineStopJournalLimit)
			oldInfo, oldErr := o.root.Stat(dataplane.NFQWS2OfflineStopJournalName)
			archiveInfo, archiveErr := history.Stat(filepath.Base(name))
			if statErr != nil || readErr != nil || oldErr != nil || archiveErr != nil || !os.SameFile(historyInfo, current) || !offlineNFQImageEqual(archived, o.image) || !os.SameFile(oldInfo, archiveInfo) {
				return dataplane.ErrReviewChanged
			}
			return o.current(ctx)
		}
		if err := checkHistory(); err != nil {
			return err
		}
		err = errors.Join(history.Sync(), o.root.Sync())
		if err != nil {
			return err
		}
		if err := checkHistory(); err != nil {
			return err
		}
		if err := o.checkpoint("history"); err != nil {
			return err
		}
	}
	return o.save(ctx)
}

func (o *offlineNFQStopOwner) applyNotEntered() (bool, error) {
	for _, name := range []string{"latest-plan.json", "latest-committed-plan.json", "latest-execution.json"} {
		image, err := readOfflineNFQImage(o.root, name, 1<<20)
		if err != nil {
			return false, err
		}
		if !offlineNFQImageEqual(image, o.intent.Original[name]) {
			return false, nil
		}
	}
	name := filepath.Join("transactions", o.intent.Target.PlanID)
	file, err := offlineNFQOpenFile(o.root, name)
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	defer file.Close()
	entries, err := file.ReadDir(1)
	if errors.Is(err, io.EOF) && len(entries) == 0 {
		return true, nil // Crash during Manager.prepareExecutionRoot, no effect.
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	return false, nil
}

func (o *offlineNFQStopOwner) readback() error {
	if o.intent.Publication == nil {
		return dataplane.ErrExecutionJournal
	}
	for name, expected := range o.intent.Publication.After {
		image, err := readOfflineNFQImage(o.root, name, 1<<20)
		if err != nil || !offlineNFQImageEqual(image, expected) {
			return dataplane.ErrExecutionJournal
		}
	}
	return nil
}

func runOfflineNFQWS2Stop(ctx context.Context, m *dataplane.Manager, store *config.Store, configPath, dnsPath string, native offlineNFQStopNative) (OfflineNFQWS2StopResult, error) {
	failed := func(err error) (OfflineNFQWS2StopResult, error) {
		return OfflineNFQWS2StopResult{}, errors.Join(ErrOfflineNFQWS2Stop, err)
	}
	if ctx == nil || ctx.Err() != nil || m == nil || store == nil || native.inspect == nil || native.inactive == nil || native.retry == nil || native.hooks == nil || native.publication == nil || native.complete == nil {
		return failed(nil)
	}
	if _, finite := ctx.Deadline(); !finite || !filepath.IsAbs(configPath) || filepath.Clean(configPath) != configPath || !filepath.IsAbs(dnsPath) || filepath.Clean(dnsPath) != dnsPath {
		return failed(nil)
	}
	root, err := openNFQWS2HookJournal(m.StateRoot)
	if err != nil {
		return failed(err)
	}
	defer root.Close()
	configRoot, err := ownedfs.Open(filepath.Dir(configPath))
	if err != nil {
		return failed(err)
	}
	defer configRoot.Close()
	image, err := readOfflineNFQImage(root, dataplane.NFQWS2OfflineStopJournalName, dataplane.NFQWS2OfflineStopJournalLimit)
	if err != nil {
		return failed(err)
	}
	o := &offlineNFQStopOwner{root: root, configRoot: configRoot, path: m.StateRoot, configPath: configPath, image: image, store: store, manager: m, native: native}
	if image.Exists {
		o.intent, err = dataplane.DecodeNFQWS2OfflineStopIntent(image.Data)
		if err != nil || o.intent.StateRoot != m.StateRoot || o.intent.ConfigPath != configPath || o.intent.DNSPath != dnsPath {
			return failed(err)
		}
		if err := o.current(ctx); err != nil {
			return failed(err)
		}
		if o.intent.State != "complete" {
			if err := o.durable(ctx); err != nil {
				return failed(err)
			}
		}
	}
	if !image.Exists || o.intent.State == "complete" && !offlineNFQConfigEqual(store.Get(), o.intent.ConfigAfter) {
		if err := o.begin(ctx, dnsPath); err != nil {
			return failed(err)
		}
		if err := o.checkpoint("intent"); err != nil {
			return failed(err)
		}
	}
	if o.intent.State == "complete" {
		if o.readback() != nil || !offlineNFQConfigEqual(store.Get(), o.intent.ConfigAfter) {
			return failed(dataplane.ErrReviewChanged)
		}
		actual, err := readOfflineNFQImage(configRoot, filepath.Base(configPath), 1<<20)
		if err != nil || !offlineNFQImageEqual(actual, o.intent.AfterImage) {
			return failed(config.ErrRevisionChanged)
		}
		observed, err := native.inspect(ctx, o.intent.Plan)
		if err != nil || !observed.Matches(o.intent.Source, true) {
			return failed(dataplane.ErrReviewChanged)
		}
		if err := native.inactive(ctx); err != nil {
			return failed(err)
		}
		if err := o.guard(ctx, true, true); err != nil {
			return failed(err)
		}
		if err := o.readback(); err != nil {
			return failed(err)
		}
		return OfflineNFQWS2StopResult{Stopped: true, PlanID: o.intent.Target.PlanID, Revision: o.intent.ConfigAfter.Revision}, nil
	}
	if expected, pending, err := offlineNFQHookTargets(o.intent); err != nil || !pending || !reflect.DeepEqual(expected, o.intent.HooksAfter) {
		return failed(dataplane.ErrReviewChanged)
	}
	ctx = dataplane.WithReviewGuard(ctx, func(c context.Context) error {
		return o.guard(c, o.intent.State != "pending", o.intent.State == "applying")
	})
	if err := o.guard(ctx, o.intent.State != "pending", o.intent.State == "applying"); err != nil {
		return failed(err)
	}
	if o.intent.State == "pending" {
		settleApp, settleBoot, closeReview, reviewErr := native.hooks(ctx, o.intent.AppliedAt)
		if reviewErr != nil {
			// Only an actual previously durable intent can authorize the narrow
			// no-process retry. The source reads that same WAL itself.
			if err := native.retry(ctx); err != nil {
				return failed(errors.Join(reviewErr, err))
			}
		} else {
			defer func() {
				if closeReview != nil {
					closeReview()
				}
			}()
		}
		if err := o.guard(ctx, false, false); err != nil {
			return failed(err)
		}
		if _, err := m.Deactivate(ctx); err != nil {
			return failed(err)
		}
		if err := o.checkpoint("deactivated"); err != nil {
			return failed(err)
		}
		if err := o.guard(ctx, true, false); err != nil {
			return failed(err)
		}
		if reviewErr != nil {
			settleApp, settleBoot, closeReview, err = native.hooks(ctx, o.intent.AppliedAt)
			if err != nil {
				return failed(err)
			}
			defer closeReview()
		}
		if err := settleApp(); err != nil {
			return failed(err)
		}
		if err := o.checkpoint("app-settled"); err != nil {
			return failed(err)
		}
		if err := o.guard(ctx, true, false); err != nil {
			return failed(err)
		}
		if err := settleBoot(); err != nil {
			return failed(err)
		}
		if err := o.checkpoint("boot-settled"); err != nil {
			return failed(err)
		}
		o.intent.State = "inactive"
		if err := o.guard(ctx, true, false); err != nil {
			return failed(err)
		}
		if err := o.save(ctx); err != nil {
			return failed(err)
		}
		if err := o.checkpoint("inactive"); err != nil {
			return failed(err)
		}
	}
	if o.intent.State == "inactive" {
		o.intent.State = "applying"
		if err := o.save(ctx); err != nil {
			return failed(err)
		}
		if err := o.checkpoint("applying"); err != nil {
			return failed(err)
		}
	}
	if o.intent.Publication == nil {
		unentered, err := o.applyNotEntered()
		if err != nil {
			return failed(err)
		}
		if unentered {
			if _, err := m.Apply(ctx, o.intent.Target, nil); err != nil {
				return failed(err) // Keep actual failed execution; no repair-to-green.
			}
			if err := o.checkpoint("plan"); err != nil {
				return failed(err)
			}
		}
		publication, err := native.publication(ctx, o.intent.Plan, o.intent.Target, o.intent.Original)
		if err != nil {
			return failed(err)
		}
		o.intent.Publication = &publication
		if err := o.save(ctx); err != nil {
			return failed(err)
		}
		if err := o.checkpoint("publication"); err != nil {
			return failed(err)
		}
	}
	if err := native.complete(ctx, o.intent.Plan, o.intent.Target, o.intent.Original, *o.intent.Publication); err != nil {
		return failed(err)
	}
	if err := o.readback(); err != nil {
		return failed(err)
	}
	if err := o.guard(ctx, true, true); err != nil {
		return failed(err)
	}
	if !offlineNFQConfigEqual(store.Get(), o.intent.ConfigAfter) {
		// The raw durable before-image was checked above. Use the actual Store
		// clone for nil/empty omitted fields; no external bytes are adopted.
		before := store.Get()
		if !offlineNFQConfigEqual(before, o.intent.ConfigBefore) {
			return failed(config.ErrRevisionChanged)
		}
		if _, err := store.CommitNFQWS2OfflineStop(ctx, before, o.intent.Resolved, o.intent.AppliedAt); err != nil {
			return failed(err)
		}
	}
	if err := o.checkpoint("config"); err != nil {
		return failed(err)
	}
	if !offlineNFQConfigEqual(store.Get(), o.intent.ConfigAfter) || o.readback() != nil {
		return failed(dataplane.ErrReviewChanged)
	}
	if err := o.guard(ctx, true, true); err != nil {
		return failed(err)
	}
	o.intent.State = "complete"
	if err := o.save(ctx); err != nil {
		return failed(err)
	}
	if err := o.checkpoint("complete"); err != nil {
		return failed(err)
	}
	return OfflineNFQWS2StopResult{Stopped: true, PlanID: o.intent.Target.PlanID, Revision: o.intent.ConfigAfter.Revision}, nil
}
