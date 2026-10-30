package dataplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// VerifyNFQWS2RebootStop admits only the original Stop's metadata cleanup for
// an exact first-start receipt from an earlier boot. It is not stopped-state
// settlement: the caller must still run Deactivate and VerifyNFQWS2Inactive.
// The retained startup provider, collector and process/queue readers supply
// every absence observation; callers cannot substitute callbacks or a DTO.
func (r *RuntimeInactivitySourceReview) VerifyNFQWS2RebootStop(ctx context.Context, plan Plan, instance string) error {
	if err := r.CheckCurrent(ctx); err != nil {
		return err
	}
	review, err := r.reviewNFQWS2RebootStop(ctx, plan, instance)
	if err != nil {
		return err
	}
	if err := r.CheckCurrent(ctx); err != nil {
		return err
	}
	return review.current(ctx)
}

// The private core lets complete-source tests use the existing adapter's
// observation seam; production surrounds it with the actual provider's
// CheckCurrent and always keeps the original bound association below.
func (r *RuntimeInactivitySourceReview) reviewNFQWS2RebootStop(ctx context.Context, plan Plan, instance string) (*nfqws2RebootStopReview, error) {
	if !r.currentAssociation(ctx) || !nfqws2RebootStopPlan(plan) || !validNFQWS2BootHookInstance(instance) {
		return nil, ErrRuntimeInactivity
	}
	identity := r.source.identity
	a, err := r.manager.committedNFQWS2(plan)
	if err != nil || a != r.nfq {
		return nil, errors.Join(ErrReviewChanged, err)
	}
	lease, err := a.verifyOwnedLists(false)
	if err != nil || lease == nil || lease.FirstStart == nil || lease.FirstStart.Process == nil ||
		(lease.FirstStart.Phase != nfqws2FirstRunning && lease.FirstStart.Phase != nfqws2FirstStopped) ||
		!kernelBootIDPattern.MatchString(lease.FirstStart.Process.BootID) || lease.FirstStart.Process.BootID == r.source.identity.BootID ||
		nfqws2HookInstance(lease) != instance {
		return nil, errors.Join(ErrRuntimeInactivity, err)
	}
	transaction, ok := a.firstStartTransaction(plan)
	if !ok || lease.Transaction != transaction {
		return nil, ErrReviewChanged
	}
	before, err := r.nfqws2RebootStopFiles(ctx, transaction)
	if err != nil {
		return nil, err
	}
	for name, hash := range map[string]string{"nfqws2.conf.staged": lease.ConfigHash, "S51nfqws2.staged": lease.InitHash} {
		raw, exists, err := nfqws2Read(filepath.Join(transaction, name))
		if err != nil || !exists || nfqws2Hash(raw) != hash {
			return nil, errors.Join(ErrReviewChanged, err)
		}
	}
	if err := a.firstStartScriptSafe("owned_stop"); err != nil {
		return nil, err
	}
	config, exists, err := nfqws2Read(a.ConfigPath)
	if err != nil || !exists {
		return nil, errors.Join(ErrReviewChanged, err)
	}
	expected, err := a.firstStartConfig(plan, config)
	if err != nil || !bytes.Equal(config, expected) {
		return nil, errors.Join(ErrReviewChanged, err)
	}
	pid, exists, err := nfqws2Read(a.firstStartPIDPath())
	if err != nil || exists && strings.TrimSpace(string(pid)) != strconv.Itoa(lease.FirstStart.Process.PID) {
		return nil, errors.Join(ErrReviewChanged, err)
	}
	// This existing check reads the complete actual process, queue and kernel
	// inventories without requiring historical metadata to say "stopped" first.
	if err := a.firstStartRuntimeAbsent(ctx); err != nil {
		return nil, err
	}
	return &nfqws2RebootStopReview{sources: r, plan: plan, lease: lease, files: before, identity: identity}, nil
}

// The reboot fallback is only the closed, domain-list first-start runtime.
// Direct and mixed routes keep their existing admission path; the adapter
// list alone cannot establish this scope because Build omits direct from it.
func nfqws2RebootStopPlan(plan Plan) bool {
	if !nfqws2HookPlan(plan) || len(plan.Adapters) != 1 || plan.SchemaVersion != SchemaVersion || plan.RouteCount != len(plan.Routes) ||
		plan.DNS != nil || plan.DomainPolicy != nil || plan.SyntheticDNS != nil || plan.SuspendDNS || plan.DiscardDNS ||
		plan.NetworkProfileID != "" || len(plan.RetiringAdapters) != 0 || !validPlanID(plan.PlanID) || !validPlanDigest(plan.Digest) || plan.PlanID != "dp-"+plan.Digest[:16] {
		return false
	}
	for _, route := range plan.Routes {
		if route.Resolved != "nfqws2" || route.ServiceID == "" || len(route.Domains) == 0 || len(route.CIDRs) != 0 ||
			len(route.Sources) != 0 || len(route.SourceRefs) != 0 || len(route.Ingress) != 0 || route.WireGuardProfileRevision != "" ||
			route.NetworkPolicyGeneration != "" || route.NetworkPolicyRole != "" {
			return false
		}
	}
	return true
}

// This retained image is private to one invocation and cannot authorize an
// effect. The public method closes the native source check before comparing
// every original file and the complete plan again.
type nfqws2RebootStopReview struct {
	sources  *RuntimeInactivitySourceReview
	plan     Plan
	lease    *nfqws2Lease
	files    nfqws2InactiveFiles
	identity netidentity.Identity
}

func (v *nfqws2RebootStopReview) current(ctx context.Context) error {
	r := v.sources
	if !r.currentAssociation(ctx) || r.source.identity != v.identity {
		return ErrRuntimeInactivity
	}
	current, err := r.manager.committedNFQWS2(v.plan)
	if err != nil || current != r.nfq {
		return errors.Join(ErrReviewChanged, err)
	}
	after, err := r.nfqws2RebootStopFiles(ctx, v.lease.Transaction)
	if err != nil || !v.files.same(after) {
		return errors.Join(ErrReviewChanged, err)
	}
	currentLease, err := r.nfq.readLease()
	if err != nil || !reflect.DeepEqual(currentLease, v.lease) {
		return errors.Join(ErrReviewChanged, err)
	}
	if current, err := r.manager.committedNFQWS2(v.plan); err != nil || current != r.nfq {
		return errors.Join(ErrReviewChanged, err)
	}
	if !r.currentAssociation(ctx) || r.source.identity != v.identity {
		return ErrRuntimeInactivity
	}
	return ctx.Err()
}

// Preserve file identities as well as bytes, including the protected parent
// of an absent .run/PID file. A replacement directory or a same-byte replaced
// lease cannot inherit the earlier observation. No state is written here.
func (r *RuntimeInactivitySourceReview) nfqws2RebootStopFiles(ctx context.Context, transaction string) (nfqws2InactiveFiles, error) {
	if !r.currentAssociation(ctx) || r.source.platform.protected == nil {
		return nil, ErrRuntimeInactivity
	}
	images := nfqws2InactiveFiles{}
	protected := r.source.platform.protected
	listPaths := r.nfq.ownedListPaths()
	paths := r.nfq.firstStartHookFilePaths(transaction)
	// An interrupted or foreign writer is not metadata that Stop may adopt.
	// Keep the ordinary inactive observer's closed private-directory grammar.
	key := nfqws2Hash([]byte(nfqws2LeaseFile))
	lock := ".state-" + key + ".lock"
	dir, err := os.Open(r.nfq.StateRoot)
	if err != nil {
		return nil, err
	}
	opened, statErr := dir.Stat()
	entries, readErr := dir.ReadDir(3)
	_ = dir.Close()
	info, err := os.Lstat(r.nfq.StateRoot)
	if err != nil || statErr != nil || !protected(info, true, true) || !os.SameFile(opened, info) || readErr != nil && !errors.Is(readErr, io.EOF) || len(entries) > 2 {
		return nil, ErrRuntimeInactivity
	}
	images[r.nfq.StateRoot] = nfqws2InactiveImage{info: info}
	for _, entry := range entries {
		switch entry.Name() {
		case nfqws2LeaseFile:
		case lock:
			paths = append(paths, filepath.Join(r.nfq.StateRoot, lock))
		default:
			return nil, ErrRuntimeInactivity
		}
	}
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		private := filepath.Dir(path) == r.nfq.StateRoot
		fileProtected := protected
		for _, list := range listPaths {
			if path == list && r.source.platform.foreignList != nil {
				fileProtected = func(info os.FileInfo, directory, _ bool) bool {
					return !directory && r.source.platform.foreignList(info)
				}
				break
			}
		}
		parent := filepath.Dir(path)
		for {
			info, err := os.Lstat(parent)
			if errors.Is(err, os.ErrNotExist) {
				images[parent] = nfqws2InactiveImage{}
				next := filepath.Dir(parent)
				if next == parent {
					return nil, ErrRuntimeInactivity
				}
				parent = next
				continue
			}
			if err != nil || !protected(info, true, private) {
				return nil, errors.Join(ErrRuntimeInactivity, err)
			}
			images[parent] = nfqws2InactiveImage{info: info}
			break
		}
		before, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			images[path] = nfqws2InactiveImage{}
			continue
		}
		if err != nil || !fileProtected(before, false, private) {
			return nil, errors.Join(ErrRuntimeInactivity, err)
		}
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		opened, statErr := file.Stat()
		raw, readErr := io.ReadAll(io.LimitReader(file, (8<<20)+1))
		_ = file.Close()
		after, closeErr := os.Lstat(path)
		if statErr != nil || readErr != nil || closeErr != nil || len(raw) > 8<<20 || ctx.Err() != nil ||
			!fileProtected(after, false, private) || !os.SameFile(before, opened) || !os.SameFile(opened, after) ||
			after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) || after.Mode() != before.Mode() || int64(len(raw)) != before.Size() {
			return nil, ErrRuntimeInactivity
		}
		if path == filepath.Join(r.nfq.StateRoot, lock) && !bytes.Equal(raw, []byte("RAZVILKA state file writer v1 "+key+"\n")) {
			return nil, ErrRuntimeInactivity
		}
		images[path] = nfqws2InactiveImage{info: after, digest: sha256.Sum256(raw)}
	}
	return images, ctx.Err()
}
