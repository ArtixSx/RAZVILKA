package dataplane

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/ArtixSx/razvilka/internal/physicalscope"
)

type wgProbeKernelLink struct{ name, kind string }

func (a *WARPWireGuardAdapter) wgProbeLinks(ctx context.Context) ([]wgProbeKernelLink, error) {
	if a.wgCommandTools != nil {
		runner, ok := a.Runner.(wgExecRunner)
		if !ok || runner.adapter != a {
			return nil, ErrWGOperationOwner
		}
		facts, err := runner.readProbeKernelLinks(ctx)
		if err != nil {
			return nil, err // Bound source refusal never revives a CLI fallback.
		}
		if err := wgKernelLinkFactsComplete(facts); err != nil {
			return nil, err
		}
		links := make([]wgProbeKernelLink, 0, len(facts))
		for _, fact := range facts {
			links = append(links, wgProbeKernelLink{fact.Name, fact.Kind})
		}
		return links, nil
	}
	// Keep the existing legacy structured-CLI inspection. No text decoder or
	// unbound kernel reader is introduced for callers without original tools.
	data, err := a.run(ctx, a.ip(), "-j", "-d", "link", "show")
	if err != nil || len(data) > 1<<20 {
		return nil, wgCanaryIdentityInspectionError("link inventory is unavailable")
	}
	var rows []struct {
		Name     string `json:"ifname"`
		LinkInfo struct {
			Kind string `json:"info_kind"`
		} `json:"linkinfo"`
	}
	if json.Unmarshal(data, &rows) != nil || rows == nil || len(rows) > 4096 {
		return nil, wgCanaryIdentityInspectionError("link inventory is invalid")
	}
	links := make([]wgProbeKernelLink, 0, len(rows))
	for _, row := range rows {
		links = append(links, wgProbeKernelLink{row.Name, row.LinkInfo.Kind})
	}
	return links, nil
}

// Same operation/barriers as wgExecRunner.Run, with no command or mutation
// invocation minted. Kernel facts are discarded on any closing revocation;
// unlike a started mutation there is no successful effect ACK to preserve.
func (r wgExecRunner) readProbeKernelLinks(ctx context.Context) ([]physicalscope.WGKernelLink, error) {
	if ctx == nil {
		return nil, ErrWGOperationOwner
	}
	o, owned := ctx.Value(wgOperationOwnerKey{}).(*wgOperationOwner)
	m, material := ctx.Value(wgOperationMaterialKey{}).(*WGOperationMaterial)
	if !owned || !material || m == nil || o == nil || o.self != o || o.material != m || o.scope == nil || o.adapter != r.adapter {
		return nil, ErrWGOperationOwner
	}
	m.barrier.RLock()
	defer m.barrier.RUnlock()
	o.scope.startMu.RLock()
	defer o.scope.startMu.RUnlock()
	cleanup := wgOperationCleanup(ctx)
	if err := o.check(ctx, cleanup); err != nil {
		return nil, err
	}
	tools := o.adapter.wgCommandTools
	if !tools.valid(o.adapter.ID()) {
		return nil, ErrWGOperationOwner
	}
	source, ok := tools.Runner.(wgInactivityKernelLinkSource)
	if !ok {
		return nil, ErrWGOperationOwner
	}
	links, err := source.ReadWGKernelLinks(ctx, tools.Identity)
	closing := errors.Join(o.check(ctx, cleanup), ctx.Err())
	if closing != nil && !cleanup {
		o.mu.Lock()
		o.revoked = errors.Join(o.revoked, closing)
		o.mu.Unlock()
	}
	if err != nil || closing != nil {
		return nil, errors.Join(err, closing)
	}
	return append([]physicalscope.WGKernelLink(nil), links...), nil
}
