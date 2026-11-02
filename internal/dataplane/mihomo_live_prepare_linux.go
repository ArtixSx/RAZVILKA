//go:build linux

package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"

	"github.com/ArtixSx/razvilka/internal/backendprofile"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/netresolve"
	"github.com/ArtixSx/razvilka/internal/providerprofile"
	"github.com/ArtixSx/razvilka/internal/publicfetch"
)

func (a *MihomoProbeAdapter) prepareLive(ctx context.Context, plan Plan, root string) (result *mihomoLiveResource, resultErr error) {
	a.mu.Lock()
	options, proxy := a.liveOptions, a.liveProxy
	a.mu.Unlock()
	if options == nil || proxy == nil || root != filepath.Join(options.Manager.StateRoot, "transactions", plan.PlanID, "mihomo") {
		return nil, errMihomoLiveMaterial
	}
	id, err := mihomoLiveIntentNode(plan)
	if err != nil {
		return nil, err
	}
	preparation := &mihomoLivePreparation{}
	a.mu.Lock()
	if a.livePreparing != nil || a.livePending != nil || a.liveActive != nil || a.busy || a.pending != nil {
		a.mu.Unlock()
		return nil, errMihomoLiveMaterial
	}
	a.livePreparing = preparation
	a.mu.Unlock()
	transferred := false
	defer func() {
		if !transferred {
			resultErr = errors.Join(resultErr, a.closeLivePreparation(preparation))
		}
	}()
	if err := options.History.CheckWrite(ctx, 6); err != nil {
		return nil, err
	}
	control, err := options.Gate.ReviewControlEpoch(ctx, options.ControlRoot)
	preparation.control = control
	if err != nil {
		return nil, err
	}
	childControl, err := options.Gate.ReviewControlEpoch(ctx, options.ControlRoot)
	preparation.childControl = childControl
	if err != nil {
		return nil, err
	}
	cleanup, err := options.Gate.ReviewExclusiveCleanup(ctx)
	if err != nil {
		return nil, err
	}
	var source *components.MihomoLiveSource
	profileID, err := options.FreshProfile(ctx)
	if err != nil || profileID != plan.NetworkProfileID {
		return nil, errors.Join(ErrNetworkChanged, err)
	}
	node, err := ReviewNodeDefaultSource(ctx, options.Nodes, "mihomo:"+id)
	if err != nil {
		return nil, err
	}
	service, err := FrozenProbeService(plan.Routes[0])
	if err != nil {
		return nil, err
	}
	if err := options.ResourceGuard(ctx, plan, "", netip.Addr{}); err != nil {
		return nil, err
	}
	var host string
	err = node.WithMaterial(ctx, func(material []byte) error {
		profile, err := providerprofile.VLESSProfileFromJSON(material)
		if err != nil || profile.Transport != "tcp" || profile.Security != "tls" || profile.Insecure {
			return errMihomoLiveMaterial
		}
		host = profile.Server
		return nil
	})
	if err != nil {
		return nil, err
	}
	addresses, err := netresolve.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addresses) == 0 || len(addresses) > 64 {
		return nil, errors.Join(errMihomoLiveMaterial, err)
	}
	for _, address := range addresses {
		if !address.Is4() || !publicfetch.PublicAddress(address) {
			return nil, errMihomoLiveMaterial
		}
		if err := options.ResourceGuard(ctx, plan, host, address); err != nil {
			return nil, err
		}
	}
	sort.Slice(addresses, func(i, j int) bool { return addresses[i].Compare(addresses[j]) < 0 })
	addresses = slices.Compact(addresses)
	source, err = a.components.OpenMihomoLiveSource(ctx)
	preparation.source = source
	if err != nil {
		return nil, err
	}
	profile, err := reviewMihomoLiveProfile(ctx, node, source, addresses[0], proxy.SOCKSPort)
	if err != nil {
		return nil, err
	}
	profileRef, err := source.ReviewProfileReference(ctx, profile)
	if err != nil {
		return nil, err
	}
	identity, err := a.provider.Observe(ctx)
	if err != nil {
		return nil, err
	}
	var sidecarConfig []byte
	if proxy.effectiveSidecar() == "hev" {
		if proxy.hevInstalledCheck == nil {
			return nil, errMihomoLiveMaterial
		}
		if err := proxy.hevInstalledCheck(ctx); err != nil {
			return nil, err
		}
		sidecarConfig, err = proxy.hevConfig()
	} else {
		// This closed profile requires the supported modern dialect. Actual
		// native schema/check validation occurs after COMMON is published.
		sidecarConfig, err = buildSOCKSTunnelConfigForSchema(proxy.Interface, proxy.TunnelCIDR, proxy.SOCKSPort, singBoxSidecarSchema{modernAddress: true, dnsMode: true})
	}
	if err != nil {
		return nil, err
	}
	binary, err := os.Open(proxy.sidecarBinary())
	if err != nil {
		return nil, err
	}
	info, statErr := binary.Stat()
	hash, hashErr := mihomoLiveHashFile(ctx, binary, 256<<20)
	closeErr := binary.Close()
	if err := errors.Join(statErr, hashErr, closeErr); err != nil {
		return nil, err
	}
	prefixes, rules, err := resolvePolicyRules(ctx, plan, "mihomo", nil)
	if err != nil {
		return nil, err
	}
	state := PolicyState{Interface: proxy.Interface, Table: proxy.Table, PriorityBase: proxy.Priority, Prefixes: prefixes, Rules: rules}
	for _, address := range addresses {
		state.Exclusions = append(state.Exclusions, netip.PrefixFrom(address, 32).String())
	}
	state.Exclusions = sortedUnique(state.Exclusions)
	initializePolicyLayout(&state)
	if err := proxy.prepareForwarding(ctx, &state); err != nil {
		return nil, err
	}
	definition := ExecutionMihomoLiveDefinition{Schema: 1, Plan: cloneExecutionResourcePlan(plan), Source: source.Reference(), Node: node.Reference(), Profile: profileRef, Service: service, NetworkProfile: profileID, NetworkIdentity: identity, EndpointHost: host, Endpoint: addresses[0], EndpointAddresses: slices.Clone(addresses), Sidecar: MihomoLiveSidecarReference{Kind: proxy.effectiveSidecar(), BinarySHA256: hash, BinarySize: info.Size(), ConfigSHA256: nodeDefaultSourceMaterialHash(sidecarConfig)}, Policy: state}
	if err := definition.validate(); err != nil {
		return nil, err
	}
	r, err := a.issueLive(ctx, source, node, profile, options.History, control, childControl, definition)
	if r != nil {
		r.mu.Lock()
		r.proxy = proxy
		r.cleanup = cleanup
		r.mu.Unlock()
		transferred = true
		a.mu.Lock()
		if a.livePreparing == preparation {
			a.livePreparing = nil
		}
		a.mu.Unlock()
	}
	return r, err
}

func (r *mihomoLiveResource) engineImage(ctx context.Context) ([]byte, error) {
	var config []byte
	err := r.node.WithMaterial(ctx, func(material []byte) error {
		raw, err := mihomoNodeSourceProfile(material)
		defer clear(raw)
		if err != nil {
			return err
		}
		generated, err := backendprofile.MihomoPinnedForProbe(string(raw), backendprofile.MihomoOptions{SOCKSPort: r.definition.Profile.SOCKSPort}, r.definition.EndpointHost, r.definition.Endpoint)
		if err != nil {
			return err
		}
		config = []byte(generated.Config)
		if nodeDefaultSourceMaterialHash(config) != r.definition.Profile.ConfigSHA256 {
			clear(config)
			config = nil
			return errMihomoLiveMaterial
		}
		return nil
	})
	if err != nil {
		clear(config)
		return nil, err
	}
	return config, nil
}
