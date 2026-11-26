package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

type xrayRetirementProcessIdentity struct {
	routeidentity.Receipt
	Namespace string
}

type xrayRetirementPair [2]xrayRetirementProcessIdentity

// Only coherent local fixtures replace this leaf. Nil always reads actual
// owned processes; it never delegates to action/boot/controller/identity hooks.
type xrayRetirementPairObserver func(context.Context, [2]ProcessSpec) (xrayRetirementPair, error)

func (a *ProxyTunnelAdapter) observeXrayRetirementPair(ctx context.Context, snapshot proxySnapshot) (xrayRetirementPair, error) {
	var zero xrayRetirementPair
	if ctx == nil || ctx.Err() != nil || !a.isXrayRetirement() || !snapshot.RuntimeEngineExists || !snapshot.RuntimeSideExists || snapshot.BootID == "" {
		return zero, ErrProxyPolicyUnknown
	}
	specs := [2]ProcessSpec{a.engineProcess(), a.sidecarProcess()}
	var argsHashes [2]string
	for i := range specs {
		specs[i].Args = append([]string(nil), specs[i].Args...)
		argv := strings.Join(append([]string{specs[i].Binary}, specs[i].Args...), "\x00") + "\x00"
		if len(argv) > 64<<10 {
			return zero, ErrProxyPolicyUnknown
		}
		argsHashes[i] = routeidentity.Hash([]byte(argv))
	}
	observe := a.xrayRetirementPairObserver
	if observe == nil {
		allowProcTables := a.xrayPreviousMode == proxyXrayModeNode && snapshot.PreviousXrayMode == string(proxyXrayModeNode) && specs[0].RouteProof && specs[1].RouteProof
		observe = func(ctx context.Context, specs [2]ProcessSpec) (xrayRetirementPair, error) {
			return observeXrayRetirementPairLocal(ctx, specs, allowProcTables)
		}
	}
	pair, err := observe(ctx, specs)
	if err != nil || ctx.Err() != nil {
		return zero, errors.Join(ErrProxyPolicyUnknown, err, ctx.Err())
	}
	configs := [2][]byte{snapshot.RuntimeEngine, snapshot.RuntimeSidecar}
	for i, member := range pair {
		birth, birthErr := strconv.ParseUint(member.StartTicks, 10, 64)
		if member.Version != 1 || member.PID <= 1 || member.PID == pair[1-i].PID || member.BootID != snapshot.BootID ||
			birthErr != nil || birth == 0 || strconv.FormatUint(birth, 10) != member.StartTicks || member.Executable == "" || len(member.Executable) > 4096 ||
			member.ArgsHash != argsHashes[i] || member.ConfigHash != routeidentity.Hash(configs[i]) ||
			member.Namespace == "" || len(member.Namespace) > 4096 || member.Namespace != pair[1-i].Namespace {
			return zero, ErrProxyPolicyUnknown
		}
	}
	return pair, nil
}

// One factual pair observation, with two full passes and no arbitrary hooks
// between members. This proves current continuity, not future atomic lifetime.
func observeXrayRetirementPairLocal(ctx context.Context, specs [2]ProcessSpec, allowProcTables bool) (xrayRetirementPair, error) {
	var pair xrayRetirementPair
	for pass := 0; pass < 2; pass++ {
		var current xrayRetirementPair
		for i, spec := range specs {
			receipt, err := readXrayRetirementMember(ctx, spec)
			if err != nil {
				return pair, err
			}
			current[i].Receipt = receipt
		}
		pids := [2]int{current[0].PID, current[1].PID}
		var links [3]xrayRetirementNSLink
		for i, path := range []string{"/proc/self/ns/net", filepath.Join("/proc", strconv.Itoa(pids[0]), "ns/net"), filepath.Join("/proc", strconv.Itoa(pids[1]), "ns/net")} {
			links[i].name, links[i].err = os.Readlink(path)
		}
		namespace, err := xrayRetirementNamespace(ctx, allowProcTables, links)
		if err == nil && namespace == "" {
			namespace, err = xrayRetirementProcTables(ctx, pids, func() error {
				for i, spec := range specs {
					receipt, err := readXrayRetirementMember(ctx, spec)
					if err != nil || receipt != current[i].Receipt {
						return errors.Join(ErrProxyPolicyUnknown, err)
					}
				}
				return ctx.Err()
			})
		}
		if err != nil {
			return pair, err
		}
		for i := range current {
			current[i].Namespace = namespace
		}
		if pass != 0 && current != pair {
			return pair, ErrProxyPolicyUnknown
		}
		pair = current
	}
	return pair, ctx.Err()
}

type xrayRetirementNSLink struct {
	name string
	err  error
}

func xrayRetirementNamespace(ctx context.Context, allowProcTables bool, links [3]xrayRetirementNSLink) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if links[0].err == nil && links[0].name != "" && len(links[0].name) <= 4096 {
		for _, link := range links[1:] {
			if link.err != nil || link.name != links[0].name {
				return "", errors.Join(ErrProxyPolicyUnknown, link.err)
			}
		}
		return links[0].name, nil
	}
	for _, link := range links {
		if !allowProcTables || !errors.Is(link.err, os.ErrNotExist) {
			return "", errors.Join(ErrProxyPolicyUnknown, link.err)
		}
	}
	// All three kernel links are absent. The caller still owes a positive proof.
	return "", nil
}

func readXrayRetirementMember(ctx context.Context, spec ProcessSpec) (routeidentity.Receipt, error) {
	var zero routeidentity.Receipt
	if ctx == nil || ctx.Err() != nil || validateProcessSpec(spec) != nil {
		return zero, ErrProxyPolicyUnknown
	}
	pid, err := readManagedPID(spec)
	if err != nil {
		return zero, errors.Join(ErrProxyPolicyUnknown, err)
	}
	identity, err := captureProxyProcessIdentity(ctx, spec, pid)
	if err != nil {
		return zero, errors.Join(ErrProxyPolicyUnknown, err)
	}
	if spec.RouteProof {
		raw, err := readBoundedSidecar(spec.PIDPath + routeidentity.ReceiptSuffix)
		var saved routeidentity.Receipt
		if err != nil || json.Unmarshal(raw, &saved) != nil || saved != identity {
			return zero, errors.Join(ErrProxyPolicyUnknown, err)
		}
	}
	return identity, ctx.Err()
}
