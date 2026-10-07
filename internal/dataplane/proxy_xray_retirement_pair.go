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
		observe = observeXrayRetirementPairLocal
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
func observeXrayRetirementPairLocal(ctx context.Context, specs [2]ProcessSpec) (xrayRetirementPair, error) {
	var pair xrayRetirementPair
	for pass := 0; pass < 2; pass++ {
		var current xrayRetirementPair
		for i, spec := range specs {
			if ctx == nil || ctx.Err() != nil || validateProcessSpec(spec) != nil {
				return pair, ErrProxyPolicyUnknown
			}
			pid, err := readManagedPID(spec)
			if err != nil {
				return pair, errors.Join(ErrProxyPolicyUnknown, err)
			}
			identity, err := captureProxyProcessIdentity(ctx, spec, pid)
			if err != nil {
				return pair, errors.Join(ErrProxyPolicyUnknown, err)
			}
			if spec.RouteProof {
				raw, err := readBoundedSidecar(spec.PIDPath + routeidentity.ReceiptSuffix)
				var saved routeidentity.Receipt
				if err != nil || json.Unmarshal(raw, &saved) != nil || saved != identity {
					return pair, errors.Join(ErrProxyPolicyUnknown, err)
				}
			}
			namespace, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "ns/net"))
			self, selfErr := os.Readlink("/proc/self/ns/net")
			if err != nil || selfErr != nil || namespace == "" || len(namespace) > 4096 || namespace != self {
				return pair, errors.Join(ErrProxyPolicyUnknown, err, selfErr)
			}
			current[i] = xrayRetirementProcessIdentity{Receipt: identity, Namespace: namespace}
		}
		if pass != 0 && current != pair {
			return pair, ErrProxyPolicyUnknown
		}
		pair = current
	}
	return pair, ctx.Err()
}
