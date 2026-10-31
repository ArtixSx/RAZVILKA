package dataplane

import (
	"encoding/json"
	"net/netip"
	"slices"
	"strconv"

	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

// NFQWSProbeSpec describes one router-origin socket, never an authority to
// bind a port, reserve a queue or start a process. Only the original live
// socket issuer may admit this compiler input to COMMON.
type NFQWSProbeSpec struct {
	Source, Destination                         netip.AddrPort
	SocketDevice, SocketInode                   uint64
	Epoch, ValidationGeneration, CriteriaDigest string
}

func validateNFQWSProbeIntent(plan Plan, spec NFQWSScopedSpec) (NFQWSScopedSpec, error) {
	p, c := spec.Probe, spec.Candidate
	if p == nil || plan.SchemaVersion != SchemaVersion || plan.PlanID == "" || len(plan.PlanID) > 128 || !lanPolicyHash(plan.Digest) || plan.Revision == 0 || plan.NetworkProfileID == "" || !plan.Ready || plan.SafeMode || plan.Noop || len(plan.Blockers) != 0 || len(plan.ResourceConflicts) != 0 || plan.LAN != nil || len(plan.Routes) != 1 || spec.Queue != 200 || !nfqwsScopedSpecNetworkValid(spec) || spec.NetworkIdentity == nil || len(spec.Matches) != 0 || c.ID == "" || len(c.ID) > 128 || !nfqws2ManagedHex(c.Incarnation, 32) || !lanPolicyHash(c.ArgumentsSHA256) || c.ServiceID == "" || c.IPFamily != "ipv4" || len(c.Traffic) != 1 || c.Traffic[0] != (NFQWSScopedTraffic{Protocol: "tcp", First: 443, Last: 443}) {
		return NFQWSScopedSpec{}, ErrNFQWSScopedOwner
	}
	if !p.Source.IsValid() || !p.Source.Addr().Is4() || p.Source.Addr().IsUnspecified() || p.Source.Addr().IsLoopback() || p.Source.Port() == 0 || !p.Destination.IsValid() || !domainPolicyTCPPublicIPv4(p.Destination.Addr()) || p.Destination.Port() != 443 || p.SocketInode == 0 || !nfqws2ManagedHex(p.Epoch, 32) || !nfqws2ManagedHex(p.ValidationGeneration, 32) || !lanPolicyHash(p.CriteriaDigest) {
		return NFQWSScopedSpec{}, ErrNFQWSScopedOwner
	}
	r := plan.Routes[0]
	if r.ServiceID != c.ServiceID || AdapterID(r.Resolved) != "nfqws2" || len(r.Domains) != 0 || len(r.Sources) != 0 || len(r.Ingress) != 0 || len(r.SourceRefs) != 0 || r.NetworkPolicyGeneration != "" || len(r.CIDRs) != 1 || r.CIDRs[0] != p.Destination.Addr().String()+"/32" {
		return NFQWSScopedSpec{}, ErrNFQWSScopedOwner
	}
	return spec.Clone(), nil
}

func compileNFQWSProbePlan(plan Plan, spec NFQWSScopedSpec) (*NFQWSScopedPlan, error) {
	data, err := json.Marshal(struct {
		Plan Plan
		Spec NFQWSScopedSpec
	}{plan, spec})
	if err != nil || len(data) > 256<<10 {
		return nil, ErrNFQWSScopedOwner
	}
	generation := routeidentity.Hash(append([]byte("nfqws-router-probe-v1\x00"), data...))
	name := "RZP_" + generation[:18] + "_4"
	probe, candidate := spec.Probe, spec.Candidate
	p := &NFQWSScopedPlan{spec: spec.Clone(), resources: NFQWSScopedResources{Queue: spec.Queue, NetNamespace: spec.NetNamespace, Generation: generation, PlanID: plan.PlanID, PlanDigest: plan.Digest, NetworkProfileID: plan.NetworkProfileID, Revision: plan.Revision, CandidateID: candidate.ID, Incarnation: candidate.Incarnation, ArgumentsHash: candidate.ArgumentsSHA256, BootID: spec.BootID, SessionID: spec.SessionID, CommandSHA256: spec.CommandSHA256, Chains: []string{name}, NetworkIdentity: cloneNFQWSScopedNetworkIdentity(spec.NetworkIdentity)}}
	// Mark zero excludes nfqws-generated marked packets and preserves unrelated
	// router policy. The only OUTPUT jump includes the kernel-owned source port.
	tuple := []string{"-s", probe.Source.Addr().String() + "/32", "-d", probe.Destination.Addr().String() + "/32", "-p", "tcp", "-m", "tcp", "--sport", strconv.Itoa(int(probe.Source.Port())), "--dport", "443", "-m", "mark", "--mark", "0x0/0xffffffff"}
	body := append(slices.Clone(tuple), "-j", "NFQUEUE", "--queue-num", "200")
	jump := append(slices.Clone(tuple), "-j", name)
	p.chains = []nfqwsScopedChain{{tool: PolicyEffectIPTables, name: name, body: [][]string{body}, jumps: [][]string{jump}}}
	p.mixed = PolicyEffectPlan{Generation: generation, Effects: []PolicyEffect{
		{Tool: PolicyEffectIPTables, Add: []string{"-t", "mangle", "-N", name}, Delete: []string{"-t", "mangle", "-X", name}},
		{Tool: PolicyEffectIPTables, Add: append([]string{"-t", "mangle", "-A", name}, body...), Delete: append([]string{"-t", "mangle", "-D", name}, body...), Needs: []int{0}},
		{Tool: PolicyEffectIPTables, Add: append([]string{"-t", "mangle", "-A", "OUTPUT"}, jump...), Delete: append([]string{"-t", "mangle", "-D", "OUTPUT"}, jump...), Needs: []int{1}},
	}}
	p.digest, err = PolicyEffectPlanDigest(p.mixed)
	if err != nil {
		return nil, err
	}
	return p, nil
}
