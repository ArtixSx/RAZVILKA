package dataplane

import (
	"net/netip"
	"strconv"
)

// Only a comparison/compiler input. The accepted original FD, original
// capture and native kernel observer are mandatory at the actual issuer.
type domainTCPBaselineFlowSpec struct {
	Capture        DomainPolicyTCPCaptureSpec
	Source, Target netip.AddrPort
	Egress         string
}

const (
	domainTCPBaselineTable = "31000"
	domainTCPBaselineMark  = "0x525a0001/0xffffffff"
)

func (s domainTCPBaselineFlowSpec) valid() bool {
	return s.Capture.valid() && s.Capture.Client.Address.IsPrivate() &&
		s.Source.IsValid() && s.Source.Addr() == s.Capture.Client.Address && s.Source.Port() != 0 &&
		s.Target.IsValid() && s.Target.Addr() == s.Capture.Xray.RealIP && domainPolicyTCPPublicIPv4(s.Target.Addr()) && (s.Target.Port() == 80 || s.Target.Port() == 443) &&
		proxyFirewallInterface.MatchString(s.Egress) && s.Egress != "lo" && s.Egress != s.Capture.Client.Interface
}

// The supported native baseline keeps the original client source address AND
// port. Exact reply marks/local routing deliver that transparent socket's
// packets; exact NOTRACK rules avoid creating an unrelated forwarded CT entry.
// NAT, nonstandard RPDB and foreign packet hooks are rejected by the original
// kernel observer before this plan can be issued. One flow may own table31000
// in a namespace at a time; this compiler never chooses another free table.
func compileDomainTCPBaselineFlow(s domainTCPBaselineFlowSpec) (PolicyEffectPlan, error) {
	if !s.valid() {
		return PolicyEffectPlan{}, ErrDomainTCPBaselineKernel
	}
	client := s.Source.Addr().String() + "/32"
	real := s.Target.Addr().String() + "/32"
	clientPort := strconv.Itoa(int(s.Source.Port()))
	realPort := strconv.Itoa(int(s.Target.Port()))
	p := PolicyEffectPlan{Generation: s.Capture.Xray.Generation}
	p.Effects = []PolicyEffect{
		{Tool: PolicyEffectIP, Add: []string{"-4", "route", "add", "local", client, "dev", "lo", "table", domainTCPBaselineTable, "proto", "static"}, Delete: []string{"-4", "route", "del", "local", client, "dev", "lo", "table", domainTCPBaselineTable, "proto", "static"}},
		{Tool: PolicyEffectIP, Add: []string{"-4", "rule", "add", "priority", domainTCPBaselineTable, "to", client, "iif", s.Egress, "fwmark", domainTCPBaselineMark, "lookup", domainTCPBaselineTable}, Delete: []string{"-4", "rule", "del", "priority", domainTCPBaselineTable, "to", client, "iif", s.Egress, "fwmark", domainTCPBaselineMark, "lookup", domainTCPBaselineTable}, Needs: []int{0}},
	}
	appendRule := func(table, hook string, tuple []string, action []string, needs []int) {
		body := append([]string{hook}, tuple...)
		body = append(body, action...)
		p.Effects = append(p.Effects, PolicyEffect{Tool: PolicyEffectIPTables, Add: append([]string{"-t", table, "-I", hook, "1"}, body[1:]...), Delete: append([]string{"-t", table, "-D"}, body...), Needs: needs})
	}
	out := []string{"-o", s.Egress, "-s", client, "-d", real, "-p", "tcp", "-m", "tcp", "--sport", clientPort, "--dport", realPort}
	in := []string{"-i", s.Egress, "-s", real, "-d", client, "-p", "tcp", "-m", "tcp", "--sport", realPort, "--dport", clientPort}
	appendRule("raw", "OUTPUT", out, []string{"-j", "CT", "--notrack"}, []int{0, 1})
	appendRule("raw", "PREROUTING", in, []string{"-j", "CT", "--notrack"}, []int{0, 1, 2})
	appendRule("mangle", "PREROUTING", in, []string{"-j", "MARK", "--set-xmark", domainTCPBaselineMark}, []int{0, 1, 2, 3})
	if _, err := PolicyEffectPlanDigest(p); err != nil {
		return PolicyEffectPlan{}, err
	}
	return p, nil
}
