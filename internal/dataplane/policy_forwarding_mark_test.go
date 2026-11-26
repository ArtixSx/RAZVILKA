package dataplane

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestProxyFirewallManagedMarkNormalizationIsStrict(t *testing.T) {
	planned := []string{"-i", "br0", "-o", "rz-sing", "-s", "192.168.1.25/32", "-d", "198.51.100.20/32", "-m", "mark", "--mark", LANPolicyGateMatch, "-j", "ACCEPT"}
	actual := []string{"-s", "192.168.1.25/32", "-d", "198.51.100.20/32", "-i", "br0", "-o", "rz-sing", "-m", "mark", "--mark", "536870912/671088640", "-j", "ACCEPT"}
	if proxyFirewallRuleKey(planned) != proxyFirewallRuleKey(actual) || strings.HasPrefix(proxyFirewallRuleKey(planned), "!") {
		t.Fatal("numeric mark equivalent/reordered fields did not normalize")
	}
	for _, mark := range []string{"0x20000000/0x20000000", "0x28000000/0x28000000", "0x20000000", "0x100000000/0x28000000", "-1/0x28000000", "0x20000000/garbage", "0x20000000/0x28000000/0x1"} {
		changed := append([]string(nil), actual...)
		changed[11] = mark
		if proxyFirewallRuleKey(changed) == proxyFirewallRuleKey(planned) {
			t.Fatal("changed/unknown mark became owned", mark)
		}
	}
	duplicated := append(append([]string(nil), planned...), "--mark", LANPolicyGateMatch)
	if !strings.HasPrefix(proxyFirewallRuleKey(duplicated), "!") {
		t.Fatal("duplicate mark selector accepted")
	}
}

func TestManagedForwardingReorderedKernelReadbackAndChangedMask(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		for _, changedMask := range []bool{false, true} {
			t.Run(fmt.Sprintf("ipv6=%t/changed-mask=%t", v6, changedMask), func(t *testing.T) {
				a, r, state := proxyForwardingFixture(t)
				base := a.Runner
				if v6 {
					state.Prefixes = []string{"2001:db8::20/128"}
					state.Rules = []PolicyRule{{Source: "fd00::25/128", Destination: state.Prefixes[0]}}
					a.Runner = networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
						joined := strings.Join(args, " ")
						if name == "ip" && joined == "-6 route get fd00::25" {
							return []byte("fd00::25 dev br0 src fd00::1"), nil
						}
						if name == "ip" && joined == "-6 route show table main match fd00::25/128" {
							return []byte("fd00::/64 dev br0 proto kernel metric 256"), nil
						}
						return base.Run(ctx, name, args...)
					})
				}
				state.NetworkPolicyGeneration = strings.Repeat("a", 64)
				state.Rules[0].Ingress, state.Rules[0].Managed = "br0", true
				initializePolicyLayout(&state)
				var err error
				state.Forwarding, err = a.compileForwarding(context.Background(), state)
				if err != nil {
					t.Fatal(err)
				}
				if err := a.installForwarding(context.Background(), state); err != nil {
					t.Fatal(err)
				}
				installed := a.Runner
				a.Runner = networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
					output, err := installed.Run(ctx, name, args...)
					if err != nil || (name != "iptables" && name != "ip6tables") || len(args) != 3 || args[2] != "-S" {
						return output, err
					}
					lines := strings.Split(string(output), "\n")
					for index, line := range lines {
						fields := strings.Fields(line)
						if len(fields) < 4 || fields[0] != "-A" || !strings.Contains(line, state.Forwarding.Chain) || len(fields)%2 != 0 {
							continue
						}
						reordered := append([]string(nil), fields[:2]...)
						for i := len(fields) - 2; i >= 2; i -= 2 {
							value := fields[i+1]
							if fields[i] == "--mark" {
								value = "536870912/671088640"
								if changedMask {
									value = "0x20000000/0x20000000"
								}
							}
							reordered = append(reordered, fields[i], value)
						}
						lines[index] = strings.Join(reordered, " ")
					}
					return []byte(strings.Join(lines, "\n")), nil
				})
				calls := len(r.firewall.calls)
				if err := a.verifyForwarding(context.Background(), state); (err != nil) != changedMask {
					t.Fatal("kernel mark/readback verdict mismatch", err)
				}
				err = a.removeForwarding(context.Background())
				if (err != nil) != changedMask {
					t.Fatal("cleanup mark/readback verdict mismatch", err)
				}
				if changedMask {
					for _, call := range r.firewall.calls[calls:] {
						if strings.Contains(call, " -D ") && strings.Contains(call, "--mark") || strings.Contains(call, " -F ") {
							t.Fatal("changed mark grant was deleted", call)
						}
					}
					if !regularFile(a.forwardingPath()) {
						t.Fatal("unknown grant lost retained ownership lease")
					}
					tool := "iptables"
					if v6 {
						tool = "ip6tables"
					}
					if len(r.firewall.table(tool, "filter")[state.Forwarding.Chain]) == 0 || len(r.firewall.table(tool, "nat")[state.Forwarding.Chain]) == 0 {
						t.Fatal("unknown marked chain was removed")
					}
				}
			})
		}
	}
}
