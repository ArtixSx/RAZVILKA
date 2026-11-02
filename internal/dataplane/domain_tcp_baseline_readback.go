package dataplane

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"slices"
)

// Pure exact comparison only. Callers must authenticate the original live
// resource/COMMON intent before omitting any of these owned rows from a view.
func domainTCPBaselineFlowReadback(image DomainTCPBaselineReadImage, rows []backendInventoryRow, spec domainTCPBaselineFlowSpec) (DomainTCPBaselineReadImage, []backendInventoryRow, []int, error) {
	plan, err := compileDomainTCPBaselineFlow(spec)
	if err != nil {
		return image, nil, nil, err
	}
	counts := make([]int, 5)
	strip := func(raw []byte, isRule bool) ([]byte, error) {
		if len(raw) > 2<<20 || nfqws2ManagedUniqueJSON(raw) != nil {
			return nil, ErrDomainTCPBaselineKernel
		}
		var entries []json.RawMessage
		if json.Unmarshal(raw, &entries) != nil {
			return nil, ErrDomainTCPBaselineKernel
		}
		filtered := make([]json.RawMessage, 0, len(entries))
		for _, entry := range entries {
			var fields map[string]json.RawMessage
			if json.Unmarshal(entry, &fields) != nil {
				return nil, ErrDomainTCPBaselineKernel
			}
			read := func(name string) string {
				var v string
				if json.Unmarshal(fields[name], &v) == nil {
					return v
				}
				return string(fields[name])
			}
			owned := read("table") == domainTCPBaselineTable
			if isRule {
				owned = owned || read("priority") == domainTCPBaselineTable || read("fwmark") == "0x525a0001"
			}
			if !owned {
				filtered = append(filtered, entry)
				continue
			}
			if read("table") != domainTCPBaselineTable {
				return nil, ErrDomainTCPBaselineKernel
			}
			prefix, parseErr := netip.ParsePrefix(read("dst"))
			if parseErr != nil {
				a, e := netip.ParseAddr(read("dst"))
				if e != nil {
					return nil, ErrDomainTCPBaselineKernel
				}
				prefix = netip.PrefixFrom(a, 32)
			}
			if prefix != netip.PrefixFrom(spec.Source.Addr(), 32) {
				return nil, ErrDomainTCPBaselineKernel
			}
			if isRule {
				for key := range fields {
					if !slices.Contains([]string{"priority", "src", "dst", "table", "iif", "fwmark", "fwmask", "protocol"}, key) {
						return nil, ErrDomainTCPBaselineKernel
					}
				}
				if read("priority") != domainTCPBaselineTable || read("src") != "all" || read("iif") != spec.Egress || read("fwmark") != "0x525a0001" || len(fields["fwmask"]) != 0 && read("fwmask") != "0xffffffff" || len(fields["protocol"]) != 0 && read("protocol") != "boot" && read("protocol") != "static" {
					return nil, ErrDomainTCPBaselineKernel
				}
				counts[1]++
			} else {
				for key := range fields {
					if !slices.Contains([]string{"type", "dst", "dev", "table", "protocol", "scope", "flags"}, key) {
						return nil, ErrDomainTCPBaselineKernel
					}
				}
				if read("type") != "local" || read("dev") != "lo" || read("protocol") != "static" || read("scope") != "host" || len(fields["flags"]) != 0 && !bytes.Equal(fields["flags"], []byte("[]")) {
					return nil, ErrDomainTCPBaselineKernel
				}
				counts[0]++
			}
		}
		return json.Marshal(filtered)
	}
	image.Rules, err = strip(image.Rules, true)
	if err != nil {
		return image, nil, nil, err
	}
	image.Routes, err = strip(image.Routes, false)
	if err != nil {
		return image, nil, nil, err
	}
	filtered := make([]backendInventoryRow, 0, len(rows))
	for _, row := range rows {
		matched := -1
		for i := 2; i < len(plan.Effects); i++ {
			expected, e := domainTCPCaptureEffectRow(plan.Effects[i])
			if e != nil {
				return image, nil, nil, e
			}
			if row.Family == expected.Family && row.Table == expected.Table && slices.Equal(row.Tokens, expected.Tokens) {
				matched = i
				break
			}
		}
		if matched < 0 {
			filtered = append(filtered, row)
		} else {
			counts[matched]++
		}
	}
	for _, count := range counts {
		if count > 1 {
			return image, nil, nil, ErrDomainTCPBaselineKernel
		}
	}
	return image, filtered, counts, nil
}
