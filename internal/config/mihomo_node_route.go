package config

import (
	"errors"
	"net/netip"
	"strings"
)

// Explicit manual scope only. This is syntax normalization, never a runtime,
// service, node-health or automatic-selection permission.
func NormalizeMihomoNodeSources(sources []string) ([]string, error) {
	if len(sources) == 0 || len(sources) > 64 {
		return nil, errors.New("explicit Mihomo client scope required")
	}
	normalized, err := NormalizeSources(sources)
	if err != nil || len(normalized) == 0 || len(normalized) > 64 {
		return nil, errors.New("invalid Mihomo client scope")
	}
	for _, raw := range normalized {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() {
			return nil, errors.New("Mihomo client scope requires canonical private IPv4")
		}
		private := false
		for _, space := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"} {
			allowed := netip.MustParsePrefix(space)
			private = private || prefix.Bits() >= allowed.Bits() && allowed.Contains(prefix.Addr())
		}
		if !private {
			return nil, errors.New("Mihomo client scope requires private IPv4")
		}
	}
	return normalized, nil
}

// This dedicated writer does not add Mihomo to legacy node health, groups or
// AUTO. Only the original manual Apply may call it after its own fresh proof.
func (s *Store) ApplyMihomoNodeRouteScopeWithImage(id, node string, sources []string, revision uint64) (Config, func() error, error) {
	if id == "" || len(id) > 128 || strings.ContainsAny(id, "/\\\x00\r\n") || !validPolicyNode(node) {
		return Config{}, nil, errors.New("invalid manual Mihomo node selection")
	}
	normalized, err := NormalizeMihomoNodeSources(sources)
	if err != nil {
		return Config{}, nil, err
	}
	return s.commitNodeRouteWithImage(id, "mihomo:"+node, &normalized, revision)
}
