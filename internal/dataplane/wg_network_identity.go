package dataplane

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/netip"
	"slices"
	"strings"
)

// Script-friendly per-peer readback checks the live peer without reading the
// interface private key or printing PSKs. Output and diagnostic errors stay
// private; none is included in an admission error.
func (a *WARPWireGuardAdapter) verifyOwnedWGNetworkPeer(ctx context.Context, profile []byte) error {
	config, _, _, err := nativeWGConfig(string(profile))
	if err != nil {
		return err
	}
	section, peers := "", 0
	expected := map[string]string{}
	for _, line := range strings.Split(config, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			if section == "Peer" {
				peers++
			}
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found || section != "Peer" {
			continue
		}
		key = strings.TrimSpace(key)
		if _, duplicate := expected[key]; duplicate {
			return ErrWGCanaryIdentityInspection
		}
		expected[key] = strings.TrimSpace(value)
	}
	if peers != 1 || expected["PublicKey"] == "" || expected["Endpoint"] == "" {
		return ErrWGCanaryIdentityInspection
	}
	read := func(kind string) ([]string, error) {
		data, err := a.run(ctx, a.wg(), "show", a.interfaceName(), kind)
		defer clear(data)
		if err != nil || len(data) > 128<<10 {
			return nil, ErrWGCanaryIdentityInspection
		}
		fields := strings.Fields(string(data))
		if len(fields) == 0 || len(fields) > 2048 || fields[0] != expected["PublicKey"] {
			return nil, ErrWGCanaryIdentityInspection
		}
		return fields, nil
	}
	peer, err := read("peers")
	if err != nil || len(peer) != 1 {
		return errors.Join(err, ErrWGCanaryIdentityInspection)
	}
	endpoint, err := read("endpoints")
	if err != nil || len(endpoint) != 2 || endpoint[1] != expected["Endpoint"] {
		return errors.Join(err, ErrWGCanaryIdentityInspection)
	}
	allowed, err := read("allowed-ips")
	if err != nil {
		return err
	}
	normalize := func(raw string) ([]string, error) {
		var values []string
		seen := map[string]bool{}
		for _, value := range strings.FieldsFunc(raw, func(c rune) bool { return c == ',' || c == ' ' || c == '\t' }) {
			prefix, err := netip.ParsePrefix(value)
			if err != nil || prefix.Addr().Is4In6() || len(values) >= maxPolicyPrefixes || seen[prefix.Masked().String()] {
				return nil, ErrWGCanaryIdentityInspection
			}
			value = prefix.Masked().String()
			seen[value] = true
			values = append(values, value)
		}
		if len(values) == 0 {
			return nil, ErrWGCanaryIdentityInspection
		}
		slices.Sort(values)
		return values, nil
	}
	want, err := normalize(expected["AllowedIPs"])
	if err != nil {
		return err
	}
	actual, err := normalize(strings.Join(allowed[1:], ","))
	if err != nil || !slices.Equal(actual, want) {
		return errors.Join(err, ErrWGCanaryIdentityInspection)
	}
	psk, err := read("preshared-keys")
	if err != nil || len(psk) != 2 {
		return errors.Join(err, ErrWGCanaryIdentityInspection)
	}
	if expected["PresharedKey"] == "" {
		if psk[1] != "(none)" {
			return ErrWGCanaryIdentityInspection
		}
	} else {
		want, e1 := base64.StdEncoding.Strict().DecodeString(expected["PresharedKey"])
		actual, e2 := base64.StdEncoding.Strict().DecodeString(psk[1])
		defer clear(want)
		defer clear(actual)
		if e1 != nil || e2 != nil || len(want) != 32 || len(actual) != 32 || subtle.ConstantTimeCompare(want, actual) != 1 {
			return ErrWGCanaryIdentityInspection
		}
	}
	return ctx.Err()
}
