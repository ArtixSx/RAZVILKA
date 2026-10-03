package dataplane

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// ErrWGCanaryIdentityInUse is a local safety rejection, not a failed service or
// handshake. It must not downgrade the live peer or authorize its restart.
var ErrWGCanaryIdentityInUse = errors.New("WireGuard candidate identity is already in use; simultaneous verification would risk the live peer")

// Unknown local inventory also grants no network mutation or peer reputation.
var ErrWGCanaryIdentityInspection = errors.New("WireGuard candidate identity inspection is inconclusive")

func wgCanaryIdentityInspectionError(reason string) error {
	return fmt.Errorf("%w: %s", ErrWGCanaryIdentityInspection, reason)
}

// Compare public identities only: no showconf/dump, private key or PSK readback.
// Reject even if the server key/endpoint/PSK differs: these are not proof that
// two configurations cannot reach the same remote peer. Includes foreign links,
// other RAZVILKA engines and configured links that are currently administratively
// down. External network owners must serialize changes with the coordinator.
func (a *WARPWireGuardAdapter) ensureWGCanaryIdentityFree(ctx context.Context, profile []byte) error {
	public, err := wgRuntimePublicKey(profile)
	if err != nil {
		return err
	}
	wg := *a
	wg.EngineID = "wireguard"
	awg := *a
	awg.EngineID = "amneziawg"
	// WG is an explicit override for this adapter's CLI only.
	if a.ID() == "amneziawg" {
		wg.WG = ""
	} else {
		awg.WG = ""
	}
	tools := map[string]string{"wireguard": wg.wg(), "amneziawg": awg.wg()}
	if a.wg() == "" {
		return wgCanaryIdentityInspectionError("public identity inspection is unavailable")
	}
	// A missing companion CLI must not hide a live interface of that backend.
	data, err := a.run(ctx, a.ip(), "-j", "-d", "link", "show")
	if err != nil || len(data) > 1<<20 {
		return wgCanaryIdentityInspectionError("link inventory is unavailable")
	}
	var links []struct {
		Name     string `json:"ifname"`
		LinkInfo struct {
			Kind string `json:"info_kind"`
		} `json:"linkinfo"`
	}
	if json.Unmarshal(data, &links) != nil || links == nil || len(links) > 4096 {
		return wgCanaryIdentityInspectionError("link inventory is invalid")
	}
	for _, link := range links {
		if (link.LinkInfo.Kind == "wireguard" || link.LinkInfo.Kind == "amneziawg") && tools[link.LinkInfo.Kind] == "" {
			return wgCanaryIdentityInspectionError("cannot inspect an existing tunnel backend")
		}
	}
	for _, kind := range []string{"wireguard", "amneziawg"} {
		tool := tools[kind]
		if tool == "" {
			continue
		}
		data, err := a.run(ctx, tool, "show", "all", "public-key")
		if err != nil || len(data) > 1<<20 {
			return wgCanaryIdentityInspectionError("public identity readback failed")
		}
		identities, err := wgCanaryPublicInventory(data, public)
		if err != nil {
			return err
		}
		for _, link := range links {
			if link.LinkInfo.Kind == kind && !identities[link.Name] {
				return wgCanaryIdentityInspectionError("public inventory omitted a kernel tunnel")
			}
		}
	}
	return ctx.Err()
}

func wgCanaryPublicIdentities(data []byte, candidate string) error {
	_, err := wgCanaryPublicInventory(data, candidate)
	return err
}

func wgCanaryPublicInventory(data []byte, candidate string) (map[string]bool, error) {
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 || len(fields[0]) > 15 || strings.ContainsAny(fields[0], "/\\\x00") || seen[fields[0]] || len(seen) >= 4096 {
			return nil, wgCanaryIdentityInspectionError("public identity inventory is invalid")
		}
		seen[fields[0]] = true
		if fields[1] == "(none)" {
			continue
		}
		key, err := base64.StdEncoding.Strict().DecodeString(fields[1])
		if err != nil || len(key) != 32 {
			return nil, wgCanaryIdentityInspectionError("public identity inventory is invalid")
		}
		if fields[1] == candidate {
			return nil, ErrWGCanaryIdentityInUse
		}
	}
	return seen, nil
}
