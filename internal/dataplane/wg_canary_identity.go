package dataplane

import (
	"context"
	"encoding/base64"
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
	return a.inspectWGProbeIdentity(ctx, profile, "")
}

// The exception is usable only by a separately verified owned-runtime probe.
// It never authorizes creating another interface with the same private key.
func (a *WARPWireGuardAdapter) inspectWGProbeIdentity(ctx context.Context, profile []byte, ownedInterface string) error {
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
	if a.wgCommandTools != nil {
		tools = map[string]string{"wireguard": a.wgCommandTools.WG, "amneziawg": a.wgCommandTools.AWG}
	}
	if a.wg() == "" {
		return wgCanaryIdentityInspectionError("public identity inspection is unavailable")
	}
	// A missing companion CLI must not hide a live interface of that backend.
	links, err := a.wgProbeLinks(ctx)
	if err != nil {
		return errors.Join(wgCanaryIdentityInspectionError("link inventory is unavailable"), err)
	}
	for _, link := range links {
		if (link.kind == "wireguard" || link.kind == "amneziawg") && tools[link.kind] == "" {
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
		permitted := ""
		if kind == "wireguard" && a.ID() != "amneziawg" || kind == "amneziawg" && a.ID() == "amneziawg" {
			permitted = ownedInterface
		}
		identities, err := wgCanaryPublicInventoryForProbe(data, public, permitted)
		if err != nil {
			return err
		}
		for _, link := range links {
			if link.kind == kind && !identities[link.name] {
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
	return wgCanaryPublicInventoryForProbe(data, candidate, "")
}

func wgCanaryPublicInventoryForProbe(data []byte, candidate, ownedInterface string) (map[string]bool, error) {
	seen := map[string]bool{}
	ownedCandidate := false
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
		if fields[1] == candidate && fields[0] != ownedInterface {
			return nil, ErrWGCanaryIdentityInUse
		}
		if fields[1] == candidate && fields[0] == ownedInterface {
			ownedCandidate = true
		}
	}
	if ownedInterface != "" && !ownedCandidate {
		return nil, wgCanaryIdentityInspectionError("public inventory omitted the owned identity")
	}
	return seen, nil
}
