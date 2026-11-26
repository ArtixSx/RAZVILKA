package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"time"

	"github.com/ArtixSx/razvilka/internal/providerprofile"
)

// NewExactXrayNodeCheckerSlots checks canonical NodeStore VLESS material with
// a native, isolated Xray process. The caller must give it a distinct state
// directory. Its default ports do not overlap the Sing-box checker's slots.
// Xray evidence is deliberately identified as xray:<node>, never sing-box.
func NewExactXrayNodeCheckerSlots(stateRoot string, slots int) *ExactNodeChecker {
	c := NewExactNodeCheckerSlots(stateRoot, slots)
	c.engine, c.Port = "xray", 19181+MaxExactNodeSlots
	return c
}

// EngineID is fixed at construction and identifies the runtime whose path
// was measured. An empty engine retains the historical Sing-box constructor.
func (c *ExactNodeChecker) EngineID() string {
	if c != nil && c.engine == "xray" {
		return "xray"
	}
	return "sing-box"
}

func exactXrayProfile(raw []byte) (providerprofile.VLESSProfile, error) {
	p, err := providerprofile.VLESSProfileFromJSON(raw)
	if err != nil {
		return p, err
	}
	// The exact-node boundary cannot accept a supplied selector tag or chain.
	if _, err := inspectExactNodeOutbound(raw); err != nil {
		return p, err
	}
	_, _, err = providerprofile.CompileXrayConfig(p)
	return p, err
}

func (c *ExactNodeChecker) prepareXraySession(ctx context.Context, session exactNodeSession, request NodeCheckRequest, endpoint exactNodeEndpoint) (exactNodeSession, error) {
	if session.Spec.Binary == "" {
		return session, ErrExactNodeRuntime
	}
	data, err := compilePinnedXrayNodeConfig(request.Outbound, endpoint, session.Port)
	if err != nil {
		return session, err
	}
	defer clear(data)
	if !exactSingBoxTransportSupported(request.Outbound) {
		// Recheck after DNS/prefilter and immediately before materialization;
		// a runtime replacement cannot make a stale capability usable.
		if err := c.requireXHTTPRuntime(ctx, session.Spec.Binary); err != nil {
			return session, err
		}
	}
	if err := os.MkdirAll(session.Root, 0o700); err != nil {
		return session, errors.New("candidate directory unavailable")
	}
	if err := writeAtomic(session.Spec.MatchArg, data, 0o600); err != nil {
		return session, errors.New("write candidate")
	}
	checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(checkCtx, session.Spec.Binary, "run", "-test", "-config", session.Spec.MatchArg).CombinedOutput()
	clear(output) // Runtime diagnostics may contain credentials or endpoints.
	if err != nil {
		return session, errors.New("xray check failed")
	}
	return session, nil
}

func compilePinnedXrayNodeConfig(raw []byte, endpoint exactNodeEndpoint, port int) ([]byte, error) {
	p, err := exactXrayProfile(raw)
	if err != nil {
		return nil, ErrExactNodeUnsupported
	}
	if !endpoint.Pinned.IsValid() || !publicNodeAddresses([]netip.Addr{endpoint.Pinned}) || p.Server != endpoint.Host || p.Port != endpoint.Port {
		return nil, errors.New("candidate endpoint is not pinned to its profile")
	}
	// Retain SNI before substituting the exact IP selected by the prefilter.
	if p.ServerName == "" {
		p.ServerName = p.Server
	}
	p.Server = endpoint.Pinned.String()
	data, _, err := providerprofile.CompileXrayConfig(p)
	if err != nil {
		return nil, ErrExactNodeUnsupported
	}
	defer clear(data)
	var document map[string]any
	if json.Unmarshal(data, &document) != nil {
		return nil, errors.New("invalid candidate")
	}
	document["inbounds"] = []any{map[string]any{
		"tag": "rz-node-check-in", "listen": "127.0.0.1", "port": port,
		"protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": false},
	}}
	return json.MarshalIndent(document, "", "  ")
}
