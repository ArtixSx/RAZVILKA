package usquediag

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"path/filepath"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/systemprobe"
)

const ownedPathBasis = "official-release-owned-path-inference"

// OwnedRuntimeRequest is assembled by the adapter from its ProcessSpec and
// trusted current epoch, never from HTTP/receipt fields. Observe is local-only.
type OwnedRuntimeRequest struct {
	Root, Binary, SOCKSAddress string
	Transport                  string
	Endpoint                   netip.AddrPort
	Environment                func(context.Context) (string, error)
}

type OwnedServiceProbe struct {
	ID, URL   string
	Challenge bool
}

type OwnedUDPProbe struct{ Target netip.AddrPort }

type OwnedNetworkRequest struct {
	SOCKSAddress string
	Services     []OwnedServiceProbe
	UDP          *OwnedUDPProbe
	Timeout      time.Duration
}

type OwnedApplicationProof struct {
	Warp, Colo, Loc, EgressIP string
	ConfirmedRoutes           []string
	UDPConfirmed              bool
}

// Identity contains no keys/config/argv/environ. PeerObservation describes
// exactly what procfs supplied; it never means ALPN or packet attribution.
type OwnedRuntimeIdentity struct {
	BindingID       string `json:"binding_id"`
	RuntimeID       string `json:"runtime_id"`
	BinarySHA256    string `json:"binary_sha256"`
	SessionSHA256   string `json:"session_sha256"`
	ArgsSHA256      string `json:"args_sha256"`
	EnvironmentID   string `json:"environment_id"`
	Transport       string `json:"transport"`
	Endpoint        string `json:"endpoint"`
	PeerObservation string `json:"peer_observation"`
	SocketBinding   string `json:"socket_binding"`
	SourceCommit    string `json:"source_commit"`
}

// This is evidence of a source-bound USQUE path carrying actual WARP/service
// requests. ProtocolPath is an inference from an independently pinned binary,
// its sole selected endpoint/args and successful owned SOCKS path. Negotiated
// ALPN/QUIC peer is deliberately not asserted. UDPForwarding is a separate
// optional nonce challenge through SOCKS UDP ASSOCIATE, not a TUN claim.
type OwnedRuntimeEvidence struct {
	Origin          string               `json:"origin"`
	CheckedAt       string               `json:"checked_at"`
	ValidUntil      string               `json:"valid_until"`
	Identity        OwnedRuntimeIdentity `json:"identity"`
	ProofBasis      string               `json:"proof_basis"`
	ProtocolPath    string               `json:"protocol_path"`
	Negotiated      bool                 `json:"negotiated"`
	Warp            string               `json:"warp"`
	Colo            string               `json:"colo,omitempty"`
	Loc             string               `json:"loc,omitempty"`
	EgressIP        string               `json:"egress_ip,omitempty"`
	ConfirmedRoutes []string             `json:"confirmed_routes,omitempty"`
	UDPForwarding   bool                 `json:"udp_forwarding"`
}

type OwnedProbeOptions struct {
	Enabled   bool
	Runtime   OwnedRuntimeRequest
	Network   OwnedNetworkRequest
	Authority func(context.Context) error
}

// ProbeOwnedUSQUE is an explicit worker/action entry point. It starts no
// process, changes no config/route, and never registers an account. Admission
// is re-read before network and after evidence, independently of receipt TTL.
func ProbeOwnedUSQUE(ctx context.Context, options OwnedProbeOptions) (OwnedRuntimeEvidence, error) {
	return probeOwnedUSQUE(ctx, options, observeOwnedUSQUE, probeOwnedNetwork, time.Now)
}

func probeOwnedUSQUE(ctx context.Context, o OwnedProbeOptions, observe func(context.Context, OwnedRuntimeRequest) (OwnedRuntimeIdentity, error), probe func(context.Context, OwnedNetworkRequest) (OwnedApplicationProof, error), now func() time.Time) (OwnedRuntimeEvidence, error) {
	if !o.Enabled || o.Authority == nil {
		return OwnedRuntimeEvidence{}, errors.New("owned-probe-admission-required")
	}
	if err := validateOwnedRuntime(o.Runtime); err != nil {
		return OwnedRuntimeEvidence{}, err
	}
	if o.Runtime.SOCKSAddress != o.Network.SOCKSAddress {
		return OwnedRuntimeEvidence{}, errors.New("owned-probe-listener-mismatch")
	}
	if err := validateOwnedNetworkRequest(o.Network); err != nil {
		return OwnedRuntimeEvidence{}, err
	}
	window, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	ctx = window
	if err := ctx.Err(); err != nil {
		return OwnedRuntimeEvidence{}, errors.New("owned-probe-canceled")
	}
	if err := o.Authority(ctx); err != nil {
		return OwnedRuntimeEvidence{}, errors.New("owned-probe-admission-refused")
	}
	started := now()
	before, err := observe(ctx, o.Runtime)
	if err != nil {
		return OwnedRuntimeEvidence{}, err
	}
	if err := o.Authority(ctx); err != nil {
		return OwnedRuntimeEvidence{}, errors.New("owned-probe-admission-refused")
	}
	app, err := probe(ctx, o.Network)
	if err != nil {
		return OwnedRuntimeEvidence{}, err
	}
	after, err := observe(ctx, o.Runtime)
	if err != nil || before != after {
		return OwnedRuntimeEvidence{}, errors.New("owned-probe-runtime-changed")
	}
	if err := o.Authority(ctx); err != nil {
		return OwnedRuntimeEvidence{}, errors.New("owned-probe-admission-refused")
	}
	checked := now()
	if ctx.Err() != nil || checked.Before(started) || checked.Sub(started) > 30*time.Second || (app.Warp != "on" && app.Warp != "plus") {
		return OwnedRuntimeEvidence{}, errors.New("owned-probe-window-invalid")
	}
	return OwnedRuntimeEvidence{Origin: "managed-usque-canary", CheckedAt: checked.UTC().Format(time.RFC3339Nano), ValidUntil: checked.Add(MaxCanaryAge).UTC().Format(time.RFC3339Nano), Identity: after, ProofBasis: ownedPathBasis, ProtocolPath: after.Transport, Warp: app.Warp, Colo: app.Colo, Loc: app.Loc, EgressIP: app.EgressIP, ConfirmedRoutes: append([]string{}, app.ConfirmedRoutes...), UDPForwarding: app.UDPConfirmed}, nil
}

// CanaryEvidence keeps the existing receipt path/layout while carrying a typed
// managed proof. It deliberately leaves the legacy installed-session BindingID
// empty; the legacy capability evaluator cannot adopt this different identity.
func (e OwnedRuntimeEvidence) CanaryEvidence() CanaryEvidence {
	copy := e
	copy.ConfirmedRoutes = append([]string{}, e.ConfirmedRoutes...)
	return CanaryEvidence{CheckedAt: e.CheckedAt, ValidUntil: e.ValidUntil, Transport: e.ProtocolPath, Endpoint: e.Identity.Endpoint, Warp: e.Warp, Colo: e.Colo, Loc: e.Loc, EgressIP: e.EgressIP, ConfirmedRoutes: append([]string{}, e.ConfirmedRoutes...), Owned: &copy}
}

// ObserveOwnedUSQUE only reads local runtime/epoch facts; suitable for a GET
// readback callback. It performs no tunnel/service probe or registration.
func ObserveOwnedUSQUE(ctx context.Context, request OwnedRuntimeRequest) (OwnedRuntimeIdentity, error) {
	if err := validateOwnedRuntime(request); err != nil {
		return OwnedRuntimeIdentity{}, err
	}
	return observeOwnedUSQUE(ctx, request)
}

// OwnedUSQUEEnvironment adapts the existing adapter FreshProfile callback. No
// cached/receipt/UI profile is accepted; observing the epoch remains local.
func OwnedUSQUEEnvironment(fresh func(context.Context) (string, error)) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		if fresh == nil {
			return "", errors.New("owned-runtime-epoch-unavailable")
		}
		profile, err := fresh(ctx)
		if err != nil || !systemprobe.ValidWANProfileID(profile) {
			return "", errors.New("owned-runtime-epoch-unavailable")
		}
		data, _ := json.Marshal([]string{"usque-environment-v1", profile})
		digest := sha256.Sum256(data)
		return hex.EncodeToString(digest[:]), nil
	}
}

// SelectedOwnedUSQUEEndpoint returns the explicit IPv4 pin for the existing
// strict adapter ABI. It rejects upstream's implicit H2 default and DNS names.
func SelectedOwnedUSQUEEndpoint(session []byte, transport string) (netip.AddrPort, error) {
	values, err := ownedConfigValues(session)
	if err != nil || (transport != "HTTP/2" && transport != "QUIC") {
		return netip.AddrPort{}, errors.New("owned-runtime-endpoint-invalid")
	}
	key := "endpoint_v4"
	if transport == "HTTP/2" {
		key = "endpoint_h2_v4"
	}
	var raw string
	if json.Unmarshal(values[key], &raw) != nil {
		return netip.AddrPort{}, errors.New("owned-runtime-endpoint-invalid")
	}
	address, err := netip.ParseAddr(raw)
	if err != nil || !address.Is4() || address.Is4In6() || address.String() != raw || !ownedPublicAddress(address) {
		return netip.AddrPort{}, errors.New("owned-runtime-endpoint-invalid")
	}
	return netip.AddrPortFrom(address, 443), nil
}

// Upstream decodes a struct and matches JSON field names case-insensitively.
// Admit only canonical lower-case, unique top-level keys so a map read cannot
// select a different pin from the executable's struct decoder.
func ownedConfigValues(raw []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return nil, errors.New("owned-runtime-config-invalid")
	}
	values := map[string]json.RawMessage{}
	for decoder.More() {
		name, err := decoder.Token()
		key, ok := name.(string)
		if err != nil || !ok || key != strings.ToLower(key) {
			return nil, errors.New("owned-runtime-config-invalid")
		}
		if _, duplicate := values[key]; duplicate {
			return nil, errors.New("owned-runtime-config-invalid")
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return nil, errors.New("owned-runtime-config-invalid")
		}
		values[key] = value
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return nil, errors.New("owned-runtime-config-invalid")
	}
	var trailing json.RawMessage
	if decoder.Decode(&trailing) != io.EOF {
		return nil, errors.New("owned-runtime-config-invalid")
	}
	return values, nil
}

func validateOwnedRuntime(r OwnedRuntimeRequest) error {
	if !filepath.IsAbs(r.Root) || !filepath.IsAbs(r.Binary) || r.Environment == nil || (r.Transport != "HTTP/2" && r.Transport != "QUIC") || !r.Endpoint.IsValid() || r.Endpoint.Port() != 443 || r.Endpoint.Addr().Is4In6() || !r.Endpoint.Addr().Is4() || !ownedPublicAddress(r.Endpoint.Addr()) {
		return errors.New("owned-runtime-options-invalid")
	}
	// The existing adapter/verifier has no outer --ipv6 flag. Support its exact
	// IPv4 ABI; adding IPv6 requires an explicit strict-args profile, not a guess.
	address, err := netip.ParseAddrPort(r.SOCKSAddress)
	if err != nil || !address.Addr().Is4() || !address.Addr().IsLoopback() || address.Port() < 1024 || address.String() != r.SOCKSAddress {
		return errors.New("owned-runtime-listener-invalid")
	}
	return nil
}

func ownedIdentityBinding(i OwnedRuntimeIdentity) string {
	data, _ := json.Marshal([]string{"owned-usque-path-v1", i.RuntimeID, i.BinarySHA256, i.SessionSHA256, i.ArgsSHA256, i.EnvironmentID, i.Transport, i.Endpoint, i.PeerObservation, i.SocketBinding, i.SourceCommit})
	s := sha256.Sum256(data)
	return hex.EncodeToString(s[:])
}

// OwnedEvidenceFresh checks a trusted producer-owned receipt's current binding
// and age. Digests bind runtime identity, not the provenance of proof fields;
// imported or client-declared fields must never acquire probe/apply authority.
func OwnedEvidenceFresh(e OwnedRuntimeEvidence, current OwnedRuntimeIdentity, now time.Time) bool {
	checked, a := time.Parse(time.RFC3339Nano, e.CheckedAt)
	until, b := time.Parse(time.RFC3339Nano, e.ValidUntil)
	valid := stringsHasOwnedRuntime(current) && safeOwnedEvidence(e)
	return valid && a == nil && b == nil && e.Origin == "managed-usque-canary" && e.ProofBasis == ownedPathBasis && !e.Negotiated && (e.Warp == "on" || e.Warp == "plus") && e.ProtocolPath == current.Transport && e.Identity == current && canaryDigest(current.BindingID) && current.BindingID == ownedIdentityBinding(current) && checked.Before(until) && !checked.After(now) && now.Before(until) && until.Sub(checked) <= MaxCanaryAge
}

func safeOwnedEvidence(e OwnedRuntimeEvidence) bool {
	if !stringsHasOwnedRuntime(e.Identity) || e.Identity.BindingID != ownedIdentityBinding(e.Identity) || e.Origin != "managed-usque-canary" || e.ProofBasis != ownedPathBasis || e.ProtocolPath != e.Identity.Transport || e.Negotiated || (e.Warp != "on" && e.Warp != "plus") || len(e.ConfirmedRoutes) > 8 {
		return false
	}
	if _, err := time.Parse(time.RFC3339Nano, e.CheckedAt); err != nil {
		return false
	}
	if _, err := time.Parse(time.RFC3339Nano, e.ValidUntil); err != nil {
		return false
	}
	if e.Colo != "" && !coloPattern.MatchString(e.Colo) || e.Loc != "" && !locPattern.MatchString(e.Loc) {
		return false
	}
	if e.EgressIP != "" {
		address, err := netip.ParseAddr(e.EgressIP)
		if err != nil || address.Is4In6() || address.String() != e.EgressIP || !ownedPublicAddress(address) {
			return false
		}
	}
	seen := map[string]bool{}
	for _, id := range e.ConfirmedRoutes {
		if !ownedServiceID(id) || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}
