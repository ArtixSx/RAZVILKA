package cloudflareprovider

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

const (
	SourceLocalRegistration = "local-registration"
	maxRegistrationText     = 1024
	maxRegistrationItems    = 16
	registrationTerms       = "cloudflare-client-current"
)

var (
	ErrRegistration          = errors.New("Cloudflare registration candidate is invalid")
	ErrRegistrationTerms     = errors.New("explicit Cloudflare terms acceptance is required")
	ErrRegistrationAPIAbsent = errors.New("Cloudflare registration API is not configured")
)

// RegistrationRequest is the complete request visible to an API adapter. It
// deliberately has no private-key field: a private key must never cross the
// registrar boundary.
type RegistrationRequest struct {
	PublicKey     string `json:"public_key"`
	AcceptTerms   bool   `json:"accept_terms"`
	TermsRevision string `json:"terms_revision"`
	Locale        string `json:"locale"`
	Model         string `json:"model"`
}

// RegistrationResponse contains server-issued private account material. Its
// secret fields are never JSON encoded or exposed through Candidate.Public.
// The optional ConsumerRegistrationAPI implements one bounded live request;
// registration is still not evidence of tunnel or service availability.
type RegistrationResponse struct {
	DeviceID      string   `json:"-"`
	AccessToken   string   `json:"-"`
	PeerPublicKey string   `json:"peer_public_key"`
	Addresses     []string `json:"addresses"`
	Endpoints     []string `json:"endpoints"`
	APISchema     string   `json:"api_schema"`
	TermsRevision string   `json:"terms_revision"`
}

func (RegistrationResponse) String() string   { return "[private Cloudflare registration response]" }
func (RegistrationResponse) GoString() string { return "[private Cloudflare registration response]" }

type RegistrationAPI interface {
	Register(context.Context, RegistrationRequest) (RegistrationResponse, error)
}

// RegistrationCandidate owns local and server secrets only in memory. Public
// returns a detached, non-runnable view. ImportCandidate persists only into the
// private store; a separate candidate scope controls tunnel material export.
type RegistrationCandidate struct {
	preview    Account
	privateKey []byte
	response   RegistrationResponse
}

func (candidate RegistrationCandidate) Public() Account {
	view := candidate.preview
	view.AssignedAddresses = append([]string(nil), candidate.preview.AssignedAddresses...)
	return view
}

func (candidate RegistrationCandidate) MarshalJSON() ([]byte, error) {
	return json.Marshal(candidate.Public())
}

func (RegistrationCandidate) String() string   { return "[private Cloudflare registration candidate]" }
func (RegistrationCandidate) GoString() string { return "[private Cloudflare registration candidate]" }

type Registrar struct {
	API    RegistrationAPI
	Random io.Reader
	Now    func() time.Time
	// CheckpointKey is an optional trusted local durability callback, invoked
	// before the first remote request. The API adapter never receives this key.
	CheckpointKey func([]byte) error
}

func (registrar Registrar) NewCandidate(ctx context.Context, acceptTerms bool) (RegistrationCandidate, error) {
	if !acceptTerms {
		return RegistrationCandidate{}, ErrRegistrationTerms
	}
	if registrar.API == nil {
		return RegistrationCandidate{}, ErrRegistrationAPIAbsent
	}
	if err := ctx.Err(); err != nil {
		return RegistrationCandidate{}, err
	}
	random := registrar.Random
	if random == nil {
		random = rand.Reader
	}
	privateKey, err := ecdh.X25519().GenerateKey(random)
	if err != nil {
		return RegistrationCandidate{}, ErrRegistration
	}
	privateBytes := append([]byte(nil), privateKey.Bytes()...)
	if registrar.CheckpointKey != nil {
		checkpoint := append([]byte(nil), privateBytes...)
		err := registrar.CheckpointKey(checkpoint)
		eraseBytes(checkpoint)
		if err != nil {
			eraseBytes(privateBytes)
			return RegistrationCandidate{}, ErrRegistration
		}
	}
	publicBytes := privateKey.PublicKey().Bytes()
	request := RegistrationRequest{
		PublicKey:     base64.StdEncoding.EncodeToString(publicBytes),
		AcceptTerms:   true,
		TermsRevision: registrationTerms,
		Locale:        "en_US",
		Model:         "RAZVILKA",
	}
	response, err := registrar.API.Register(ctx, request)
	if err != nil || ctx.Err() != nil || validateRegistrationResponse(response, request.TermsRevision) != nil {
		for index := range privateBytes {
			privateBytes[index] = 0
		}
		if ctx.Err() != nil {
			return RegistrationCandidate{}, ctx.Err()
		}
		return RegistrationCandidate{}, safeRegistrationError(err)
	}
	now := time.Now().UTC()
	if registrar.Now != nil {
		now = registrar.Now().UTC()
	}
	return makeRegistrationCandidate(privateBytes, publicBytes, response, now), nil
}

func makeRegistrationCandidate(privateBytes, publicBytes []byte, response RegistrationResponse, now time.Time) RegistrationCandidate {
	preview := Account{
		Provider:             "cloudflare",
		SourceKind:           SourceLocalRegistration,
		Ownership:            "locally-generated-candidate",
		Verification:         "registered-unverified",
		HasPrivateKey:        true,
		HasAccessToken:       true,
		HasDeviceID:          true,
		Format:               "cloudflare-registration-v1",
		Transport:            "wireguard",
		PublicKeyFingerprint: digest(publicBytes),
		AssignedAddresses:    canonicalRegistrationAddresses(response.Addresses),
		CreatedAt:            now,
		UpdatedAt:            now,
	}
	return RegistrationCandidate{preview: preview, privateKey: privateBytes, response: cloneRegistrationResponse(response)}
}

func (candidate RegistrationCandidate) snapshot() (Import, error) {
	if len(candidate.privateKey) != 32 || validateRegistrationResponse(candidate.response, registrationTerms) != nil {
		return Import{}, ErrRegistration
	}
	raw, err := json.Marshal(localRegistrationSnapshot{
		Schema: 1, PrivateKey: base64.StdEncoding.EncodeToString(candidate.privateKey),
		DeviceID: candidate.response.DeviceID, AccessToken: candidate.response.AccessToken,
		PeerPublicKey: candidate.response.PeerPublicKey, Addresses: append([]string(nil), candidate.response.Addresses...),
		Endpoints: append([]string(nil), candidate.response.Endpoints...), APISchema: candidate.response.APISchema,
		TermsRevision: candidate.response.TermsRevision,
	})
	if err != nil || len(raw) > MaxImportBytes {
		return Import{}, ErrRegistration
	}
	return parseStoredImport(SourceLocalRegistration, raw)
}

type localRegistrationSnapshot struct {
	Schema        int      `json:"schema"`
	PrivateKey    string   `json:"private_key"`
	DeviceID      string   `json:"device_id"`
	AccessToken   string   `json:"access_token"`
	PeerPublicKey string   `json:"peer_public_key"`
	Addresses     []string `json:"addresses"`
	Endpoints     []string `json:"endpoints"`
	APISchema     string   `json:"api_schema"`
	TermsRevision string   `json:"terms_revision"`
}

func inspectLocalRegistration(data []byte, view *Account) error {
	fields, err := readJSONObject(data)
	if err != nil || len(fields) != 9 {
		return ErrImport
	}
	for _, name := range []string{"schema", "private_key", "device_id", "access_token", "peer_public_key", "addresses", "endpoints", "api_schema", "terms_revision"} {
		if _, exists := fields[name]; !exists {
			return ErrImport
		}
	}
	var snapshot localRegistrationSnapshot
	if json.Unmarshal(data, &snapshot) != nil || snapshot.Schema != 1 {
		return ErrImport
	}
	privateBytes, err := wireGuardKey(snapshot.PrivateKey)
	if err != nil {
		return ErrImport
	}
	privateKey, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		return ErrImport
	}
	response := RegistrationResponse{
		DeviceID: snapshot.DeviceID, AccessToken: snapshot.AccessToken,
		PeerPublicKey: snapshot.PeerPublicKey, Addresses: snapshot.Addresses,
		Endpoints: snapshot.Endpoints, APISchema: snapshot.APISchema, TermsRevision: snapshot.TermsRevision,
	}
	if validateRegistrationResponse(response, registrationTerms) != nil {
		return ErrImport
	}
	view.HasPrivateKey, view.HasAccessToken, view.HasDeviceID = true, true, true
	view.Format, view.Transport = "cloudflare-registration-v1", "wireguard"
	view.PublicKeyFingerprint = digest(privateKey.PublicKey().Bytes())
	view.AssignedAddresses = canonicalRegistrationAddresses(snapshot.Addresses)
	return nil
}

func validateRegistrationResponse(response RegistrationResponse, termsRevision string) error {
	if !boundedSecret(response.DeviceID) || !boundedSecret(response.AccessToken) || response.TermsRevision != termsRevision || !boundedPublicText(response.APISchema) {
		return ErrRegistration
	}
	if _, err := wireGuardKey(response.PeerPublicKey); err != nil {
		return ErrRegistration
	}
	addresses := canonicalRegistrationAddresses(response.Addresses)
	if len(addresses) == 0 || len(addresses) != len(response.Addresses) || len(response.Endpoints) == 0 || len(response.Endpoints) > maxRegistrationItems {
		return ErrRegistration
	}
	seen := map[string]bool{}
	for _, endpoint := range response.Endpoints {
		host, portText, err := net.SplitHostPort(endpoint)
		if err != nil {
			return ErrRegistration
		}
		address, err := netip.ParseAddr(host)
		port, portErr := strconv.Atoi(portText)
		if err != nil || portErr != nil || !address.IsGlobalUnicast() || address.IsPrivate() || port < 1 || port > 65535 {
			return ErrRegistration
		}
		canonical := net.JoinHostPort(address.String(), strconv.Itoa(port))
		if endpoint != canonical || seen[canonical] {
			return ErrRegistration
		}
		seen[canonical] = true
	}
	return nil
}

func canonicalRegistrationAddresses(input []string) []string {
	if len(input) == 0 || len(input) > maxRegistrationItems {
		return nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(input))
	for _, raw := range input {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		// WARP client addresses are tunnel-local (commonly 172.16/12), so private
		// prefixes are valid here. Public endpoint validation remains stricter.
		if err != nil || !prefix.Addr().IsGlobalUnicast() || prefix.Addr().IsLoopback() || prefix.Addr().IsLinkLocalUnicast() {
			return nil
		}
		value := prefix.String()
		if seen[value] {
			return nil
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func boundedSecret(value string) bool {
	return value != "" && len(value) <= maxRegistrationText && !strings.ContainsAny(value, "\x00\r\n")
}

func boundedPublicText(value string) bool {
	return boundedSecret(value) && !strings.ContainsAny(value, "<>/\\")
}

func cloneRegistrationResponse(response RegistrationResponse) RegistrationResponse {
	response.Addresses = append([]string(nil), response.Addresses...)
	response.Endpoints = append([]string(nil), response.Endpoints...)
	return response
}

func (request RegistrationRequest) String() string {
	return fmt.Sprintf("Cloudflare registration request(public_key_fingerprint=%s)", digest([]byte(request.PublicKey)))
}
