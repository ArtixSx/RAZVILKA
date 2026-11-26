// Package nativeaccept prepares an opt-in native existing-account USQUE check.
// It issues no process/namespace authority. The ordinary graph has no concrete
// CORE issuer yet; the command remains blocked before account/process/network IO.
package nativeaccept

import (
	"context"
	"net/netip"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/systemprobe"
)

type Request struct {
	Enabled                 bool
	Transport               string
	Binary, BinarySHA256    string
	Account, AccountSHA256  string
	WorkParent              string
	SOCKSPort               uint16
	Timeout, CleanupTimeout time.Duration
}

// Acquisition is constructed from arguments plus a fresh native observation.
// It is not serialized, loaded from a receipt or accepted from an HTTP client.
// The issuer must additionally bind it to the original retained execution's
// review/control authority and actual network namespace. A WAN token is not a
// namespace grant. Acquire must retain the original scope even on partial error.
type Acquisition struct {
	Request Request
	Network systemprobe.WANProfile
}

// Issuer is a pending CORE integration dependency, NOT an implementation of an
// authority factory. Presence of an interface/callback does not prove admission.
// No OSProcessController, self-update-only barrier or reconstructed DTO adapter
// is provided here. Only a concrete original-execution issuer may supply it.
type Issuer interface {
	Acquire(context.Context, Acquisition) (Execution, error)
}

// Launch is a detached exact command and immutable asset/network binding.
// CORE must pin these assets, namespace and original review under the same
// retained scope, then consume one-use admission at the actual Cmd.Start.
// It must assign ProcessEnvironment explicitly (never inherit ambient proxies)
// and return only after the exact child's genuine passport/listener readiness.
// The short start admission must not hold the control lock across readiness.
// Start may return an error after launching: the retained Execution must still
// own and settle that exact child. No fallback, retry or PID adoption is allowed.
type Launch struct {
	Process            dataplane.ProcessSpec
	BinarySHA256       string
	ConfigSHA256       string
	Endpoint           netip.AddrPort
	Transport          string
	Environment        string
	ProcessEnvironment []string
}

// Execution is the pending retained CORE contract. Current must use the given
// new bounded context to check original review/control/network/namespace facts.
// StopAndJoin and VerifySettled must use the original retained cleanup grant,
// exact child birth/session, join/ECHILD/ACK and receipt-owned settlement. Process
// absence or a failed observer is insufficient. Release is allowed only after
// settlement and owned staged-secret removal; any failure keeps CORE's fence and
// recovery handle retained. These methods must honor their context deadlines.
type Execution interface {
	Current(context.Context) error
	Start(context.Context, Launch) error
	StopAndJoin(context.Context) error
	VerifySettled(context.Context) error
	Release(context.Context) error
}

// Observation describes the successful producer and independent readback at
// check time. Successful settlement stops the child; failed cleanup can leave
// settlement pending. In either case this is historical evidence, not a current
// tunnel or renewed receipt. No private bytes are output.
type Observation struct {
	CheckedAt       string `json:"checked_at"`
	OriginalExpiry  string `json:"original_valid_until"`
	BindingID       string `json:"binding_id"`
	RuntimeID       string `json:"runtime_id"`
	BinarySHA256    string `json:"binary_sha256"`
	SessionSHA256   string `json:"session_sha256"`
	EnvironmentID   string `json:"environment_id"`
	Endpoint        string `json:"endpoint"`
	ProofBasis      string `json:"proof_basis"`
	Warp            string `json:"warp"`
	Negotiated      bool   `json:"negotiated"`
	ReadbackMatched bool   `json:"readback_matched_during_check"`
}

// Result only contains fixed codes and allowlisted, validated observation data.
// Never append raw errors, command output, paths, account JSON, argv or logs.
type Result struct {
	Status        string       `json:"status"`
	Code          string       `json:"code"`
	Transport     string       `json:"transport,omitempty"`
	Settlement    string       `json:"settlement"`
	SecretCleanup string       `json:"staged_secret_cleanup"`
	Observation   *Observation `json:"observation,omitempty"`
}

func (r Result) ExitCode() int {
	if r.Status == "passed" {
		return 0
	}
	if r.Status == "blocked" {
		return 3
	}
	if r.Code == "arguments-invalid" || r.Code == "opt-in-required" {
		return 2
	}
	return 1
}
