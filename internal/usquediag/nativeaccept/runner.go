package nativeaccept

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/routeidentity"
	"github.com/ArtixSx/razvilka/internal/systemprobe"
	"github.com/ArtixSx/razvilka/internal/usquediag"
)

type stagedAssets interface {
	Path() string
	Verify(context.Context) error
	RemoveSecret(context.Context) error
	Close() error
}

// Private test seams only. Run always selects genuine producer/observer/native
// IO; neither arguments nor saved JSON can replace these functions.
type runnerIO struct {
	goos, goarch string
	now          func() time.Time
	fresh        func(context.Context) (systemprobe.WANProfile, error)
	load         func(context.Context, Request) ([]byte, error)
	stage        func(context.Context, Request, []byte) (stagedAssets, error)
	produce      func(context.Context, usquediag.OwnedProbeOptions) (usquediag.OwnedRuntimeEvidence, error)
	observe      func(context.Context, usquediag.OwnedRuntimeRequest) (usquediag.OwnedRuntimeIdentity, error)
}

func Run(ctx context.Context, request Request, issuer Issuer) Result {
	return run(ctx, request, issuer, runnerIO{
		goos: runtime.GOOS, goarch: runtime.GOARCH, now: time.Now,
		fresh: systemprobe.FreshWANProfile, load: loadAssets, stage: stageAssets,
		produce: usquediag.ProbeOwnedUSQUE, observe: usquediag.ObserveOwnedUSQUE,
	})
}

func run(parent context.Context, r Request, issuer Issuer, io runnerIO) (result Result) {
	result = Result{Status: "failed", Code: "check-failed", Settlement: "not-acquired", SecretCleanup: "not-staged"}
	if code := validate(r); code != "" {
		result.Code = code
		return result
	}
	result.Transport = r.Transport
	if io.goos != "linux" {
		result.Status, result.Code = "blocked", "native-linux-required"
		return result
	}
	// This cut precedes even native epoch observation and all asset IO. An
	// ambient process controller/receipt/callback cannot fill the missing issuer.
	if issuer == nil {
		result.Status, result.Code = "blocked", "core-retained-issuer-unavailable"
		return result
	}
	if !usquediag.OwnedUSQUENativeBinaryAudited(r.BinarySHA256, io.goarch) {
		result.Code = "binary-not-audited-for-native-architecture"
		return result
	}
	if parent == nil {
		result.Code = "context-required"
		return result
	}
	ctx, cancel := context.WithTimeout(parent, r.Timeout)
	defer cancel()
	if ctx.Err() != nil {
		result.Code = "check-canceled"
		return result
	}
	network, err := io.fresh(ctx)
	if err != nil || ctx.Err() != nil || !systemprobe.ValidWANProfileID(network.ID) || network.WANInterface == "" {
		result.Code = "native-network-identity-unavailable"
		return result
	}
	execution, acquireErr := issuer.Acquire(ctx, Acquisition{Request: r, Network: network})
	if execution == nil {
		result.Code = "core-acquisition-refused"
		return result
	}
	result.Settlement = "pending"
	var staged stagedAssets
	// Always settle the original scope, including Acquire/Start partial errors.
	// Cancellation does not mint fresh authority: this separate bounded context
	// is usable only by the original execution's retained cleanup grant.
	defer func() {
		cleanup, done := context.WithTimeout(context.WithoutCancel(parent), r.CleanupTimeout)
		defer done()
		closed := false
		if staged != nil {
			defer func() {
				if !closed {
					_ = staged.Close() // even when secrets must remain
				}
			}()
		}
		if err := execution.StopAndJoin(cleanup); err != nil || cleanup.Err() != nil {
			result.Status, result.Code = "failed", "core-stop-join-unsettled"
			return
		}
		if err := execution.VerifySettled(cleanup); err != nil || cleanup.Err() != nil {
			result.Status, result.Code = "failed", "core-settlement-unverified"
			return
		}
		result.Settlement = "settled"
		if staged != nil {
			if err := staged.RemoveSecret(cleanup); err != nil || cleanup.Err() != nil {
				result.Status, result.Code = "failed", "staged-secret-retained"
				return
			}
			result.SecretCleanup = "removed"
			closeErr := staged.Close()
			closed = true
			if closeErr != nil {
				result.Status, result.Code = "failed", "staged-descriptors-unsettled"
				return
			}
		}
		if err := execution.Release(cleanup); err != nil || cleanup.Err() != nil {
			result.Status, result.Code = "failed", "core-release-unsettled"
		}
	}()
	if acquireErr != nil || ctx.Err() != nil {
		result.Code = "core-acquisition-refused"
		return result
	}
	// Every fresh callback is bracketed by original authority, including the
	// closing callback. The factory must independently retain actual namespace.
	authority := func(c context.Context) error {
		if c.Err() != nil || execution.Current(c) != nil {
			return errors.New("native-admission-refused")
		}
		current, err := io.fresh(c)
		if err != nil || current != network || c.Err() != nil || execution.Current(c) != nil || c.Err() != nil {
			return errors.New("native-admission-refused")
		}
		return nil
	}
	if authority(ctx) != nil {
		result.Code = "core-current-refused"
		return result
	}
	account, err := io.load(ctx, r)
	defer clear(account)
	if err != nil || ctx.Err() != nil || len(account) == 0 || len(account) > accountLimit || routeidentity.Hash(account) != r.AccountSHA256 {
		result.Code = "pinned-assets-unavailable"
		return result
	}
	endpoint, err := usquediag.ValidateOwnedUSQUENativeAssets(account, r.Transport, r.BinarySHA256, io.goarch)
	if err != nil {
		result.Code = "existing-account-invalid"
		return result
	}
	if authority(ctx) != nil {
		result.Code = "core-current-refused"
		return result
	}
	staged, err = io.stage(ctx, r, account)
	if staged != nil {
		result.SecretCleanup = "retained"
	}
	if err != nil || staged == nil || ctx.Err() != nil {
		result.Code = "staging-failed"
		return result
	}
	root := staged.Path()
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || filepath.Dir(root) != r.WorkParent || root == r.WorkParent {
		result.Code = "staging-binding-invalid"
		return result
	}
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(r.SOCKSPort)))
	environment := usquediag.OwnedUSQUEEnvironment(func(c context.Context) (string, error) {
		p, err := io.fresh(c)
		if err != nil || p != network || c.Err() != nil {
			return "", errors.New("native-network-changed")
		}
		return p.ID, nil
	})
	env, err := environment(ctx)
	if err != nil || staged.Verify(ctx) != nil || authority(ctx) != nil || ctx.Err() != nil {
		result.Code = "pre-start-binding-refused"
		return result
	}
	spec := processSpec(r, root)
	// Pass detached args to CORE: a callback cannot rewrite the local expected
	// argv. CORE still must validate/pin them at the actual start primitive.
	launch := Launch{Process: spec, BinarySHA256: r.BinarySHA256, ConfigSHA256: r.AccountSHA256, Endpoint: endpoint, Transport: r.Transport, Environment: env}
	launch.Process.Args = append([]string(nil), spec.Args...)
	launch.ProcessEnvironment = []string{"LANG=C", "HTTP_PROXY=", "HTTPS_PROXY=", "ALL_PROXY=", "http_proxy=", "https_proxy=", "all_proxy=", "NO_PROXY=", "no_proxy="}
	if err := execution.Start(ctx, launch); err != nil || ctx.Err() != nil {
		result.Code = "core-start-refused"
		return result
	}
	if staged.Verify(ctx) != nil || authority(ctx) != nil {
		result.Code = "post-start-binding-refused"
		return result
	}
	request := usquediag.OwnedRuntimeRequest{Root: root, Binary: r.Binary, SOCKSAddress: address, Transport: r.Transport, Endpoint: endpoint, Environment: environment}
	started := io.now()
	proof, err := io.produce(ctx, usquediag.OwnedProbeOptions{Enabled: true, Runtime: request,
		Network: usquediag.OwnedNetworkRequest{SOCKSAddress: address, Timeout: min(r.Timeout, 20*time.Second)}, Authority: authority})
	if err != nil || ctx.Err() != nil {
		result.Code = "owned-producer-refused"
		return result
	}
	// Finish all external authority/epoch/stage checks BEFORE a separate real
	// local identity leaf. The pinned environment here is already checked; it
	// cannot call an authority/epoch callback after the final procfs observation.
	if staged.Verify(ctx) != nil || authority(ctx) != nil {
		result.Code = "closing-authority-refused"
		return result
	}
	request.Environment = func(c context.Context) (string, error) { return env, c.Err() }
	current, err := io.observe(ctx, request)
	now := io.now()
	checked, checkedErr := time.Parse(time.RFC3339Nano, proof.CheckedAt)
	argsHash := routeidentity.Hash([]byte(strings.Join(append([]string{spec.Binary}, spec.Args...), "\x00") + "\x00"))
	if err != nil || ctx.Err() != nil || checkedErr != nil || checked.Before(started) || now.Before(started) || now.Sub(started) > r.Timeout ||
		current.BinarySHA256 != r.BinarySHA256 || current.SessionSHA256 != r.AccountSHA256 || current.ArgsSHA256 != argsHash || current.EnvironmentID != env ||
		current.Transport != r.Transport || current.Endpoint != endpoint.String() || !usquediag.OwnedEvidenceFresh(proof, current, now) {
		result.Code = "independent-readback-refused"
		return result
	}
	result.Observation = &Observation{CheckedAt: proof.CheckedAt, OriginalExpiry: proof.ValidUntil, BindingID: current.BindingID, RuntimeID: current.RuntimeID,
		BinarySHA256: current.BinarySHA256, SessionSHA256: current.SessionSHA256, EnvironmentID: current.EnvironmentID, Endpoint: current.Endpoint,
		ProofBasis: proof.ProofBasis, Warp: proof.Warp, Negotiated: proof.Negotiated, ReadbackMatched: true}
	result.Status, result.Code = "passed", "owned-path-observed-and-settled"
	return result
}

func processSpec(r Request, root string) dataplane.ProcessSpec {
	config := filepath.Join(root, "engine.json")
	args := []string{"-c", config, "socks", "-b", "127.0.0.1", "-p", strconv.Itoa(int(r.SOCKSPort)), "--always-reconnect", "-S"}
	if r.Transport == "HTTP/2" {
		args = append(args, "--http2")
	}
	return dataplane.ProcessSpec{ID: "usque-canary", Binary: r.Binary, Args: args, Dir: root,
		PIDPath: filepath.Join(root, "engine.pid"), LogPath: filepath.Join(root, "engine.log"), MatchArg: config, RouteProof: true}
}
