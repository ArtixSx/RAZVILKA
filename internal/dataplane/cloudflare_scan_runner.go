package dataplane

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/cloudflareprovider"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

const (
	cloudflareScanInterface = "rz-cf-scan"
	cloudflareScanTable     = 220
	cloudflareScanPriority  = 18060
)

// CloudflareScanRunner owns one isolated WireGuard attempt at a time. Its
// fixed interface/table/priority are checked empty before use; only a source
// rule for the candidate tunnel address is installed, so LAN/default routing
// remains unchanged.
type CloudflareScanRunner struct {
	adapter   *WARPWireGuardAdapter
	stateRoot string
	services  map[string]catalog.Service
	httpProbe cloudflareScanHTTPProbe
	mu        sync.Mutex
}

var _ cloudflareprovider.ScanAttemptRunner = (*CloudflareScanRunner)(nil)

func NewCloudflareScanRunner(adapter *WARPWireGuardAdapter, stateRoot string, services []catalog.Service) *CloudflareScanRunner {
	known := make(map[string]catalog.Service, len(services))
	for _, service := range services {
		if scanServiceID(service.ID) && service.ProbeURL != "" {
			known[service.ID] = service
		}
	}
	return &CloudflareScanRunner{
		adapter: adapter, stateRoot: stateRoot, services: known,
		httpProbe: newCloudflareScanHTTPProbe(),
	}
}

func (runner *CloudflareScanRunner) RunScanAttempt(ctx context.Context, candidate cloudflareprovider.WireGuardCandidate, request cloudflareprovider.ScanRunRequest) (attempt cloudflareprovider.ScanAttempt, retErr error) {
	phase := "setup"
	attempt.StartedAt = time.Now().UTC().Truncate(time.Second)
	defer func() {
		if attempt.FinishedAt.IsZero() {
			attempt.FinishedAt = time.Now().UTC()
		}
		if retErr != nil && attempt.Failure == nil {
			attempt.Failure = describeCloudflareScanFailure(phase, retErr)
		}
	}()
	if runner == nil || runner.adapter == nil || runner.adapter.ID() != "warp-wg" || request.Attempt < 1 || request.Attempt > cloudflareprovider.MaxScanAttempts {
		return attempt, errors.New("Cloudflare scan runner is not configured")
	}
	service, ok := runner.services[request.ServiceID]
	if !ok {
		return attempt, errors.New("Cloudflare scan service is not configured")
	}
	if !runner.mu.TryLock() {
		return attempt, errors.New("Cloudflare scan runner is busy")
	}
	defer runner.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return attempt, err
	}
	root, err := openCloudflareScanRoot(runner.stateRoot)
	if err != nil {
		return attempt, err
	}
	defer root.Close()
	phase = "ownership"
	unlock, err := acquireCloudflareScanLock(root)
	if err != nil {
		return attempt, errors.New("Cloudflare scan runner is busy")
	}
	defer unlock()
	if err := ctx.Err(); err != nil {
		return attempt, err
	}
	attemptRoot, err := root.MkdirTemp("", "attempt-")
	if err != nil {
		return attempt, errors.New("create Cloudflare scan attempt")
	}
	preview := candidate.Public()
	phase = "stage"
	attempt.Candidate = preview
	attempt.ServiceID = request.ServiceID
	// `wg latest-handshakes` has one-second precision. Truncating the attempt
	// start preserves the real ordering without treating that precision loss as
	// a pre-attempt handshake.
	attempt.StartedAt = time.Now().UTC().Truncate(time.Second)
	configName := filepath.Join(attemptRoot, "candidate.conf")
	var config bytes.Buffer
	if err := candidate.WriteConfig(&config); err != nil {
		_ = root.RemoveAll(attemptRoot)
		return attempt, errors.New("serialize Cloudflare scan candidate")
	}
	serialized := config.Bytes()
	defer wipeScanBytes(serialized)
	if err := root.WriteAtomic(configName, serialized, 0o600); err != nil {
		_ = root.RemoveAll(attemptRoot)
		return attempt, errors.New("stage Cloudflare scan candidate")
	}

	sandbox := *runner.adapter
	sandbox.EngineID = "warp-wg"
	sandbox.Configs = nil
	sandbox.Interface = cloudflareScanInterface
	sandbox.Table = cloudflareScanTable
	sandbox.PriorityBase = cloudflareScanPriority
	sandbox.StateRoot = filepath.Join(runner.stateRoot, attemptRoot)
	sandbox.RuntimeConfigPath = filepath.Join(runner.stateRoot, configName)
	sandbox.NativeOnly = true
	ownership := &cloudflareScanOwnership{runner: sandbox.Runner, ip: sandbox.ip()}
	sandbox.Runner = ownership
	source, err := firstIPv4TunnelAddress(preview.Addresses)
	if err != nil {
		_ = root.RemoveAll(attemptRoot)
		return attempt, err
	}
	interfaceStarted, policyInstalled := false, false
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		var cleanupErr error
		if policyInstalled {
			cleanupErr = sandbox.cleanupCanaryPolicy(cleanupCtx, source)
		}
		if ownership.interfaceOwned {
			if stopErr := sandbox.stopInterface(cleanupCtx); cleanupErr == nil {
				cleanupErr = stopErr
			}
		}
		if removeErr := root.RemoveAll(attemptRoot); cleanupErr == nil {
			cleanupErr = removeErr
		}
		if cleanupErr == nil && interfaceStarted && sandbox.interfaceActive(cleanupCtx) {
			cleanupErr = errors.New("Cloudflare scan interface cleanup is unconfirmed")
		}
		if cleanupErr == nil && policyInstalled {
			cleanupErr = sandbox.ensureCanaryPolicyFree(cleanupCtx)
		}
		attempt.CleanupConfirmed = cleanupErr == nil
		if cleanupErr != nil {
			attempt.Failure = describeCloudflareScanFailure("cleanup", cleanupErr)
			retErr = errors.Join(retErr, errors.New("Cloudflare scan cleanup failed"))
		}
	}()

	phase = "ownership"
	if sandbox.interfaceActive(ctx) {
		return attempt, errors.New("Cloudflare scan interface is already active")
	}
	if err := sandbox.ensureCanaryPolicyFree(ctx); err != nil {
		return attempt, err
	}
	if err := sandbox.ensureScanSourceFree(ctx, source); err != nil {
		return attempt, err
	}
	phase = "interface"
	if err := sandbox.startInterface(ctx); err != nil {
		attempt.Failure = describeCloudflareScanFailure(phase, err)
		return attempt, errors.New("start Cloudflare scan interface")
	}
	interfaceStarted = true
	phase = "policy"
	if err := sandbox.installCanaryPolicy(ctx, source); err != nil {
		return attempt, err
	}
	policyInstalled = true

	phase = "http-probe"
	facts, err := runner.httpProbe.observe(ctx, source.String(), preview.RoutePathID, service)
	if err != nil {
		return attempt, err
	}
	attempt.Reachable = true
	attempt.DirectEgressIP = facts.DirectEgressIP
	attempt.EgressIP = facts.EgressIP
	attempt.Trace = facts.Trace
	attempt.Service = facts.Service
	phase = "handshake"
	if err := sandbox.confirmHandshake(ctx, sandbox.interfaceName()); err != nil {
		return attempt, err
	}
	output, err := sandbox.run(ctx, sandbox.wg(), "show", sandbox.interfaceName(), "latest-handshakes")
	if err != nil {
		return attempt, errors.New("read Cloudflare scan handshake")
	}
	handshakeAt, ok := latestHandshakeTime(string(output), time.Now())
	if !ok {
		return attempt, errors.New("Cloudflare scan handshake timestamp is invalid")
	}
	attempt.HandshakeAt = handshakeAt
	phase = "mtu"
	mtu, err := sandbox.observedInterfaceMTU(ctx)
	if err != nil {
		return attempt, err
	}
	attempt.ConfirmedMTU = mtu
	attempt.FinishedAt = time.Now().UTC()
	return attempt, nil
}

// Track successful create operations, including a partial start followed by
// cancellation. An error while creating the interface never grants ownership.
// The native adapter's best-effort rollback uses the attempt context; this
// outer runner can finish only its own rollback with a fresh cleanup context.
type cloudflareScanOwnership struct {
	runner         NFQWS2Runner
	ip             string
	interfaceOwned bool
}

func (owner *cloudflareScanOwnership) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if owner.runner == nil {
		return nil, errors.New("Cloudflare command runner is unavailable")
	}
	output, err := owner.runner.Run(ctx, name, args...)
	if err == nil && name == owner.ip {
		switch {
		case slices.Equal(args, []string{"link", "add", "dev", cloudflareScanInterface, "type", "wireguard"}):
			owner.interfaceOwned = true
		case slices.Equal(args, []string{"link", "delete", "dev", cloudflareScanInterface}):
			owner.interfaceOwned = false
		}
	}
	return output, err
}

func describeCloudflareScanFailure(stage string, err error) *cloudflareprovider.ScanFailure {
	var httpFailure *cloudflareprovider.ScanFailure
	if errors.As(err, &httpFailure) {
		copy := *httpFailure
		return &copy
	}
	failure := &cloudflareprovider.ScanFailure{Stage: stage, ReasonCode: "operation-failed"}
	if errors.Is(err, context.Canceled) {
		failure.ReasonCode = "cancelled"
		return failure
	}
	if errors.Is(err, context.DeadlineExceeded) {
		failure.ReasonCode = "timeout"
		return failure
	}
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "source address is already used"):
		failure.ReasonCode = "source-address-conflict"
	case strings.Contains(message, "interface is already active"):
		failure.ReasonCode = "interface-already-active"
	case strings.Contains(message, "runner is busy"):
		failure.ReasonCode = "scanner-busy"
	case strings.Contains(message, "root is not private"):
		failure.ReasonCode = "private-directory-required"
	case strings.Contains(message, "create interface:"):
		failure.ReasonCode = "interface-create-failed"
	case strings.Contains(message, "wg setconf:"):
		failure.ReasonCode = "wireguard-config-rejected"
	case strings.Contains(message, "assign address "):
		failure.ReasonCode = "interface-address-failed"
	case strings.Contains(message, "set mtu:"):
		failure.ReasonCode = "interface-mtu-failed"
	case strings.Contains(message, "bring interface up:"):
		failure.ReasonCode = "interface-up-failed"
	case strings.Contains(message, "handshake"):
		failure.ReasonCode = "handshake-unconfirmed"
	case strings.Contains(message, "policy") || strings.Contains(message, "table") || strings.Contains(message, "rule"):
		failure.ReasonCode = "policy-operation-failed"
	}
	switch {
	case strings.Contains(message, "operation not supported"):
		failure.SystemCode = "operation-not-supported"
	case strings.Contains(message, "operation not permitted") || strings.Contains(message, "permission denied"):
		failure.SystemCode = "permission-denied"
	case strings.Contains(message, "file exists"):
		failure.SystemCode = "resource-exists"
	case strings.Contains(message, "cannot find device") || strings.Contains(message, "no such device"):
		failure.SystemCode = "device-unavailable"
	case strings.Contains(message, "invalid argument"):
		failure.SystemCode = "invalid-argument"
	case strings.Contains(message, "no such file") || strings.Contains(message, "not found"):
		failure.SystemCode = "resource-unavailable"
	case strings.Contains(message, "deadline exceeded") || strings.Contains(message, "timeout"):
		failure.SystemCode = "timeout"
	}
	return failure
}

func (adapter *WARPWireGuardAdapter) ensureScanSourceFree(ctx context.Context, source netip.Addr) error {
	output, err := adapter.run(ctx, adapter.ip(), "-o", "address", "show")
	if err != nil {
		return errors.New("inspect Cloudflare scan source address")
	}
	fields := strings.Fields(string(output))
	for index := 0; index+1 < len(fields); index++ {
		if fields[index] != "inet" && fields[index] != "inet6" {
			continue
		}
		prefix, parseErr := netip.ParsePrefix(fields[index+1])
		if parseErr == nil && prefix.Addr().Unmap() == source.Unmap() {
			return errors.New("Cloudflare scan source address is already used")
		}
	}
	return nil
}

func openCloudflareScanRoot(path string) (*ownedfs.Root, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) == filepath.VolumeName(path)+string(filepath.Separator) {
		return nil, errors.New("Cloudflare scan root is invalid")
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return nil, errors.New("create Cloudflare scan root")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("Cloudflare scan root is not private")
	}
	root, err := ownedfs.Open(path)
	if err != nil {
		return nil, errors.New("open Cloudflare scan root")
	}
	return root, nil
}

func (adapter *WARPWireGuardAdapter) observedInterfaceMTU(ctx context.Context) (int, error) {
	output, err := adapter.run(ctx, adapter.ip(), "-o", "link", "show", "dev", adapter.interfaceName())
	if err != nil {
		return 0, errors.New("inspect Cloudflare scan MTU")
	}
	fields := strings.Fields(string(output))
	for index := 0; index+1 < len(fields); index++ {
		if fields[index] != "mtu" {
			continue
		}
		mtu, parseErr := strconv.Atoi(fields[index+1])
		if parseErr == nil && mtu >= 576 && mtu <= 1500 {
			return mtu, nil
		}
	}
	return 0, fmt.Errorf("Cloudflare scan MTU was not observed")
}

func wipeScanBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
