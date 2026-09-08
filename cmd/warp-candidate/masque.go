package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/cloudflareprovider"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/probecheck"
	"github.com/ArtixSx/razvilka/internal/systemprobe"
	"golang.org/x/net/proxy"
)

const supportedUSQUE = "4.2.1"
const traceURL = "https://1.1.1.1/cdn-cgi/trace"

type limitedOutput struct {
	writer    io.Writer
	remaining int64
}

func (out *limitedOutput) Write(data []byte) (int, error) {
	n := len(data)
	if int64(len(data)) > out.remaining {
		data = data[:out.remaining]
	}
	if len(data) > 0 {
		if _, err := out.writer.Write(data); err != nil {
			return 0, err
		}
		out.remaining -= int64(len(data))
	}
	return n, nil
}

func capabilities(ctx context.Context, binary, expected, wg, ip string) map[string]any {
	out := map[string]any{"os": runtime.GOOS, "arch": runtime.GOARCH, "wg_tool": findTool(wg, "/opt/bin/wg", "/opt/sbin/wg", "wg") != "", "ip_tool": findTool(ip, "/opt/sbin/ip", "/opt/bin/ip", "ip") != "", "scan_mutations": "owned temporary runtime only; no activation"}
	_, moduleErr := os.Stat("/sys/module/wireguard")
	out["wireguard_module_loaded"] = moduleErr == nil
	if binary == "" {
		out["masque_ready"] = false
		out["masque_reason"] = "separate USQUE binary required"
		return out
	}
	identity, err := inspectUSQUE(ctx, binary, expected)
	out["usque"] = identity
	out["masque_ready"] = err == nil
	if err != nil {
		out["masque_reason"] = err.Error()
	}
	return out
}

func findTool(explicit string, candidates ...string) string {
	if explicit != "" {
		candidates = []string{explicit}
	}
	for _, path := range candidates {
		if found, err := exec.LookPath(path); err == nil {
			return found
		}
	}
	return ""
}

func inspectUSQUE(parent context.Context, binary, expected string) (map[string]any, error) {
	identity := map[string]any{"required_version": supportedUSQUE}
	if !filepath.IsAbs(binary) {
		return identity, errors.New("USQUE must have a verified absolute binary path")
	}
	file, err := os.Open(binary)
	if err != nil {
		return identity, errors.New("USQUE binary is unavailable")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 128<<20 {
		return identity, errors.New("USQUE binary is invalid")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return identity, errors.New("USQUE checksum failed")
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	identity["sha256"] = digest
	if len(expected) != 64 || expected != digest {
		return identity, errors.New("explicit verified USQUE checksum is required")
	}
	ctx, cancel := context.WithTimeout(parent, 6*time.Second)
	defer cancel()
	version, err := exec.CommandContext(ctx, binary, "version").Output()
	if err != nil || len(version) > 4096 || !regexp.MustCompile(`(?:^|[^0-9])v?4\.2\.1(?:[^0-9.]|$)`).Match(version) {
		return identity, errors.New("USQUE version capability gate rejected this build")
	}
	identity["version"] = supportedUSQUE
	help, err := exec.CommandContext(ctx, binary, "socks", "--help").Output()
	if err != nil || len(help) > 64<<10 {
		return identity, errors.New("USQUE SOCKS capability inspection failed")
	}
	for _, required := range []string{"--bind", "--port", "--http2", "--insecure", "--connect-port", "--no-tunnel-ipv6"} {
		if !strings.Contains(string(help), required) {
			return identity, errors.New("USQUE required SOCKS capability is missing")
		}
	}
	identity["server_pin_required"] = true
	return identity, nil
}

func generateMasque(parent context.Context, root, binary, expected string, accepted bool) (map[string]any, error) {
	if !accepted {
		return nil, cloudflareprovider.ErrRegistrationTerms
	}
	identity, err := inspectUSQUE(parent, binary, expected)
	if err != nil {
		return nil, err
	}
	if err := newPrivateRoot(root); err != nil {
		return nil, err
	}
	report := map[string]any{"transport": "masque", "state": "registration-requested", "binary": identity, "automatic_retry": false}
	if err := writePrivateJSON(filepath.Join(root, "registration.json"), report); err != nil {
		return report, err
	}
	log, err := os.OpenFile(filepath.Join(root, "registration.private.log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return report, errors.New("create private registration log")
	}
	defer log.Close()
	ctx, cancel := context.WithTimeout(parent, 45*time.Second)
	defer cancel()
	profilePath := filepath.Join(root, "masque.json")
	command := exec.CommandContext(ctx, binary, "--config", profilePath, "register", "--accept-tos", "--name", "RAZVILKA-candidate")
	command.Dir = root
	bounded := &limitedOutput{writer: log, remaining: 64 << 10}
	command.Stdout, command.Stderr = bounded, bounded
	command.WaitDelay = 2 * time.Second
	err = command.Run()
	_ = os.Chmod(profilePath, 0o600)
	report["state"] = "remote-creation-or-enrollment-uncertain"
	if err == nil {
		profile, readErr := readPrivate(profilePath)
		if readErr == nil {
			defer wipe(profile)
			readErr = validateMasqueProfile(profile)
		}
		if readErr == nil {
			report["state"] = "registered-unverified"
			report["profile_file"] = "masque.json"
		} else {
			err = readErr
		}
	}
	_ = writePrivateJSON(filepath.Join(root, "registration-result.json"), report)
	if err != nil {
		return report, errors.New("MASQUE registration did not produce a validated private profile; inspect private log, do not repeat automatically")
	}
	return report, nil
}

func validateMasqueProfile(profile []byte) error {
	parsed, err := cloudflareprovider.ParseImport(cloudflareprovider.SourceUSQUE, profile)
	if err != nil || parsed.Preview().Format != "usque-v1" || parsed.Preview().Transport != "masque-usque" {
		return errors.New("MASQUE config must contain validated P-256 client key, endpoint server pin and public endpoints")
	}
	return nil
}

type masqueAttempt struct {
	Mode            string           `json:"mode"`
	Attempt         int              `json:"attempt"`
	WARP            bool             `json:"warp_confirmed"`
	DifferentEgress bool             `json:"different_egress"`
	ServiceStatus   int              `json:"service_http_status,omitempty"`
	ServiceVerdict  evidence.Verdict `json:"service_verdict,omitempty"`
	Cleanup         bool             `json:"cleanup_confirmed"`
	NegativeControl bool             `json:"negative_control_confirmed"`
	Verified        bool             `json:"verified"`
	Reason          string           `json:"reason,omitempty"`
}

func scanMasque(parent context.Context, root, profilePath, binary, expected, mode string, service catalog.Service) (map[string]any, error) {
	modes, err := scanModes(mode)
	if err != nil {
		return nil, err
	}
	identity, err := inspectUSQUE(parent, binary, expected)
	if err != nil {
		return nil, err
	}
	profile, err := readPrivate(profilePath)
	if err != nil {
		return nil, err
	}
	defer wipe(profile)
	if err := validateMasqueProfile(profile); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(parent, 4*time.Minute)
	defer cancel()
	network, err := systemprobe.FreshWANProfile(ctx)
	if err != nil || !systemprobe.ValidWANProfileID(network.ID) {
		return nil, errors.New("current WAN epoch is unavailable")
	}
	results := []masqueAttempt{}
	working := []string{}
	for _, currentMode := range modes {
		passes := 0
		for attempt := 1; attempt <= 2; attempt++ {
			current, profileErr := systemprobe.FreshWANProfile(ctx)
			if profileErr != nil || current.ID != network.ID {
				return map[string]any{"results": results, "activation": false}, errors.New("WAN epoch changed before MASQUE attempt")
			}
			result := runMasqueAttempt(ctx, root, profile, binary, currentMode, attempt, service)
			current, profileErr = systemprobe.FreshWANProfile(ctx)
			if profileErr != nil || current.ID != network.ID {
				result.Verified = false
				result.Reason = "network-profile-changed"
			}
			results = append(results, result)
			if result.Verified {
				passes++
			}
			if !result.Cleanup || ctx.Err() != nil || result.Reason == "network-profile-changed" {
				return map[string]any{"results": results, "activation": false}, errors.New("MASQUE scan stopped after cleanup, cancellation or network guard")
			}
		}
		if passes == 2 {
			working = append(working, currentMode)
		}
	}
	out := map[string]any{"transport": "masque", "binary": identity, "network_profile_id": network.ID, "service_id": service.ID, "probe_scope": "primary-catalog-probe", "results": results, "working_modes": working, "activation": false, "udp_service_tested": false, "ipv6_service_tested": false}
	if len(working) == 0 {
		return out, errors.New("neither requested MASQUE mode passed two isolated service attempts")
	}
	return out, nil
}

func scanModes(mode string) ([]string, error) {
	switch mode {
	case "h2":
		return []string{"h2"}, nil
	case "h3":
		return []string{"h3"}, nil
	case "both":
		return []string{"h2", "h3"}, nil
	default:
		return nil, errors.New("MASQUE mode must be h2, h3, or both")
	}
}

func runMasqueAttempt(parent context.Context, root string, profile []byte, binary, mode string, number int, service catalog.Service) (result masqueAttempt) {
	result.Mode, result.Attempt, result.Cleanup = mode, number, true
	dir, err := os.MkdirTemp(root, "masque-attempt-")
	if err != nil {
		result.Reason = "private-attempt-directory-failed"
		return
	}
	profilePath := filepath.Join(dir, "config.json")
	if err := writePrivate(profilePath, profile); err != nil {
		result.Reason = "private-profile-stage-failed"
		return
	}
	defer os.Remove(profilePath)
	log, err := os.OpenFile(filepath.Join(dir, "process.private.log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		result.Reason = "private-log-failed"
		return
	}
	defer log.Close()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		result.Reason = "loopback-port-unavailable"
		return
	}
	address := listener.Addr().String()
	_, port, _ := net.SplitHostPort(address)
	_ = listener.Close()
	ctx, cancel := context.WithTimeout(parent, 48*time.Second)
	defer cancel()
	args := []string{"--config", profilePath, "socks", "--bind", "127.0.0.1", "--port", port, "--connect-port", "443", "--no-tunnel-ipv6"}
	if mode == "h2" {
		args = append(args, "--http2")
	}
	command := exec.CommandContext(ctx, binary, args...)
	command.Dir = dir
	command.WaitDelay = 2 * time.Second
	bounded := &limitedOutput{writer: log, remaining: 64 << 10}
	command.Stdout, command.Stderr = bounded, bounded
	if err := command.Start(); err != nil {
		result.Reason = "candidate-process-start-failed"
		return
	}
	waited := make(chan error, 1)
	go func() { waited <- command.Wait() }()
	result.Cleanup = false
	defer func() {
		_ = command.Process.Kill()
		select {
		case <-waited:
			result.Cleanup = true
		case <-time.After(4 * time.Second):
			result.Cleanup = false
		}
		controlCtx, controlCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer controlCancel()
		result.NegativeControl = closedSOCKSControl(controlCtx, address)
		result.Verified = result.WARP && result.DifferentEgress && result.ServiceVerdict == evidence.VerdictPass && result.Cleanup && result.NegativeControl
		if !result.Cleanup {
			result.Reason = "cleanup-unconfirmed"
		} else if !result.NegativeControl {
			result.Reason = "negative-control-failed"
		}
	}()
	if err := waitLoopback(ctx, address); err != nil {
		result.Reason = "candidate-listener-unavailable"
		return
	}
	direct := directClient()
	defer direct.CloseIdleConnections()
	directTrace, err := getTrace(ctx, direct)
	if err != nil {
		result.Reason = "direct-trace-failed"
		return
	}
	client, closeClient, err := socksClient(address)
	if err != nil {
		result.Reason = "isolated-client-failed"
		return
	}
	defer closeClient()
	trace, err := getTrace(ctx, client)
	if err != nil {
		result.Reason = "masque-trace-failed"
		return
	}
	result.WARP = trace.WARP == "on"
	result.DifferentEgress = trace.IP != directTrace.IP && directTrace.WARP == "off"
	if !result.WARP || !result.DifferentEgress {
		result.Reason = "egress-control-not-confirmed"
		return
	}
	result.ServiceStatus, result.ServiceVerdict, err = getService(ctx, client, service)
	if err != nil || result.ServiceVerdict != evidence.VerdictPass {
		result.Reason = "service-not-confirmed"
	}
	return
}

func closedSOCKSControl(ctx context.Context, address string) bool {
	// A failed HTTP request alone could be a network outage behind somebody
	// else's listener. The exact candidate port must also have closed.
	connection, err := (&net.Dialer{Timeout: 300 * time.Millisecond}).DialContext(ctx, "tcp", address)
	if err == nil {
		_ = connection.Close()
		return false
	}
	probe, closeProbe, err := socksClient(address)
	if err != nil {
		return false
	}
	defer closeProbe()
	_, err = getTrace(ctx, probe)
	return err != nil
}

func waitLoopback(ctx context.Context, address string) error {
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		connection, err := (&net.Dialer{Timeout: 150 * time.Millisecond}).DialContext(ctx, "tcp", address)
		if err == nil {
			_ = connection.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("listener timeout")
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func directClient() *http.Client {
	return &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSHandshakeTimeout: 8 * time.Second}, Timeout: 14 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func socksClient(address string) (*http.Client, func(), error) {
	dialer, err := proxy.SOCKS5("tcp", address, nil, &net.Dialer{Timeout: 10 * time.Second})
	if err != nil {
		return nil, nil, errors.New("create isolated SOCKS client")
	}
	contextDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return nil, nil, errors.New("SOCKS context capability unavailable")
	}
	transport := &http.Transport{Proxy: nil, DialContext: contextDialer.DialContext, DisableKeepAlives: true, TLSHandshakeTimeout: 8 * time.Second}
	client := &http.Client{Transport: transport, Timeout: 14 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return client, transport.CloseIdleConnections, nil
}

func getTrace(ctx context.Context, client *http.Client) (cloudflareprovider.TraceEvidence, error) {
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, traceURL, nil)
	response, err := client.Do(request)
	if err != nil {
		return cloudflareprovider.TraceEvidence{}, errors.New("trace request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return cloudflareprovider.TraceEvidence{}, errors.New("trace status failed")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, cloudflareprovider.MaxTraceBytes+1))
	if err != nil {
		return cloudflareprovider.TraceEvidence{}, errors.New("trace read failed")
	}
	return cloudflareprovider.ParseCloudflareTrace(body)
}

func getService(ctx context.Context, client *http.Client, service catalog.Service) (int, evidence.Verdict, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, service.ProbeURL, nil)
	if err != nil {
		return 0, evidence.VerdictError, errors.New("invalid catalog probe")
	}
	request.Header.Set("User-Agent", "RAZVILKA-Candidate/1")
	request.Header.Set("Range", "bytes=0-32767")
	redirects := []string{}
	response, err := probecheck.RecordingClient(client, service, &redirects).Do(request)
	if err != nil {
		return 0, evidence.VerdictError, errors.New("service request failed")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, probecheck.MaxBodyBytes+1))
	if err != nil {
		return response.StatusCode, evidence.VerdictError, errors.New("service read failed")
	}
	truncated := len(body) > probecheck.MaxBodyBytes || response.ContentLength > int64(len(body))
	if len(body) > probecheck.MaxBodyBytes {
		body = body[:probecheck.MaxBodyBytes]
	}
	assessment := probecheck.Evaluate(service, probecheck.ServiceProbe(service), probecheck.Observation{RequestedURL: service.ProbeURL, FinalURL: probecheck.FinalURL(response, service.ProbeURL), RedirectChain: redirects, HTTPStatus: response.StatusCode, ContentType: response.Header.Get("Content-Type"), Body: body, BodyTruncated: truncated})
	return response.StatusCode, assessment.Verdict, nil
}
