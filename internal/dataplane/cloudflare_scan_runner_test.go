package dataplane

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/cloudflareprovider"
)

type scanRegistrationAPI struct{}

func (scanRegistrationAPI) Register(_ context.Context, request cloudflareprovider.RegistrationRequest) (cloudflareprovider.RegistrationResponse, error) {
	return cloudflareprovider.RegistrationResponse{
		DeviceID: "device", AccessToken: "token",
		PeerPublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)),
		Addresses:     []string{"172.16.0.2/32", "2606:4700:110::2/128"},
		Endpoints:     []string{"162.159.192.1:2408"}, APISchema: "registration-v1",
		TermsRevision: request.TermsRevision,
	}, nil
}

func withScanCandidate(t *testing.T, consume func(cloudflareprovider.WireGuardCandidate)) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := cloudflareprovider.OpenStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	registration, err := (cloudflareprovider.Registrar{
		API: scanRegistrationAPI{}, Random: bytes.NewReader(bytes.Repeat([]byte{7}, 64)),
	}).NewCandidate(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	account, err := store.ImportCandidate(context.Background(), registration)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WithWireGuardCandidate(context.Background(), account.ID, cloudflareprovider.CandidateOptions{}, func(_ context.Context, candidate cloudflareprovider.WireGuardCandidate) error {
		consume(candidate)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCloudflareScanRunnerOwnsTemporaryInterfacePolicyAndCleanup(t *testing.T) {
	root := t.TempDir()
	fake := &warpFakeRunner{}
	adapter := NewWARPWireGuardAdapter(nil, filepath.Join(root, "adapter"))
	adapter.WG, adapter.IP, adapter.Runner = "wg", "ip", fake
	adapter.HandshakeTimeout = time.Millisecond
	service := catalog.Service{ID: "telegram", Name: "Telegram", ProbeURL: "https://service.example/check"}
	runner := NewCloudflareScanRunner(adapter, filepath.Join(root, "scanner"), []catalog.Service{service})
	runner.httpProbe = cloudflareScanHTTPProbe{
		directClient: cloudflareProbeClient("ip=9.9.9.9\ncolo=DME\nwarp=off\n", 200, "ok"),
		traceURL:     "https://trace.example/cdn-cgi/trace",
		boundClient: func(source string) (*http.Client, func(), error) {
			if source != "172.16.0.2" {
				t.Fatal("unexpected source", source)
			}
			return cloudflareProbeClient("ip=8.8.8.8\ncolo=AMS\nwarp=on\n", 200, "ok"), func() {}, nil
		},
	}
	withScanCandidate(t, func(candidate cloudflareprovider.WireGuardCandidate) {
		attempt, err := runner.RunScanAttempt(context.Background(), candidate, cloudflareprovider.ScanRunRequest{Attempt: 1, ServiceID: "telegram"})
		if err != nil || !attempt.CleanupConfirmed || fake.active || attempt.ConfirmedMTU != 1280 {
			t.Fatalf("attempt=%+v active=%v err=%v", attempt, fake.active, err)
		}
		if result := cloudflareprovider.EvaluateScanAttempt(attempt, time.Now().UTC(), time.Minute); !result.Verified {
			t.Fatalf("runner evidence was not exact: %+v", result)
		}
	})
	entries, err := os.ReadDir(filepath.Join(root, "scanner"))
	if err != nil || len(entries) != 1 || entries[0].Name() != cloudflareScanLockFile {
		t.Fatalf("scan secret workspace remained: %v err=%v", entries, err)
	}
	joined := strings.Join(fake.calls, "\n")
	for _, required := range []string{
		"ip link add dev rz-cf-scan type wireguard",
		"ip route add default dev rz-cf-scan table 220",
		"ip rule add priority 18060 from 172.16.0.2/32 lookup 220",
		"ip rule del priority 18060 from 172.16.0.2/32 lookup 220",
		"ip link delete dev rz-cf-scan",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("runner call missing %q:\n%s", required, joined)
		}
	}
}

func TestCloudflareScanLockRejectsConcurrentOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scanner")
	root, err := openCloudflareScanRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	release, err := acquireCloudflareScanLock(root)
	if err != nil {
		t.Fatal(err)
	}
	if second, secondErr := acquireCloudflareScanLock(root); secondErr == nil {
		second()
		t.Fatal("concurrent Cloudflare scanner acquired the same OS lock")
	}
	release()
	reacquired, err := acquireCloudflareScanLock(root)
	if err != nil {
		t.Fatal("released Cloudflare scan lock stayed busy:", err)
	}
	reacquired()
}

func TestLatestHandshakeRejectsFutureTimestamp(t *testing.T) {
	now := time.Date(2026, 9, 1, 23, 30, 0, 0, time.UTC)
	if _, ok := latestHandshakeTime("peer\t"+strconv.FormatInt(now.Add(time.Minute).Unix(), 10)+"\n", now); ok {
		t.Fatal("future WireGuard handshake was accepted")
	}
	want := now.Add(-time.Second)
	got, ok := latestHandshakeTime("peer\t"+strconv.FormatInt(want.Unix(), 10)+"\n", now)
	if !ok || !got.Equal(want) {
		t.Fatalf("fresh handshake got=%v ok=%v", got, ok)
	}
}

func TestCloudflareScanRunnerFailsClosedWhenCleanupIsUnconfirmed(t *testing.T) {
	root := t.TempDir()
	fake := &warpFakeRunner{failDelete: true}
	adapter := NewWARPWireGuardAdapter(nil, filepath.Join(root, "adapter"))
	adapter.WG, adapter.IP, adapter.Runner = "wg", "ip", fake
	adapter.HandshakeTimeout = time.Millisecond
	service := catalog.Service{ID: "telegram", ProbeURL: "https://service.example/check"}
	runner := NewCloudflareScanRunner(adapter, filepath.Join(root, "scanner"), []catalog.Service{service})
	runner.httpProbe = cloudflareScanHTTPProbe{
		directClient: cloudflareProbeClient("ip=9.9.9.9\ncolo=DME\nwarp=off\n", 200, "ok"), traceURL: "https://trace.example/cdn-cgi/trace",
		boundClient: func(string) (*http.Client, func(), error) {
			return cloudflareProbeClient("ip=8.8.8.8\ncolo=AMS\nwarp=on\n", 200, "ok"), func() {}, nil
		},
	}
	withScanCandidate(t, func(candidate cloudflareprovider.WireGuardCandidate) {
		attempt, err := runner.RunScanAttempt(context.Background(), candidate, cloudflareprovider.ScanRunRequest{Attempt: 1, ServiceID: "telegram"})
		if err == nil || attempt.CleanupConfirmed || !fake.active {
			t.Fatalf("cleanup failure was hidden: attempt=%+v active=%v err=%v", attempt, fake.active, err)
		}
	})
}

func TestCloudflareScanRunnerRejectsSourceAddressAlreadyInUse(t *testing.T) {
	root := t.TempDir()
	fake := &warpFakeRunner{addressOutput: "5: lan0    inet 172.16.0.2/24 brd 172.16.0.255 scope global lan0\n"}
	adapter := NewWARPWireGuardAdapter(nil, filepath.Join(root, "adapter"))
	adapter.WG, adapter.IP, adapter.Runner = "wg", "ip", fake
	service := catalog.Service{ID: "telegram", ProbeURL: "https://service.example/check"}
	runner := NewCloudflareScanRunner(adapter, filepath.Join(root, "scanner"), []catalog.Service{service})
	withScanCandidate(t, func(candidate cloudflareprovider.WireGuardCandidate) {
		attempt, err := runner.RunScanAttempt(context.Background(), candidate, cloudflareprovider.ScanRunRequest{Attempt: 1, ServiceID: "telegram"})
		if err == nil || fake.active || fake.starts != 0 || !attempt.CleanupConfirmed {
			t.Fatalf("occupied source reached runtime: attempt=%+v active=%v starts=%d err=%v", attempt, fake.active, fake.starts, err)
		}
		if attempt.StartedAt.IsZero() || attempt.FinishedAt.IsZero() || attempt.FinishedAt.Before(attempt.StartedAt) || attempt.Failure == nil {
			t.Fatalf("early failure lost timestamps or diagnostic: %+v", attempt)
		}
		result := cloudflareprovider.EvaluateScanAttempt(attempt, time.Now().UTC(), time.Minute)
		if result.Verified || result.Stage != "ownership" || result.ReasonCode != "source-address-conflict" {
			t.Fatalf("ownership error was hidden: %+v", result)
		}
	})
}

func TestCloudflareScanDiagnosticsNeverExposeRawCommandOutput(t *testing.T) {
	diagnostic := describeCloudflareScanFailure("interface", errors.New("wg setconf: private-key-marker endpoint-marker: invalid argument"))
	if diagnostic.Stage != "interface" || diagnostic.ReasonCode != "wireguard-config-rejected" || diagnostic.SystemCode != "invalid-argument" {
		t.Fatalf("unexpected safe diagnostic: %+v", diagnostic)
	}
	raw, err := json.Marshal(diagnostic)
	if err != nil || strings.Contains(string(raw), "marker") || strings.Contains(diagnostic.Error(), "marker") {
		t.Fatal("raw command output leaked into public diagnostics")
	}
	for _, failure := range []struct {
		err  error
		want string
	}{{context.Canceled, "cancelled"}, {context.DeadlineExceeded, "timeout"}} {
		if got := describeCloudflareScanFailure("interface", failure.err); got.ReasonCode != failure.want {
			t.Fatalf("context failure lost cause: %+v", got)
		}
	}
}

type cancelledCloudflareStart struct {
	base   *warpFakeRunner
	cancel context.CancelFunc
}

func (runner cancelledCloudflareStart) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if name == "wg" && len(args) > 0 && args[0] == "setconf" {
		runner.cancel()
		return nil, context.Canceled
	}
	return runner.base.Run(ctx, name, args...)
}

func TestCloudflareScanCleansPartialStartAfterCancellation(t *testing.T) {
	root := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake := &warpFakeRunner{}
	adapter := NewWARPWireGuardAdapter(nil, filepath.Join(root, "adapter"))
	adapter.WG, adapter.IP, adapter.Runner = "wg", "ip", cancelledCloudflareStart{base: fake, cancel: cancel}
	runner := NewCloudflareScanRunner(adapter, filepath.Join(root, "scanner"), []catalog.Service{{ID: "telegram", ProbeURL: "https://service.example/check"}})
	withScanCandidate(t, func(candidate cloudflareprovider.WireGuardCandidate) {
		attempt, err := runner.RunScanAttempt(ctx, candidate, cloudflareprovider.ScanRunRequest{Attempt: 1, ServiceID: "telegram"})
		if err == nil || fake.starts != 1 || fake.active || !attempt.CleanupConfirmed || attempt.Failure == nil {
			t.Fatalf("partial interface survived cancellation: attempt=%+v starts=%d active=%v err=%v", attempt, fake.starts, fake.active, err)
		}
	})
}

func TestCloudflareScanFailedCreateNeverDeletesUnownedInterface(t *testing.T) {
	root := t.TempDir()
	fake := &warpFakeRunner{failStart: true}
	adapter := NewWARPWireGuardAdapter(nil, filepath.Join(root, "adapter"))
	adapter.WG, adapter.IP, adapter.Runner = "wg", "ip", fake
	runner := NewCloudflareScanRunner(adapter, filepath.Join(root, "scanner"), []catalog.Service{{ID: "telegram", ProbeURL: "https://service.example/check"}})
	withScanCandidate(t, func(candidate cloudflareprovider.WireGuardCandidate) {
		attempt, err := runner.RunScanAttempt(context.Background(), candidate, cloudflareprovider.ScanRunRequest{Attempt: 1, ServiceID: "telegram"})
		if err == nil || !fake.active || !attempt.CleanupConfirmed || attempt.Failure == nil || attempt.Failure.ReasonCode != "interface-create-failed" {
			t.Fatalf("failed create changed ownership: attempt=%+v active=%v err=%v", attempt, fake.active, err)
		}
		if strings.Contains(strings.Join(fake.calls, "\n"), "link delete") {
			t.Fatal("unowned interface was deleted")
		}
	})
}
