package warp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLegacyEnrollmentCannotMintOrRemoveAccountAfterRestart(t *testing.T) {
	for _, accountExists := range []bool{false, true} {
		m := newNativeTestManager(t)
		if err := os.MkdirAll(m.Root, 0o700); err != nil {
			t.Fatal(err)
		}
		const account = "existing-private-account"
		if accountExists {
			if err := os.WriteFile(m.accountPath(), []byte(account), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		for restart := 0; restart < 2; restart++ {
			m.nativeAPI = nil
			// A nonexistent executable ensures rejection precedes any command.
			if _, err := m.Generate(context.Background(), true, true); !errors.Is(err, ErrNativeGeneratorRequired) {
				t.Fatalf("legacy registration accepted: %v", err)
			}
			if accountExists {
				data, err := os.ReadFile(m.accountPath())
				if err != nil || string(data) != account {
					t.Fatal("existing account lost")
				}
			} else if _, err := os.Stat(m.accountPath()); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("account minted")
			}
			m = New(m.Root, m.BackupRoot, m.EngineConfigs)
		}
	}
}

func TestTCPReachabilityDoesNotConfirmH2H3OrUDP(t *testing.T) {
	now := time.Now().UTC()
	result := connectivitySummary(ConnectivityProbe{}, ConnectivityProbe{Ready: true, Target: "162.159.198.2:443"}, now)
	if !result.MASQUETCP.Ready || result.MASQUEHTTP2.Ready || result.MASQUEHTTP3.Ready || result.UDPCapability.Ready || !result.CheckedAt.Equal(now) {
		t.Fatalf("TCP promoted to transport proof: %+v", result)
	}
}

func TestActivationErrorReadbackAndPersistenceWithholdPrivateDetails(t *testing.T) {
	m := newNativeTestManager(t)
	const secret = "private-device-marker private-token-marker PrivateKey=private-key-marker"
	if err := m.RecordActivation(false, secret); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(m.Root, "health-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "private-") {
		t.Fatal("activation error persisted secrets")
	}
	// Simulate a file written by an older version; readback must also redact it.
	var document healthDocument
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	document.State.LastActivationError = secret
	data, _ = json.Marshal(document)
	if err := os.WriteFile(filepath.Join(m.Root, "health-policy.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	restarted := New(m.Root, m.BackupRoot, m.EngineConfigs)
	view, _ := json.Marshal(restarted.Health())
	if strings.Contains(string(view), "private-") {
		t.Fatal("legacy error leaked into readback")
	}
}

func TestWGCFCommandErrorNeverReturnsPrivateOutput(t *testing.T) {
	t.Setenv("RAZVILKA_D13_PRIVATE_OUTPUT_FIXTURE", "1")
	bin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	m := newNativeTestManager(t)
	if err := os.MkdirAll(m.Root, 0o700); err != nil {
		t.Fatal(err)
	}
	out, err := m.runLocked(context.Background(), bin, "-test.run=^TestWGCFPrivateOutputHelper$")
	if err == nil || out != "" || strings.Contains(err.Error(), "private-") {
		t.Fatalf("private output escaped: %q %v", out, err)
	}
	for _, raw := range []string{"private-token-marker", "wgcf v2.2.24 private-token-marker", "2.2.24-private-token-marker"} {
		if safeWGCFVersion(raw) != "" {
			t.Fatal("version output exposed arbitrary text")
		}
	}
	if safeWGCFVersion("wgcf v2.2.24\nprivate-token-marker") != "2.2.24" {
		t.Fatal("safe version missing")
	}
}

func TestWGCFPrivateOutputHelper(t *testing.T) {
	if os.Getenv("RAZVILKA_D13_PRIVATE_OUTPUT_FIXTURE") != "1" {
		return
	}
	fmt.Fprintln(os.Stdout, "private-device-marker private-token-marker PrivateKey=private-key-marker")
	fmt.Fprintln(os.Stderr, "private-token-marker")
	os.Exit(1)
}
