package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/evidence"
)

func TestMain(m *testing.M) {
	if os.Getenv("RAZVILKA_USQUE_TEST_HELPER") == "1" {
		if len(os.Args) > 1 && os.Args[1] == "version" {
			fmt.Println("usque version v4.2.1")
			os.Exit(0)
		}
		if len(os.Args) > 1 && os.Args[1] == "socks" {
			fmt.Println("--bind --port --http2 --insecure --connect-port --no-tunnel-ipv6")
			os.Exit(0)
		}
		fmt.Println("fixture-private-process-log")
		time.Sleep(time.Minute)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestRuntimeAndTermsGatesHaveNoSideEffects(t *testing.T) {
	for _, args := range [][]string{
		{"generate-wg"}, {"generate-masque"}, {"scan-wg"}, {"scan-masque"},
	} {
		root := filepath.Join(t.TempDir(), "new-candidate")
		args = append(args, "--work-root", root)
		if _, err := run(context.Background(), args); err == nil {
			t.Fatalf("missing gate accepted: %v", args)
		}
		if _, err := os.Stat(root); !os.IsNotExist(err) {
			t.Fatalf("gate created candidate state: %v", args)
		}
	}
}

func TestGenerationDoesNotReuseAnExistingWorkRoot(t *testing.T) {
	root := t.TempDir()
	marker := filepath.Join(root, "existing.conf")
	if err := os.WriteFile(marker, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := run(context.Background(), []string{"generate-wg", "--work-root", root, "--accept-tos"}); err == nil {
		t.Fatal("existing work-root allowed another registration")
	}
	got, _ := os.ReadFile(marker)
	if string(got) != "unchanged" {
		t.Fatal("generation changed an existing artifact")
	}
}

func TestUSQUECapabilityGateRequiresChecksumAndPinnedVersion(t *testing.T) {
	t.Setenv("RAZVILKA_USQUE_TEST_HELPER", "1")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(binary)
	sum := sha256.Sum256(data)
	expected := hex.EncodeToString(sum[:])
	if _, err := inspectUSQUE(context.Background(), binary, ""); err == nil {
		t.Fatal("missing binary digest accepted")
	}
	if _, err := inspectUSQUE(context.Background(), binary, strings.Repeat("0", 64)); err == nil {
		t.Fatal("wrong binary digest accepted")
	}
	identity, err := inspectUSQUE(context.Background(), binary, expected)
	if err != nil || identity["version"] != "4.2.1" || identity["server_pin_required"] != true {
		t.Fatalf("capability inspection failed: %+v, %v", identity, err)
	}
}

func TestMasqueCanceledAttemptCleansItsOwnProcessAndConfig(t *testing.T) {
	t.Setenv("RAZVILKA_USQUE_TEST_HELPER", "1")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Millisecond)
	defer cancel()
	result := runMasqueAttempt(ctx, root, []byte(`{"private_key":"fixture"}`), binary, "h2", 1, catalog.Service{ID: "fixture", ProbeURL: "https://example.com"})
	if result.Verified || !result.Cleanup || !result.NegativeControl || result.Reason != "candidate-listener-unavailable" {
		t.Fatalf("canceled child retained authority/runtime: %+v", result)
	}
	leftover, err := filepath.Glob(filepath.Join(root, "masque-attempt-*", "config.json"))
	if err != nil || len(leftover) != 0 {
		t.Fatal("private temporary config survived attempt cleanup")
	}
}

func TestBoundedProcessLogConsumesWithoutKeepingExtraOutput(t *testing.T) {
	var buffer bytes.Buffer
	out := &limitedOutput{writer: &buffer, remaining: 4}
	if n, err := out.Write([]byte("private-overflow")); err != nil || n != 16 {
		t.Fatalf("write result: %d %v", n, err)
	}
	if buffer.String() != "priv" {
		t.Fatalf("log limit ignored: %q", buffer.String())
	}
}

func TestSocksClientHasNoDirectFallback(t *testing.T) {
	client, closeClient, err := socksClient("127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	defer closeClient()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := getTrace(ctx, client); err == nil {
		t.Fatal("unavailable SOCKS endpoint unexpectedly used a direct connection")
	}
}

func TestNegativeControlRejectsAListenerThatSurvivedCleanup(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if closedSOCKSControl(ctx, listener.Addr().String()) {
		t.Fatal("a surviving listener was accepted as cleanup evidence")
	}
}

func TestServiceProbePreservesBlockedVerdict(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) }))
	defer server.Close()
	status, verdict, err := getService(context.Background(), server.Client(), catalog.Service{ID: "fixture", ProbeURL: server.URL})
	if err != nil || status != 403 || verdict == evidence.VerdictPass {
		t.Fatalf("blocked page became service proof: %d %s %v", status, verdict, err)
	}
}

func TestMASQUEProfileValidationRejectsMissingServerPin(t *testing.T) {
	if err := validateMasqueProfile([]byte(`{"private_key":"not-a-key","id":"private-device","access_token":"private-token","endpoint_pub_key":""}`)); err == nil {
		t.Fatal("missing TLS server pin accepted")
	}
	for _, mode := range []string{"h2", "h3", "both"} {
		if _, err := scanModes(mode); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := scanModes("insecure"); err == nil {
		t.Fatal("unsupported mode accepted")
	}
}
