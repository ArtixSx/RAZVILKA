//go:build linux

package nativeowner

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

func usqueRegistrationFixture(t *testing.T) (*operationgate.Gate, USQUERegistrationBinding) {
	t.Helper()
	sha := map[string]string{
		"amd64":  "a3ad4dce52cc33825fd8bfab520bb2a03f80891b69920819aa391d6a42c6bf10",
		"arm64":  "8e8b0e141b59088eb1331876ad67a24e7ed4eb23ea6174bf63452d7545e2d002",
		"mips":   "c7dd8a80eca37e5e5770073d72c85630d671e6d288214185c2f9bf246f01f59d",
		"mipsle": "2b466b9595704c6741472d1ffd17ef004d676871005504401105b5cd277c0dbf",
	}[runtime.GOARCH]
	if sha == "" {
		t.Skip("no audited upstream release for this architecture")
	}
	root := t.TempDir()
	control := filepath.Join(root, "control")
	if _, err := operationgate.InitializeSelfUpdateControl(context.Background(), control); err != nil {
		t.Fatal(err)
	}
	configs := engineconfig.New(filepath.Join(root, "stage"), filepath.Join(root, "backups"))
	configs.LiveRoot = filepath.Join(root, "live")
	return &operationgate.Gate{}, USQUERegistrationBinding{
		ControlRoot: control, BinarySHA256: sha, AcceptTOS: true, Configs: configs,
		Review: func(context.Context) error { return nil },
	}
}

func usqueRegistrationFixtureSession(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]string{
		"private_key": base64.StdEncoding.EncodeToString(private), "endpoint_pub_key": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: peer})),
		"id": "generated-fixture-device", "access_token": "generated-fixture-token", "endpoint_v4": "162.159.198.2", "endpoint_h2_v4": "162.159.198.2", "ipv4": "172.16.0.2",
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func prepareUSQUERegistrationFixture(t *testing.T, gate *operationgate.Gate, binding USQUERegistrationBinding, registrar usqueRegistrar) (USQUERegistrationResult, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ctx, release, err := gate.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	return prepareUSQUEInitial(ctx, gate, binding, func(context.Context) error { return nil }, registrar)
}

func TestUSQUEInitialRegistrationStagesAndRestoresOnePrivateSession(t *testing.T) {
	gate, binding := usqueRegistrationFixture(t)
	profile := usqueRegistrationFixtureSession(t)
	calls := 0
	register := func(_ context.Context, root *ownedfs.Root, _ func(context.Context) error, _ *operationgate.ControlEpochReview) ([]byte, error) {
		calls++
		reserved, err := root.ReadLimited(usqueRegistrationStateFile, 4096)
		if err != nil || !strings.Contains(string(reserved), binding.BinarySHA256) || strings.Contains(string(reserved), "session") {
			t.Fatal("registration ran before a private attempt was reserved", err)
		}
		return append([]byte(nil), profile...), nil
	}
	first, err := prepareUSQUERegistrationFixture(t, gate, binding, register)
	if err != nil || first.Reused || first.SHA256 != usqueRegistrationDigest(profile) || calls != 1 {
		t.Fatalf("first staging result=%+v calls=%d err=%v", first, calls, err)
	}
	slot, err := binding.Configs.ReadExpert("usque", "main")
	if err != nil || slot.Source != "staged" || slot.Content != string(profile) {
		t.Fatal("the candidate was not staged unchanged", err)
	}
	if err := binding.Configs.Discard("usque", "main"); err != nil {
		t.Fatal(err)
	}
	second, err := prepareUSQUERegistrationFixture(t, gate, binding, register)
	if err != nil || !second.Reused || second.SHA256 != first.SHA256 || calls != 1 {
		t.Fatalf("stored session was not restored once: result=%+v calls=%d err=%v", second, calls, err)
	}
}

func TestUSQUEInitialRegistrationUnknownNeverRepeats(t *testing.T) {
	gate, binding := usqueRegistrationFixture(t)
	calls := 0
	register := func(context.Context, *ownedfs.Root, func(context.Context) error, *operationgate.ControlEpochReview) ([]byte, error) {
		calls++
		return nil, errors.New("upstream-log-must-not-be-in-public-error")
	}
	for i := 0; i < 2; i++ {
		result, err := prepareUSQUERegistrationFixture(t, gate, binding, register)
		if !errors.Is(err, ErrUSQUERegistrationPending) || err.Error() != ErrUSQUERegistrationPending.Error() || result.SHA256 != "" || calls != 1 {
			t.Fatalf("uncertain request result=%+v calls=%d err=%v", result, calls, err)
		}
	}
}

func TestUSQUEInitialRegistrationNoChildRestoresEligibility(t *testing.T) {
	gate, binding := usqueRegistrationFixture(t)
	profile := usqueRegistrationFixtureSession(t)
	calls := 0
	register := func(context.Context, *ownedfs.Root, func(context.Context) error, *operationgate.ControlEpochReview) ([]byte, error) {
		calls++
		if calls == 1 {
			return nil, errUSQUERegistrationNoChild
		}
		return append([]byte(nil), profile...), nil
	}
	if _, err := prepareUSQUERegistrationFixture(t, gate, binding, register); !errors.Is(err, ErrUSQUERegistrationChanged) || errors.Is(err, ErrUSQUERegistrationPending) {
		t.Fatalf("definite no-start classified as a provider outcome: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(binding.ControlRoot, usqueRegistrationStateFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("definite no-start did not remove its original empty reservation", err)
	}
	if result, err := prepareUSQUERegistrationFixture(t, gate, binding, register); err != nil || result.SHA256 != usqueRegistrationDigest(profile) || calls != 2 {
		t.Fatalf("no-start prevented a later first actual attempt: calls=%d err=%v", calls, err)
	}
}

func TestUSQUEInitialRegistrationNoChildRetainsDifferentReservation(t *testing.T) {
	gate, binding := usqueRegistrationFixture(t)
	const differentNonce = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	register := func(_ context.Context, root *ownedfs.Root, _ func(context.Context) error, epoch *operationgate.ControlEpochReview) ([]byte, error) {
		state := usqueRegistrationState{Schema: 1, InstallationID: epoch.Reference().InstallationID, BinarySHA256: binding.BinarySHA256, AttemptID: differentNonce}
		if err := writeUSQUERegistrationState(root, state); err != nil {
			t.Fatal(err)
		}
		return nil, errUSQUERegistrationNoChild
	}
	if _, err := prepareUSQUERegistrationFixture(t, gate, binding, register); !errors.Is(err, ErrUSQUERegistrationPending) || !errors.Is(err, ErrUSQUERegistrationState) {
		t.Fatal("different reservation did not fence a no-start removal", err)
	}
	raw, err := os.ReadFile(filepath.Join(binding.ControlRoot, usqueRegistrationStateFile))
	if err != nil || !strings.Contains(string(raw), differentNonce) {
		t.Fatal("different reservation disappeared", err)
	}
}

func TestUSQUEInitialRegistrationLeavesChangedEditorDraftAndRecovers(t *testing.T) {
	gate, binding := usqueRegistrationFixture(t)
	profile := usqueRegistrationFixtureSession(t)
	calls := 0
	register := func(context.Context, *ownedfs.Root, func(context.Context) error, *operationgate.ControlEpochReview) ([]byte, error) {
		calls++
		if _, err := binding.Configs.Stage("usque", "main", "local editor draft"); err != nil {
			t.Fatal(err)
		}
		return append([]byte(nil), profile...), nil
	}
	if _, err := prepareUSQUERegistrationFixture(t, gate, binding, register); !errors.Is(err, ErrUSQUERegistrationSlot) || calls != 1 {
		t.Fatalf("editor collision was not retained: calls=%d err=%v", calls, err)
	}
	current, err := binding.Configs.ReadExpert("usque", "main")
	if err != nil || current.Content != "local editor draft" {
		t.Fatal("editor draft was replaced", err)
	}
	if err := binding.Configs.Discard("usque", "main"); err != nil {
		t.Fatal(err)
	}
	if result, err := prepareUSQUERegistrationFixture(t, gate, binding, register); err != nil || !result.Reused || calls != 1 {
		t.Fatalf("private completed session not recovered after editor collision: calls=%d err=%v", calls, err)
	}
}

func TestUSQUEInitialRegistrationRequiresConsentAndCurrentAdmission(t *testing.T) {
	gate, binding := usqueRegistrationFixture(t)
	for _, failure := range []error{ErrUSQUERegistrationConsent, ErrUSQUERegistrationChanged, ErrUSQUERegistrationUnsupported} {
		before := binding
		switch failure {
		case ErrUSQUERegistrationConsent:
			before.AcceptTOS = false
		case ErrUSQUERegistrationChanged:
			before.Review = func(context.Context) error { return context.Canceled }
		case ErrUSQUERegistrationUnsupported:
			before.Binary = filepath.Join(t.TempDir(), "not-an-installed-binary")
		}
		parent, cancel := context.WithTimeout(context.Background(), time.Second)
		ctx, release, err := gate.ExclusiveContext(parent)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		_, err = PrepareUSQUEInitial(ctx, gate, before)
		release()
		cancel()
		if !errors.Is(err, failure) {
			t.Fatalf("wanted %v, got %v", failure, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(binding.ControlRoot, usqueRegistrationStateFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("refused registration left a reservation", err)
	}
}

func TestUSQUERegistrationExecUsesOnlyHeldPrivateOutput(t *testing.T) {
	gate, binding := usqueRegistrationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ctx, release, err := gate.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	epoch, err := gate.ReviewControlEpoch(ctx, binding.ControlRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer epoch.Close()
	root, _, closeRoot, err := openUSQUERegistrationRoot(binding.ControlRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer closeRoot()
	path := filepath.Join(binding.ControlRoot, "local-registrar-fixture")
	fixture := []byte(`#!/bin/sh
set -eu
test "$#" -eq 6
test "$1" = --config
test "$2" = /proc/self/fd/4
test "$3" = register
test "$4" = --accept-tos
test "$5" = --name
test "$6" = RAZVILKA
printf '%s' fake-session > "$2"
printf '%s\n' diagnostic-fixture-token >&2
`)
	if err := os.WriteFile(path, fixture, 0o700); err != nil {
		t.Fatal(err)
	}
	binary, err := openHeld(ctx, path, usqueRegistrationDigest(fixture), 4096, true, true)
	if err != nil {
		t.Fatal(err)
	}
	defer binary.close()
	denied := func(context.Context, func() error) error { return context.Canceled }
	if value, err := runUSQUERegistration(ctx, root, binary, epoch.Current, denied); err != errUSQUERegistrationNoChild || len(value) != 0 {
		t.Fatal("pre-Start refusal did not prove absence of a provider child", err)
	}
	value, err := runUSQUERegistration(ctx, root, binary, epoch.Current, epoch.WithStart)
	if err != nil || string(value) != "fake-session" {
		t.Fatal("fixed private descriptor registration fixture did not complete", err)
	}
	if _, err := os.Stat(filepath.Join(binding.ControlRoot, usqueRegistrationOutput)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("temporary private output survived joined command", err)
	}
}
