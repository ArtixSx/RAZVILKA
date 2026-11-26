package warp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/cloudflareprovider"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/nativeenrollment"
)

type nativeTestAPI func(context.Context, cloudflareprovider.RegistrationRequest) (cloudflareprovider.RegistrationResponse, error)

func (api nativeTestAPI) Register(ctx context.Context, request cloudflareprovider.RegistrationRequest) (cloudflareprovider.RegistrationResponse, error) {
	return api(ctx, request)
}

func newNativeTestManager(t *testing.T) *Manager {
	t.Helper()
	root := t.TempDir()
	m := New(filepath.Join(root, "warp"), filepath.Join(root, "backup"), engineconfig.New(filepath.Join(root, "stage"), filepath.Join(root, "config-backup")))
	m.BinPaths = []string{filepath.Join(root, "no-wgcf")}
	m.ProfilePaths = []string{filepath.Join(root, "live.conf")}
	return m
}

func installNativeTestAPI(m *Manager, calls *int, checkpoint bool, fail error) {
	m.nativeAPI = func(save func([]byte) error) cloudflareprovider.RegistrationAPI {
		return nativeTestAPI(func(ctx context.Context, request cloudflareprovider.RegistrationRequest) (cloudflareprovider.RegistrationResponse, error) {
			*calls++
			peer := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("p", 32)))
			if checkpoint {
				document := map[string]any{
					"id": "private-device-marker", "token": "private-token-marker", "key": request.PublicKey, "key_type": "curve25519", "tunnel_type": "wireguard",
					"config": map[string]any{"interface": map[string]any{"addresses": map[string]string{"v4": "172.16.0.2"}}, "peers": []any{map[string]any{"public_key": peer, "endpoint": map[string]any{"v4": "162.159.192.8:0", "ports": []int{2408, 500}}}}},
				}
				encoded, _ := json.Marshal(document)
				if err := save(encoded); err != nil {
					return cloudflareprovider.RegistrationResponse{}, err
				}
			}
			if fail != nil {
				return cloudflareprovider.RegistrationResponse{}, fail
			}
			return cloudflareprovider.RegistrationResponse{DeviceID: "private-device-marker", AccessToken: "private-token-marker", PeerPublicKey: peer, Addresses: []string{"172.16.0.2/32"}, Endpoints: []string{"162.159.192.8:2408", "162.159.192.8:500"}, APISchema: cloudflareprovider.ConsumerRegistrationVersion, TermsRevision: request.TermsRevision}, nil
		})
	}
}

func TestNativeGenerateStagesAndReusesValidatedAccountWithoutWGCF(t *testing.T) {
	m := newNativeTestManager(t)
	calls := 0
	installNativeTestAPI(m, &calls, true, nil)
	if err := os.WriteFile(m.ProfilePaths[0], []byte(validProfile), 0o600); err != nil {
		t.Fatal(err)
	}
	status := m.Status(context.Background())
	if !status.GeneratorInstalled || status.GeneratorKind != "native-cloudflare" || status.AccountRegistered {
		t.Fatalf("native status=%+v", status)
	}
	first, err := m.Generate(context.Background(), true, false)
	if err != nil || !first.OK || first.Source != "native-cloudflare" || calls != 1 {
		t.Fatalf("generate=%+v calls=%d err=%v", first, calls, err)
	}
	second, err := m.Generate(context.Background(), false, false)
	if err != nil || calls != 1 || second.SHA256 != first.SHA256 {
		t.Fatalf("reuse re-registered: calls=%d err=%v", calls, err)
	}
	status = m.Status(context.Background())
	if !status.AccountRegistered || !status.CandidateStaged || status.RegistrationState != "registered" {
		t.Fatalf("registered status=%+v", status)
	}
	encoded, _ := json.Marshal(status)
	if strings.Contains(string(encoded), "private-") {
		t.Fatal("status disclosed enrollment secrets")
	}
	working, err := os.ReadFile(m.ProfilePaths[0])
	if err != nil || string(working) != validProfile {
		t.Fatal("generation changed working profile")
	}
	if readNativeTestDocument(t, m).Has(nativePending) {
		t.Fatal("completed registration remained pending")
	}
}

func TestNativePendingWithoutResponseBlocksEveryNewEnrollmentAfterRestart(t *testing.T) {
	m := newNativeTestManager(t)
	calls := 0
	installNativeTestAPI(m, &calls, false, context.DeadlineExceeded)
	if _, err := m.Generate(context.Background(), true, false); !errors.Is(err, ErrEnrollmentPending) {
		t.Fatal("uncertain request did not stay pending", err)
	}
	restarted := New(m.Root, m.BackupRoot, m.EngineConfigs)
	installNativeTestAPI(restarted, &calls, true, nil)
	for _, fresh := range []bool{false, true} {
		if _, err := restarted.Generate(context.Background(), true, fresh); !errors.Is(err, ErrEnrollmentPending) {
			t.Fatal("unresolved registration was replaced", err)
		}
	}
	if calls != 1 {
		t.Fatalf("uncertain POST was retried %d times", calls)
	}
	status := restarted.Status(context.Background())
	if status.RegistrationState != "pending-review" || status.RecoveryAvailable || status.AccountRegistered {
		t.Fatalf("uncertain status=%+v", status)
	}
}

func TestNativeRecoveryUsesOriginalResponseAndKeyWithoutNewPOST(t *testing.T) {
	m := newNativeTestManager(t)
	calls := 0
	installNativeTestAPI(m, &calls, true, context.Canceled)
	if _, err := m.Generate(context.Background(), true, false); !errors.Is(err, ErrEnrollmentPending) {
		t.Fatal(err)
	}
	status := m.Status(context.Background())
	if !status.RecoveryAvailable || status.AccountRegistered {
		t.Fatalf("checkpoint status=%+v", status)
	}
	restarted := New(m.Root, m.BackupRoot, m.EngineConfigs)
	installNativeTestAPI(restarted, &calls, false, errors.New("must never run"))
	result, err := restarted.Generate(context.Background(), false, true)
	if err != nil || !result.OK || calls != 1 || result.FreshAccount {
		t.Fatalf("recovery=%+v calls=%d err=%v", result, calls, err)
	}
	if got := restarted.Status(context.Background()); !got.AccountRegistered || got.RegistrationState != "registered" {
		t.Fatalf("recovered status=%+v", got)
	}
}

func TestNativeFreshKeepsPreviousEnrollmentAndLegacyAccount(t *testing.T) {
	m := newNativeTestManager(t)
	calls := 0
	installNativeTestAPI(m, &calls, true, nil)
	if _, err := m.Generate(context.Background(), true, false); err != nil {
		t.Fatal(err)
	}
	before := readNativeTestDocument(t, m).Get(nativeCurrent)
	var previous nativeEnrollment
	if err := json.Unmarshal(before, &previous); err != nil {
		t.Fatal(err)
	}
	previousKey := readNativeTestDocument(t, m).Get(previous.Directory + "/private-key.bin")
	legacy := []byte("legacy-account-secret-marker")
	if err := os.WriteFile(m.accountPath(), legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := m.Generate(context.Background(), true, true)
	if err != nil || !result.FreshAccount || calls != 2 {
		t.Fatalf("rotation=%+v calls=%d err=%v", result, calls, err)
	}
	key := readNativeTestDocument(t, m).Get(previous.Directory + "/private-key.bin")
	if string(key) != string(previousKey) {
		t.Fatal("previous enrollment was overwritten")
	}
	gotLegacy, err := os.ReadFile(m.accountPath())
	if err != nil || string(gotLegacy) != string(legacy) {
		t.Fatal("rotation modified legacy enrollment")
	}
}

func TestNativeMissingTermsAndLegacyReuseNeverRegister(t *testing.T) {
	m := newNativeTestManager(t)
	calls := 0
	installNativeTestAPI(m, &calls, true, nil)
	if _, err := m.Generate(context.Background(), false, false); !errors.Is(err, ErrTermsAcceptanceRequired) {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.accountPath(), []byte("retained legacy account"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Generate(context.Background(), true, false); !errors.Is(err, ErrLegacyGeneratorRequired) {
		t.Fatal("legacy reuse silently created new enrollment", err)
	}
	if calls != 0 {
		t.Fatal("preflight performed registration")
	}
}

func TestNativeCorruptStateCannotTriggerRegistration(t *testing.T) {
	m := newNativeTestManager(t)
	calls := 0
	installNativeTestAPI(m, &calls, true, nil)
	if err := os.MkdirAll(m.nativeRootPath(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(m.nativeRootPath(), nativeCurrent), []byte(`{"schema":1,"directory":"../../other"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Generate(context.Background(), true, true); !errors.Is(err, ErrEnrollmentStore) || calls != 0 {
		t.Fatalf("corrupt state initiated registration: calls=%d err=%v", calls, err)
	}
}

func TestNativeInterruptedStagingRecoversSameEnrollment(t *testing.T) {
	m := newNativeTestManager(t)
	calls := 0
	installNativeTestAPI(m, &calls, true, nil)
	badStage := filepath.Join(t.TempDir(), "stage-file")
	if err := os.WriteFile(badStage, []byte("occupied"), 0o600); err != nil {
		t.Fatal(err)
	}
	goodConfigs := m.EngineConfigs
	m.EngineConfigs = engineconfig.New(badStage, t.TempDir())
	if _, err := m.Generate(context.Background(), true, false); err == nil {
		t.Fatal("invalid staging unexpectedly succeeded")
	}
	m.EngineConfigs = goodConfigs
	if result, err := m.Generate(context.Background(), false, false); err != nil || !result.OK || calls != 1 {
		t.Fatalf("staging retry lost original enrollment: calls=%d err=%v", calls, err)
	}
}

func TestNativePendingIntentIsExclusive(t *testing.T) {
	m := newNativeTestManager(t)
	calls := 0
	installNativeTestAPI(m, &calls, true, nil)
	target, err := nativeenrollment.Open(m.Root)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	if _, err := m.Generate(context.Background(), true, true); err == nil || calls != 0 {
		t.Fatal("a competing writer sent registration")
	}
}

func readNativeTestDocument(t *testing.T, m *Manager) nativeenrollment.Document {
	t.Helper()
	image, err := nativeenrollment.ReadEffective(context.Background(), m.Root)
	if err != nil {
		t.Fatal(err)
	}
	d, err := nativeenrollment.Decode(image)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestNativeLegacyMigrationCopiesProviderWithoutPOSTOrSourceChanges(t *testing.T) {
	m := newNativeTestManager(t)
	calls := 0
	installNativeTestAPI(m, &calls, true, nil)
	first, err := m.Generate(context.Background(), true, false)
	if err != nil {
		t.Fatal(err)
	}
	d := readNativeTestDocument(t, m)
	entry, _, err := readNativeEnrollment(d, nativeCurrent)
	if err != nil {
		t.Fatal(err)
	}
	legacy := m.nativeRootPath()
	if err := os.MkdirAll(filepath.Join(legacy, entry.Directory, "provider"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, f := range d.Files {
		if strings.HasSuffix(f.Name, "registration.private.json") {
			continue
		}
		if err := os.WriteFile(filepath.Join(legacy, filepath.FromSlash(f.Name)), f.Data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	candidate, err := cloudflareprovider.RecoverConsumerCandidate(d.Get(entry.Directory+"/private-key.bin"), d.Get(entry.Directory+"/response.private.json"), entry.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := cloudflareprovider.OpenStore(filepath.Join(legacy, entry.Directory, "provider"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.ImportCandidate(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	provider.Close()
	providerFile := filepath.Join(legacy, entry.Directory, "provider", "accounts.private.json")
	before, err := os.ReadFile(providerFile)
	if err != nil {
		t.Fatal(err)
	}
	beforeInfo, _ := os.Stat(providerFile)
	if err := os.Remove(filepath.Join(m.Root, nativeenrollment.FileName)); err != nil {
		t.Fatal(err)
	}
	copy, err := m.ExportNativePrivateIfPresent(context.Background())
	if err != nil || copy == nil {
		t.Fatal("legacy private export failed", err)
	}
	if _, err := os.Stat(filepath.Join(m.Root, nativeenrollment.FileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("read-only backup migrated canonical state")
	}
	second, err := m.Generate(context.Background(), false, false)
	if err != nil || second.SHA256 != first.SHA256 || calls != 1 {
		t.Fatal("migration did not reuse exact registration", err)
	}
	after, _ := os.ReadFile(providerFile)
	afterInfo, _ := os.Stat(providerFile)
	if string(after) != string(before) || !afterInfo.ModTime().Equal(beforeInfo.ModTime()) || afterInfo.Mode() != beforeInfo.Mode() {
		t.Fatal("legacy provider source changed")
	}
	if !readNativeTestDocument(t, m).Has(entry.Directory + "/provider/accounts.private.json") {
		t.Fatal("canonical migration omitted original provider")
	}
}

func TestNativePrivateRestoreRetainsPendingAndMakesNoRegistration(t *testing.T) {
	source := newNativeTestManager(t)
	calls := 0
	installNativeTestAPI(source, &calls, true, nil)
	if _, err := source.Generate(context.Background(), true, false); err != nil {
		t.Fatal(err)
	}
	old, err := source.ExportNativePrivateIfPresent(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	installNativeTestAPI(source, &calls, false, context.DeadlineExceeded)
	if _, err := source.Generate(context.Background(), true, true); !errors.Is(err, ErrEnrollmentPending) {
		t.Fatal(err)
	}
	pending, err := source.ExportNativePrivateIfPresent(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	restored := newNativeTestManager(t)
	installNativeTestAPI(restored, &calls, true, errors.New("must never register"))
	target, err := restored.BeginNativeRestore(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	before, _ := target.Read(context.Background())
	after, err := target.MergeImage(context.Background(), *pending)
	if err != nil {
		t.Fatal(err)
	}
	if err := target.CompareAndSwap(context.Background(), before, after); err != nil {
		t.Fatal(err)
	}
	if _, err := target.MergeImage(context.Background(), *old); !errors.Is(err, nativeenrollment.ErrConflict) {
		t.Fatal("older backup erased unresolved request", err)
	}
	target.Close()
	if got := restored.Status(context.Background()); got.RegistrationState != "pending-review" || !got.AccountRegistered || got.CandidateStaged {
		t.Fatalf("restore activated/staged registration or lost status: %+v", got)
	}
	if _, err := restored.Generate(context.Background(), true, true); !errors.Is(err, ErrEnrollmentPending) || calls != 2 {
		t.Fatal("restore permitted duplicate POST", err)
	}
	got, err := restored.ExportNativePrivateIfPresent(context.Background())
	if err != nil || got.SHA256 != pending.SHA256 {
		t.Fatal("pending original image changed", err)
	}
}
