package cloudflareprovider

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func wgFixture() []byte {
	private := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	public := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	return []byte("[Interface]\nPrivateKey = " + private + "\nAddress = 172.16.0.2/32, 2606:4700:110::2/128\nDNS = 1.1.1.1\nMTU = 1280\n[Peer]\nPublicKey = " + public + "\nEndpoint = engage.cloudflareclient.com:2408\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n")
}

func usqueFixture() []byte {
	return []byte(`{"id":"private-device-marker","private_key":"private-key-marker","access_token":"private-token-marker","endpoint_pub_key":"peer-key-marker","endpoint_v4":"162.159.198.2","future":{"license":"private-license-marker"}}`)
}

func privateStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := t.TempDir()
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path
}

func TestPrivateImportHasNoPublicSecretRepresentation(t *testing.T) {
	for _, fixture := range []struct {
		kind string
		data []byte
	}{{SourceWireGuard, wgFixture()}, {SourceUSQUE, usqueFixture()}} {
		parsed, err := ParseImport(fixture.kind, fixture.data)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(parsed)
		if err != nil {
			t.Fatal(err)
		}
		for _, text := range []string{string(encoded), fmt.Sprint(parsed), fmt.Sprintf("%+v %#v %s %q", parsed, parsed, parsed, parsed)} {
			for _, secret := range []string{"private-key-marker", "private-token-marker", "private-device-marker", "private-license-marker", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))} {
				if strings.Contains(text, secret) {
					t.Fatal("secret exposed in JSON/log preview")
				}
			}
		}
		view := parsed.Preview()
		if view.Verification != "imported-unverified" || view.Ownership != "copied-snapshot" || !view.HasPrivateKey {
			t.Fatalf("import claims excess readiness: %+v", view)
		}
		if fixture.kind == SourceWireGuard && len(view.PublicKeyFingerprint) != 64 {
			t.Fatal("WG local public fingerprint missing")
		}
		if fixture.kind == SourceUSQUE && view.PublicKeyFingerprint != "" {
			t.Fatal("unknown USQUE key encoding was guessed")
		}
	}
}

func TestStoreAtomicIdempotentSnapshotsAndRedactedRestart(t *testing.T) {
	s, path := privateStore(t)
	input := usqueFixture()
	parsed, err := ParseImport(SourceUSQUE, input)
	if err != nil {
		t.Fatal(err)
	}
	// The import owns its bytes; changing the caller's buffer is not a secret
	// store mutation and cannot corrupt a later import.
	input[0] = '!'
	first, err := s.ImportSnapshot(context.Background(), parsed)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.ImportSnapshot(context.Background(), parsed)
	if err != nil || second.ID != first.ID {
		t.Fatalf("non-idempotent import: %v", err)
	}
	if !validID(first.ID) || strings.ContainsAny(first.SecretReference, "/\\") {
		t.Fatal("public reference contains path")
	}
	stored, err := os.ReadFile(filepath.Join(path, storeFile))
	if err != nil {
		t.Fatal(err)
	}
	var doc privateDocument
	if json.Unmarshal(stored, &doc) != nil || len(doc.Accounts) != 1 || !bytes.Equal(doc.Accounts[0].Raw, usqueFixture()) {
		t.Fatal("private source snapshot lost")
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(filepath.Join(path, storeFile))
		if info.Mode().Perm() != 0o600 {
			t.Fatal("private state permissions are not 0600")
		}
	}
	reopened, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	accounts, err := reopened.List(context.Background())
	if err != nil || len(accounts) != 1 || accounts[0].ID != first.ID {
		t.Fatalf("restart: %v", err)
	}
	public, _ := json.Marshal(accounts)
	if strings.Contains(string(public), "private-") {
		t.Fatal("list exposes private values")
	}
	if accounts[0].Verification != "imported-unverified" {
		t.Fatal("restart promoted imported account")
	}
	// No runtime files, profiles or registration artifacts are created.
	files, _ := os.ReadDir(path)
	if len(files) != 2 || files[0].Name() != writerLockFile || files[1].Name() != storeFile {
		t.Fatalf("unexpected side effects: %v", files)
	}
}

func TestInvalidImportAndAmbiguousInputRejectedWithoutEcho(t *testing.T) {
	cases := []struct {
		kind string
		data []byte
	}{
		{SourceUSQUE, []byte(`{"private_key":"private-marker"}`)},
		{SourceUSQUE, append(usqueFixture(), []byte(" {}")...)},
		{SourceUSQUE, bytes.Replace(usqueFixture(), []byte(`"id":`), []byte(`"id":"duplicate","id":`), 1)},
		{SourceUSQUE, bytes.Replace(usqueFixture(), []byte("private-key-marker"), []byte("[REDACTED]"), 1)},
		{SourceWireGuard, append(wgFixture(), []byte("\nPostUp = private-marker\n")...)},
		{SourceWireGuard, append(wgFixture(), []byte("\nEndpoint = private-marker:2408\n")...)},
		{SourceWireGuard, bytes.Replace(wgFixture(), []byte(":2408"), []byte(":99999"), 1)},
		{SourceWireGuard, bytes.Repeat([]byte("x"), MaxImportBytes+1)},
		{"registration-request", usqueFixture()},
	}
	for n, item := range cases {
		_, err := ParseImport(item.kind, item.data)
		if !errors.Is(err, ErrImport) || strings.Contains(err.Error(), "private-marker") {
			t.Fatalf("case %d: %v", n, err)
		}
	}
}

func TestStoreRejectsCorruptionCancellationAndUnknownWriter(t *testing.T) {
	s, path := privateStore(t)
	parsed, _ := ParseImport(SourceUSQUE, usqueFixture())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.ImportSnapshot(ctx, parsed); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel ignored: %v", err)
	}
	if _, err := os.Stat(filepath.Join(path, storeFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cancel wrote private state")
	}
	lock := filepath.Join(path, ".import.lock")
	if err := os.WriteFile(lock, []byte("another owner"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ImportSnapshot(context.Background(), parsed); !errors.Is(err, ErrBusy) {
		t.Fatalf("unknown writer ignored: %v", err)
	}
	if b, _ := os.ReadFile(lock); string(b) != "another owner" {
		t.Fatal("foreign lock altered")
	}
	if err := os.Remove(lock); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ImportSnapshot(context.Background(), parsed); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(path, storeFile)
	before, _ := os.ReadFile(file)
	var doc privateDocument
	_ = json.Unmarshal(before, &doc)
	doc.Accounts[0].Raw = []byte("private-corruption-marker")
	data, _ := json.Marshal(doc)
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.List(context.Background()); !errors.Is(err, ErrStore) {
		t.Fatalf("corrupt state accepted: %v", err)
	}
	if _, err := s.ImportSnapshot(context.Background(), parsed); !errors.Is(err, ErrStore) {
		t.Fatalf("corrupt state overwritten: %v", err)
	}
	after, _ := os.ReadFile(file)
	if !bytes.Equal(data, after) {
		t.Fatal("corrupt private store destroyed instead of preserved for recovery")
	}
}

func TestStoreRejectsSymlinkAndBroadPermissions(t *testing.T) {
	s, path := privateStore(t)
	_ = s
	external := filepath.Join(t.TempDir(), "private.json")
	if err := os.WriteFile(external, []byte("private-marker"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(path, storeFile)); err != nil {
		t.Skip("symlinks unavailable on this host")
	}
	if opened, err := OpenStore(path); err == nil {
		_ = opened.Close()
		t.Fatal("symlink store accepted")
	}
	if runtime.GOOS != "windows" {
		broad := t.TempDir()
		if err := os.Chmod(broad, 0o755); err != nil {
			t.Fatal(err)
		}
		if opened, err := OpenStore(broad); err == nil {
			_ = opened.Close()
			t.Fatal("public-readable private directory accepted")
		}
	}
}

func FuzzParseImport(f *testing.F) {
	f.Add(SourceUSQUE, usqueFixture())
	f.Add(SourceWireGuard, wgFixture())
	f.Add(SourceWGCF, wgcfFixture())
	f.Fuzz(func(t *testing.T, kind string, input []byte) {
		parsed, err := ParseImport(kind, input)
		if err != nil && !errors.Is(err, ErrImport) {
			t.Fatalf("non-redacted error: %v", err)
		}
		if err == nil {
			data, err := json.Marshal(parsed)
			if err != nil || bytes.Contains(data, []byte(`"raw"`)) {
				t.Fatal("private field in public JSON")
			}
			if parsed.Preview().Verification != "imported-unverified" {
				t.Fatal("import promoted to verified")
			}
		}
	})
}
