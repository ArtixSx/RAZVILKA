//go:build linux

package dataplane

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

func TestUSQUELiveSessionChecksPrivateFileAndIdentity(t *testing.T) {
	for _, change := range []string{"replacement", "draft", "permissions", "symlink", "hardlink"} {
		t.Run(change, func(t *testing.T) {
			ctx := context.Background()
			root := t.TempDir()
			configs := engineconfig.New(filepath.Join(root, "stage"), filepath.Join(root, "backups"))
			configs.LiveRoot = filepath.Join(root, "live")
			slot, err := configs.Read("usque", "main")
			if err != nil || slot.Source != "missing" {
				t.Fatal("missing owned slot expected", err)
			}
			data := savedUSQUESessionFixture(t)
			if err := os.MkdirAll(filepath.Dir(slot.Path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(slot.Path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			found, info, err := readUSQUELiveSession(ctx, configs, slot.Path)
			if err != nil || len(found) == 0 {
				t.Fatal("private saved session not admitted", err)
			}
			session := &USQUELiveSession{configs: configs, path: slot.Path, file: info, sum: sha256.Sum256(found)}
			if session.sum != sha256.Sum256(data) || session.Current(ctx) != nil {
				t.Fatal("saved session authority lost before the operation")
			}
			other := filepath.Join(filepath.Dir(slot.Path), "other")
			switch change {
			case "replacement":
				if err := os.WriteFile(other, data, 0o600); err != nil {
					t.Fatal(err)
				}
				err = os.Rename(other, slot.Path)
			case "draft":
				_, err = configs.Stage("usque", "main", string(data))
			case "permissions":
				err = os.Chmod(slot.Path, 0o644)
			case "symlink":
				if err := os.Rename(slot.Path, other); err != nil {
					t.Fatal(err)
				}
				err = os.Symlink(other, slot.Path)
			case "hardlink":
				err = os.Link(slot.Path, other)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := session.Current(ctx); !errors.Is(err, ErrUSQUELiveSession) {
				t.Fatal("changed slot kept its startup authority", err)
			}
		})
	}
}

func TestUSQUELiveSessionRequiresOwnedExecutorAndReviewedFormat(t *testing.T) {
	binary := map[string]string{
		"amd64":  "a3ad4dce52cc33825fd8bfab520bb2a03f80891b69920819aa391d6a42c6bf10",
		"arm64":  "8e8b0e141b59088eb1331876ad67a24e7ed4eb23ea6174bf63452d7545e2d002",
		"mips":   "c7dd8a80eca37e5e5770073d72c85630d671e6d288214185c2f9bf246f01f59d",
		"mipsle": "2b466b9595704c6741472d1ffd17ef004d676871005504401105b5cd277c0dbf",
	}[runtime.GOARCH]
	if binary == "" {
		t.Skip("no audited USQUE for this architecture")
	}
	data := savedUSQUESessionFixture(t)
	if !validUSQUELiveSession(data, binary) || validUSQUELiveSession(data, "unknown") {
		t.Fatal("saved session selected an unsupported executor")
	}
	var changed map[string]string
	if err := json.Unmarshal(data, &changed); err != nil {
		t.Fatal(err)
	}
	changed["endpoint_h2_v4"] = ""
	data, err := json.Marshal(changed)
	if err != nil || validUSQUELiveSession(data, binary) {
		t.Fatal("an implicit alternate endpoint entered the owned canary", err)
	}
}

func savedUSQUESessionFixture(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(map[string]string{
		"private_key": base64.StdEncoding.EncodeToString(private), "endpoint_pub_key": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public})),
		"id": "fixture-device", "access_token": "fixture-token", "endpoint_v4": "162.159.198.2", "endpoint_h2_v4": "162.159.198.2", "ipv4": "172.16.0.2",
	})
	if err != nil {
		t.Fatal(err)
	}
	return data
}
