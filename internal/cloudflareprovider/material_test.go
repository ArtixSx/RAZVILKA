package cloudflareprovider

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestTunnelMaterialIsScopedRedactedAndErased(t *testing.T) {
	candidate, err := (Registrar{
		API:    &mockRegistrationAPI{result: validRegistrationResponse()},
		Random: bytes.NewReader(bytes.Repeat([]byte{13}, 64)),
	}).NewCandidate(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	store, _ := privateStore(t)
	account, err := store.ImportCandidate(context.Background(), candidate)
	if err != nil {
		t.Fatal(err)
	}
	wantPrivate := append([]byte(nil), candidate.privateKey...)
	var retained TunnelMaterial
	err = store.WithTunnelMaterial(context.Background(), account.ID, func(_ context.Context, material TunnelMaterial) error {
		retained = material
		if !bytes.Equal(material.PrivateKey(), wantPrivate) || !bytes.Equal(material.PeerPublicKey(), bytes.Repeat([]byte{9}, 32)) {
			t.Fatal("wrong tunnel keys")
		}
		if len(material.Addresses()) != 2 || len(material.Endpoints()) != 2 {
			t.Fatal("incomplete tunnel material")
		}
		encoded, _ := json.Marshal(material)
		output := string(encoded) + fmt.Sprintf(" %s %+v %#v", material, material, material)
		for _, secret := range []string{base64.StdEncoding.EncodeToString(wantPrivate), "private-device-marker", "private-token-marker"} {
			if strings.Contains(output, secret) {
				t.Fatal("material leaked through representation")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(retained.PrivateKey(), make([]byte, 32)) || !bytes.Equal(retained.PeerPublicKey(), make([]byte, 32)) {
		t.Fatal("callback key material remained usable after lease")
	}
}

func TestTunnelMaterialRejectsPassiveImportsAndHonorsContext(t *testing.T) {
	store, _ := privateStore(t)
	imported, err := ParseImport(SourceWireGuard, wgFixture())
	if err != nil {
		t.Fatal(err)
	}
	account, err := store.ImportSnapshot(context.Background(), imported)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	consume := func(context.Context, TunnelMaterial) error { called = true; return nil }
	if err := store.WithTunnelMaterial(context.Background(), account.ID, consume); !errors.Is(err, ErrTunnelMaterialUnavailable) || called {
		t.Fatal("passive import gained local tunnel capability", err)
	}
	if err := store.WithTunnelMaterial(context.Background(), "cf-00000000000000000000000000000000", consume); !errors.Is(err, ErrAccountNotFound) || called {
		t.Fatal("missing account reached consumer", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := store.WithTunnelMaterial(ctx, account.ID, consume); !errors.Is(err, context.Canceled) || called {
		t.Fatal("canceled material request reached consumer", err)
	}
}

func TestTunnelMaterialPropagatesConsumerFailure(t *testing.T) {
	candidate, _ := (Registrar{API: &mockRegistrationAPI{result: validRegistrationResponse()}, Random: bytes.NewReader(bytes.Repeat([]byte{17}, 64))}).NewCandidate(context.Background(), true)
	store, _ := privateStore(t)
	account, _ := store.ImportCandidate(context.Background(), candidate)
	want := errors.New("candidate builder stopped")
	if err := store.WithTunnelMaterial(context.Background(), account.ID, func(context.Context, TunnelMaterial) error { return want }); !errors.Is(err, want) {
		t.Fatal("consumer failure was hidden", err)
	}
}
