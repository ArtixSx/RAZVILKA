package wireguardprofile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixture = "[Interface]\nPrivateKey = YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=\nAddress = 10.66.0.2/32\n[Peer]\nPublicKey = YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=\nEndpoint = vpn.example.com:51820\nAllowedIPs = 0.0.0.0/0\n"

func TestProfilesAreSeparateRevisionCheckedAndSecretSafe(t *testing.T) {
	ctx := context.Background()
	s := New(t.TempDir())
	one, err := s.Put(ctx, "primary", "Primary", fixture, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(ctx, "reserve", "Reserve", fixture, ""); err != nil {
		t.Fatal(err)
	}
	list, err := s.List(ctx)
	if err != nil || len(list) != 2 {
		t.Fatal(list, err)
	}
	p, err := s.Get(ctx, "primary")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(p)
	for _, text := range []string{string(data), fmt.Sprintf("%+v %#v", p, p)} {
		if strings.Contains(text, "YWFh") || strings.Contains(text, "PrivateKey") || strings.Contains(text, "vpn.example") {
			t.Fatal("secret-bearing profile leaked")
		}
	}
	if _, err := s.Put(ctx, "primary", "Changed", fixture, ""); !errors.Is(err, ErrRevision) {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, "primary", "stale"); !errors.Is(err, ErrRevision) {
		t.Fatal(err)
	}
	updated, err := s.Put(ctx, "primary", "Changed", fixture, one.Revision)
	if err != nil || updated.Revision == one.Revision {
		t.Fatal(updated, err)
	}
	if err := s.Delete(ctx, "primary", updated.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, "reserve"); err != nil {
		t.Fatal("deleting primary changed reserve: ", err)
	}
}

func TestForeignProfileAndHooksNeverBecomeOwned(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s := New(dir)
	foreign := []byte("do not adopt or replace me")
	path := filepath.Join(dir, "foreign.json")
	if err := os.WriteFile(path, foreign, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(ctx, "foreign", "Foreign", fixture, ""); !errors.Is(err, ErrForeign) {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, "foreign", "whatever"); err == nil {
		t.Fatal("foreign profile deleted")
	}
	if got, _ := os.ReadFile(path); string(got) != string(foreign) {
		t.Fatal("foreign profile mutated")
	}
	for _, change := range []string{"PostUp = touch /tmp/unsafe", "SaveConfig = true", "Jc = 4", "PrivateKey = duplicate"} {
		profile := strings.Replace(fixture, "Address =", change+"\nAddress =", 1)
		if _, err := s.Put(ctx, "invalid", "Invalid", profile, ""); err == nil {
			t.Fatalf("accepted %s", change)
		}
	}
	for _, id := range []string{"../escape", "a/b", "main", "", "UPPER"} {
		if _, err := s.Put(ctx, id, "Invalid", fixture, ""); err == nil {
			t.Fatalf("accepted id %s", id)
		}
	}
}

func TestProfileKeepaliveIsOptionalAndZeroPreserved(t *testing.T) {
	for _, keepalive := range []string{"", "PersistentKeepalive = 0\n"} {
		s := New(t.TempDir())
		ctx := context.Background()
		if _, err := s.Put(ctx, "profile", "Profile", fixture+keepalive, ""); err != nil {
			t.Fatal(err)
		}
		p, err := s.Get(ctx, "profile")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(p.Config(), "PersistentKeepalive") != (keepalive != "") {
			t.Fatal("keepalive changed")
		}
	}
}
