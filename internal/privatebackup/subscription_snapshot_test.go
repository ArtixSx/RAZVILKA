package privatebackup

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/ArtixSx/razvilka/internal/providerfeed"
)

func TestEncryptedSubscriptionSnapshotPreservesTokensAndCannotBeSilentlyDropped(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	m, err := providerfeed.Open(nil, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	_, err = m.Save(context.Background(), "", providerfeed.SaveRequest{Request: providerfeed.Request{URL: "https://feed.example.org/private-path-token?secret=private-query-token"}, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	s, err := m.ExportPrivateIfPresent(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	p := NewPayload("0.18.1-dev")
	p.SubscriptionSnapshot = s
	if err := Seal(&p); err != nil {
		t.Fatal(err)
	}
	envelope, err := Encrypt(p, "synthetic-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	public, _ := json.Marshal(envelope)
	if bytes.Contains(public, []byte("private-path-token")) || bytes.Contains(public, []byte("private-query-token")) {
		t.Fatal("unencrypted subscription material leaked")
	}
	restored, err := Decrypt(envelope, "synthetic-passphrase")
	if err != nil || restored.SubscriptionSnapshot == nil || !bytes.Equal(s.Content, restored.SubscriptionSnapshot.Content) {
		t.Fatal("encrypted subscription bytes changed", err)
	}
	restored.SubscriptionSnapshot = nil
	if Validate(restored) == nil {
		t.Fatal("old decoder could silently discard subscription secrets")
	}
}
