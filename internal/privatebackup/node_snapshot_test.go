package privatebackup

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/nodestore"
)

func TestEncryptedNodeSnapshotRoundTrip(t *testing.T) {
	path := t.TempDir()
	os.Chmod(path, 0o700)
	s, err := nodestore.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	const uri = "vless://123e4567-e89b-12d3-a456-426614174000@private.example:443?security=tls&type=ws&path=%2F%3Fx%3D1%26y%3D2"
	if _, err := s.Import(context.Background(), nodestore.Source{ID: "manual", Kind: "manual"}, uri, time.Now(), time.Hour, false); err != nil {
		t.Fatal(err)
	}
	nodes, err := s.ExportPrivate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	payload := NewPayload("0.18.1-dev")
	payload.NodeSnapshot = &nodes
	if err := Seal(&payload); err != nil {
		t.Fatal(err)
	}
	envelope, err := Encrypt(payload, "synthetic-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(envelope)
	for _, secret := range []string{"123e4567", "private.example", "identity_key", "outbound"} {
		if bytes.Contains(encoded, []byte(secret)) || bytes.Contains([]byte(fmt.Sprintf("%+v %#v", nodes, nodes)), []byte(secret)) {
			t.Fatal("archive or log leaked secret")
		}
	}
	decoded, err := Decrypt(envelope, "synthetic-passphrase")
	if err != nil || decoded.NodeSnapshot == nil || !bytes.Equal(nodes.Content, decoded.NodeSnapshot.Content) {
		t.Fatal("encrypted node archive lost data")
	}
	if _, err := Decrypt(envelope, "wrong-passphrase"); err == nil {
		t.Fatal("wrong password accepted")
	}
	// An older decoder that ignores the new field still fails the payload
	// digest; it cannot report a successful restore while losing node secrets.
	decoded.NodeSnapshot = nil
	if err := Validate(decoded); err == nil {
		t.Fatal("omitted node snapshot did not invalidate archive digest")
	}
	payload.NodeSnapshot.SHA256 = "bad"
	if err := Seal(&payload); err == nil {
		t.Fatal("invalid snapshot digest accepted")
	}
}
