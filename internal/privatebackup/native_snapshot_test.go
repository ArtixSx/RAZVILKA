package privatebackup

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/ArtixSx/razvilka/internal/nativeenrollment"
	"strings"
	"testing"
)

func TestEncryptedNativeSnapshotPreservesBinaryPendingAndRejectsOldDecoder(t *testing.T) {
	d := nativeenrollment.Document{Schema: 1}
	d.Set("pending.json", []byte(`{"schema":1,"directory":"attempt-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`))
	d.Set("attempt-"+strings.Repeat("a", 32)+"/private-key.bin", []byte{0, 1, 0, 255})
	d.Set("attempt-"+strings.Repeat("a", 32)+"/response.private.json", []byte("private-provider-token-marker"))
	s, err := nativeenrollment.SnapshotOf(d)
	if err != nil {
		t.Fatal(err)
	}
	p := NewPayload("0.18.1-dev")
	p.NativeEnrollment = &s
	if err := Seal(&p); err != nil {
		t.Fatal(err)
	}
	env, err := Encrypt(p, "synthetic-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(env)
	if bytes.Contains(encoded, []byte("private-provider-token")) || strings.Contains(fmt.Sprintf("%+v %#v", s, s), "provider-token") {
		t.Fatal("private state leaked")
	}
	restored, err := Decrypt(env, "synthetic-passphrase")
	if err != nil || restored.NativeEnrollment == nil || !bytes.Equal(restored.NativeEnrollment.Content, s.Content) {
		t.Fatal("encrypted native snapshot lost bytes", err)
	}
	restored.NativeEnrollment = nil
	if Validate(restored) == nil {
		t.Fatal("older decoder could silently drop native enrollment")
	}
}
