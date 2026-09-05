package nodestore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

const good = "vless://123e4567-e89b-12d3-a456-426614174000@private-host.example:443?security=tls&sni=private-sni.example#SECRET_ALIAS"

var testTime = time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
var manual = Source{ID: "manual", Kind: "manual"}

func setup(t *testing.T) (*Store, string) {
	t.Helper()
	path := t.TempDir()
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path
}

func readBytes(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(path, fileName))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func importGood(t *testing.T, s *Store) Snapshot {
	t.Helper()
	snap, err := s.Import(context.Background(), manual, good, testTime, time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

func TestStableIdentityFreshnessAndNoSecretSnapshot(t *testing.T) {
	s, path := setup(t)
	first := importGood(t, s)
	if first.Generation != 1 || len(first.Nodes) != 1 || first.Nodes[0].State != "quarantined" || first.Nodes[0].Health.State != "not_checked" {
		t.Fatal("new node received trust")
	}
	id := first.Nodes[0].ID
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	second, err := s.Import(context.Background(), manual, strings.Replace(good, "SECRET_ALIAS", "Other", 1), testTime.Add(time.Minute), time.Hour, false)
	if err != nil || len(second.Nodes) != 1 || second.Nodes[0].ID != id || second.Nodes[0].AddedAt != testTime {
		t.Fatal("identity changed with alias or restart")
	}
	third, err := s.Import(context.Background(), Source{ID: "goida", Kind: "community"}, good, testTime.Add(time.Minute), time.Hour, false)
	if err != nil || len(third.Nodes) != 1 || len(third.Nodes[0].Origins) != 2 || third.Nodes[0].Trust != "untrusted" {
		t.Fatal("provenance lost or trust promoted")
	}
	public, _ := json.Marshal(third)
	for _, value := range []string{"123e4567", "SECRET_ALIAS", "private-host", "private-sni", "vless://", "outbound", "secret_ref", "identity_key"} {
		if bytes.Contains(public, []byte(value)) || strings.Contains(fmt.Sprintf("%+v %#v", s, s), value) {
			t.Fatal("public snapshot leaked private data")
		}
	}
	third.Nodes[0].Origins[0].SourceID = "tampered"
	third.Sources[0].Kind = "community"
	expired, err := s.Snapshot(context.Background(), testTime.Add(61*time.Minute))
	if err != nil || expired.Nodes[0].State != "expired" || expired.Nodes[0].Origins[0].SourceID != "manual" || expired.Sources[0].Kind != "manual" {
		t.Fatal("expiry or snapshot isolation broken")
	}
	changed, err := s.Import(context.Background(), manual, strings.Replace(good, "426614174000", "426614174001", 1), testTime.Add(2*time.Minute), time.Hour, false)
	if err != nil || len(changed.Nodes) != 2 || changed.Nodes[1].ID == id || changed.Nodes[1].Health.State != "not_checked" {
		t.Fatal("changed credentials reused identity/evidence")
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(filepath.Join(path, fileName))
		if info.Mode().Perm() != 0o600 {
			t.Fatal("node file not private")
		}
	}
}

func TestNodeMetadataRevealAndDeleteAreAtomic(t *testing.T) {
	s, path := setup(t)
	first := importGood(t, s)
	id := first.Nodes[0].ID
	before := readBytes(t, path)
	if _, err := s.SetAlias(context.Background(), id, "  padded  ", testTime); !errors.Is(err, ErrAlias) || !bytes.Equal(before, readBytes(t, path)) {
		t.Fatal("invalid alias changed the store")
	}
	aliased, err := s.SetAlias(context.Background(), id, "Домашний резерв", testTime)
	if err != nil || aliased.Generation != 2 || aliased.Nodes[0].Name != "Домашний резерв" {
		t.Fatal("alias was not persisted")
	}
	unchanged, err := s.SetAlias(context.Background(), id, "Домашний резерв", testTime)
	if err != nil || unchanged.Generation != 2 {
		t.Fatal("unchanged alias caused a flash write")
	}
	disabled, err := s.SetDisabled(context.Background(), id, true, testTime)
	if err != nil || disabled.Generation != 3 || !disabled.Nodes[0].Disabled || disabled.Nodes[0].State != "disabled" || disabled.Nodes[0].Health.State != "not_checked" {
		t.Fatal("disabled node gained readiness or lost metadata")
	}
	var borrowed []byte
	if err := s.WithSecret(context.Background(), id, func(material []byte) error {
		borrowed = material
		if !bytes.Contains(material, []byte("123e4567")) || !bytes.Contains(material, []byte("private-host")) {
			t.Fatal("revealed material is incomplete")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(bytes.Trim(borrowed, "\x00")) != 0 {
		t.Fatal("temporary secret copy was not cleared")
	}
	removed, err := s.Delete(context.Background(), id, testTime)
	if err != nil || len(removed.Nodes) != 0 || len(removed.Sources) != 0 {
		t.Fatal("last node was not deleted")
	}
	if _, err := os.Stat(filepath.Join(path, fileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("empty private document was not removed")
	}
	if _, err := s.Delete(context.Background(), id, testTime); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing node was not reported")
	}
}

func TestSchemaOneLoadsAndMigratesOnExplicitMutation(t *testing.T) {
	s, path := setup(t)
	first := importGood(t, s)
	s.Close()
	var legacy document
	if json.Unmarshal(readBytes(t, path), &legacy) != nil {
		t.Fatal("fixture")
	}
	legacy.Schema = legacySchema
	data, _ := json.Marshal(legacy)
	if err := os.WriteFile(filepath.Join(path, fileName), data, 0o600); err != nil {
		t.Fatal(err)
	}
	legacyBytes := readBytes(t, path)
	reopened, err := Open(path)
	if err != nil {
		t.Fatal("schema 1 did not open")
	}
	defer reopened.Close()
	if _, err := reopened.Snapshot(context.Background(), testTime); err != nil || !bytes.Equal(legacyBytes, readBytes(t, path)) {
		t.Fatal("read-only schema 1 load caused a migration write")
	}
	if _, err := reopened.SetAlias(context.Background(), first.Nodes[0].ID, "После миграции", testTime); err != nil {
		t.Fatal(err)
	}
	var migrated document
	if json.Unmarshal(readBytes(t, path), &migrated) != nil || migrated.Schema != schema || migrated.Nodes[0].Alias != "После миграции" {
		t.Fatal("explicit mutation did not persist schema 2")
	}
}

func TestUncertainMetadataMutationFencesUntilReopen(t *testing.T) {
	for _, afterWrite := range []bool{false, true} {
		t.Run(fmt.Sprint(afterWrite), func(t *testing.T) {
			s, path := setup(t)
			first := importGood(t, s)
			s.target = failingTarget{Target: s.target, afterWrite: afterWrite}
			if _, err := s.SetAlias(context.Background(), first.Nodes[0].ID, "Новая подпись", testTime); !errors.Is(err, ErrRecovery) {
				t.Fatal("uncertain metadata write reported success")
			}
			if _, err := s.Snapshot(context.Background(), testTime); !errors.Is(err, ErrRecovery) {
				t.Fatal("fenced store served a snapshot")
			}
			s.Close()
			reopened, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			snapshot, err := reopened.Snapshot(context.Background(), testTime)
			if err != nil || len(snapshot.Nodes) != 1 {
				t.Fatal("reopen did not recover a complete image")
			}
			want := "Узел " + first.Nodes[0].ID[5:13]
			if afterWrite {
				want = "Новая подпись"
			}
			if snapshot.Nodes[0].Name != want {
				t.Fatal("uncertain metadata write left a partial image")
			}
		})
	}
}

func TestPartialAndInvalidImportPreserveStore(t *testing.T) {
	s, path := setup(t)
	importGood(t, s)
	before := readBytes(t, path)
	bad := strings.Replace(good, "security=tls", "type=xhttp", 1)
	if _, err := s.Import(context.Background(), manual, bad+"\n"+good, testTime, time.Hour, false); !errors.Is(err, ErrPartial) {
		t.Fatal("unreviewed partial import allowed")
	}
	for _, input := range []struct {
		raw    string
		source Source
		ttl    time.Duration
		now    time.Time
	}{
		{bad, manual, time.Hour, testTime},
		{good, Source{ID: "manual", Kind: "community"}, time.Hour, testTime},
		{good, Source{ID: "https://secret-token", Kind: "community"}, time.Hour, testTime},
		{good, manual, maxTTL + time.Second, testTime},
		{good, manual, time.Hour, testTime.Add(-time.Minute)},
		{"hysteria2://PRIVATE_PASSWORD@host.example:443?insecure=1", manual, time.Hour, testTime},
	} {
		_, err := s.Import(context.Background(), input.source, input.raw, input.now, input.ttl, true)
		if err == nil || strings.Contains(err.Error(), "PRIVATE_PASSWORD") || !bytes.Equal(before, readBytes(t, path)) {
			t.Fatal("failed import changed store or exposed input")
		}
	}
	after, err := s.Import(context.Background(), manual, bad+"\n"+good, testTime, time.Hour, true)
	if err != nil || len(after.Nodes) != 1 {
		t.Fatal("reviewed partial import failed")
	}
}

func TestLegacyCopyIsCompleteIdempotentAndDoesNotTouchOriginal(t *testing.T) {
	s, path := setup(t)
	legacy := `{"inbounds":[{"password":"INBOUND_SECRET"}],"route":{"final":"FOREIGN_ROUTE"},"outbounds":[{"type":"vless","tag":"ALIAS_SECRET","server":"edge.example","server_port":443,"uuid":"123e4567-e89b-12d3-a456-426614174000","tls":{"enabled":true}},{"type":"direct","tag":"direct"}]}`
	original := filepath.Join(t.TempDir(), "main.json")
	if err := os.WriteFile(original, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		snap, err := s.CopyLegacyMain(context.Background(), legacy, testTime)
		if err != nil || len(snap.Nodes) != 1 || snap.Sources[0].Kind != "legacy" || snap.Generation != 1 {
			t.Fatal("migration duplicated/lost node")
		}
	}
	data, _ := os.ReadFile(original)
	if string(data) != legacy {
		t.Fatal("legacy original changed")
	}
	stored := readBytes(t, path)
	for _, foreign := range []string{"INBOUND_SECRET", "FOREIGN_ROUTE", "ALIAS_SECRET"} {
		if bytes.Contains(stored, []byte(foreign)) {
			t.Fatal("foreign config copied into nodes")
		}
	}
}

func TestSourceLimitAndParameterIdentity(t *testing.T) {
	s, path := setup(t)
	for i := range MaxSources {
		if _, err := s.Import(context.Background(), Source{ID: fmt.Sprintf("source-%d", i), Kind: "community"}, good, testTime, time.Hour, false); err != nil {
			t.Fatal(err)
		}
	}
	before := readBytes(t, path)
	if _, err := s.Import(context.Background(), Source{ID: "overflow", Kind: "community"}, good, testTime, time.Hour, false); !errors.Is(err, ErrCapacity) {
		t.Fatal("source cap not enforced")
	}
	if !bytes.Equal(before, readBytes(t, path)) {
		t.Fatal("capacity error changed disk")
	}
	snap, err := s.Import(context.Background(), Source{ID: "source-0", Kind: "community"}, good+"&invalid", testTime, time.Hour, false)
	// Fragment-only display changes do not change identity.
	if err != nil || len(snap.Nodes) != 1 {
		t.Fatal("display-only fragment changed identity")
	}
	changed := strings.Replace(good, "security=tls", "security=tls&type=ws&path=%2Fws", 1)
	snap, err = s.Import(context.Background(), Source{ID: "source-0", Kind: "community"}, changed, testTime, time.Hour, false)
	if err != nil || len(snap.Nodes) != 2 || snap.Nodes[0].ID == snap.Nodes[1].ID {
		t.Fatal("changed transport reused identity")
	}
}

func TestStoredProtocolRoundTrips(t *testing.T) {
	for _, raw := range []string{
		good,
		"hysteria2://test-password@edge.example:443?sni=front.example",
		"tuic://123e4567-e89b-12d3-a456-426614174000:test-password@edge.example:443?sni=front.example",
		"ss://YWVzLTEyOC1nY206dGVzdC1wYXNzd29yZA@edge.example:8388",
	} {
		s, path := setup(t)
		first, err := s.Import(context.Background(), manual, raw, testTime, time.Hour, false)
		if err != nil {
			t.Fatal("supported protocol import failed")
		}
		s.Close()
		reopened, err := Open(path)
		if err != nil {
			t.Fatal("supported protocol reopen failed")
		}
		after, err := reopened.Snapshot(context.Background(), testTime)
		reopened.Close()
		if err != nil || len(after.Nodes) != 1 || after.Nodes[0].ID != first.Nodes[0].ID {
			t.Fatal("protocol identity roundtrip failed")
		}
	}
}

func TestLeaseAndConcurrentImports(t *testing.T) {
	s, path := setup(t)
	if other, err := Open(path); err == nil {
		other.Close()
		t.Fatal("second writer acquired lease")
	}
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			raw := strings.Replace(good, "426614174000", fmt.Sprintf("426614174%03d", i), 1)
			if _, err := s.Import(context.Background(), manual, raw, testTime, time.Hour, false); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	snap, err := s.Snapshot(context.Background(), testTime)
	if err != nil || len(snap.Nodes) != 8 || snap.Generation != 8 {
		t.Fatal("concurrent imports lost data")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before := readBytes(t, path)
	if _, err := s.Import(ctx, manual, good, testTime, time.Hour, false); err == nil || !bytes.Equal(before, readBytes(t, path)) {
		t.Fatal("cancelled import wrote")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	other, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	other.Close()
	if _, err := s.Snapshot(context.Background(), testTime); err == nil {
		t.Fatal("closed store usable")
	}
}

func TestCorruptDocumentFailsClosed(t *testing.T) {
	for _, kind := range []string{"schema", "unknown", "duplicate", "secret", "reference", "identity", "expiry", "health", "empty"} {
		t.Run(kind, func(t *testing.T) {
			s, path := setup(t)
			importGood(t, s)
			s.Close()
			data := readBytes(t, path)
			var doc document
			if json.Unmarshal(data, &doc) != nil {
				t.Fatal("fixture")
			}
			switch kind {
			case "schema":
				doc.Schema++
			case "secret":
				doc.Secrets[0].Outbound = json.RawMessage(strings.Replace(string(doc.Secrets[0].Outbound), "426614174000", "426614174001", 1))
			case "reference":
				doc.Nodes[0].SecretRef = "../../outside"
			case "identity":
				doc.Nodes[0].ID = "forged"
			case "expiry":
				doc.Nodes[0].Origins[0].ExpiresAt = testTime.Add(90 * 24 * time.Hour)
			}
			data, _ = json.Marshal(doc)
			switch kind {
			case "unknown":
				data = append([]byte(`{"unknown":"secret",`), data[1:]...)
			case "duplicate":
				data = append([]byte(`{"schema":1,`), data[1:]...)
			case "health":
				data = append([]byte(`{"health":{"state":"available"},`), data[1:]...)
			case "empty":
				data = nil
			}
			if err := os.WriteFile(filepath.Join(path, fileName), data, 0o600); err != nil {
				t.Fatal(err)
			}
			if other, err := Open(path); err == nil {
				other.Close()
				t.Fatal("corrupt file opened")
			}
			if !bytes.Equal(data, readBytes(t, path)) {
				t.Fatal("corrupt file silently replaced")
			}
		})
	}
}

type failingTarget struct {
	restorejournal.Target
	afterWrite bool
}

func (f failingTarget) CompareAndSwap(ctx context.Context, before, after restorejournal.Image) error {
	if f.afterWrite {
		if err := f.Target.CompareAndSwap(ctx, before, after); err != nil {
			return err
		}
	}
	return restorejournal.ErrRecovery
}

func TestUncertainCommitFencesUntilReopen(t *testing.T) {
	for _, afterWrite := range []bool{false, true} {
		t.Run(fmt.Sprint(afterWrite), func(t *testing.T) {
			s, path := setup(t)
			importGood(t, s)
			s.target = failingTarget{Target: s.target, afterWrite: afterWrite}
			changed := strings.Replace(good, "426614174000", "426614174001", 1)
			if _, err := s.Import(context.Background(), manual, changed, testTime, time.Hour, false); !errors.Is(err, ErrRecovery) {
				t.Fatal("uncertain write reported success")
			}
			if _, err := s.Snapshot(context.Background(), testTime); !errors.Is(err, ErrRecovery) {
				t.Fatal("uncertain cache served")
			}
			if _, err := s.Import(context.Background(), manual, good, testTime, time.Hour, false); !errors.Is(err, ErrRecovery) {
				t.Fatal("fenced writer continued")
			}
			s.Close()
			reopened, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			snap, err := reopened.Snapshot(context.Background(), testTime)
			want := 1
			if afterWrite {
				want = 2
			}
			if err != nil || len(snap.Nodes) != want {
				t.Fatal("atomic image incomplete after uncertain write")
			}
			for _, node := range snap.Nodes {
				if node.Health.State != "not_checked" {
					t.Fatal("reopen granted health")
				}
			}
		})
	}
}

func TestUnsafeDirectoryAndSymlinkRejected(t *testing.T) {
	path := t.TempDir()
	if runtime.GOOS != "windows" {
		os.Chmod(path, 0o755)
		if s, err := Open(path); err == nil {
			s.Close()
			t.Fatal("public directory accepted")
		}
		os.Chmod(path, 0o700)
	}
	if s, err := Open("relative"); err == nil {
		s.Close()
		t.Fatal("relative root accepted")
	}
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(path, fileName)); err != nil {
		t.Skip("symlinks unavailable")
	}
	if s, err := Open(path); err == nil {
		s.Close()
		t.Fatal("symlink accepted")
	}
	data, _ := os.ReadFile(outside)
	if string(data) != "keep" {
		t.Fatal("outside file changed")
	}
}
