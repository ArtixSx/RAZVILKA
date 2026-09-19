package strategylab

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

var packTime = time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)

func testPack(t *testing.T, seq uint64) []byte {
	t.Helper()
	p := StrategyPack{Schema: 1, ID: "test-package", Sequence: seq, IssuedAt: packTime.Add(-time.Minute), ExpiresAt: packTime.Add(time.Hour), CompatibilityID: "nfqws2-zapret-auto-v1", Entries: []PackEntry{{PoolID: "tcp-tls", Name: "One", Arguments: "--filter-tcp=443 --payload=tls_client_hello --lua-desync=fake:blob=tls_clienthello:repeats=2"}}}
	b, e := json.MarshalIndent(p, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func packManager(t *testing.T, path string) *Manager {
	t.Helper()
	m, e := New(path)
	if e != nil {
		t.Fatal(e)
	}
	m.Now = func() time.Time { return packTime }
	return m
}
func mustPackImport(t *testing.T, m *Manager, data []byte, signed bool) PackImportResult {
	t.Helper()
	r, e := ReviewPack(data, signed, m.PackKeys, packTime)
	if e != nil {
		t.Fatal(e)
	}
	v, e := m.ImportPack(data, signed, r.SHA256)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func TestPackSignedPrettyPayloadAndTamper(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	data, e := SignPack(testPack(t, 2), "owner", priv, packTime)
	if e != nil {
		t.Fatal(e)
	}
	keys := map[string]ed25519.PublicKey{"owner": pub}
	v, e := ReviewPack(data, true, keys, packTime)
	if e != nil || v.Publisher != "signed:owner" || v.LiveApplied || !v.NativeRequired {
		t.Fatal(v, e)
	}
	for _, bad := range []struct {
		data []byte
		keys map[string]ed25519.PublicKey
	}{{bytes.Replace(data, []byte("One"), []byte("Two"), 1), keys}, {data, nil}, {data, map[string]ed25519.PublicKey{"owner": make([]byte, 32)}}} {
		if _, e := ReviewPack(bad.data, true, bad.keys, packTime); e == nil {
			t.Fatal("signature accepted")
		}
	}
}

func TestPackSignatureCoversSerializedPayload(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// External JSON producers need not use Go's HTML escaping. Marshaling the
	// signed envelope must not change the payload bytes after they are signed.
	for _, name := range []string{"A & B", "<strategy>", "line\u2028separator", "paragraph\u2029separator"} {
		t.Run(name, func(t *testing.T) {
			payload := bytes.Replace(testPack(t, 1), []byte("One"), []byte(name), 1)
			signed, err := SignPack(payload, "owner", priv, packTime)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ReviewPack(signed, true, map[string]ed25519.PublicKey{"owner": pub}, packTime); err != nil {
				t.Fatalf("signed output cannot be verified: %v", err)
			}
		})
	}
}

func TestPackExportAndSignRejectOversizeOutput(t *testing.T) {
	m := packManager(t, "")
	ids := make([]string, 0, 40)
	argument := "--lua-desync=fake:host=" + strings.Repeat("a", 950)
	for i := 0; i < 40; i++ {
		c, err := m.AddCandidate("tcp-tls", "Strategy "+strconv.Itoa(i), strings.Repeat(argument+" ", 7), "expert")
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, c.ID)
	}
	if data, err := m.ExportPack(ids); err == nil {
		t.Fatalf("export returned an unreadable %d-byte pack", len(data))
	}
	// An unsigned payload can fit the input budget while its signed envelope
	// exceeds it. A successful signer must always return verifiable output.
	var p StrategyPack
	if err := json.Unmarshal(testPack(t, 1), &p); err != nil {
		t.Fatal(err)
	}
	p.Entries = nil
	for _, c := range m.Snapshot().Candidates {
		p.Entries = append(p.Entries, PackEntry{PoolID: c.PoolID, Name: c.Name, Arguments: c.Arguments})
	}
	for {
		data, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		if len(data) <= MaxPackBytes {
			break
		}
		p.Entries = p.Entries[:len(p.Entries)-1]
	}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	// Spaces within arguments remain valid and survive compacting the JSON.
	p.Entries[0].Arguments += strings.Repeat(" ", MaxPackBytes-len(data))
	data, err = json.Marshal(p)
	if err != nil || len(data) != MaxPackBytes {
		t.Fatalf("bad boundary fixture: %d %v", len(data), err)
	}
	if _, err := ReviewPack(data, false, nil, packTime); err != nil {
		t.Fatalf("unsigned boundary payload must remain valid: %v", err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if signed, err := SignPack(data, "owner", priv, packTime); err == nil {
		t.Fatalf("signer returned an unreadable %d-byte envelope", len(signed))
	}
}

func TestPackSignerRejectsInconsistentPrivateKey(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key[ed25519.SeedSize] ^= 1
	if _, err := SignPack(testPack(t, 1), "owner", key, packTime); err == nil {
		t.Fatal("signed with a private key whose public half does not match its seed")
	}
}

func TestPackExportRejectsUnusableClock(t *testing.T) {
	for _, now := range []time.Time{{}, time.Unix(0, 0)} {
		m := packManager(t, "")
		v := mustPackImport(t, m, testPack(t, 1), false)
		m.Now = func() time.Time { return now }
		if _, err := m.ExportPack(v.CandidateIDs); err == nil {
			t.Fatalf("export generated an invalid sequence at %s", now)
		}
	}
}

func TestPackConcurrentEquivocationCommitsOneReceipt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "strategies.json")
	m := packManager(t, path)
	packs := [][]byte{testPack(t, 3), bytes.Replace(testPack(t, 3), []byte("One"), []byte("Two"), 1)}
	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make(chan string, len(packs))
	for _, data := range packs {
		r, err := ReviewPack(data, false, nil, packTime)
		if err != nil {
			t.Fatal(err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := m.ImportPack(data, false, r.SHA256); err == nil {
				results <- r.SHA256
			}
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	if len(results) != 1 {
		t.Fatalf("got %d successful imports for conflicting sequence", len(results))
	}
	winner := <-results
	reopened := packManager(t, path)
	if len(reopened.state.Candidates) != 1 || reopened.state.PackReceipts["personal:test-package"].SHA256 != winner {
		t.Fatal("candidates and highwater receipt were not committed together")
	}
}
func TestPackDurableHighwaterAndIdempotency(t *testing.T) {
	path := filepath.Join(t.TempDir(), "strategies.json")
	m := packManager(t, path)
	data := testPack(t, 2)
	r := mustPackImport(t, m, data, false)
	if r.Added != 1 || r.LiveApplied {
		t.Fatal(r)
	}
	before, _ := os.ReadFile(path)
	again := mustPackImport(t, m, data, false)
	after, _ := os.ReadFile(path)
	if again.Added != 0 || again.Preserved != 1 || !bytes.Equal(before, after) {
		t.Fatal("not idempotent")
	}
	m = packManager(t, path)
	for _, d := range [][]byte{testPack(t, 1), bytes.Replace(data, []byte("One"), []byte("Two"), 1)} {
		v, e := ReviewPack(d, false, nil, packTime)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = m.ImportPack(d, false, v.SHA256); e == nil {
			t.Fatal("rollback/equivocation")
		}
	}
	next := testPack(t, 3)
	v := mustPackImport(t, m, next, false)
	if v.Added != 0 || v.Preserved != 1 {
		t.Fatal(v)
	}
}
func TestPackUpdatePreservesPersonalValidationEvidenceAndSelection(t *testing.T) {
	m := packManager(t, filepath.Join(t.TempDir(), "state.json"))
	r := mustPackImport(t, m, testPack(t, 1), false)
	id := r.CandidateIDs[0]
	m.Validator = fakeValidator{result: Validation{Native: true, OK: true, Code: "PASS"}}
	if _, e := m.Validate(context.Background(), id); e != nil {
		t.Fatal(e)
	}
	m.mu.Lock()
	m.state.Evidence = append(m.state.Evidence, Evidence{CandidateID: id, ServiceID: "private-site-canary", Success: true, RouteConfirmed: true, CheckedAt: packTime.Format(time.RFC3339)})
	m.state.Selections["private-selection"] = Selection{CandidateID: id, Frozen: true}
	if e := m.saveLocked(); e != nil {
		t.Fatal(e)
	}
	old := m.state.Candidates[id]
	oldEvidence := append([]Evidence{}, m.state.Evidence...)
	oldSelections := m.state.Selections
	m.mu.Unlock()
	d := bytes.Replace(testPack(t, 2), []byte("repeats=2"), []byte("repeats=3"), 1)
	v := mustPackImport(t, m, d, false)
	if v.Added != 1 || len(m.state.Candidates) != 2 || !reflect.DeepEqual(old, m.state.Candidates[id]) || !reflect.DeepEqual(oldEvidence, m.state.Evidence) || !reflect.DeepEqual(oldSelections, m.state.Selections) {
		t.Fatal("replaced personal state")
	}
	out, e := m.ExportPack([]string{id})
	if e != nil || bytes.Contains(out, []byte("private-site-canary")) || bytes.Contains(out, []byte("validation")) || bytes.Contains(out, []byte("route_confirmed")) {
		t.Fatal(string(out), e)
	}
	if _, e := ReviewPack(out, false, nil, packTime); e != nil {
		t.Fatal(e)
	}
}
func TestPackRejectsUntrustedCommandsDuplicatesAndTime(t *testing.T) {
	for _, arg := range []string{"--lua-init=@/tmp/evil.lua", "--lua-desync=fake:blob=@/etc/passwd", "--lua-desync=arbitrary:abc=1", "--qnum=300", "--filter-tcp=443; reboot", "--lua-desync=fake:repeats=33", "--lua-desync=fake:repeats=0", "--lua-desync=fake:secret=1", "--hostlist=/tmp/list", "--lua-desync=fake:blob=unknown"} {
		t.Run(arg, func(t *testing.T) {
			if ExportableArguments(arg) == nil {
				t.Fatal("unsafe pack arg")
			}
		})
	}
	data := testPack(t, 1)
	for _, d := range [][]byte{bytes.Replace(data, []byte(`"schema": 1`), []byte(`"schema": 1,"Schema":1`), 1), bytes.Replace(data, []byte(`"entries":`), []byte(`"evidence": [],"entries":`), 1), bytes.Replace(data, []byte(`"sequence": 1`), []byte(`"sequence": 0`), 1), append(data, []byte(`{}`)...), []byte(strings.Repeat(" ", MaxPackBytes+1))} {
		if _, e := ReviewPack(d, false, nil, packTime); e == nil {
			t.Fatal("bad envelope")
		}
	}
	for _, now := range []time.Time{packTime.Add(-time.Hour), packTime.Add(2 * time.Hour)} {
		if _, e := ReviewPack(data, false, nil, now); e == nil {
			t.Fatal("bad time")
		}
	}
}
func TestPackReviewMismatchAndConcurrentWriterPreserveDisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	a, b := packManager(t, path), packManager(t, path)
	data := testPack(t, 1)
	if _, e := a.ImportPack(data, false, strings.Repeat("0", 64)); e == nil {
		t.Fatal("missing review fence")
	}
	mustPackImport(t, a, data, false)
	before, _ := os.ReadFile(path)
	v, _ := ReviewPack(testPack(t, 2), false, nil, packTime)
	if _, e := b.ImportPack(testPack(t, 2), false, v.SHA256); e == nil {
		t.Fatal("stale writer")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) || len(b.state.Candidates) != 0 || !b.writeBlocked {
		t.Fatal("clobbered state")
	}
	if _, e := b.AddCandidate("tcp-tls", "later", "--filter-tcp=443", "expert"); e == nil {
		t.Fatal("write after ambiguous state")
	}
}
func TestBuiltinPackAndExportBounds(t *testing.T) {
	m := packManager(t, "")
	data := BuiltinPack(packTime)
	r, e := ReviewPack(data, false, nil, packTime)
	if e != nil || len(r.Entries) != 2 {
		t.Fatal(r, e)
	}
	v := mustPackImport(t, m, data, false)
	if v.Added != 2 {
		t.Fatal(v)
	}
	if _, e := m.ExportPack(nil); e == nil {
		t.Fatal("empty export")
	}
	if _, e := m.ExportPack([]string{v.CandidateIDs[0], v.CandidateIDs[0]}); e == nil {
		t.Fatal("duplicate export")
	}
	out, e := m.ExportPack(v.CandidateIDs)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := ReviewPack(out, false, nil, packTime); e != nil {
		t.Fatal(e)
	}
}
func TestPackKeyLoaderRejectsUnsafeFiles(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	path := filepath.Join(t.TempDir(), "keys.json")
	data, _ := json.Marshal(map[string]ed25519.PublicKey{"owner": pub})
	if e := os.WriteFile(path, data, 0600); e != nil {
		t.Fatal(e)
	}
	keys, e := LoadPackKeys(path)
	if runtime.GOOS == "windows" {
		// Windows chmod does not enforce the POSIX owner-only trust policy.
		// Keep the loader closed instead of relaxing the policy for this test.
		if e == nil {
			t.Fatal("accepted a trust file without POSIX write restrictions")
		}
		return
	}
	if e != nil || !bytes.Equal(keys["owner"], pub) {
		t.Fatal(e)
	}
	link := path + ".link"
	if e := os.Symlink(path, link); e != nil {
		t.Fatal(e)
	}
	if _, e := LoadPackKeys(link); e == nil {
		t.Fatal("symlink")
	}
	if e := os.Chmod(path, 0666); e != nil {
		t.Fatal(e)
	}
	if _, e := LoadPackKeys(path); e == nil {
		t.Fatal("writable trust")
	}
}
