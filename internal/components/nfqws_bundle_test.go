package components

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type bundleFixtureEntry struct {
	name string
	data []byte
	kind byte
}

func bundleFixtureGzip(t *testing.T, data []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	if _, err := gz.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func bundleFixtureTar(t *testing.T, entries []bundleFixtureEntry) []byte {
	t.Helper()
	var out bytes.Buffer
	w := tar.NewWriter(&out)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Typeflag: e.kind, Mode: 0755, Format: tar.FormatUSTAR, Size: int64(len(e.data))}
		if e.kind == tar.TypeSymlink || e.kind == tar.TypeLink {
			h.Size, h.Linkname = 0, "foreign"
		}
		if err := w.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Size > 0 {
			if _, err := w.Write(e.data); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return bundleFixtureGzip(t, out.Bytes())
}

func bundleFixtureManifest(t *testing.T, flavor string) (ManagedNFQWSManifest, []byte, []bundleFixtureEntry) {
	t.Helper()
	m, err := ReviewedManagedNFQWSManifest("arm64")
	if err != nil {
		t.Fatal(err)
	}
	m.Flavor = flavor
	var entries []bundleFixtureEntry
	for i := range m.Members {
		member := &m.Members[i]
		raw := []byte(fmt.Sprintf("data-only fixture %s %s\n", flavor, member.Destination))
		member.RawSize, member.RawSHA256 = int64(len(raw)), digest(raw)
		encoded := raw
		if member.Gzip {
			encoded = bundleFixtureGzip(t, raw)
		}
		member.Size, member.SHA256 = int64(len(encoded)), digest(encoded)
		entries = append(entries, bundleFixtureEntry{member.Path, encoded, tar.TypeReg})
	}
	entries = append(entries, bundleFixtureEntry{"./opt/etc/init.d/S51nfqws2", []byte("#!/bin/sh\nexit 99\n"), tar.TypeReg})
	input := bundleFixtureContainer(t, entries)
	m.ParentAssetSize, m.ParentSHA256 = int64(len(input)), digest(input)
	return m, input, entries
}

func bundleFixtureContainer(t *testing.T, entries []bundleFixtureEntry) []byte {
	return bundleFixtureTar(t, []bundleFixtureEntry{
		{"control.tar.gz", bundleFixtureTar(t, []bundleFixtureEntry{{"./postinst", []byte("#!/bin/sh\nexit 99\n"), tar.TypeReg}}), tar.TypeReg},
		{"data.tar.gz", bundleFixtureTar(t, entries), tar.TypeReg},
		{"debian-binary", []byte("2.0\n"), tar.TypeReg},
	})
}

type bundleFixtureTransport func(*http.Request) (*http.Response, error)

func (f bundleFixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type bundleForbiddenRunner struct{ t *testing.T }

func (r bundleForbiddenRunner) Run(context.Context, string, ...string) ([]byte, error) {
	r.t.Fatal("bundle installer invoked a command/hook")
	return nil, errors.New("forbidden command")
}

func bundleFixtureManager(t *testing.T, input []byte) *Manager {
	t.Helper()
	base := t.TempDir()
	base, err := filepath.EvalSymlinks(base)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(base)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "linux" {
		// Go1.26 creates the freshly owned numbered TempDir leaf with0777
		// filtered by umask. Pin that exact leaf before making it private;
		// never chmod the Go container or another outside ancestor.
		leaf, err := os.Open(base)
		if err != nil {
			t.Fatal(err)
		}
		pinned, statErr := leaf.Stat()
		if statErr != nil || !os.SameFile(info, pinned) {
			leaf.Close()
			t.Fatal("fresh TempDir leaf identity changed", statErr)
		}
		err = errors.Join(leaf.Chmod(0700), leaf.Close())
		if err != nil {
			t.Fatal(err)
		}
	}
	// Complete generations are readonly. Relax only this fixture tree before
	// testing.TempDir cleanup, including Windows readonly file attributes.
	t.Cleanup(func() {
		_ = filepath.WalkDir(base, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.Type()&os.ModeSymlink == 0 {
				mode := os.FileMode(0600)
				if d.IsDir() {
					mode = 0700
				}
				_ = os.Chmod(path, mode)
			}
			return nil
		})
	})
	m := &Manager{StateDir: filepath.Join(base, "state"), nfqwsReleases: filepath.Join(base, "releases"), Arch: "arm64", Runner: bundleForbiddenRunner{t}, nfqwsReview: func(ManagedNFQWSManifest) error { return nil }}
	m.nfqwsFixture = &managedNFQWSFixtureBoundary{base, info}
	m.Client = &http.Client{Transport: bundleFixtureTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(input)), ContentLength: int64(len(input)), Request: r}, nil
	})}
	if runtime.GOOS != "linux" {
		// Private portable model override. Linux tests use real RENAME_NOREPLACE.
		m.nfqwsPublish = func(ctx context.Context, path, stage, generation string, admit func(func() error) error, fault func(string) error) error {
			root, err := os.OpenRoot(path)
			if err != nil {
				return err
			}
			defer root.Close()
			if _, err := root.Lstat(generation); !errors.Is(err, os.ErrNotExist) {
				return ErrManagedNFQWSBundle
			}
			return admit(func() error {
				if err := fault("after:bundle-stage-chmod"); err != nil {
					return err
				}
				return root.Rename(stage, generation)
			})
		}
	}
	return m
}

func bundleFixtureAuthority() ManagedNFQWSBundleAuthority {
	return ManagedNFQWSBundleAuthority{
		InstallationID: "0123456789abcdef0123456789abcdef", Sequence: 1, ReaderVersion: 3,
		Check: func(ctx context.Context, id string, seq, rev uint64, reader int) error {
			if id != "0123456789abcdef0123456789abcdef" || seq != 1 || rev != 7 || reader != 3 {
				return ErrRecoveryAuthority
			}
			return ctx.Err()
		},
		Admit: func(ctx context.Context, transactionID, id string, seq, rev uint64, effect string, begin func() error) error {
			if !bundleHash(transactionID, 32) || id != "0123456789abcdef0123456789abcdef" || seq != 1 || rev != 7 {
				return ErrRecoveryAuthority
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return begin()
		},
		Inactive: func(ctx context.Context) error { return ctx.Err() },
	}
}

func TestManagedNFQWSBundleInstallDescriptorLeaseAndRollback(t *testing.T) {
	ctx := context.Background()
	manifest, input, _ := bundleFixtureManifest(t, "fixture-a")
	m := bundleFixtureManager(t, input)
	a := bundleFixtureAuthority()
	receipt, err := m.InstallManagedBundle(ctx, manifest, 7, a)
	if err != nil || receipt.State != "ready-idle" {
		t.Fatal(receipt, err)
	}
	if state, pending, err := m.PendingManagedUpdate(); err != nil || pending || state.SchemaVersion != 3 || state.Phase != UpdateAcceptedIdle {
		t.Fatal(state, pending, err)
	}
	lease, err := m.AcquireManagedNFQWSRuntime(ctx, receipt.TransactionID)
	if err != nil {
		t.Fatal(err)
	}
	d := lease.Descriptor()
	if d.ReceiptID != receipt.TransactionID || d.LuaCompat != 6 || len(d.Lua) != 3 || len(d.Blobs) != 2 || d.Blobs[0].Alias != "quic_initial" || d.Blobs[1].Alias != "tls_clienthello" || filepath.Base(d.Executable.Path) != "rzv-nfqws2" {
		t.Fatal(d)
	}
	for i, name := range []string{"zapret-lib.lua", "zapret-antidpi.lua", "zapret-auto.lua"} {
		if filepath.Base(d.Lua[i].Path) != name || d.Lua[i].SHA256 != manifest.Members[i+1].RawSHA256 {
			t.Fatal("unordered Lua descriptor", d)
		}
	}
	d.Lua[0].SHA256 = "caller mutation"
	if lease.Descriptor().Lua[0].SHA256 != manifest.Members[1].RawSHA256 || lease.Check(ctx) != nil {
		t.Fatal("descriptor aliases mutable data")
	}
	if _, err := m.UpdateManagedBundle(ctx, manifest, 7, a); err == nil {
		t.Fatal("installer crossed active session's existing writer lease")
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if lease.Check(ctx) == nil {
		t.Fatal("closed session retained ownership")
	}
	next, nextInput, _ := bundleFixtureManifest(t, "fixture-b")
	m.Client.Transport = bundleFixtureTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(nextInput)), ContentLength: int64(len(nextInput)), Request: r}, nil
	})
	candidate, err := m.UpdateManagedBundle(ctx, next, 7, a)
	if err != nil || candidate.ManifestSHA256 == receipt.ManifestSHA256 {
		t.Fatal(candidate, err)
	}
	old, err := m.RecoverManagedBundle(ctx, candidate.TransactionID, "rollback", a)
	if err != nil || old != receipt {
		t.Fatal(old, err)
	}
	for _, r := range []ManagedNFQWSBundleReceipt{receipt, candidate} {
		if _, err := m.verifyManagedNFQWS(ctx, r.GenerationPath, r.ManifestSHA256); err != nil {
			t.Fatal("immutable generation lost", r, err)
		}
	}
	oldLease, err := m.AcquireManagedNFQWSRuntime(ctx, receipt.TransactionID)
	if err != nil {
		t.Fatal("original LKG unavailable", err)
	}
	if err := oldLease.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestManagedNFQWSBundleRestartAtPublicationBoundaries(t *testing.T) {
	points := []string{
		"after:" + UpdatePrepared, "before:" + UpdateStarted, "after:" + UpdateStarted,
		"before:bundle-generation", "after:bundle-stage-chmod", "after:bundle-generation", "before:" + UpdateInstalled, "after:" + UpdateInstalled,
		"before:" + UpdateAwaitingLive, "after:" + UpdateAwaitingLive,
		"before:nfqws-publish-receipt", "after:nfqws-publish-receipt",
		"before:" + UpdateAcceptedIdle, "after:" + UpdateAcceptedIdle,
	}
	for _, point := range points {
		t.Run(point, func(t *testing.T) {
			manifest, input, _ := bundleFixtureManifest(t, "fixture-a")
			m := bundleFixtureManager(t, input)
			a := bundleFixtureAuthority()
			crash := errors.New("publication interrupted")
			m.updateFault = func(p string) error {
				if p == point {
					return crash
				}
				return nil
			}
			if _, err := m.InstallManagedBundle(context.Background(), manifest, 7, a); !errors.Is(err, crash) {
				t.Fatal("fault boundary missed", err)
			}
			state, _, err := m.PendingManagedUpdate()
			if err != nil || state.TransactionID == "" {
				t.Fatal(state, err)
			}
			// New manager/lease, no download or command replay on recovery.
			n := &Manager{StateDir: m.StateDir, nfqwsReleases: m.nfqwsReleases, nfqwsFixture: m.nfqwsFixture, nfqwsPublish: m.nfqwsPublish, Runner: bundleForbiddenRunner{t}}
			receipt, err := n.RecoverManagedBundle(context.Background(), state.TransactionID, "resume", a)
			if err != nil {
				t.Fatal(err)
			}
			lease, err := n.AcquireManagedNFQWSRuntime(context.Background(), receipt.TransactionID)
			if err != nil {
				t.Fatal(err)
			}
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestManagedNFQWSBundleRefusesStopReaderNilAndActiveRuntime(t *testing.T) {
	manifest, input, _ := bundleFixtureManifest(t, "fixture-a")
	for _, mode := range []string{"reader2", "nil", "active", "different-installation", "stop-before-rename", "admission-without-effect"} {
		t.Run(mode, func(t *testing.T) {
			m := bundleFixtureManager(t, input)
			a := bundleFixtureAuthority()
			reached := false
			switch mode {
			case "reader2":
				a.ReaderVersion = 2
			case "nil":
				a.Admit = nil
			case "active":
				a.Inactive = func(context.Context) error { return errors.New("owned runtime active") }
			case "different-installation":
				a.InstallationID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			case "stop-before-rename":
				a.Admit = func(context.Context, string, string, uint64, uint64, string, func() error) error {
					reached = true
					return errors.New("durable Stop revoked epoch")
				}
			case "admission-without-effect":
				admit := a.Admit
				a.Admit = func(ctx context.Context, transactionID, id string, seq, rev uint64, effect string, begin func() error) error {
					if effect == "nfqws-publish-receipt" {
						reached = true
						return nil
					}
					return admit(ctx, transactionID, id, seq, rev, effect, begin)
				}
			}
			if _, err := m.InstallManagedBundle(context.Background(), manifest, 7, a); err == nil {
				t.Fatal("unconfirmed authority/effect accepted")
			}
			if (mode == "stop-before-rename" || mode == "admission-without-effect") && !reached {
				t.Fatal("refusal occurred before the intended actual effect boundary")
			}
			if root, err := m.managedNFQWSInventory(false); err == nil {
				defer root.Close()
				if receipt, _, err := readManagedNFQWSReceipt(root); err != nil || receipt != nil {
					t.Fatal("refusal published ready receipt", receipt, err)
				}
			}
		})
	}
}

func TestManagedNFQWSBundleMalformedArchivesNeverProducePayload(t *testing.T) {
	manifest, input, entries := bundleFixtureManifest(t, "fixture-a")
	if payload, err := extractManagedNFQWS(context.Background(), manifest, input); err != nil || len(payload) != 6 {
		t.Fatal(payload, err)
	}
	for _, mode := range []string{"traversal", "absolute", "backslash", "duplicate", "selected-symlink", "discarded-link", "missing", "wrong-member", "crc", "trailing", "oversize-gzip"} {
		t.Run(mode, func(t *testing.T) {
			m := manifest
			m.Members = append([]ManagedNFQWSMember(nil), manifest.Members...)
			e := append([]bundleFixtureEntry(nil), entries...)
			switch mode {
			case "traversal":
				e = append(e, bundleFixtureEntry{"../escape", []byte("x"), tar.TypeReg})
			case "absolute":
				e = append(e, bundleFixtureEntry{"/opt/foreign", []byte("x"), tar.TypeReg})
			case "backslash":
				e = append(e, bundleFixtureEntry{"opt\\foreign", []byte("x"), tar.TypeReg})
			case "duplicate":
				e = append(e, e[0])
			case "selected-symlink":
				e[0].kind, e[0].data = tar.TypeSymlink, nil
			case "discarded-link":
				e = append(e, bundleFixtureEntry{"./opt/foreign", nil, tar.TypeLink})
			case "missing":
				e = e[1:]
			case "wrong-member":
				e[0].data = []byte("changed")
			case "oversize-gzip":
				e[1].data = bundleFixtureGzip(t, bytes.Repeat([]byte("x"), 1<<20))
				m.Members[1].Size, m.Members[1].SHA256 = int64(len(e[1].data)), digest(e[1].data)
			}
			data := bundleFixtureContainer(t, e)
			if mode == "crc" {
				data[len(data)-8] ^= 1
			}
			if mode == "trailing" {
				data = append(data, 'x')
			}
			m.ParentAssetSize, m.ParentSHA256 = int64(len(data)), digest(data)
			if payload, err := extractManagedNFQWS(context.Background(), m, data); err == nil || payload != nil {
				t.Fatal("malformed input produced payload", payload, err)
			}
		})
	}
}

func TestManagedNFQWSBundleThirdImageAndGenerationTamperPreserved(t *testing.T) {
	manifest, input, _ := bundleFixtureManifest(t, "fixture-a")
	m := bundleFixtureManager(t, input)
	a := bundleFixtureAuthority()
	m.updateFault = func(p string) error {
		if p == "before:nfqws-publish-receipt" {
			return errors.New("interrupted")
		}
		return nil
	}
	if _, err := m.InstallManagedBundle(context.Background(), manifest, 7, a); err == nil {
		t.Fatal("fault missed")
	}
	state, _, err := m.PendingManagedUpdate()
	if err != nil {
		t.Fatal(err)
	}
	root, err := m.managedNFQWSInventory(false)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	third := []byte("{third-image}")
	if err := root.WriteAtomic(managedNFQWSReceiptName, third, 0600); err != nil {
		t.Fatal(err)
	}
	m.updateFault = nil
	if _, err := m.RecoverManagedBundle(context.Background(), state.TransactionID, "resume", a); err == nil {
		t.Fatal("third image overwritten")
	}
	if after, err := root.ReadLimited(managedNFQWSReceiptName, 4096); err != nil || !bytes.Equal(after, third) {
		t.Fatal(string(after), err)
	}
	if err := root.Remove(managedNFQWSReceiptName); err != nil {
		t.Fatal(err)
	}
	receipt, err := m.RecoverManagedBundle(context.Background(), state.TransactionID, "resume", a)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := m.AcquireManagedNFQWSRuntime(context.Background(), receipt.TransactionID)
	if err != nil {
		t.Fatal(err)
	}
	path := lease.Descriptor().Executable.Path
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("foreign change"), 0600); err != nil {
		t.Fatal(err)
	}
	if lease.Check(context.Background()) == nil || lease.Close() == nil {
		t.Fatal("changed generation retained session acceptance")
	}
	if after, err := os.ReadFile(path); err != nil || string(after) != "foreign change" {
		t.Fatal(string(after), err)
	}
}

func TestManagedNFQWSBundleOfficialPayloadDataOnly(t *testing.T) {
	path := os.Getenv("RAZVILKA_MANAGED_NFQWS_IPK")
	if path == "" {
		t.Skip("reviewed local official archive not supplied; no download")
	}
	manifest, err := ReviewedManagedNFQWSManifest("arm64")
	if err != nil {
		t.Fatal(err)
	}
	input, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	m := bundleFixtureManager(t, input)
	m.nfqwsReview = nil
	receipt, err := m.InstallManagedBundle(context.Background(), manifest, 7, bundleFixtureAuthority())
	if err != nil {
		t.Fatal(err)
	}
	lease, err := m.AcquireManagedNFQWSRuntime(context.Background(), receipt.TransactionID)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	d := lease.Descriptor()
	if d.Executable.SHA256 != manifest.Members[0].RawSHA256 || d.Flavor != manifest.Flavor || len(d.Lua) != 3 || len(d.Blobs) != 2 {
		t.Fatal(d)
	}
	for _, forbidden := range []string{"etc", "usr", "S51nfqws2", "postinst", "opkg"} {
		if _, err := os.Stat(filepath.Join(receipt.GenerationPath, forbidden)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("stock hook/path materialized", forbidden, err)
		}
	}
}

func TestManagedNFQWSBundleProductionReviewAndJournalClosure(t *testing.T) {
	manifest, _, _ := bundleFixtureManifest(t, "unreviewed")
	m := &Manager{Arch: "arm64"}
	if m.reviewManagedNFQWS(manifest) == nil {
		t.Fatal("synthetic recipe entered production catalog")
	}
	if _, err := ReviewedManagedNFQWSManifest("mips"); err == nil {
		t.Fatal("unreviewed architecture accepted")
	}
	manifest, input, _ := bundleFixtureManifest(t, "fixture-a")
	m = bundleFixtureManager(t, input)
	m.nfqwsReview = func(ManagedNFQWSManifest) error { return nil }
	receipt, err := m.InstallManagedBundle(context.Background(), manifest, 7, bundleFixtureAuthority())
	if err != nil {
		t.Fatal(err)
	}
	root, err := openUpdateRoot(m.updateJournalDir(), false)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	data, err := root.ReadLimited("current.json", 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	var doc updateJournal
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.Replace(string(data), `"schema_version":3`, `"schema_version":3,"schema_version":3`, 1))
	if err := root.WriteAtomic("current.json", data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readUpdateJournal(root); err == nil {
		t.Fatal("duplicate field accepted in schema3 journal")
	}
	if receipt.TransactionID != doc.TransactionID {
		t.Fatal("receipt lost journal binding")
	}
}

func TestManagedNFQWSBundlePreservesStockAndPermanentWriter(t *testing.T) {
	manifest, input, _ := bundleFixtureManifest(t, "fixture-a")
	m := bundleFixtureManager(t, input)
	base := filepath.Dir(m.StateDir)
	stock := map[string][]byte{
		"stock/lib/opkg/status":            []byte("unrelated installed package\n"),
		"stock/usr/bin/nfqws2":             []byte("foreign executable bytes\n"),
		"stock/etc/init.d/S51nfqws2":       []byte("foreign boot script\n"),
		"stock/etc/nfqws2/nfqws2.conf":     []byte("foreign config\n"),
		"stock/etc/ndm/netfilter.d/nfqws2": []byte("foreign hook\n"),
	}
	for name, data := range stock {
		path := filepath.Join(base, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	m.BinDir, m.InitDir, m.InfoDir, m.Opkg = filepath.Join(base, "stock/usr/bin"), filepath.Join(base, "stock/etc/init.d"), filepath.Join(base, "stock/lib/opkg/info"), filepath.Join(base, "stock/bin/opkg")
	receipt, err := m.InstallManagedBundle(context.Background(), manifest, 7, bundleFixtureAuthority())
	if err != nil {
		t.Fatal(err)
	}
	for name, expected := range stock {
		actual, err := os.ReadFile(filepath.Join(base, filepath.FromSlash(name)))
		if err != nil || !bytes.Equal(actual, expected) {
			t.Fatal("foreign stock state changed", name, string(actual), err)
		}
	}
	marker := filepath.Join(m.updateJournalDir(), ".writer.lock")
	before, err := os.Stat(marker)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := m.AcquireManagedNFQWSRuntime(context.Background(), receipt.TransactionID)
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(marker)
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("session replaced permanent writer inode", err)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AcquireManagedNFQWSRuntime(context.Background(), receipt.TransactionID); err == nil {
		t.Fatal("missing permanent inode granted session")
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing permanent inode was silently recreated", err)
	}
}
