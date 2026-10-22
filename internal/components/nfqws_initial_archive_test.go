package components

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

func initialTestTar(t *testing.T, members []nfqwsInitialMember) []byte {
	t.Helper()
	var raw bytes.Buffer
	w := tar.NewWriter(&raw)
	for _, member := range members {
		h := member.header
		h.Name = member.name
		h.Size = int64(len(member.data))
		if h.Mode == 0 {
			h.Mode = 0644
		}
		if h.Typeflag == 0 {
			h.Typeflag = tar.TypeReg
		}
		if err := w.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(member.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	gz, err := nfqwsInitialGzip(raw.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return gz
}

func initialTestArchive(t *testing.T) []byte {
	t.Helper()
	stock, err := os.ReadFile(filepath.Join("testdata", "nfqws2-keenetic-1.3.1", "S51nfqws2"))
	if err != nil {
		t.Fatal(err)
	}
	controls := []nfqwsInitialMember{{name: "control", data: []byte("Package: nfqws2-keenetic\nVersion: 1.3.1\nDepends: iptables, busybox\n")}}
	for _, name := range []string{"prerm", "preinst", "postinst", "postrm", "conffiles"} {
		controls = append(controls, nfqwsInitialMember{name: name, data: []byte("original " + name + "\n"), header: tar.Header{Uid: 1001, Gid: 1001, Mode: 0755, ModTime: time.Unix(1720000000, 0)}})
	}
	data := initialTestTar(t, []nfqwsInitialMember{{name: nfqwsInitialInitMember, data: stock, header: tar.Header{Uid: 1001, Gid: 1001, Mode: 0755, ModTime: time.Unix(1720000000, 0)}}, {name: "opt/etc/nfqws2/nfqws2.conf", data: []byte("unchanged config\n")}})
	return initialTestTar(t, []nfqwsInitialMember{{name: "control.tar.gz", data: initialTestTar(t, controls)}, {name: "data.tar.gz", data: data}, {name: "debian-binary", data: []byte("2.0\n")}})
}

func TestNFQWSInitialArchiveChangesOnlyReviewedInitAndOwners(t *testing.T) {
	source := initialTestArchive(t)
	const owner = "0123456789abcdef01234567"
	changed, err := rewriteNFQWSInitialArchive(context.Background(), source, owner)
	if err != nil {
		t.Fatal(err)
	}
	_, before, err := nfqwsInitialTar(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	_, after, err := nfqwsInitialTar(context.Background(), changed.bytes)
	if err != nil {
		t.Fatal(err)
	}
	for i, member := range before {
		if member.name == "control.tar.gz" {
			oldRaw, old, err := nfqwsInitialTar(context.Background(), member.data)
			if err != nil {
				t.Fatal(err)
			}
			newRaw, _, err := nfqwsInitialTar(context.Background(), after[i].data)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(nfqwsInitialRootOwners(oldRaw, old), newRaw) {
				t.Fatal("changed control content/mode/path outside ownership metadata")
			}
			continue
		}
		if member.name != "data.tar.gz" {
			if !bytes.Equal(member.data, after[i].data) {
				t.Fatal("changed outer member", member.name)
			}
			continue
		}
		oldRaw, oldEntries, err := nfqwsInitialTar(context.Background(), member.data)
		if err != nil {
			t.Fatal(err)
		}
		newRaw, newEntries, err := nfqwsInitialTar(context.Background(), after[i].data)
		if err != nil {
			t.Fatal(err)
		}
		if len(oldEntries) != len(newEntries) {
			t.Fatal("added payload member")
		}
		for j, old := range oldEntries {
			current := newEntries[j]
			if old.name != nfqwsInitialInitMember {
				normalized := nfqwsInitialRootOwners(oldRaw, oldEntries)
				if !bytes.Equal(normalized[old.start:old.end], newRaw[current.start:current.end]) {
					t.Fatal("changed non-init raw record", old.name)
				}
				continue
			}
			if current.header.Uid != 0 || current.header.Gid != 0 || current.header.Mode != old.header.Mode || !current.header.ModTime.Equal(old.header.ModTime) {
				t.Fatal("changed init ownership/mode/time")
			}
			original, err := engineconfig.NFQWSFirstStartOriginalInit(current.data, owner)
			if err != nil || !bytes.Equal(original, old.data) {
				t.Fatal("not exact deterministic inert transform", err)
			}
		}
	}
	if _, err := rebuildNFQWSInitialArchive(context.Background(), source, owner); err == nil {
		t.Fatal("synthetic archive obtained pinned provenance")
	}
}

func TestNFQWSInitialArchiveRejectsUnsafeFraming(t *testing.T) {
	for _, which := range []string{"traversal", "symlink", "duplicate", "oversized", "trailing"} {
		t.Run(which, func(t *testing.T) {
			entries := []nfqwsInitialMember{{name: "safe", data: []byte("data")}}
			switch which {
			case "traversal":
				entries[0].name = "../escape"
			case "symlink":
				entries[0].header = tar.Header{Typeflag: tar.TypeSymlink, Linkname: "elsewhere"}
				entries[0].data = nil
			case "duplicate":
				entries = append(entries, entries[0])
			case "oversized":
				entries[0].data = make([]byte, (4<<20)+1)
			}
			data := initialTestTar(t, entries)
			if which == "trailing" {
				data = append(data, []byte("foreign")...)
			}
			if _, _, err := nfqwsInitialTar(context.Background(), data); err == nil {
				t.Fatal("unsafe framing accepted")
			}
		})
	}
}

func TestNFQWSInitialStatusRejectsDependencyResolutionAndOtherPendingPackages(t *testing.T) {
	valid := "Package: iptables\nVersion: 1\nStatus: install user installed\n\nPackage: busybox\nVersion: 2\nStatus: install ok installed\n"
	if _, err := nfqwsInitialStatus([]byte(valid), false); err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{strings.Replace(valid, "Package: busybox", "Package: other", 1), valid + "\nPackage: unrelated\nVersion: 1\nStatus: install ok unpacked\n", valid + "\nPackage: nfqws2-keenetic\nVersion: 1.3.1\nStatus: install user installed\n", valid + "\nPackage: nfqws-keenetic\nVersion: 1\nStatus: install user installed\n"} {
		if _, err := nfqwsInitialStatus([]byte(text), false); err == nil {
			t.Fatal("unsafe package set accepted", text)
		}
	}
}

func TestNFQWSInitialSchemaFourFencesLegacyRecoveryAndReaderFloor(t *testing.T) {
	m := &Manager{StateDir: t.TempDir()}
	tx, err := m.lockUpdateJournal()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.close()
	v := &nfqwsInitialInstallTransaction{SourceSHA256: nfqwsInitialSourceSHA, SourceSize: nfqwsInitialSourceSize, DerivedSHA256: strings.Repeat("a", 64), DerivedSize: 100, InitSHA256: strings.Repeat("b", 64), Owner: strings.Repeat("c", 24), Architecture: "arm64", StatusSHA256: strings.Repeat("d", 64), InstallationID: strings.Repeat("e", 32), Sequence: 1, Derivation: nfqwsInitialDerivation}
	tx.doc = updateJournal{ManagedUpdateState: ManagedUpdateState{SchemaVersion: NFQWSInitialInstallSchema, TransactionID: strings.Repeat("f", 32), Component: "nfqws2", BeforeVersion: "absent", AfterVersion: "1.3.1"}, NFQWSInitialInstall: v, Package: "nfqws2-keenetic", PackageFile: nfqwsInitialArchiveName, PackageSHA256: v.DerivedSHA256, SupervisionVersion: 1}
	w, err := tx.initialWriter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer w.target.Close()
	if err := w.phase(context.Background(), tx, nfqwsInitialPrepared); err != nil {
		t.Fatal(err)
	}
	// Windows mandatory byte locks deny a second marker reader while held.
	if err := w.target.Close(); err != nil {
		t.Fatal(err)
	}
	if floor, err := RequiredRetainedManagedUpdateReadVersion(context.Background(), m.StateDir); err != nil || floor != 4 {
		t.Fatal("initial state not advertised as schema4", floor, err)
	}
	if _, pending, err := m.PendingManagedUpdate(); err != nil || !pending {
		t.Fatal("prepared initial state not fenced", pending, err)
	}
	for _, phase := range []string{UpdateAbandoned, UpdateAcceptedIdle, UpdateRolledBack} {
		candidate := tx.doc
		candidate.Phase = phase
		if validateUpdateJournal(candidate) == nil {
			t.Fatal("generic phase accepted initial ownership", phase)
		}
	}
	data, _ := json.Marshal(tx.doc)
	var old struct {
		ManagedUpdateState
		Package       string `json:"package"`
		PackageFile   string `json:"package_file"`
		PackageSHA256 string `json:"package_sha256"`
	}
	if strictJSON(data, &old) == nil {
		t.Fatal("old strict reader accepted new initial field")
	}
}

func TestNFQWSInitialPinnedUniversalArchiveLocalEvidence(t *testing.T) {
	// Optional local upstream evidence; hermetic tests above never bypass the
	// production pinned hash. CI need not redistribute the universal binaries.
	source, err := os.ReadFile(filepath.Join("..", "..", ".review-local", "nfq-initial-install-review", "upstream-1.3.1-all-entware.ipk"))
	if os.IsNotExist(err) {
		t.Skip("private pinned upstream evidence not present")
	}
	if err != nil {
		t.Fatal(err)
	}
	a, err := rebuildNFQWSInitialArchive(context.Background(), source, "0123456789abcdef01234567")
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := os.ReadFile(filepath.Join("..", "engineconfig", "testdata", "nfqws2-first-start-1.3.1.conf"))
	if err != nil {
		t.Fatal(err)
	}
	expected := bytes.Replace(baseline, []byte(`NFQWS_BASE_ARGS="--lua-init=`), []byte("NFQWS_BASE_ARGS=\"--fastpath-workaround=auto\n                 --lua-init="), 1)
	expected = bytes.Replace(expected, []byte("IPV6_ENABLED=0\n"), []byte("IPV6_ENABLED=1\n"), 1)
	if !bytes.Equal(expected, a.files["opt/etc/nfqws2/nfqws2.conf"].data) {
		t.Fatal("pinned config differs beyond the reviewed stock variant")
	}
	if digest(a.bytes) == nfqwsInitialSourceSHA {
		t.Fatal("derivative claimed upstream digest")
	}
	if _, err := engineconfig.NFQWSFirstStartInitOwner(a.init); err != nil {
		t.Fatal(err)
	}
}
