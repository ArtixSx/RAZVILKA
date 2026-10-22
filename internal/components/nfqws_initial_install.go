package components

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

var nfqwsInitialArchitectures = map[string]string{"arm64": "aarch64", "arm": "armv7", "386": "x86", "amd64": "x86_64", "mips": "mips", "mipsle": "mipsel", "mips64": "mips64"}

// Bound once by actual startup dataplane wiring. An installed-version DTO or
// a successful shell status cannot implement the runtime/process/kernel proof.
type NFQWSInitialInstallSource interface {
	WithInitialNFQWSInstall(context.Context, func(context.Context, func(context.Context) error) error) error
}

type NFQWSInitialInstallAuthority struct {
	InstallationID     string
	Sequence, Revision uint64
	Check              func(context.Context, string, uint64, uint64, int) error
}

func (a NFQWSInitialInstallAuthority) check(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || !bundleHash(a.InstallationID, 32) || a.Sequence == 0 || a.Check == nil {
		return ErrRecoveryAuthority
	}
	return a.Check(ctx, a.InstallationID, a.Sequence, a.Revision, NFQWSInitialInstallSchema)
}

func (m *Manager) BindNFQWSInitialInstallSource(source NFQWSInitialInstallSource) error {
	if m == nil || source == nil || m.initialNFQSource != nil {
		return ErrNFQWSInitialInstall
	}
	m.initialNFQSource = source
	return nil
}

// InstallInitialNFQWS installs a DERIVATIVE of the pinned upstream IPK. It
// never upgrades/removes a package, resolves dependencies, or starts NFQWS2.
// Any error after durable prepared intent remains pending; no automatic replay
// or blind removal/stock restoration is permitted for partial opkg effects.
func (m *Manager) InstallInitialNFQWS(ctx context.Context, authority NFQWSInitialInstallAuthority) (result Result, resultErr error) {
	result = Result{Component: "nfqws2", Action: "install"}
	if m == nil {
		return result, NoMutation(ErrNFQWSInitialInstall)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.nfqwsPackageMutationGuard("nfqws2"); err != nil {
		return result, NoMutation(err)
	}
	if m.initialNFQSource == nil || authority.check(ctx) != nil {
		return result, NoMutation(ErrNFQWSInitialInstall)
	}
	if _, ok := m.Runner.(supervisedPackageRunner); !ok {
		return result, NoMutation(ErrNFQWSInitialInstall)
	}
	if _, ok := nfqwsInitialArchitectures[m.Arch]; !ok {
		return result, NoMutation(ErrNFQWSInitialInstall)
	}
	if _, native := m.Runner.(execRunner); native && (runtime.GOOS != "linux" || m.InitDir != "/opt/etc/init.d" || m.InfoDir != "" && m.InfoDir != "/opt/lib/opkg/info" || m.BinDir != "/opt/bin") {
		return result, NoMutation(ErrNFQWSInitialInstall)
	}
	err := m.initialNFQSource.WithInitialNFQWSInstall(ctx, func(held context.Context, absence func(context.Context) error) error {
		tx, err := m.lockUpdateJournal()
		if err != nil {
			return NoMutation(err)
		}
		defer tx.close()
		if err := tx.requireIdle(); err != nil {
			return NoMutation(err)
		}
		writer, err := tx.initialWriter(held)
		if err != nil {
			return NoMutation(err)
		}
		defer writer.target.Close()
		check := func(c context.Context) error {
			if err := authority.check(c); err != nil {
				return err
			}
			return absence(c)
		}
		before, err := m.nfqwsInitialPreflight(held)
		if err != nil {
			return NoMutation(err)
		}
		if err := check(held); err != nil {
			return NoMutation(err)
		}
		source, err := m.downloadNFQWSInitialArchive(held)
		if err != nil {
			return NoMutation(err)
		}
		owner := nfqwsInitialOwner(m.StateDir)
		archive, err := rebuildNFQWSInitialArchive(held, source, owner)
		if err != nil {
			return NoMutation(err)
		}
		current, err := m.nfqwsInitialPreflight(held)
		if err != nil || !bytes.Equal(before, current) {
			return NoMutation(errors.Join(ErrNFQWSInitialInstall, err))
		}
		if err := check(held); err != nil {
			return NoMutation(err)
		}
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return NoMutation(err)
		}
		id := hex.EncodeToString(nonce[:])
		if err := tx.root.MkdirAll(id, 0700); err != nil {
			return NoMutation(err)
		}
		stage, err := ownedfs.Open(filepath.Join(m.updateJournalDir(), id))
		if err != nil {
			return NoMutation(err)
		}
		defer stage.Close()
		if err := stage.WriteAtomic("upstream.ipk", source, 0600); err != nil {
			return NoMutation(err)
		}
		if err := stage.WriteAtomic(nfqwsInitialArchiveName, archive.bytes, 0600); err != nil {
			return NoMutation(err)
		}
		if err := errors.Join(syncUpdateDirectory(stage), syncUpdateDirectory(tx.root)); err != nil {
			return NoMutation(err)
		}
		v := &nfqwsInitialInstallTransaction{SourceSHA256: nfqwsInitialSourceSHA, SourceSize: nfqwsInitialSourceSize, DerivedSHA256: digest(archive.bytes), DerivedSize: int64(len(archive.bytes)), InitSHA256: digest(archive.init), Owner: owner, Architecture: m.Arch, StatusSHA256: digest(before), InstallationID: authority.InstallationID, Sequence: authority.Sequence, Revision: authority.Revision, Derivation: nfqwsInitialDerivation}
		if err := stage.WriteAtomic("derivation.json", nfqwsInitialDerivationManifest(v), 0600); err != nil {
			return NoMutation(err)
		}
		if err := syncUpdateDirectory(stage); err != nil {
			return NoMutation(err)
		}
		tx.doc = updateJournal{ManagedUpdateState: ManagedUpdateState{SchemaVersion: NFQWSInitialInstallSchema, TransactionID: id, Component: "nfqws2", BeforeVersion: "absent", AfterVersion: "1.3.1"}, NFQWSInitialInstall: v, Package: "nfqws2-keenetic", PackageFile: nfqwsInitialArchiveName, PackageSHA256: v.DerivedSHA256, SupervisionVersion: 1}
		// The durable prepared record is the no-replay boundary, even if the
		// following admission check fails before a package process was started.
		result.TransactionID = id
		if err := writer.phase(held, tx, nfqwsInitialPrepared); err != nil {
			return err
		}
		result.TransactionID = id
		if err := check(held); err != nil {
			return err
		}
		current, err = m.nfqwsInitialPreflight(held)
		if err != nil || !bytes.Equal(before, current) {
			return errors.Join(ErrNFQWSInitialInstall, err)
		}
		path, err := tx.loadNFQWSInitialArchive(held)
		if err != nil {
			return err
		}
		if err := writer.phase(held, tx, nfqwsInitialStarted); err != nil {
			return err
		}
		if err := check(held); err != nil {
			return err
		}
		if err := tx.fault("before:initial-install-command"); err != nil {
			return err
		}
		current, err = m.nfqwsInitialPreflight(held)
		if err != nil || !bytes.Equal(before, current) {
			return errors.Join(ErrNFQWSInitialInstall, err)
		}
		if err := check(held); err != nil {
			return err
		}
		out, err := tx.runInitialNFQWSPackage(held, path)
		result.Output = boundedOutput(out)
		if fault := tx.fault("after:initial-install-command"); fault != nil {
			return errors.Join(ErrUpdateUnknown, err, fault)
		}
		if err != nil {
			return errors.Join(ErrUpdateUnknown, err)
		}
		if err := check(held); err != nil {
			return err
		}
		seal, err := m.verifyNFQWSInitialInstall(held, archive, before)
		if err != nil {
			return err
		}
		if err := check(held); err != nil {
			return err
		}
		if err := tx.fault("after:initial-install-readback"); err != nil {
			return err
		}
		// No installed version or exit zero alone can reach the terminal image.
		v.ReadbackSHA256 = seal
		accepted := tx.doc
		accepted.Phase = nfqwsInitialAccepted
		accepted.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		data, err := json.Marshal(accepted)
		if err != nil {
			return err
		}
		if validateNFQWSInitialJournal(accepted) != nil {
			return ErrNFQWSInitialInstall
		}
		if err := stage.WriteAtomic("initial-verified.json", data, 0600); err != nil {
			return err
		}
		if err := syncUpdateDirectory(stage); err != nil {
			return err
		}
		if err := m.writeLifecycleReceipt(lifecycleReceipt{SchemaVersion: 1, Component: "nfqws2", Package: "nfqws2-keenetic", Provider: "opkg", Action: "install", AfterVersion: "1.3.1", CompletedAt: accepted.UpdatedAt, TransactionID: id, Acceptance: UpdateAcceptedIdle, NFQWSDerived: v}); err != nil {
			return err
		}
		if err := check(held); err != nil {
			return err
		}
		if err := writer.phaseGuarded(held, tx, nfqwsInitialAccepted, func() error {
			if err := check(held); err != nil {
				return err
			}
			current, err := m.verifyNFQWSInitialInstall(held, archive, before)
			if err != nil || current != seal {
				return errors.Join(ErrNFQWSInitialInstall, err)
			}
			return check(held)
		}); err != nil {
			return err
		}
		result.OK = true
		result.InstalledIdleAccepted = true
		result.Output += "\nУстановлен производный пакет NFQWS2 1.3.1 с inert init RAZVILKA. Обработка трафика не запущена."
		return nil
	})
	if err != nil {
		if result.TransactionID != "" {
			return result, errors.Join(ErrUpdatePending, err)
		}
		return result, err
	}
	return result, nil
}

func (m *Manager) nfqwsInitialPrefix() (string, error) {
	prefix := filepath.Dir(filepath.Dir(m.InitDir))
	if m.StateDir == "" || !filepath.IsAbs(m.StateDir) || !filepath.IsAbs(prefix) || prefix == filepath.VolumeName(prefix)+string(filepath.Separator) ||
		filepath.Join(prefix, "etc", "init.d") != m.InitDir || filepath.Clean(m.infoDir()) != filepath.Join(prefix, "lib", "opkg", "info") {
		return "", ErrNFQWSInitialInstall
	}
	return prefix, nil
}

func (m *Manager) nfqwsInitialPreflight(ctx context.Context) ([]byte, error) {
	prefix, err := m.nfqwsInitialPrefix()
	if err != nil {
		return nil, err
	}
	root, err := m.openNFQWSInitialPrefix(prefix)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	for _, path := range []string{"etc/nfqws2", "etc/init.d/S51nfqws2", "etc/init.d/nfqws2-keenetic", "usr/bin/nfqws2", "etc/ndm/netfilter.d/100-nfqws2.sh", "var/run/nfqws2.pid", "var/log/nfqws2.log", "tmp/nfqws2_install_type", "tmp/nfqws2_binary"} {
		_, err := root.Stat(filepath.FromSlash(path))
		if !errors.Is(err, os.ErrNotExist) {
			return nil, errors.Join(ErrNFQWSInitialInstall, err)
		}
	}
	info, err := os.ReadDir(m.infoDir())
	if err != nil {
		return nil, err
	}
	for _, entry := range info {
		if strings.HasPrefix(entry.Name(), "nfqws2-keenetic.") {
			return nil, ErrNFQWSInitialInstall
		}
	}
	status, err := m.run(ctx, "status")
	if err != nil {
		return nil, err
	}
	if _, err := nfqwsInitialStatus(status, false); err != nil {
		return nil, err
	}
	return status, nil
}

func nfqwsInitialStatus(data []byte, installed bool) (map[string]string, error) {
	if len(data) == 0 || len(data) > 4<<20 || bytes.ContainsRune(data, '\r') {
		return nil, ErrNFQWSInitialInstall
	}
	records := map[string]string{}
	for _, paragraph := range strings.Split(strings.TrimSpace(string(data)), "\n\n") {
		fields := map[string]string{}
		for _, line := range strings.Split(paragraph, "\n") {
			if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
				continue
			}
			key, value, ok := strings.Cut(line, ":")
			if !ok || fields[key] != "" {
				return nil, ErrNFQWSInitialInstall
			}
			fields[key] = strings.TrimSpace(value)
		}
		name := fields["Package"]
		state := strings.Fields(fields["Status"])
		if name == "" || records[name] != "" || len(state) != 3 || state[0] != "install" || (state[1] != "ok" && state[1] != "user") || state[2] != "installed" || fields["Version"] == "" {
			return nil, ErrNFQWSInitialInstall
		}
		if name == "tpws-keenetic" || name == "nfqws-keenetic" || name == "nfqws2-keenetic" && !installed {
			return nil, ErrNFQWSInitialInstall
		}
		records[name] = paragraph
	}
	for _, dependency := range []string{"iptables", "busybox"} {
		if records[dependency] == "" {
			return nil, fmt.Errorf("%w: необходим уже установленный пакет %s в базе opkg", ErrNFQWSInitialInstall, dependency)
		}
	}
	if installed && records["nfqws2-keenetic"] == "" {
		return nil, ErrNFQWSInitialInstall
	}
	return records, nil
}

func (m *Manager) verifyNFQWSInitialInstall(ctx context.Context, a *nfqwsInitialArchive, before []byte) (string, error) {
	prefix, err := m.nfqwsInitialPrefix()
	if err != nil {
		return "", err
	}
	root, err := m.openNFQWSInitialPrefix(prefix)
	if err != nil {
		return "", err
	}
	defer root.Close()
	proof := map[string]string{}
	for name, member := range a.files {
		if strings.HasPrefix(name, "opt/tmp/") {
			continue
		}
		path := strings.TrimPrefix(name, "opt/")
		live, err := root.ReadLimited(filepath.FromSlash(path), 4<<20)
		if err != nil {
			return "", err
		}
		info, err := root.Stat(filepath.FromSlash(path))
		if err != nil || !info.Mode().IsRegular() || nfqwsInitialMetadata(info, m.nfqwsFixture != nil) != nil || !updateModeMatches(info.Mode().Perm(), os.FileMode(member.header.Mode).Perm()) {
			return "", fmt.Errorf("%w: unsafe installed member metadata %s", ErrNFQWSInitialInstall, name)
		}
		proof[path] = fmt.Sprintf("%s:%o", digest(live), info.Mode().Perm())
		if name == "opt/etc/nfqws2/nfqws2.conf" {
			if engineconfig.NFQWSFirstStartStockConfig(live) != nil {
				return "", fmt.Errorf("%w: installed stock config is unsupported", ErrNFQWSInitialInstall)
			}
			for _, key := range []string{"ISP_INTERFACE", "IPV6_ENABLED"} {
				re := regexp.MustCompile(`(?m)^` + key + `=.*$`)
				live = re.ReplaceAll(live, []byte(key+"=<postinst>"))
				member.data = re.ReplaceAll(member.data, []byte(key+"=<postinst>"))
			}
		}
		if !bytes.Equal(live, member.data) {
			return "", fmt.Errorf("%w: installed member %s differs", ErrNFQWSInitialInstall, name)
		}
	}
	binary, err := root.ReadLimited(filepath.FromSlash("usr/bin/nfqws2"), 4<<20)
	if err != nil || !bytes.Equal(binary, a.files["opt/tmp/nfqws2_binary/nfqws2-"+nfqwsInitialArchitectures[m.Arch]].data) {
		return "", fmt.Errorf("%w: relocated executable differs from pinned architecture", ErrNFQWSInitialInstall)
	}
	info, err := root.Stat(filepath.FromSlash("usr/bin/nfqws2"))
	if err != nil || nfqwsInitialMetadata(info, m.nfqwsFixture != nil) != nil || runtime.GOOS != "windows" && info.Mode().Perm()&0111 == 0 {
		return "", ErrNFQWSInitialInstall
	}
	proof["usr/bin/nfqws2"] = fmt.Sprintf("%s:%o", digest(binary), info.Mode().Perm())
	for _, path := range []string{"etc/nfqws2/nfqws2.conf.run", "var/run/nfqws2.pid", "tmp/nfqws2_binary", "tmp/nfqws2_install_type", "etc/init.d/nfqws2-keenetic"} {
		if _, err := root.Stat(filepath.FromSlash(path)); !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("%w: unexpected post-install resource %s", ErrNFQWSInitialInstall, path)
		}
	}
	meta, err := ownedfs.Open(m.infoDir())
	if err != nil {
		return "", err
	}
	defer meta.Close()
	for name, expected := range a.control {
		live, err := meta.ReadLimited("nfqws2-keenetic."+name, 64<<10)
		if err != nil || !bytes.Equal(live, expected) {
			return "", fmt.Errorf("%w: package metadata differs %s", ErrNFQWSInitialInstall, name)
		}
		info, err := meta.Stat("nfqws2-keenetic." + name)
		if err != nil || nfqwsInitialMetadata(info, m.nfqwsFixture != nil) != nil {
			return "", ErrNFQWSInitialInstall
		}
		proof["info/"+name] = fmt.Sprintf("%s:%o", digest(live), info.Mode().Perm())
	}
	listed, err := meta.ReadLimited("nfqws2-keenetic.list", 64<<10)
	if err != nil {
		return "", err
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(listed)), "\n") {
		if seen[line] || a.files[strings.TrimPrefix(line, "/")].name == "" {
			return "", fmt.Errorf("%w: unexpected package list entry", ErrNFQWSInitialInstall)
		}
		seen[line] = true
	}
	if len(seen) != len(a.files) {
		return "", fmt.Errorf("%w: incomplete package list", ErrNFQWSInitialInstall)
	}
	info, err = meta.Stat("nfqws2-keenetic.list")
	if err != nil || nfqwsInitialMetadata(info, m.nfqwsFixture != nil) != nil {
		return "", ErrNFQWSInitialInstall
	}
	proof["info/list"] = fmt.Sprintf("%s:%o", digest(listed), info.Mode().Perm())
	after, err := m.run(ctx, "status")
	if err != nil {
		return "", err
	}
	old, err := nfqwsInitialStatus(before, false)
	if err != nil {
		return "", err
	}
	next, err := nfqwsInitialStatus(after, true)
	if err != nil {
		return "", err
	}
	if len(next) != len(old)+1 || !strings.Contains("\n"+next["nfqws2-keenetic"]+"\n", "\nVersion: 1.3.1\n") {
		return "", ErrNFQWSInitialInstall
	}
	for name, record := range old {
		if next[name] != record {
			return "", ErrNFQWSInitialInstall
		}
	}
	proof["opkg-status"] = digest(after)
	names := make([]string, 0, len(proof))
	for name := range proof {
		names = append(names, name)
	}
	sort.Strings(names)
	var seal strings.Builder
	for _, name := range names {
		fmt.Fprintf(&seal, "%s\x00%s\n", name, proof[name])
	}
	return digest([]byte(seal.String())), ctx.Err()
}

func (m *Manager) openNFQWSInitialPrefix(prefix string) (*ownedfs.Root, error) {
	canonical, err := filepath.EvalSymlinks(prefix)
	if err != nil {
		return nil, err
	}
	root, err := ownedfs.Open(canonical)
	if err != nil {
		return nil, err
	}
	fail := func(path string) (*ownedfs.Root, error) {
		root.Close()
		return nil, fmt.Errorf("%w: каталог %s должен принадлежать root:root и не разрешать запись группе или остальным", ErrNFQWSInitialInstall, filepath.Join(prefix, path))
	}
	info, err := root.RootInfo()
	if err != nil || nfqwsInitialMetadata(info, m.nfqwsFixture != nil) != nil {
		return fail("")
	}
	for _, path := range []string{"etc", "etc/init.d", "etc/ndm", "etc/ndm/netfilter.d", "etc/nfqws2", "etc/nfqws2/lists", "etc/nfqws2/lua", "etc/nfqws2/blobs", "usr", "usr/bin", "lib", "lib/opkg", "lib/opkg/info", "var", "var/run", "var/log", "tmp"} {
		info, err := root.Stat(filepath.FromSlash(path))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.IsDir() || nfqwsInitialMetadata(info, m.nfqwsFixture != nil) != nil {
			return fail(path)
		}
	}
	return root, nil
}

func (tx *updateTransaction) runInitialNFQWSPackage(ctx context.Context, path string) ([]byte, error) {
	if tx.doc.NFQWSInitialInstall == nil || tx.doc.Phase != nfqwsInitialStarted || tx.doc.SupervisionVersion != 1 {
		return nil, ErrNFQWSInitialInstall
	}
	verified, err := tx.loadNFQWSInitialArchive(ctx)
	if err != nil || verified != path {
		return nil, ErrNFQWSInitialInstall
	}
	runner, ok := tx.manager.Runner.(supervisedPackageRunner)
	if !ok {
		return nil, ErrNFQWSInitialInstall
	}
	root, err := ownedfs.Open(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	if _, err := root.Stat("install.supervision.json"); !errors.Is(err, os.ErrNotExist) {
		return nil, ErrUpdateUnknown
	}
	record := packageSupervision{Schema: 1, TransactionID: tx.doc.TransactionID, Component: "nfqws2", Action: "install", Containment: packageContainment, State: "intent"}
	bounded, cancel := context.WithTimeout(ctx, defaultDuration(tx.manager.Timeout, 90*time.Second))
	defer cancel()
	args := []string{"install", "--nodeps", path}
	return tx.manager.withPackageParents(args, func() ([]byte, error) {
		return runner.runSupervised(bounded, tx.manager.Opkg, args, record, root, filepath.Dir(path))
	})
}
