//go:build linux && (amd64 || arm64)

package dataplane

import (
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// ROOT's explicit fixed deployment fixture, never a production tool issuer.
// Only these two reviewed alias/version/main-image combinations are selected.
type backendNativeProfile struct {
	aliases          [2]string
	version, mainSHA string
	dirs, extensions []string
	pinned           map[string]string
}

func backendNativeFixtureProfile(mode string) (backendNativeProfile, error) {
	switch mode {
	case "linux70":
		return backendNativeProfile{aliases: [2]string{"/usr/sbin/iptables-legacy", "/usr/sbin/ip6tables-legacy"}, version: "1.8.11 (legacy)", mainSHA: "da62b7b5a7371424906138fa1eba11ec922b256969e5fa3dfa716949abafe8ac", dirs: []string{"/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu", "/lib/aarch64-linux-gnu", "/usr/lib/aarch64-linux-gnu", "/lib", "/usr/lib"}, extensions: []string{"/usr/lib/x86_64-linux-gnu/xtables", "/usr/lib/aarch64-linux-gnu/xtables", "/usr/lib/xtables"}}, nil
	case "stock-nc1812":
		return backendNativeProfile{aliases: [2]string{"/opt/sbin/iptables", "/opt/sbin/ip6tables"}, version: "1.4.21", mainSHA: "966a3efa461f9f42a9f48dfb8c0bc8b5ef858aac1130adf5f84e3724b3ec2acf", dirs: []string{"/opt/lib", "/lib", "/usr/lib"}, extensions: []string{"/opt/lib/iptables", "/opt/lib/xtables"}, pinned: map[string]string{"/opt/lib/libip4tc.so.0.1.0": "70b9df4548483520cfcdcb89cddbe7ff2faa7cae89ed53e22ad60544fdca1c2a", "/opt/lib/libip6tc.so.0.1.0": "48a62bbcb302d06abdc438720de6275f63435cd77e87a9379ba5f7aa463788de"}}, nil
	}
	return backendNativeProfile{}, errBackendInventory
}

type backendNativeImage struct {
	path string
	file *os.File
	info os.FileInfo
	hash [32]byte
}
type backendNativeNode struct {
	path, link string
	info       os.FileInfo
}
type backendNativeReview struct {
	profile        backendNativeProfile
	images         []*backendNativeImage
	nodes          []backendNativeNode
	extensionNames map[string][]string
	bytes          int64
	calls          int
}

// Diagnostic labels are compiled constants. Never print an underlying error:
// it may contain deployment paths, ELF names or command output.
type backendNativeDiagnostic struct {
	stage string
	cause error
}

func (e *backendNativeDiagnostic) Error() string { return "backend native tool fixture: " + e.stage }
func (e *backendNativeDiagnostic) Unwrap() error { return e.cause }
func backendNativeStage(stage string, err error) error {
	if err == nil {
		err = errBackendInventory
	}
	return &backendNativeDiagnostic{stage: stage, cause: err}
}
func backendNativeTrace(err error) string {
	var stages []string
	for len(stages) < 16 {
		var diagnostic *backendNativeDiagnostic
		if !errors.As(err, &diagnostic) {
			break
		}
		stages = append(stages, diagnostic.stage)
		err = diagnostic.cause
	}
	if len(stages) == 0 {
		return "UNCLASSIFIED"
	}
	return strings.Join(stages, "/")
}

func (r *backendNativeReview) close() error {
	var err error
	for _, image := range r.images {
		err = errors.Join(err, image.file.Close())
	}
	return err
}
func backendNativeHash(ctx context.Context, file *os.File, size int64) ([32]byte, error) {
	var result [32]byte
	if size <= 0 || size > 16<<20 {
		return result, backendNativeStage("HASH_SIZE", nil)
	}
	h := sha256.New()
	buffer := make([]byte, 32<<10)
	for offset := int64(0); offset < size; {
		if ctx.Err() != nil {
			return result, backendNativeStage("HASH_CONTEXT", ctx.Err())
		}
		n, err := file.ReadAt(buffer[:min(int64(len(buffer)), size-offset)], offset)
		if n <= 0 || err != nil && !errors.Is(err, io.EOF) {
			return result, backendNativeStage("HASH_READ", err)
		}
		_, _ = h.Write(buffer[:n])
		offset += int64(n)
	}
	copy(result[:], h.Sum(nil))
	return result, nil
}
func (r *backendNativeReview) path(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", backendNativeStage("PATH_FORM", nil)
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", backendNativeStage("PATH_RESOLVE", err)
	}
	for _, start := range []string{path, canonical} {
		for current := start; ; current = filepath.Dir(current) {
			info, err := os.Lstat(current)
			if err != nil {
				return "", backendNativeStage("PATH_LSTAT", err)
			}
			st, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				return "", backendNativeStage("PATH_STAT_TYPE", nil)
			}
			if st.Uid != 0 {
				return "", backendNativeStage("PATH_UID", nil)
			}
			if info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0022 != 0 {
				return "", backendNativeStage("PATH_WRITE_MODE", nil)
			}
			link := ""
			if info.Mode()&os.ModeSymlink != 0 {
				link, err = os.Readlink(current)
				if err != nil {
					return "", backendNativeStage("PATH_READLINK", err)
				}
			}
			r.nodes = append(r.nodes, backendNativeNode{path: current, link: link, info: info})
			if current == "/" {
				break
			}
		}
	}
	return canonical, nil
}
func (r *backendNativeReview) image(ctx context.Context, path string) (*backendNativeImage, error) {
	canonical, err := r.path(path)
	if err != nil {
		return nil, err
	}
	for _, image := range r.images {
		if image.path == canonical {
			return image, nil
		}
	}
	if len(r.images) >= 384 {
		return nil, backendNativeStage("IMAGE_COUNT", nil)
	}
	file, err := os.Open(canonical)
	if err != nil {
		return nil, backendNativeStage("IMAGE_OPEN", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, backendNativeStage("IMAGE_STAT", err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 16<<20 || r.bytes+info.Size() > 64<<20 {
		_ = file.Close()
		return nil, backendNativeStage("IMAGE_BOUNDS", nil)
	}
	hash, err := backendNativeHash(ctx, file, info.Size())
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	image := &backendNativeImage{path: canonical, file: file, info: info, hash: hash}
	r.images = append(r.images, image)
	r.bytes += info.Size()
	if pinned, ok := r.profile.pinned[canonical]; ok && hex.EncodeToString(hash[:]) != pinned {
		return nil, backendNativeStage("IMAGE_PIN", nil)
	}
	e, err := elf.NewFile(file)
	if err != nil {
		return nil, backendNativeStage("ELF_OPEN", err)
	}
	defer e.Close()
	machine := elf.EM_X86_64
	if runtime.GOARCH == "arm64" {
		machine = elf.EM_AARCH64
	}
	if e.Class != elf.ELFCLASS64 || e.Data != elf.ELFDATA2LSB || e.Machine != machine || e.Type != elf.ET_DYN && e.Type != elf.ET_EXEC {
		return nil, backendNativeStage("ELF_TARGET", nil)
	}
	for _, section := range e.Sections {
		if section.Type != elf.SHT_NOBITS && (section.Offset > uint64(info.Size()) || section.Size > uint64(info.Size())-section.Offset) || section.Flags&elf.SHF_COMPRESSED != 0 {
			return nil, backendNativeStage("ELF_SECTION_BOUNDS", nil)
		}
		if section.Type == elf.SHT_STRTAB && section.Size > 1<<20 {
			return nil, backendNativeStage("ELF_STRING_BOUNDS", nil)
		}
	}
	for _, program := range e.Progs {
		if program.Off > uint64(info.Size()) || program.Filesz > uint64(info.Size())-program.Off {
			return nil, backendNativeStage("ELF_PROGRAM_BOUNDS", nil)
		}
		if program.Type == elf.PT_INTERP {
			data, err := io.ReadAll(io.LimitReader(program.Open(), 4097))
			if err != nil || len(data) < 2 || len(data) > 4096 || data[len(data)-1] != 0 {
				return nil, backendNativeStage("ELF_INTERPRETER_FORM", err)
			}
			if _, err := r.image(ctx, string(data[:len(data)-1])); err != nil {
				return nil, backendNativeStage("ELF_INTERPRETER", err)
			}
		}
	}
	// Fixture allows only fixed protected search roots; no caller loader flags.
	for _, tag := range []elf.DynTag{elf.DT_RPATH, elf.DT_RUNPATH} {
		paths, err := e.DynString(tag)
		if err != nil {
			return nil, backendNativeStage("ELF_SEARCH_READ", err)
		}
		for _, value := range paths {
			for _, dir := range strings.Split(value, ":") {
				if !slices.Contains(r.profile.dirs, dir) {
					return nil, backendNativeStage("ELF_SEARCH_ROOT", nil)
				}
			}
		}
	}
	needed, err := e.ImportedLibraries()
	if err != nil || len(needed) > 32 {
		return nil, backendNativeStage("ELF_DEPENDENCY_LIST", err)
	}
	for _, name := range needed {
		if name == "" || filepath.Base(name) != name || strings.ContainsAny(name, "\\\x00") {
			return nil, backendNativeStage("ELF_DEPENDENCY_FORM", nil)
		}
		found := ""
		for _, dir := range r.profile.dirs {
			candidate := filepath.Join(dir, name)
			if _, err := os.Lstat(candidate); err == nil {
				found = candidate
				break
			} else if !errors.Is(err, os.ErrNotExist) {
				return nil, backendNativeStage("ELF_DEPENDENCY_LOOKUP", err)
			}
		}
		if found == "" {
			return nil, backendNativeStage("ELF_DEPENDENCY_MISSING", nil)
		}
		if _, err := r.image(ctx, found); err != nil {
			return nil, backendNativeStage("ELF_DEPENDENCY", err)
		}
	}
	return image, nil
}
func (r *backendNativeReview) version(ctx context.Context, index int) error {
	c, cancel := context.WithCancel(ctx)
	defer cancel()
	out := &backendInventoryOutput{limit: 256, onOverflow: cancel}
	command := exec.CommandContext(c, r.profile.aliases[index], "--version")
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	command.Stdout, command.Stderr = out, out
	command.WaitDelay = 100 * time.Millisecond
	if errors.Join(command.Run(), c.Err()) != nil {
		return backendNativeStage("VERSION_EXEC", nil)
	}
	name := []string{"iptables", "ip6tables"}[index]
	if strings.TrimSpace(string(out.data)) != name+" v"+r.profile.version {
		return backendNativeStage("VERSION_VALUE", nil)
	}
	return nil
}
func (r *backendNativeReview) check(ctx context.Context, identity netidentity.Identity) error {
	r.calls++
	if ctx == nil || ctx.Err() != nil || identity.Validate() != nil {
		return backendNativeStage("CHECK_SCOPE", nil)
	}
	for _, node := range r.nodes {
		info, err := os.Lstat(node.path)
		if err != nil || !os.SameFile(info, node.info) || info.Mode() != node.info.Mode() {
			return backendNativeStage("CHECK_PATH_IMAGE", err)
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 {
			return backendNativeStage("CHECK_PATH_UID", nil)
		}
		if node.link != "" {
			link, err := os.Readlink(node.path)
			if err != nil || link != node.link {
				return backendNativeStage("CHECK_PATH_LINK", err)
			}
		}
	}
	for _, image := range r.images {
		current, err := os.Stat(image.path)
		if err != nil || !os.SameFile(current, image.info) || current.Size() != image.info.Size() || current.ModTime() != image.info.ModTime() {
			return backendNativeStage("CHECK_IMAGE_PATH", err)
		}
		held, err := image.file.Stat()
		if err != nil || !os.SameFile(held, current) {
			return backendNativeStage("CHECK_IMAGE_HELD", err)
		}
		hash, err := backendNativeHash(ctx, image.file, current.Size())
		if err != nil {
			return backendNativeStage("CHECK_IMAGE_HASH", err)
		}
		if hash != image.hash {
			return backendNativeStage("CHECK_IMAGE_CHANGED", nil)
		}
	}
	for dir, names := range r.extensionNames {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return backendNativeStage("CHECK_EXTENSION_READ", err)
		}
		var closing []string
		for _, entry := range entries {
			closing = append(closing, entry.Name())
		}
		if !slices.Equal(names, closing) {
			return backendNativeStage("CHECK_EXTENSION_NAMES", nil)
		}
	}
	// A preload file would invalidate this narrow fixture's reviewed loader set.
	for _, path := range []string{"/etc/ld.so.preload", "/opt/etc/ld.so.preload"} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return backendNativeStage("CHECK_PRELOAD", err)
		}
	}
	for i := range r.profile.aliases {
		if err := r.version(ctx, i); err != nil {
			return backendNativeStage([]string{"CHECK_VERSION_V4", "CHECK_VERSION_V6"}[i], err)
		}
	}
	if err := ctx.Err(); err != nil {
		return backendNativeStage("CHECK_CONTEXT", err)
	}
	return nil
}
func backendNativeHeldTools(ctx context.Context, profile backendNativeProfile) (*backendNativeReview, error) {
	r := &backendNativeReview{profile: profile, extensionNames: map[string][]string{}}
	fail := func(err error) (*backendNativeReview, error) { _ = r.close(); return nil, err }
	for i, alias := range profile.aliases {
		image, err := r.image(ctx, alias)
		if err != nil {
			return fail(backendNativeStage([]string{"ALIAS_V4", "ALIAS_V6"}[i], err))
		}
		if hex.EncodeToString(image.hash[:]) != profile.mainSHA {
			return fail(backendNativeStage([]string{"MAIN_PIN_V4", "MAIN_PIN_V6"}[i], nil))
		}
	}
	for path := range profile.pinned {
		if _, err := r.image(ctx, path); err != nil {
			return fail(backendNativeStage("PINNED_IMAGE", err))
		}
	}
	for _, dir := range profile.extensions {
		entries, err := os.ReadDir(dir)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || len(entries) > 256 {
			return fail(backendNativeStage("EXTENSION_LIST", err))
		}
		if _, err := r.path(dir); err != nil {
			return fail(backendNativeStage("EXTENSION_ROOT", err))
		}
		var names []string
		for _, entry := range entries {
			names = append(names, entry.Name())
			if !strings.HasSuffix(entry.Name(), ".so") || entry.IsDir() {
				return fail(backendNativeStage("EXTENSION_ENTRY_FORM", nil))
			}
			if _, err := r.image(ctx, filepath.Join(dir, entry.Name())); err != nil {
				return fail(backendNativeStage("EXTENSION_IMAGE", err))
			}
		}
		r.extensionNames[dir] = names
	}
	if len(r.extensionNames) == 0 {
		return fail(backendNativeStage("EXTENSION_SET_EMPTY", nil))
	}
	return r, nil
}

func TestBackendInventoryFullNativeObservation(t *testing.T) {
	mode := os.Getenv("RAZVILKA_BACKEND_INVENTORY_NATIVE")
	if mode == "" {
		t.Skip("ROOT full collector fixture opt-in disabled")
	}
	if os.Geteuid() != 0 {
		t.Fatal("backend full observation: stage=UID outcome=unknown capability=ungranted")
	}
	profile, err := backendNativeFixtureProfile(mode)
	if err != nil {
		t.Fatal("backend full observation: stage=PROFILE outcome=unknown capability=ungranted")
	}
	setup, cancel := context.WithTimeout(context.Background(), backendInventoryTimeout)
	defer cancel()
	provider := netidentity.NewProcProvider()
	if mode == "stock-nc1812" {
		provider, err = netidentity.NewReviewedStockNC1812Provider(setup)
		if err != nil {
			t.Fatal("backend full observation: stage=PROVIDER outcome=unknown capability=ungranted")
		}
	}
	expected, err := provider.Observe(setup)
	if err != nil {
		t.Fatal("backend full observation: stage=IDENTITY outcome=unknown capability=ungranted")
	}
	review, err := backendNativeHeldTools(setup, profile)
	if err != nil {
		t.Fatalf("backend full observation: stage=TOOLS tool-step=%s setup-deadline-expired=%t outcome=unknown capability=ungranted", backendNativeTrace(err), setup.Err() != nil)
	}
	defer func() {
		if review.close() != nil {
			t.Error("backend full observation: stage=TOOLS_CLOSE outcome=unknown capability=ungranted")
		}
	}()
	tools := BackendInventoryTools{Runner: nfqws2ExecRunner{}, IPTables: profile.aliases[0], IP6Tables: profile.aliases[1], ReviewSHA256: profile.mainSHA, Check: review.check}
	collector, err := NewBackendInventory(provider, tools)
	if mode == "stock-nc1812" {
		collector, err = NewReviewedStockNC1812BackendInventory(provider, tools)
	}
	if err != nil {
		t.Fatal("backend full observation: stage=CONSTRUCTOR outcome=unknown capability=ungranted")
	}
	ctx, stop := context.WithTimeout(context.Background(), backendInventoryTimeout)
	defer stop()
	start := time.Now()
	snapshot, err := collector.Read(ctx, expected)
	if err != nil || ctx.Err() != nil || snapshot.Schema != 1 || snapshot.Scope.Network != expected || !snapshot.Coverage.LegacyRegisteredBothFamilies || !snapshot.Coverage.RegisteredTablesComplete || !snapshot.Coverage.NativeNFTAllFamilies || snapshot.NFTState == BackendNFTUnknown {
		stage := "CAPTURE"
		var staged *backendInventoryFailure
		if errors.As(err, &staged) {
			stage = staged.stage
		}
		t.Fatalf("backend full observation: stage=%s tool-step=%s outcome=unknown elapsed-ms=%d deadline-expired=%t tool-checks=%d capability=ungranted", stage, backendNativeTrace(err), time.Since(start).Milliseconds(), ctx.Err() != nil, review.calls)
	}
	state := "COMPLETE_EMPTY"
	if snapshot.NFTState == BackendNFTPresent {
		state = "PRESENT"
	}
	if snapshot.NFTState == BackendNFTNoRegisteredSubsystemAtCapture {
		state = "NO_REGISTERED_SUBSYSTEM_AT_CAPTURE"
	}
	if (snapshot.RequireComplete() == nil) != (snapshot.NFTState != BackendNFTPresent) {
		t.Fatal("backend full observation: stage=SCHEMA outcome=unknown capability=ungranted")
	}
	t.Logf("backend full observation: mode=%s outcome=validated-full rows=%d nft-tables=%d nft-state=%s complete-coverage=true closing-scope=true elapsed-ms=%d tool-checks=%d capability=ungranted", mode, len(snapshot.Rows), len(snapshot.NFTTables), state, time.Since(start).Milliseconds(), review.calls)
}
