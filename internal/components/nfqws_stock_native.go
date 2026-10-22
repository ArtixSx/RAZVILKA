package components

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

var ErrStockNFQWSNative = errors.New("stock NFQWS2 native parameter review unavailable or changed")
var ErrStockNFQWSVersion = errors.New("stock NFQWS2 wrapper version is unsupported for native parameter validation")
var ErrStockNFQWSInit = errors.New("stock NFQWS2 init script is unsupported for native parameter validation")

// Exact read-only nfqws2-keenetic 1.3.1 router snapshot: its _startup_args is
// the assembly modeled by engineconfig. A version label cannot certify an
// edited init. Only the deterministic three-UDP-guard + inert-dispatch edit may be
// reconstructed to this exact stock SHA for parameter review. That recognises
// bytes, not the dataplane lease/permission needed before any shell action.
const stockNFQWSInitSHA256 = "3c3edefdab45e1f9f7db7a9c28dae2e3c18cf6b50547045d16c7de7cbad4dacc"

type stockNFQWSFile struct {
	root   *ownedfs.Root
	file   *os.File
	name   string
	info   os.FileInfo
	hash   [32]byte
	size   int64
	dir    string
	parent os.FileInfo
}

// StockNFQWSNativeReview is a no-interception PARAMETER CHECK owner. It is
// deliberately not a ManagedNFQWSRuntimeLease, Lua approval, packet proof or
// Start permission. It retains the component writer and exact installed files
// for one dry-run; a detached hash/DTO cannot construct or reuse this owner.
type StockNFQWSNativeReview struct {
	self                       *StockNFQWSNativeReview
	manager                    *Manager
	tx                         *updateTransaction
	runner                     Runner
	mu                         sync.Mutex
	files                      []*stockNFQWSFile
	absent                     []string
	binary                     string
	initDir, infoDir, stateDir string
	arguments                  []string
	ownedInitOwner             string
	closed, used               bool
}

func (*StockNFQWSNativeReview) String() string { return "[stock NFQWS2 parameter review]" }

// ReviewStockNFQWSNative uses this actual component Manager's installed opkg
// layout and existing writer fence. 1.3.1's postinst relocates a multiarch
// executable; it does NOT list /opt/usr/bin/nfqws2 as a directly owned entry.
// The control/list/postinst record and actual relocated bytes are all retained.
// There are no package checksums in that wrapper: this is local installation
// ownership/currentness, not a claim of signed upstream provenance.
func (m *Manager) ReviewStockNFQWSNative(ctx context.Context, arguments []string) (*StockNFQWSNativeReview, error) {
	if m == nil || ctx == nil || ctx.Err() != nil || m.StateDir == "" || m.Runner == nil || len(arguments) == 0 || len(arguments) > 256 || len(strings.Join(arguments, " ")) > 48<<10 {
		return nil, ErrStockNFQWSNative
	}
	prefix := filepath.Dir(filepath.Dir(filepath.Clean(m.InitDir)))
	infoDir := defaultValue(m.InfoDir, "/opt/lib/opkg/info")
	if !filepath.IsAbs(prefix) || prefix == filepath.VolumeName(prefix)+string(filepath.Separator) || filepath.Join(prefix, "etc", "init.d") != filepath.Clean(m.InitDir) || filepath.Join(prefix, "lib", "opkg", "info") != filepath.Clean(infoDir) {
		return nil, ErrStockNFQWSNative
	}
	tx, err := m.lockUpdateJournal()
	if err != nil {
		return nil, err
	}
	r := &StockNFQWSNativeReview{manager: m, tx: tx, runner: m.Runner, binary: filepath.Join(prefix, "usr", "bin", "nfqws2"), arguments: slices.Clone(arguments), initDir: m.InitDir, infoDir: m.InfoDir, stateDir: m.StateDir}
	r.self = r
	keep := false
	defer func() {
		if !keep {
			_ = r.Close()
		}
	}()
	if err = tx.requireIdle(); err != nil {
		return nil, err
	}
	control, err := r.capture(filepath.Join(infoDir, "nfqws2-keenetic.control"), 64<<10)
	if err != nil {
		return nil, err
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(control), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok {
			if _, duplicate := fields[key]; duplicate {
				return nil, ErrStockNFQWSNative
			}
			fields[key] = strings.TrimSpace(value)
		}
	}
	if fields["Package"] != "nfqws2-keenetic" {
		return nil, ErrStockNFQWSNative
	}
	if fields["Version"] != "1.3.1" {
		return nil, ErrStockNFQWSVersion
	}
	list, err := r.capture(filepath.Join(infoDir, "nfqws2-keenetic.list"), 64<<10)
	if err != nil {
		return nil, err
	}
	listed := map[string]bool{}
	for _, line := range strings.Split(string(list), "\n") {
		listed[strings.TrimSpace(line)] = true
	}
	if !listed["/opt/etc/init.d/S51nfqws2"] || !listed["/opt/etc/nfqws2/nfqws2.conf"] {
		return nil, ErrStockNFQWSNative
	}
	postinst, err := r.capture(filepath.Join(infoDir, "nfqws2-keenetic.postinst"), 64<<10)
	if err != nil {
		return nil, err
	}
	if !strings.Contains(string(postinst), `BINFILE="/opt/usr/bin/nfqws2"`) || !strings.Contains(string(postinst), `cp -f "/opt/tmp/nfqws2_binary/nfqws2-$ARCH" "$BINFILE"`) {
		return nil, ErrStockNFQWSNative
	}
	hasBinary := false
	for name := range listed {
		if strings.HasPrefix(name, "/opt/tmp/nfqws2_binary/nfqws2-") {
			hasBinary = true
		}
	}
	if !hasBinary {
		return nil, ErrStockNFQWSNative
	}
	if _, err = r.capture(r.binary, 64<<20); err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" && r.files[len(r.files)-1].info.Mode().Perm()&0111 == 0 {
		return nil, ErrStockNFQWSNative
	}
	init, err := r.capture(filepath.Join(m.InitDir, "S51nfqws2"), 128<<10)
	if err != nil {
		return nil, err
	}
	initHash := sha256.Sum256(init)
	if hex.EncodeToString(initHash[:]) != stockNFQWSInitSHA256 {
		owner, err := engineconfig.NFQWSFirstStartInitOwner(init)
		if err != nil {
			return nil, ErrStockNFQWSInit
		}
		original, err := engineconfig.NFQWSFirstStartOriginalInit(init, owner)
		if err != nil {
			return nil, ErrStockNFQWSInit
		}
		originalHash := sha256.Sum256(original)
		if hex.EncodeToString(originalHash[:]) != stockNFQWSInitSHA256 {
			return nil, ErrStockNFQWSInit
		}
	}
	// No shell/config is executed here. Only package-listed file-backed Lua
	// declarations are admitted; inline Lua and arbitrary expert scripts refuse.
	seen := map[string]bool{}
	for _, arg := range arguments {
		if !strings.HasPrefix(arg, "--") || strings.ContainsAny(arg, "\x00\r\n") {
			return nil, ErrStockNFQWSNative
		}
		name, _, _ := strings.Cut(arg, "=")
		switch name {
		case "--dry-run", "--intercept", "--daemon", "--pidfile", "--debug":
			return nil, ErrStockNFQWSNative
		}
		path := ""
		if strings.HasPrefix(arg, "--lua-init=") {
			var ok bool
			path, ok = strings.CutPrefix(arg, "--lua-init=@")
			if !ok {
				return nil, ErrStockNFQWSNative
			}
		}
		if strings.HasPrefix(arg, "--blob=") {
			_, path, _ = strings.Cut(arg, ":@")
		}
		if path == "" {
			continue
		}
		if !filepath.IsAbs(path) || filepath.ToSlash(filepath.Clean(path)) != filepath.ToSlash(path) {
			return nil, ErrStockNFQWSNative
		}
		path = filepath.Clean(path)
		rel, err := filepath.Rel(prefix, path)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil, ErrStockNFQWSNative
		}
		packagePath := "/opt/" + filepath.ToSlash(rel)
		if !listed[packagePath] && !listed[packagePath+".gz"] {
			return nil, ErrStockNFQWSNative
		}
		if seen[path] {
			continue
		}
		seen[path] = true
		if _, err = os.Lstat(path); errors.Is(err, os.ErrNotExist) && listed[packagePath+".gz"] {
			r.absent = append(r.absent, path)
			path += ".gz"
		} else if err != nil {
			return nil, ErrStockNFQWSNative
		}
		if _, err = r.capture(path, 8<<20); err != nil {
			return nil, err
		}
	}
	if err = r.current(ctx); err != nil {
		return nil, err
	}
	keep = true
	return r, nil
}

func (r *StockNFQWSNativeReview) capture(path string, limit int64) ([]byte, error) {
	root, err := ownedfs.Open(filepath.Dir(path))
	if err != nil {
		return nil, ErrStockNFQWSNative
	}
	name := filepath.Base(path)
	f, err := root.OpenFile(name, os.O_RDONLY|updateFileFlags(), 0)
	if err != nil {
		root.Close()
		return nil, ErrStockNFQWSNative
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit || runtime.GOOS != "windows" && info.Mode().Perm()&0022 != 0 {
		f.Close()
		root.Close()
		return nil, ErrStockNFQWSNative
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) != info.Size() {
		f.Close()
		root.Close()
		return nil, ErrStockNFQWSNative
	}
	parent, err := root.RootInfo()
	if err != nil || runtime.GOOS != "windows" && parent.Mode().Perm()&0022 != 0 {
		f.Close()
		root.Close()
		return nil, ErrStockNFQWSNative
	}
	r.files = append(r.files, &stockNFQWSFile{root: root, file: f, name: name, info: info, hash: sha256.Sum256(data), size: info.Size(), dir: filepath.Dir(path), parent: parent})
	return data, nil
}

func (r *StockNFQWSNativeReview) current(ctx context.Context) error {
	if r == nil || r.self != r || r.closed || ctx == nil || ctx.Err() != nil || r.tx == nil || r.tx.requireIdle() != nil {
		return ErrStockNFQWSNative
	}
	if r.manager == nil || r.manager.InitDir != r.initDir || r.manager.InfoDir != r.infoDir || r.manager.StateDir != r.stateDir {
		return ErrStockNFQWSNative
	}
	for _, path := range r.absent {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return ErrStockNFQWSNative
		}
	}
	for _, binding := range r.files {
		parent, err := os.Lstat(binding.dir)
		if err != nil || !parent.IsDir() || !os.SameFile(parent, binding.parent) || parent.Mode() != binding.parent.Mode() {
			return ErrStockNFQWSNative
		}
		if r.ownedInitOwner != "" && binding.dir == r.initDir && binding.name == "S51nfqws2" {
			if err := r.currentOwnedInit(binding); err != nil {
				return err
			}
			continue
		}
		info, err := binding.root.Stat(binding.name)
		if err != nil || !os.SameFile(info, binding.info) || info.Size() != binding.size || info.Mode() != binding.info.Mode() || binding.root.Check(binding.name) != nil {
			return ErrStockNFQWSNative
		}
		if _, err = binding.file.Seek(0, io.SeekStart); err != nil {
			return ErrStockNFQWSNative
		}
		h := sha256.New()
		n, err := io.Copy(h, io.LimitReader(binding.file, binding.size+1))
		if err != nil || n != binding.size || !slices.Equal(h.Sum(nil), binding.hash[:]) {
			return ErrStockNFQWSNative
		}
	}
	return nil
}

// DryRun always fixes no-effect mode itself. It never performs the separate
// intercept=0 Lua-init phase and never returns a receipt that can authorize it.
func (r *StockNFQWSNativeReview) DryRun(ctx context.Context) error {
	if r == nil {
		return ErrStockNFQWSNative
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.used || r.current(ctx) != nil {
		return ErrStockNFQWSNative
	}
	r.used = true
	_, runErr := r.runner.Run(ctx, r.binary, append([]string{"--dry-run", "--intercept=0"}, r.arguments...)...)
	if err := r.current(ctx); err != nil {
		return err
	}
	if runErr != nil {
		return errors.New("stock NFQWS2 native parameters rejected")
	}
	return nil
}

// CheckCurrent rechecks the same retained files and original component writer.
// It grants no launch permission and cannot be recreated from detached hashes;
// a consumer must keep this actual review open across its bounded operation.
func (r *StockNFQWSNativeReview) CheckCurrent(ctx context.Context) error {
	if r == nil {
		return ErrStockNFQWSNative
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.current(ctx)
}

// CheckCurrentWithOwnedInit permits only the fixed reversible three-UDP-guard
// and inert-dispatch edit for this original owner's init. Binary/Lua/package files
// and component writer remain retained. This is currentness, not Start authority.
func (r *StockNFQWSNativeReview) CheckCurrentWithOwnedInit(ctx context.Context, owner string) error {
	if r == nil {
		return ErrStockNFQWSNative
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.bindOwnedInit(owner); err != nil {
		return err
	}
	return r.current(ctx)
}

func (r *StockNFQWSNativeReview) bindOwnedInit(owner string) error {
	if r.self != r || r.closed || r.ownedInitOwner != "" && r.ownedInitOwner != owner {
		return ErrStockNFQWSNative
	}
	for _, binding := range r.files {
		if binding.dir == r.initDir && binding.name == "S51nfqws2" {
			data, err := stockNFQWSReadRetained(binding)
			if err != nil {
				return err
			}
			original, err := stockNFQWSOriginalInit(data)
			if err != nil {
				return ErrStockNFQWSInit
			}
			if _, err := engineconfig.NFQWSFirstStartInit(original, owner); err != nil {
				return ErrStockNFQWSInit
			}
			r.ownedInitOwner = owner
			return nil
		}
	}
	return ErrStockNFQWSInit
}

func stockNFQWSReadRetained(binding *stockNFQWSFile) ([]byte, error) {
	if _, err := binding.file.Seek(0, io.SeekStart); err != nil {
		return nil, ErrStockNFQWSNative
	}
	data, err := io.ReadAll(io.LimitReader(binding.file, binding.size+1))
	if err != nil || int64(len(data)) != binding.size || sha256.Sum256(data) != binding.hash {
		return nil, ErrStockNFQWSNative
	}
	return data, nil
}

// A retired inert script can belong to a former instance. Recognise its
// actual exact deterministic bytes before considering another owner; a marker
// alone never grants ownership or permits the coordinator's later mutation.
func stockNFQWSOriginalInit(data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	if hex.EncodeToString(hash[:]) == stockNFQWSInitSHA256 {
		return slices.Clone(data), nil
	}
	beforeOwner, err := engineconfig.NFQWSFirstStartInitOwner(data)
	if err != nil {
		return nil, ErrStockNFQWSInit
	}
	original, err := engineconfig.NFQWSFirstStartOriginalInit(data, beforeOwner)
	if err != nil {
		return nil, ErrStockNFQWSInit
	}
	hash = sha256.Sum256(original)
	if hex.EncodeToString(hash[:]) != stockNFQWSInitSHA256 {
		return nil, ErrStockNFQWSInit
	}
	return original, nil
}

func (r *StockNFQWSNativeReview) currentOwnedInit(binding *stockNFQWSFile) error {
	prior, err := stockNFQWSReadRetained(binding)
	if err != nil {
		return err
	}
	original, err := stockNFQWSOriginalInit(prior)
	if err != nil {
		return ErrStockNFQWSInit
	}
	hash := sha256.Sum256(original)
	if hex.EncodeToString(hash[:]) != stockNFQWSInitSHA256 {
		return ErrStockNFQWSInit
	}
	guarded, err := engineconfig.NFQWSFirstStartInit(original, r.ownedInitOwner)
	if err != nil {
		return ErrStockNFQWSInit
	}
	f, err := binding.root.OpenFile(binding.name, os.O_RDONLY|updateFileFlags(), 0)
	if err != nil {
		return ErrStockNFQWSNative
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode() != binding.info.Mode() || info.Size() > 128<<10 {
		return ErrStockNFQWSNative
	}
	data, err := io.ReadAll(io.LimitReader(f, (128<<10)+1))
	if err != nil || int64(len(data)) != info.Size() || !bytes.Equal(data, prior) && !bytes.Equal(data, guarded) {
		return ErrStockNFQWSInit
	}
	actual, err := binding.root.Stat(binding.name)
	if err != nil || !os.SameFile(info, actual) || binding.root.Check(binding.name) != nil {
		return ErrStockNFQWSNative
	}
	return nil
}

// ReviewClosedFirstStartParameters validates the canonical closed config for
// another exact domain/exclusion image (including rollback) through the SAME
// original binary and assets. Only the three inline lists may differ from the
// original reviewed argv; nothing is reacquired from a changed installation.
func (r *StockNFQWSNativeReview) ReviewClosedFirstStartParameters(ctx context.Context, config []byte, owner string) error {
	if r == nil || ctx == nil {
		return ErrStockNFQWSNative
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.bindOwnedInit(owner); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := r.current(ctx); err != nil {
		return err
	}
	effective, err := engineconfig.NFQWSFirstStartEffectiveConfig(config, owner)
	if err != nil {
		return err
	}
	args, err := engineconfig.NFQWSStartupArguments(effective, nil)
	if err != nil {
		return err
	}
	lists, _, err := stockNFQWSClosedInlineArguments(args)
	if err != nil {
		return err
	}
	original, err := engineconfig.NFQWSFirstStartOriginalConfig(config, owner)
	if err != nil {
		return err
	}
	canonical, err := engineconfig.NFQWSFirstStartConfig(original, owner, lists["--hostlist-domains"], lists["--hostlist-exclude-domains"], lists["--ipset-exclude-ip"])
	if err != nil || !bytes.Equal(canonical, config) {
		return ErrStockNFQWSNative
	}
	return r.reviewClosedFirstStartArguments(ctx, args)
}

func stockNFQWSClosedInlineArguments(arguments []string) (map[string][]string, []string, error) {
	lists := map[string][]string{}
	fixed := []string{}
	for _, arg := range arguments {
		flag, value, _ := strings.Cut(arg, "=")
		switch flag {
		case "--hostlist-domains", "--hostlist-exclude-domains", "--ipset-exclude-ip":
			if _, exists := lists[flag]; exists || value == "" {
				return nil, nil, ErrStockNFQWSNative
			}
			lists[flag] = strings.Split(value, ",")
		default:
			fixed = append(fixed, arg)
		}
	}
	if len(lists["--hostlist-domains"]) == 0 {
		return nil, nil, ErrStockNFQWSNative
	}
	return lists, fixed, nil
}

// Caller holds the original review mutex, and canonical config recognition
// above has already established the inline values. This also supports a
// relocated private test model without misbinding /opt assets to other files.
func (r *StockNFQWSNativeReview) reviewClosedFirstStartArguments(ctx context.Context, args []string) error {
	_, originalFixed, err := stockNFQWSClosedInlineArguments(r.arguments)
	if err != nil {
		return err
	}
	_, candidateFixed, err := stockNFQWSClosedInlineArguments(args)
	if err != nil || !slices.Equal(originalFixed, candidateFixed) {
		return ErrStockNFQWSNative
	}
	if err := r.current(ctx); err != nil {
		return err
	}
	_, runErr := r.runner.Run(ctx, r.binary, append([]string{"--dry-run", "--intercept=0"}, args...)...)
	if err := r.current(ctx); err != nil {
		return err
	}
	if runErr != nil {
		return errors.New("stock NFQWS2 native parameters rejected")
	}
	return nil
}

func (r *StockNFQWSNativeReview) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.self != r {
		return ErrStockNFQWSNative
	}
	if r.closed {
		return nil
	}
	r.closed = true
	var err error
	for _, binding := range r.files {
		err = errors.Join(err, binding.file.Close(), binding.root.Close())
	}
	if r.tx != nil {
		r.tx.close()
		r.tx = nil
	}
	return err
}
