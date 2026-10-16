package strategylab

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

var ErrNFQWSDomainMaterial = errors.New("original CORE NFQ domain material unavailable or changed")

// Files alone grant no compatibility, queue, scope or execution permission.
type nfqDomainFiles struct {
	self             *nfqDomainFiles
	path             string
	include, exclude compatibilityFileBinding
	infos            [2]os.FileInfo
	parent, anchor   os.FileInfo
	root             *ownedfs.Root
	files            [2]*os.File
	images           [2][]byte
	closed           bool
}

func newNFQDomainFiles(parent string, include, exclude []string) (*nfqDomainFiles, error) {
	positive, err := nfqDomainNames(include, false)
	if err != nil {
		return nil, err
	}
	negative, err := nfqDomainNames(exclude, true)
	if err != nil {
		return nil, err
	}
	remaining := false
	for _, name := range positive {
		covered := false
		for _, no := range negative {
			covered = covered || name == no || strings.HasSuffix(name, "."+no)
		}
		remaining = remaining || !covered
	}
	if !remaining || !compatibilityCleanPath(parent) {
		return nil, ErrNFQWSDomainMaterial
	}
	info, err := os.Lstat(parent)
	if err != nil || !nfqDomainPrivateDirectory(info) {
		return nil, ErrNFQWSDomainMaterial
	}
	nonce, err := compatibilityNonce()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(parent, "nfq-domain-"+nonce)
	if err := os.Mkdir(path, 0700); err != nil {
		return nil, err
	}
	root, err := ownedfs.Open(path)
	if err != nil {
		return nil, err
	}
	f := &nfqDomainFiles{path: path, root: root, parent: info}
	f.self = f
	keep := false
	defer func() {
		if !keep {
			_ = f.close()
		}
	}()
	f.anchor, err = root.RootInfo()
	if err != nil {
		return nil, err
	}
	f.images = [2][]byte{nfqDomainImage("INCLUDE", positive), nfqDomainImage("EXCLUDE", negative)}
	for i, name := range []string{"include.list", "exclude.list"} {
		writer, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		_, writeErr := writer.Write(f.images[i])
		err = errors.Join(writeErr, writer.Chmod(0400), writer.Sync(), writer.Close())
		if err != nil {
			return nil, err
		}
		f.files[i], err = root.OpenFile(name, nfqDomainReadFlags(), 0)
		if err != nil {
			return nil, err
		}
		f.infos[i], err = f.files[i].Stat()
		if err != nil {
			return nil, err
		}
		binding := compatibilityFileBinding{Path: filepath.Join(path, name), Size: int64(len(f.images[i]))}
		binding.SHA256, _ = nfqDomainHash(f.images[i])
		if i == 0 {
			f.include = binding
		} else {
			f.exclude = binding
		}
	}
	var syncErr error
	if runtime.GOOS != "windows" {
		syncErr = root.Sync()
	}
	if err := errors.Join(syncErr, f.current()); err != nil {
		return nil, err
	}
	keep = true
	return f, nil
}

func nfqDomainNames(raw []string, empty bool) ([]string, error) {
	if len(raw) > 256 || !empty && len(raw) == 0 {
		return nil, ErrNFQWSDomainMaterial
	}
	names := slices.Clone(raw)
	for _, name := range names {
		canonical, err := config.PolicyDomain(name)
		_, ipErr := netip.ParseAddr(name)
		if err != nil || canonical != name || !strings.Contains(name, ".") || ipErr == nil || len(name) > 253 || strings.ContainsAny(name, "^*#/;\r\n\x00\t ") {
			return nil, ErrNFQWSDomainMaterial
		}
	}
	slices.Sort(names)
	return slices.Compact(names), nil
}

func nfqDomainImage(kind string, names []string) []byte {
	image := "# RAZVILKA CORE NFQ " + kind + " V1\n"
	if len(names) > 0 {
		image += strings.Join(names, "\n") + "\n"
	}
	return []byte(image)
}

func nfqDomainPrivateDirectory(info os.FileInfo) bool {
	return info != nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 && (runtime.GOOS == "windows" || info.Mode().Perm()&0077 == 0)
}

func (f *nfqDomainFiles) current() error {
	if f == nil || f.self != f || f.closed || f.root == nil {
		return ErrNFQWSDomainMaterial
	}
	checkRoots := func() error {
		parent, err := os.Lstat(filepath.Dir(f.path))
		anchor, heldErr := f.root.RootInfo()
		current, pathErr := os.Lstat(f.path)
		if err != nil || heldErr != nil || pathErr != nil || !nfqDomainPrivateDirectory(parent) || !nfqDomainPrivateDirectory(current) || !os.SameFile(parent, f.parent) || !os.SameFile(anchor, f.anchor) || !os.SameFile(current, f.anchor) {
			return ErrNFQWSDomainMaterial
		}
		return nil
	}
	if err := checkRoots(); err != nil {
		return err
	}
	for i, name := range []string{"include.list", "exclude.list"} {
		if f.files[i] == nil || f.infos[i] == nil {
			return ErrNFQWSDomainMaterial
		}
		before, err := f.root.Stat(name)
		held, heldErr := f.files[i].Stat()
		if err != nil || heldErr != nil || !before.Mode().IsRegular() || !os.SameFile(before, f.infos[i]) || !os.SameFile(held, f.infos[i]) || before.Size() != int64(len(f.images[i])) || runtime.GOOS != "windows" && before.Mode().Perm() != 0400 {
			return ErrNFQWSDomainMaterial
		}
		data, err := io.ReadAll(io.NewSectionReader(f.files[i], 0, int64(len(f.images[i]))+1))
		after, statErr := f.root.Stat(name)
		if err != nil || statErr != nil || !bytes.Equal(data, f.images[i]) || !os.SameFile(after, before) || after.Size() != before.Size() || after.Mode() != before.Mode() {
			return ErrNFQWSDomainMaterial
		}
	}
	entries, err := f.root.ReadDir(3)
	if err != nil || len(entries) != 2 {
		return ErrNFQWSDomainMaterial
	}
	for _, entry := range entries {
		if entry.Name() != "include.list" && entry.Name() != "exclude.list" {
			return ErrNFQWSDomainMaterial
		}
	}
	return checkRoots()
}

func (f *nfqDomainFiles) close() error {
	if f == nil {
		return nil
	}
	if f.self != f {
		return ErrNFQWSDomainMaterial
	}
	if f.closed {
		return nil
	}
	f.closed = true
	var err error
	for _, file := range f.files {
		if file != nil {
			err = errors.Join(err, file.Close())
		}
	}
	if f.root != nil {
		err = errors.Join(err, f.root.Close())
	}
	return err
}

func (f *nfqDomainFiles) arguments(candidate []string) ([]string, error) {
	if err := f.current(); err != nil {
		return nil, err
	}
	if err := nfqDomainCandidate(candidate); err != nil {
		return nil, err
	}
	return append(slices.Clone(candidate), nfqDomainArguments(f.include.Path, f.exclude.Path)...), nil
}

func nfqDomainCandidate(candidate []string) error {
	if ExportableArguments(strings.Join(candidate, " ")) != nil {
		return ErrNFQWSDomainMaterial
	}
	parsed, err := parseArguments(strings.Join(candidate, " "))
	if err != nil || !slices.Equal(parsed, candidate) {
		return ErrNFQWSDomainMaterial
	}
	filters, strategies := 0, 0
	for _, arg := range candidate {
		if arg == "--filter-tcp=443" {
			filters++
			continue
		}
		value, ok := strings.CutPrefix(arg, "--lua-desync=")
		if !ok {
			return ErrNFQWSDomainMaterial
		}
		kind, _, _ := strings.Cut(value, ":")
		if kind != "fake" && kind != "multisplit" && kind != "hostfakesplit" {
			return ErrNFQWSDomainMaterial
		}
		strategies++
	}
	if filters != 1 || strategies == 0 || strategies > 8 {
		return ErrNFQWSDomainMaterial
	}
	return nil
}

func nfqDomainArguments(include, exclude string) []string {
	return []string{"--reasm-disable=tls_client_hello", "--fastpath-workaround=0", "--ipcache-hostname=0", "--hostlist=" + include, "--hostlist-exclude=" + exclude}
}

func nfqDomainHash(data []byte) (string, error) {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}
