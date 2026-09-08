package updatecheck

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

const maximumExpandedBytes int64 = 512 << 20
const maximumArchiveEntries = 4096

// Download verifies GitHub's authenticated asset digest while streaming to a
// new owned file; no unverified archive content is ever executed.
func Download(ctx context.Context, client *http.Client, asset Asset, root *ownedfs.Root, name string, progress func(int64)) error {
	if !validDigest(asset.Digest) || asset.Size <= 0 || asset.Size > MaximumArchiveBytes {
		return errors.New("asset-size-or-digest-invalid")
	}
	response, err := officialGET(ctx, client, asset.URL)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.ContentLength >= 0 && response.ContentLength != asset.Size {
		return errors.New("asset-length-changed")
	}
	f, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			_ = root.Remove(name)
		}
	}()
	h := sha256.New()
	writer := io.MultiWriter(f, h)
	buffer := make([]byte, 64<<10)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, readErr := response.Body.Read(buffer)
		if n > 0 {
			total += int64(n)
			if total > asset.Size {
				return errors.New("asset-too-large")
			}
			if _, err := writer.Write(buffer[:n]); err != nil {
				return err
			}
			if progress != nil {
				progress(total)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return errors.New("asset-download-interrupted")
		}
	}
	if total != asset.Size || "sha256:"+hex.EncodeToString(h.Sum(nil)) != asset.Digest {
		return errors.New("asset-sha256-mismatch")
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}

// ExtractInstallFiles validates every tar entry and extracts only the fixed
// files used by the transactional installer. Links, traversal, duplicates and
// excessive expanded data are rejected even when the entry would be ignored.
func ExtractInstallFiles(ctx context.Context, root *ownedfs.Root, archive string, release Release) (map[string]string, error) {
	f, err := root.OpenFile(archive, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, errors.New("archive-gzip-invalid")
	}
	defer gz.Close()
	gz.Multistream(false)
	limited := &io.LimitedReader{R: gz, N: maximumExpandedBytes + 1}
	reader := tar.NewReader(limited)
	prefix := "RAZVILKA-" + release.Version + "/"
	required := requiredInstallFiles(release)
	seen := map[string]bool{}
	hashes := map[string]string{}
	for count := 0; ; count++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.New("archive-tar-invalid")
		}
		name := strings.TrimSuffix(header.Name, "/")
		if count >= maximumArchiveEntries || name == "" || strings.ContainsAny(name, "\\\x00\r\n") || path.Clean(name) != name || path.IsAbs(name) || name == ".." || strings.HasPrefix(name, "../") || seen[name] || header.Size < 0 || header.Size > maximumExpandedBytes {
			return nil, errors.New("archive-entry-refused")
		}
		seen[name] = true
		if name != strings.TrimSuffix(prefix, "/") && !strings.HasPrefix(name, prefix) {
			return nil, errors.New("archive-root-refused")
		}
		if header.Typeflag == tar.TypeDir {
			continue
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			return nil, errors.New("archive-link-or-special-entry")
		}
		rel := strings.TrimPrefix(name, prefix)
		maximum, wanted := required[rel]
		if !wanted {
			continue
		}
		if header.Size <= 0 || header.Size > maximum {
			return nil, errors.New("archive-file-size-refused")
		}
		destination := filepath.Join("bundle", filepath.FromSlash(rel))
		if err := root.MkdirAll(filepath.Dir(destination), 0700); err != nil {
			return nil, err
		}
		out, err := root.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		h := sha256.New()
		_, copyErr := io.Copy(io.MultiWriter(out, h), reader)
		syncErr := out.Sync()
		closeErr := out.Close()
		if copyErr != nil || syncErr != nil || closeErr != nil {
			return nil, errors.New("archive-write-failed")
		}
		hashes[rel] = hex.EncodeToString(h.Sum(nil))
	}
	if limited.N <= 0 {
		return nil, errors.New("archive-expanded-limit")
	}
	if _, err := io.Copy(io.Discard, limited); err != nil || limited.N <= 0 {
		return nil, errors.New("archive-gzip-footer-or-limit")
	}
	for name := range required {
		if hashes[name] == "" {
			return nil, errors.New("archive-required-file-missing")
		}
	}
	binaryHash := hashes["dist/"+release.Binary.Name]
	if "sha256:"+binaryHash != release.Binary.Digest {
		return nil, errors.New("archive-binary-digest-mismatch")
	}
	bin, err := root.OpenFile("bundle/dist/"+release.Binary.Name, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	info, statErr := bin.Stat()
	image, elfErr := elf.NewFile(bin)
	if statErr != nil || info.Size() != release.Binary.Size || elfErr != nil {
		bin.Close()
		return nil, errors.New("binary-architecture-invalid")
	}
	valid := release.Architecture == "arm64" && image.Machine == elf.EM_AARCH64 && image.Class == elf.ELFCLASS64 && image.Data == elf.ELFDATA2LSB || release.Architecture == "amd64" && image.Machine == elf.EM_X86_64 && image.Class == elf.ELFCLASS64 && image.Data == elf.ELFDATA2LSB || release.Architecture == "mips" && image.Machine == elf.EM_MIPS && image.Class == elf.ELFCLASS32 && image.Data == elf.ELFDATA2MSB || release.Architecture == "mipsle" && image.Machine == elf.EM_MIPS && image.Class == elf.ELFCLASS32 && image.Data == elf.ELFDATA2LSB
	bin.Close()
	if !valid {
		return nil, errors.New("binary-architecture-invalid")
	}
	manifest, err := root.ReadLimited("bundle/dist/SHA256SUMS", 64<<10)
	if err != nil {
		return nil, err
	}
	found := false
	scanner := bufio.NewScanner(strings.NewReader(string(manifest)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 {
			continue
		}
		name := strings.TrimPrefix(strings.TrimPrefix(fields[1], "*"), "dist/")
		if name == release.Binary.Name {
			if found || fields[0] != binaryHash {
				return nil, errors.New("binary-manifest-mismatch")
			}
			found = true
		}
	}
	if scanner.Err() != nil || !found {
		return nil, errors.New("binary-manifest-missing")
	}
	return hashes, nil
}

func requiredInstallFiles(release Release) map[string]int64 {
	return map[string]int64{"scripts/upgrade-entware.sh": 256 << 10, "scripts/rollback-entware.sh": 256 << 10, "scripts/S99razvilka": 256 << 10, "configs/service-catalog.json": 2 << 20, "configs/community-catalog.json": 2 << 20, "configs/sources.json": 2 << 20, "configs/config.example.json": 2 << 20, "dist/SHA256SUMS": 64 << 10, "dist/" + release.Binary.Name: MaximumBinaryBytes}
}

func VerifyExtracted(root *ownedfs.Root, hashes map[string]string, release Release) error {
	required := requiredInstallFiles(release)
	if len(hashes) != 9 || release.Binary.Name != "razvilka-linux-"+release.Architecture || hashes["dist/"+release.Binary.Name] != strings.TrimPrefix(release.Binary.Digest, "sha256:") {
		return errors.New("prepared-files-invalid")
	}
	for name, expected := range hashes {
		maximum, ok := required[name]
		if !ok || len(expected) != 64 {
			return errors.New("prepared-files-invalid")
		}
		f, err := root.OpenFile(filepath.Join("bundle", filepath.FromSlash(name)), os.O_RDONLY, 0)
		if err != nil {
			return err
		}
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() > maximum {
			f.Close()
			return errors.New("prepared-file-invalid")
		}
		h := sha256.New()
		_, err = io.Copy(h, io.LimitReader(f, MaximumBinaryBytes+1))
		f.Close()
		if err != nil || hex.EncodeToString(h.Sum(nil)) != expected {
			return errors.New("prepared-file-changed")
		}
	}
	return nil
}
