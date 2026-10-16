package strategylab

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Capture byte identity only after owner review. Hashing a file does not grant
// provenance; the production helper separately checks protected Linux paths.
func compatibilityFileBindingAt(path string, limit int64) (compatibilityFileBinding, error) {
	var result compatibilityFileBinding
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || limit <= 0 {
		return result, errors.New("compatibility file requires a clean absolute path")
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > limit {
		return result, errors.New("compatibility file is missing, unsafe or exceeds its bound")
	}
	f, err := os.Open(path)
	if err != nil {
		return result, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return result, errors.New("compatibility file changed while opening")
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(f, limit+1))
	if err != nil || n != opened.Size() || n > limit {
		return result, errors.New("compatibility file changed while hashing")
	}
	after, err := f.Stat()
	current, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || !current.Mode().IsRegular() || !os.SameFile(opened, current) || after.Size() != opened.Size() || !after.ModTime().Equal(opened.ModTime()) {
		return result, errors.New("compatibility file identity changed while hashing")
	}
	return compatibilityFileBinding{Path: path, SHA256: hex.EncodeToString(hash.Sum(nil)), Size: n}, nil
}

func compatibilityCaptureFiles(binary string, base []string) (compatibilityFileBinding, []compatibilityFileBinding, error) {
	if _, err := compatibilityAssertions(base, []string{"--lua-desync=fake:blob=0x00000000"}); err != nil {
		return compatibilityFileBinding{}, nil, err
	}
	program, err := compatibilityFileBindingAt(binary, 64<<20)
	if err != nil {
		return program, nil, err
	}
	seen := map[string]bool{}
	assets := []compatibilityFileBinding{}
	for _, arg := range base {
		var path string
		if strings.HasPrefix(arg, "--lua-init=@") {
			path = strings.TrimPrefix(arg, "--lua-init=@")
		} else {
			_, path, _ = strings.Cut(arg, ":@")
		}
		if seen[path] {
			continue
		}
		seen[path] = true
		binding, err := compatibilityFileBindingAt(path, 4<<20)
		if err != nil {
			return program, nil, err
		}
		assets = append(assets, binding)
	}
	if len(assets) > 16 {
		return program, nil, errors.New("too many compatibility assets")
	}
	return program, assets, nil
}

func compatibilityFilesUnchanged(review compatibilityReview) error {
	program, assets, err := compatibilityCaptureFiles(review.Binary.Path, review.BaseArguments)
	if err != nil || program != review.Binary || len(assets) != len(review.Assets) {
		return errors.New("reviewed compatibility binary/assets changed")
	}
	for i := range assets {
		if assets[i] != review.Assets[i] {
			return errors.New("reviewed compatibility asset bytes changed")
		}
	}
	if review.Domain != nil {
		return compatibilityDomainFilesCurrent(*review.Domain)
	}
	return nil
}
