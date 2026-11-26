package strategylab

import (
	"crypto/ed25519"
	"io"
	"os"
)

// LoadPackKeys only reads an owner-provisioned public-key file. A package is
// never allowed to provide its own root of trust. No keys means no signed import.
func LoadPackKeys(path string) (map[string]ed25519.PublicKey, error) {
	if path == "" {
		return nil, nil
	}
	before, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !before.Mode().IsRegular() || before.Mode().Perm()&0022 != 0 || before.Size() > 16384 {
		return nil, ErrPack
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	after, e := f.Stat()
	if e != nil || !os.SameFile(before, after) {
		return nil, ErrPack
	}
	data, e := io.ReadAll(io.LimitReader(f, 16385))
	if e != nil || len(data) > 16384 {
		return nil, ErrPack
	}
	var keys map[string]ed25519.PublicKey
	if strictPackJSON(data, &keys) != nil || len(keys) == 0 || len(keys) > 16 {
		return nil, ErrPack
	}
	for id, key := range keys {
		if !packID.MatchString(id) || len(key) != ed25519.PublicKeySize {
			return nil, ErrPack
		}
	}
	return keys, nil
}
