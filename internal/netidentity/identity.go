// Package netidentity observes network scope. An Identity is a binding, never
// backend completeness, process ownership, or permission to perform effects.
package netidentity

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

const Version = 1

type Kind string

const (
	ProcNetInode          Kind = "proc-net-inode"
	ReviewedSingleInitNet Kind = "reviewed-single-init-net"
)

var ErrUnknown = errors.New("fresh network identity is unavailable")

// Identity is comparable. All five fields are always present in its canonical
// wire form; the inactive variant's fields must be empty or zero.
type Identity struct {
	Version              int    `json:"version"`
	Kind                 Kind   `json:"kind"`
	BootID               string `json:"boot_id"`
	Inode                uint64 `json:"inode"`
	PlatformReviewSHA256 string `json:"platform_review_sha256"`
}

func (v Identity) Validate() error {
	if v.Version != Version || !validBoot(v.BootID) {
		return ErrUnknown
	}
	switch v.Kind {
	case ProcNetInode:
		if v.Inode == 0 || v.PlatformReviewSHA256 != "" {
			return ErrUnknown
		}
	case ReviewedSingleInitNet:
		if v.Inode != 0 || v.PlatformReviewSHA256 != nc1812Profile().hash() {
			return ErrUnknown
		}
	default:
		return ErrUnknown
	}
	return nil
}
func validBoot(s string) bool {
	if len(s) != 36 || s == "00000000-0000-0000-0000-000000000000" {
		return false
	}
	for i := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if s[i] != '-' {
				return false
			}
			continue
		}
		if !(s[i] >= '0' && s[i] <= '9' || s[i] >= 'a' && s[i] <= 'f') {
			return false
		}
	}
	return true
}

type identityWire Identity

func Encode(v Identity) ([]byte, error) {
	if err := v.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(identityWire(v))
}
func Decode(raw []byte) (Identity, error) {
	if len(raw) == 0 || len(raw) > 1024 {
		return Identity{}, ErrUnknown
	}
	var w identityWire
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&w) != nil || d.Decode(new(any)) != io.EOF {
		return Identity{}, ErrUnknown
	}
	v := Identity(w)
	canonical, err := Encode(v)
	// This also rejects duplicate/missing fields, noncanonical numbers, old
	// strings, mixed variants, whitespace and trailing data.
	if err != nil || !bytes.Equal(raw, canonical) {
		return Identity{}, ErrUnknown
	}
	return v, nil
}
func (v Identity) MarshalJSON() ([]byte, error) { return Encode(v) }
func (v *Identity) UnmarshalJSON(raw []byte) error {
	value, err := Decode(raw)
	if err != nil {
		return err
	}
	*v = value
	return nil
}
