package components

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"github.com/ArtixSx/razvilka/internal/backendprofile"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

var ErrMihomoNativeValidation = errors.New("Mihomo native profile validation is unconfirmed")

type MihomoNativeValidation struct {
	ConfigSHA256    string `json:"config_sha256"`
	Version         string `json:"version"`
	NativeValidated bool   `json:"native_validated"`
	ServiceVerified bool   `json:"service_verified"`
	LiveApplied     bool   `json:"live_applied"`
}

// Only the closed existing compiler can supply a native config. Provider URLs,
// original hooks/DNS/TUN/controllers and arbitrary imported commands never reach
// the native test. Its actual process executes from the same reviewed held FD.
func (m *Manager) ValidateMihomoProfileGuarded(ctx context.Context, source string, options backendprofile.MihomoOptions, expected string, guard, start func(context.Context, func() error) error) (result MihomoNativeValidation, err error) {
	if m == nil || ctx == nil || guard == nil || start == nil {
		return result, ErrRecoveryAuthority
	}
	profile, err := backendprofile.Mihomo(source, options)
	if err != nil || len(profile.Config) > 1<<20 || digest([]byte(profile.Config)) != expected {
		return result, errors.Join(err, ErrMihomoNativeValidation)
	}
	data := []byte(profile.Config)
	defer clear(data)
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := guard(ctx, func() error { return ctx.Err() }); err != nil {
		return result, err
	}
	s, err := m.openMihomoRelease(false)
	if err != nil {
		return result, err
	}
	defer func() {
		err = errors.Join(err, s.close())
		if err != nil {
			result = MihomoNativeValidation{}
		}
	}()
	if err := s.j.RequireIdle(ctx); err != nil {
		return result, err
	}
	image, err := s.files["a_binary"].Read(ctx)
	if err != nil {
		return result, err
	}
	ref, err := mihomoArtifactReferenceOf(image)
	if err != nil {
		return result, err
	}
	receiptImage, err := s.files["b_receipt"].Read(ctx)
	if err != nil {
		return result, err
	}
	var receipt externalReceipt
	if !receiptImage.Exists || json.Unmarshal(receiptImage.Data, &receipt) != nil || receipt.Version != ReviewedMihomoVersion || receipt.SHA256 != ref.SHA256 {
		return result, ErrMihomoNativeValidation
	}
	_, _, artifacts, _, err := m.mihomoReleaseLayout()
	if err != nil {
		return result, err
	}
	err = guard(ctx, func() error { return nativeValidateMihomoProfile(ctx, artifacts, image, data, start) })
	if err != nil {
		return result, errors.Join(ErrMihomoNativeValidation, err)
	}
	for name, before := range map[string]restorejournal.Image{"a_binary": image, "b_receipt": receiptImage} {
		after, err := s.files[name].Read(ctx)
		if err != nil || after.Exists != before.Exists || !bytes.Equal(after.Data, before.Data) {
			return result, errors.Join(err, restorejournal.ErrConflict)
		}
	}
	if err := guard(ctx, func() error { return ctx.Err() }); err != nil {
		return result, err
	}
	return MihomoNativeValidation{ConfigSHA256: expected, Version: ReviewedMihomoVersion, NativeValidated: true}, nil
}
