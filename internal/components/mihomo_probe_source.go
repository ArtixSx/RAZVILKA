package components

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"sync"

	"github.com/ArtixSx/razvilka/internal/backendprofile"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// Comparison data only. A serialized reference cannot recreate the original
// installed writer lease, grant a process, or issue a route/service result.
type MihomoProbeReference struct {
	Version      string                  `json:"version"`
	BinarySHA256 string                  `json:"binary_sha256"`
	BinarySize   int64                   `json:"binary_size"`
	ReviewSHA256 string                  `json:"review_sha256"`
	ConfigSHA256 string                  `json:"config_sha256"`
	ServerHost   string                  `json:"server_host"`
	Endpoint     netip.Addr              `json:"endpoint"`
	SOCKSPort    int                     `json:"socks_port"`
	ParentOrigin MihomoProbeParentOrigin `json:"parent_origin,omitzero"`
}

type MihomoProbeSource struct {
	self                *MihomoProbeSource
	manager             *Manager
	session             *mihomoReleaseSession
	mu                  sync.Mutex
	closed              bool
	probeUsed           bool
	probe               *MihomoProbeProcess
	closeErr            error
	artifacts           string
	image, receipt      restorejournal.Image
	profile             []byte
	reference           MihomoProbeReference
	guard               func(context.Context, func() error) error
	parentOrigin        mihomoProbeOriginOwner
	publishParentOrigin bool
}

func (*MihomoProbeSource) String() string   { return "[private original Mihomo probe source]" }
func (*MihomoProbeSource) GoString() string { return "[private original Mihomo probe source]" }

// ReviewMihomoProbe retains the SAME installed binary/receipt writer leases.
// It does not start a process. The scoped consumer must separately reserve its
// original execution resource and admit an actual native Start.
func (m *Manager) ReviewMihomoProbe(ctx context.Context, raw string, options backendprofile.MihomoOptions, review, host string, endpoint netip.Addr, guard func(context.Context, func() error) error) (source *MihomoProbeSource, err error) {
	return m.reviewMihomoProbe(ctx, raw, options, review, host, endpoint, guard, true)
}

// ReviewMihomoProbeLegacy preserves the reader4 wire format after a trusted
// caller's fresh reader4 fleet admission. The same private actual parent and
// Linux death backstop are retained; same-boot cold retirement is unavailable.
func (m *Manager) ReviewMihomoProbeLegacy(ctx context.Context, raw string, options backendprofile.MihomoOptions, review, host string, endpoint netip.Addr, guard func(context.Context, func() error) error) (*MihomoProbeSource, error) {
	return m.reviewMihomoProbe(ctx, raw, options, review, host, endpoint, guard, false)
}

func (m *Manager) reviewMihomoProbe(ctx context.Context, raw string, options backendprofile.MihomoOptions, review, host string, endpoint netip.Addr, guard func(context.Context, func() error) error, publishOrigin bool) (source *MihomoProbeSource, err error) {
	if m == nil || ctx == nil || guard == nil {
		return nil, ErrRecoveryAuthority
	}
	base, err := backendprofile.Mihomo(raw, options)
	if err != nil || digest([]byte(base.Config)) != review {
		return nil, errors.Join(err, ErrMihomoNativeValidation)
	}
	pinned, err := backendprofile.MihomoPinnedForProbe(raw, options, host, endpoint)
	if err != nil || len(pinned.Config) > 1<<20 {
		return nil, errors.Join(err, ErrMihomoNativeValidation)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := guard(ctx, func() error { return ctx.Err() }); err != nil {
		return nil, err
	}
	session, err := m.openMihomoRelease(false)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, session.close())
			source = nil
		}
	}()
	if err = session.j.RequireIdle(ctx); err != nil {
		return nil, err
	}
	image, err := session.files["a_binary"].Read(ctx)
	if err != nil {
		return nil, err
	}
	ref, err := mihomoArtifactReferenceOf(image)
	if err != nil {
		return nil, err
	}
	approved, err := mihomoReviewedRawArtifact(m.Arch)
	if err != nil || ref != approved {
		return nil, ErrRecoveryAuthority
	}
	receipt, err := session.files["b_receipt"].Read(ctx)
	if err != nil {
		return nil, err
	}
	var owner externalReceipt
	if !receipt.Exists || json.Unmarshal(receipt.Data, &owner) != nil || owner.Version != ReviewedMihomoVersion || owner.SHA256 != ref.SHA256 {
		return nil, ErrRecoveryAuthority
	}
	_, _, artifacts, _, err := m.mihomoReleaseLayout()
	if err != nil {
		return nil, err
	}
	source = &MihomoProbeSource{manager: m, session: session, artifacts: artifacts, image: image, receipt: receipt, profile: []byte(pinned.Config), guard: guard, publishParentOrigin: publishOrigin,
		reference: MihomoProbeReference{Version: owner.Version, BinarySHA256: ref.SHA256, BinarySize: ref.Size, ReviewSHA256: review, ConfigSHA256: digest([]byte(pinned.Config)), ServerHost: host, Endpoint: endpoint, SOCKSPort: options.SOCKSPort}}
	source.self = source
	source.parentOrigin, err = captureMihomoProbeOrigin(ctx)
	if err != nil {
		clear(source.profile)
		return nil, err
	}
	if source.parentOrigin != nil && publishOrigin {
		source.reference.ParentOrigin = source.parentOrigin.reference()
	}
	if err = source.Current(ctx); err != nil {
		if source.parentOrigin != nil {
			err = errors.Join(err, source.parentOrigin.close())
		}
		clear(source.profile)
		return nil, err
	}
	return source, nil
}

func (s *MihomoProbeSource) Reference() MihomoProbeReference {
	if s == nil || s.self != s {
		return MihomoProbeReference{}
	}
	return s.reference
}

// OwnedBy compares the original installed manager pointer only. Equal paths or
// a serialized reference cannot recreate the held writer lease.
func (s *MihomoProbeSource) OwnedBy(manager *Manager) bool {
	return s != nil && s.self == s && manager != nil && s.manager == manager
}

func (s *MihomoProbeSource) currentLocked(ctx context.Context) error {
	if s.closed || s.session == nil || s.manager == nil || s.guard == nil || ctx == nil || digest(s.profile) != s.reference.ConfigSHA256 {
		return ErrRecoveryAuthority
	}
	return s.guard(ctx, func() error {
		if s.parentOrigin != nil {
			if s.publishParentOrigin && s.parentOrigin.reference() != s.reference.ParentOrigin || !s.publishParentOrigin && !s.reference.ParentOrigin.IsZero() {
				return ErrMihomoProbeOrigin
			}
			if err := s.parentOrigin.current(ctx); err != nil {
				return err
			}
		} else if !s.reference.ParentOrigin.IsZero() {
			return ErrMihomoProbeOrigin
		}
		approved, pinErr := mihomoReviewedRawArtifact(s.manager.Arch)
		if pinErr != nil || approved.SHA256 != s.reference.BinarySHA256 || approved.Size != s.reference.BinarySize {
			return restorejournal.ErrConflict
		}
		_, _, artifacts, paths, err := s.manager.mihomoReleaseLayout()
		if err != nil || artifacts != s.artifacts {
			return errors.Join(err, restorejournal.ErrConflict)
		}
		for name, path := range s.session.paths {
			if paths[name] != path {
				return restorejournal.ErrConflict
			}
		}
		if err := s.session.j.RequireIdle(ctx); err != nil {
			return err
		}
		for name, before := range map[string]restorejournal.Image{"a_binary": s.image, "b_receipt": s.receipt} {
			after, err := s.session.files[name].Read(ctx)
			if err != nil || after.Exists != before.Exists || !bytes.Equal(after.Data, before.Data) {
				return errors.Join(err, restorejournal.ErrConflict)
			}
		}
		return ctx.Err()
	})
}

func (s *MihomoProbeSource) Current(ctx context.Context) error {
	if s == nil || s.self != s {
		return ErrRecoveryAuthority
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.currentLocked(ctx)
}

func (s *MihomoProbeSource) Close() error {
	if s == nil || s.self != s {
		return ErrRecoveryAuthority
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return s.closeErr
	}
	if s.probe != nil {
		return ErrMihomoProbePending
	}
	s.closed = true
	clear(s.profile)
	if s.parentOrigin != nil {
		s.closeErr = s.parentOrigin.close()
	}
	s.closeErr = errors.Join(s.closeErr, s.session.close())
	return s.closeErr
}
