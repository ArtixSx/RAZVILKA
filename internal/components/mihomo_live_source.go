package components

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/backendprofile"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

var ErrMihomoLiveOwner = errors.New("original live Mihomo owner is unavailable or changed")

// Comparison data only. Publishing a new live execution record requires its
// own reader admission; this reference grants no process or packet authority.
type MihomoLiveReference struct {
	Schema       int                     `json:"schema"`
	Version      string                  `json:"version"`
	BinarySHA256 string                  `json:"binary_sha256"`
	BinarySize   int64                   `json:"binary_size"`
	ParentOrigin MihomoProbeParentOrigin `json:"parent_origin"`
}

// MihomoLiveSource retains the actual installed writer session. It has no
// request context, selected route, cleanup verdict or reconstructed PID.
type MihomoLiveSource struct {
	mu             sync.Mutex
	self           *MihomoLiveSource
	manager        *Manager
	session        *mihomoReleaseSession
	artifacts      string
	image, receipt restorejournal.Image
	origin         mihomoProbeOriginOwner
	reference      MihomoLiveReference
	children       map[*MihomoLiveProcess]bool
	profiles       map[*MihomoLiveProfile]bool
	closed         bool
	closeErr       error
}

func (*MihomoLiveSource) String() string   { return "[private original live Mihomo source]" }
func (*MihomoLiveSource) GoString() string { return "[private original live Mihomo source]" }

func (m *Manager) OpenMihomoLiveSource(ctx context.Context) (source *MihomoLiveSource, err error) {
	if m == nil {
		return nil, ErrMihomoLiveOwner
	}
	if err := mihomoLiveFinite(ctx); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	session, err := m.openMihomoRelease(false)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, session.close())
		}
	}()
	if err = session.j.RequireIdle(ctx); err != nil {
		return nil, err
	}
	image, err := session.files["a_binary"].Read(ctx)
	if err != nil {
		return nil, err
	}
	actual, err := mihomoArtifactReferenceOf(image)
	if err != nil {
		return nil, err
	}
	expected, err := mihomoReviewedRawArtifact(m.Arch)
	if err != nil || actual != expected {
		return nil, ErrMihomoLiveOwner
	}
	receipt, err := session.files["b_receipt"].Read(ctx)
	if err != nil {
		return nil, err
	}
	var owner externalReceipt
	if !receipt.Exists || json.Unmarshal(receipt.Data, &owner) != nil || owner.Version != ReviewedMihomoVersion || owner.SHA256 != actual.SHA256 {
		return nil, ErrMihomoLiveOwner
	}
	_, _, artifacts, _, err := m.mihomoReleaseLayout()
	if err != nil {
		return nil, err
	}
	origin, err := captureMihomoProbeOrigin(ctx)
	if err != nil {
		return nil, err
	}
	if origin == nil {
		return nil, ErrMihomoLiveOwner
	}
	source = &MihomoLiveSource{manager: m, session: session, artifacts: artifacts, image: cloneMihomoImage(image), receipt: cloneMihomoImage(receipt), origin: origin, children: map[*MihomoLiveProcess]bool{}, reference: MihomoLiveReference{Schema: 1, Version: owner.Version, BinarySHA256: actual.SHA256, BinarySize: actual.Size, ParentOrigin: origin.reference()}}
	source.self = source
	source.profiles = map[*MihomoLiveProfile]bool{}
	if err = source.Current(ctx); err != nil {
		err = errors.Join(err, origin.close())
		source = nil
		return nil, err
	}
	return source, nil
}

func (s *MihomoLiveSource) OwnedBy(m *Manager) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.self == s && !s.closed && s.closeErr == nil && s.manager == m
}
func (s *MihomoLiveSource) Reference() MihomoLiveReference {
	if s == nil || s.self != s {
		return MihomoLiveReference{}
	}
	return s.reference
}
func (s *MihomoLiveSource) Current(ctx context.Context) error {
	if s == nil || ctx == nil {
		return ErrMihomoLiveOwner
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.currentLocked(ctx)
}
func (s *MihomoLiveSource) currentLocked(ctx context.Context) error {
	if err := s.currentPrefixLocked(ctx); err != nil {
		return err
	}
	actual, err := s.session.files["a_binary"].Read(ctx)
	if err != nil || !sameMihomoImage(actual, s.image) {
		return errors.Join(ErrMihomoLiveOwner, err)
	}
	return s.currentReceiptLocked(ctx)
}

func (s *MihomoLiveSource) currentPrefixLocked(ctx context.Context) error {
	if err := mihomoLiveFinite(ctx); err != nil {
		return err
	}
	if s.self != s || s.closed || s.closeErr != nil || s.manager == nil || s.session == nil || s.origin == nil || s.reference.ParentOrigin != s.origin.reference() {
		return ErrMihomoLiveOwner
	}
	if err := s.origin.current(ctx); err != nil {
		return err
	}
	approved, err := mihomoReviewedRawArtifact(s.manager.Arch)
	if err != nil || approved.SHA256 != s.reference.BinarySHA256 || approved.Size != s.reference.BinarySize {
		return ErrMihomoLiveOwner
	}
	_, _, artifacts, paths, err := s.manager.mihomoReleaseLayout()
	if err != nil || artifacts != s.artifacts {
		return errors.Join(ErrMihomoLiveOwner, err)
	}
	for name, path := range s.session.paths {
		if paths[name] != path {
			return ErrMihomoLiveOwner
		}
	}
	if err := s.session.j.RequireIdle(ctx); err != nil {
		return err
	}
	return nil
}

func (s *MihomoLiveSource) currentReceiptLocked(ctx context.Context) error {
	receipt, err := s.session.files["b_receipt"].Read(ctx)
	if err != nil || !sameMihomoImage(receipt, s.receipt) {
		return errors.Join(ErrMihomoLiveOwner, err)
	}
	return ctx.Err()
}

// Only read-frame boundaries use the actual same-invocation pool hash FD.
// Ordinary Current and every native Start retain their existing full path.
func (s *MihomoLiveSource) currentComparedLocked(ctx context.Context, compare func(context.Context, *restorejournal.ArtifactSourceComparison) error) error {
	if err := s.currentPrefixLocked(ctx); err != nil {
		return err
	}
	target, ok := s.session.files["a_binary"].(*restorejournal.ArtifactFileTarget)
	if !ok || target == nil || compare == nil {
		return ErrMihomoLiveOwner
	}
	return target.WithExpectedReadComparison(ctx, s.image, func(held context.Context, image restorejournal.Image, proof *restorejournal.ArtifactSourceComparison) error {
		if !sameMihomoImage(image, s.image) {
			return ErrMihomoLiveOwner
		}
		if err := s.currentReceiptLocked(held); err != nil {
			return err
		}
		return compare(held, proof)
	})
}

func mihomoLiveFinite(ctx context.Context) error {
	if ctx == nil {
		return ErrMihomoLiveOwner
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline, ok := ctx.Deadline()
	if !ok || !time.Now().Before(deadline) {
		return ErrMihomoLiveOwner
	}
	return nil
}

type MihomoLiveProfile struct {
	self                 *MihomoLiveProfile
	source               *MihomoLiveSource
	config               []byte
	configSHA, reviewSHA string
	endpoint             netip.Addr
	port                 int
}

func (*MihomoLiveProfile) String() string   { return "[private generated live Mihomo profile]" }
func (*MihomoLiveProfile) GoString() string { return "[private generated live Mihomo profile]" }

// ReviewProfile retains only the existing conservative pinned compiler's
// output. The original node/plan owner independently admits packet resources;
// this private data is neither native validation nor a selected-node grant.
func (s *MihomoLiveSource) ReviewProfile(ctx context.Context, raw string, options backendprofile.MihomoOptions, review, host string, endpoint netip.Addr) (*MihomoLiveProfile, error) {
	if err := s.Current(ctx); err != nil {
		return nil, err
	}
	base, err := backendprofile.Mihomo(raw, options)
	if err != nil || digest([]byte(base.Config)) != review {
		return nil, ErrMihomoLiveOwner
	}
	pinned, err := backendprofile.MihomoPinnedForProbe(raw, options, host, endpoint)
	if err != nil || len(pinned.Config) > 1<<20 {
		return nil, ErrMihomoLiveOwner
	}
	p := &MihomoLiveProfile{source: s, config: []byte(pinned.Config), configSHA: digest([]byte(pinned.Config)), reviewSHA: review, endpoint: endpoint, port: options.SOCKSPort}
	p.self = p
	if err := s.Current(ctx); err != nil {
		clear(p.config)
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.currentLocked(ctx); err != nil {
		clear(p.config)
		return nil, err
	}
	s.profiles[p] = true
	return p, nil
}

func (s *MihomoLiveSource) Close() error {
	if s == nil || s.self != s {
		return ErrMihomoLiveOwner
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if len(s.children) != 0 || s.closeErr != nil {
		return errors.Join(ErrMihomoLiveOwner, s.closeErr)
	}
	s.closeErr = errors.Join(s.origin.close(), s.session.close())
	if s.closeErr != nil {
		return errors.Join(ErrMihomoLiveOwner, s.closeErr)
	}
	for profile := range s.profiles {
		clear(profile.config)
	}
	s.profiles = nil
	s.closed = true
	return nil
}
