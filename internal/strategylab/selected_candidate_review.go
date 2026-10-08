package strategylab

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

var ErrSelectedCandidateChanged = errors.New("saved StrategyLab selection or its reviewed material is not current")

// SelectedCandidateReview is issued only by the configured Manager, from its
// saved selection and the same live component lease. It observes source and
// completed compatibility; it grants no list, queue, LAN or launch permission.
// Detached Candidate/Selection values cannot replace this original handle.
type SelectedCandidateReview struct {
	self       *SelectedCandidateReview
	mu         sync.Mutex
	closed     bool
	binding    adaptiveCandidateBinding
	selection  Selection
	path       string
	image      restorejournal.Image
	file       os.FileInfo
	parent     os.FileInfo
	provider   *SupervisedCompatibilityProvider
	review     compatibilityReview
	runtime    *components.ManagedNFQWSRuntimeLease
	descriptor components.NFQWSRuntimeDescriptor
}

func (m *Manager) RetainSelectedCandidateReview(ctx context.Context, serviceID, protocol, family string, runtime *components.ManagedNFQWSRuntimeLease) (*SelectedCandidateReview, error) {
	if m == nil || runtime == nil || selectedReviewContext(ctx) != nil || serviceID == "" || strings.TrimSpace(serviceID) != serviceID || strings.ContainsAny(serviceID, "|\x00\r\n") || !validProtocol(protocol) || !validFamily(family) {
		return nil, errors.Join(ErrSelectedCandidateChanged, selectedReviewContext(ctx))
	}
	if err := runtime.Check(ctx); err != nil {
		return nil, errors.Join(ErrSelectedCandidateChanged, err)
	}
	foundation, err := newManagerAdaptiveFoundation(m)
	if err != nil {
		return nil, err
	}
	m.mu.RLock()
	selection, exists := m.state.Selections[selectionKey(serviceID, protocol, family)]
	candidate := adaptiveCandidateDetached(m.state.Candidates[selection.CandidateID])
	m.mu.RUnlock()
	if !exists || selection.ServiceID != serviceID || selection.Protocol != protocol || selection.IPFamily != family {
		return nil, ErrSelectedCandidateChanged
	}
	binding, err := foundation.bind(candidate)
	if err != nil {
		return nil, err
	}
	r := &SelectedCandidateReview{binding: binding, selection: selection, runtime: runtime, descriptor: runtime.Descriptor()}
	r.self = r
	m.mu.RLock()
	defer m.mu.RUnlock()
	r.path = m.Path
	r.image = restorejournal.Image{Exists: m.image.Exists, Data: slices.Clone(m.image.Data)}
	validator, err := adaptiveManagedValidatorLocked(m)
	if err != nil {
		return nil, err
	}
	r.provider = validator.(CompatibleValidator).Provider.(*SupervisedCompatibilityProvider)
	r.review = r.provider.review
	r.review.Assets = slices.Clone(r.review.Assets)
	r.review.BaseArguments = slices.Clone(r.review.BaseArguments)
	if err := compatibilityProtectedReview(r.path, r.review); err != nil {
		return nil, errors.Join(ErrSelectedCandidateChanged, err)
	}
	r.file, err = selectedReviewFileIdentity(r.path)
	if err == nil {
		r.parent, err = selectedReviewFileIdentity(filepath.Dir(r.path))
	}
	if err != nil {
		return nil, errors.Join(ErrSelectedCandidateChanged, err)
	}
	if err := r.currentLocked(ctx); err != nil {
		return nil, err
	}
	return r, nil
}

func selectedReviewContext(ctx context.Context) error {
	if ctx == nil {
		return ErrSelectedCandidateChanged
	}
	deadline, finite := ctx.Deadline()
	if !finite || !time.Now().Before(deadline) {
		return errors.Join(ErrSelectedCandidateChanged, ctx.Err())
	}
	return ctx.Err()
}

// Descriptor Stat captures identity now; some portable Lstat implementations
// defer loading file identity until SameFile, which is too late after rename.
func selectedReviewFileIdentity(path string) (os.FileInfo, error) {
	before, err := os.Lstat(path)
	if err != nil || before.Mode()&os.ModeSymlink != 0 {
		return nil, errors.Join(ErrSelectedCandidateChanged, err)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	opened, statErr := f.Stat()
	after, pathErr := os.Lstat(path)
	closeErr := f.Close()
	if statErr != nil || pathErr != nil || closeErr != nil || !os.SameFile(before, opened) || !os.SameFile(after, opened) {
		return nil, errors.Join(ErrSelectedCandidateChanged, statErr, pathErr, closeErr)
	}
	return opened, nil
}

func (r *SelectedCandidateReview) Candidate() Candidate {
	if r == nil || r.self != r {
		return Candidate{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return Candidate{}
	}
	return adaptiveCandidateDetached(r.binding.candidate)
}

func (r *SelectedCandidateReview) Selection() Selection {
	if r == nil || r.self != r {
		return Selection{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return Selection{}
	}
	return r.selection
}

func (r *SelectedCandidateReview) Current(ctx context.Context) error {
	return r.WithCurrent(ctx, func() error { return nil })
}

// WithCurrent holds only this handle and the existing StrategyLab Manager read
// lock. The short synchronous use MUST NOT reenter this handle or Manager, call
// App Store/Gate, close the component lease, or span NFQ admission/transfer.
// Checks use only the component lease, protected files and read-only control;
// no native validation, App Store/Gate acquisition or state writes occur here.
func (r *SelectedCandidateReview) WithCurrent(ctx context.Context, use func() error) error {
	if r == nil || r.self != r || r.binding.manager == nil || use == nil {
		return ErrSelectedCandidateChanged
	}
	if err := selectedReviewContext(ctx); err != nil {
		return errors.Join(ErrSelectedCandidateChanged, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrSelectedCandidateChanged
	}
	m := r.binding.manager
	m.mu.RLock()
	defer m.mu.RUnlock()
	if err := r.currentLocked(ctx); err != nil {
		return err
	}
	useErr := use()
	return errors.Join(useErr, r.currentLocked(ctx))
}

// Close joins any synchronous observation before retiring this original
// handle. The consumer still owns the component lease and closes it only after
// its actual process and COMMON cleanup have finished.
func (r *SelectedCandidateReview) Close() error {
	if r == nil || r.self != r {
		return ErrSelectedCandidateChanged
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	return nil
}

// Caller holds Manager.mu.RLock and (after issuance) the original handle lock.
func (r *SelectedCandidateReview) currentLocked(ctx context.Context) error {
	if err := r.sourceLocked(ctx); err != nil {
		return err
	}
	// A legacy/native-QA compatibility publisher cannot become a production
	// source by attaching a component DTO after its unadmitted publication.
	if r.provider.self != r.provider || r.provider.managedControl == nil || !r.provider.managedControl.MatchesControlRoot(r.review.ControlPath) || !compatibilityJSONEqual(r.descriptor, r.provider.managedDescriptor) {
		return ErrSelectedCandidateChanged
	}
	ref := r.provider.managedControl.Reference()
	if ref.InstallationID != r.review.InstallationID || ref.Sequence != r.review.Sequence {
		return ErrSelectedCandidateChanged
	}
	if err := compatibilityControlCurrent(ctx, r.review); err != nil {
		return errors.Join(ErrSelectedCandidateChanged, err)
	}
	if r.runtime == nil || r.runtime.Check(ctx) != nil || !compatibilityJSONEqual(r.runtime.Descriptor(), r.descriptor) || selectedReviewMaterial(r.review, r.descriptor) != nil {
		return ErrSelectedCandidateChanged
	}
	if err := compatibilityProtectedReview(r.path, r.review); err != nil {
		return errors.Join(ErrSelectedCandidateChanged, err)
	}
	if err := compatibilityFilesUnchanged(r.review); err != nil {
		return errors.Join(ErrSelectedCandidateChanged, err)
	}
	if err := compatibilityControlCurrent(ctx, r.review); err != nil {
		return errors.Join(ErrSelectedCandidateChanged, err)
	}
	if err := r.sourceLocked(ctx); err != nil {
		return err
	}
	if err := r.runtime.Check(ctx); err != nil {
		return errors.Join(ErrSelectedCandidateChanged, err)
	}
	if !compatibilityJSONEqual(r.runtime.Descriptor(), r.descriptor) || selectedReviewContext(ctx) != nil {
		return ErrSelectedCandidateChanged
	}
	if err := compatibilityProtectedReview(r.path, r.review); err != nil {
		return errors.Join(ErrSelectedCandidateChanged, err)
	}
	if err := errors.Join(compatibilityControlCurrent(ctx, r.review), selectedReviewContext(ctx)); err != nil {
		return errors.Join(ErrSelectedCandidateChanged, err)
	}
	return nil
}

// This source-only leaf also supports portable model tests. Its result cannot
// issue a public review: currentLocked additionally requires the genuine lease,
// Linux ownership, reviewed material and current control.
func (r *SelectedCandidateReview) sourceLocked(ctx context.Context) error {
	m := r.binding.manager
	if m == nil || selectedReviewContext(ctx) != nil || m.Path != r.path || !compatibilityCleanPath(r.path) || m.compatibilityUnknownLocked() || m.writeBlocked || m.nativeRunning || !r.image.Exists || !m.image.Exists || !bytes.Equal(m.image.Data, r.image.Data) {
		return ErrSelectedCandidateChanged
	}
	selection, exists := m.state.Selections[selectionKey(r.selection.ServiceID, r.selection.Protocol, r.selection.IPFamily)]
	candidate, candidateExists := m.state.Candidates[r.binding.candidate.ID]
	if !exists || !candidateExists || selection != r.selection || !adaptiveCandidateIdentityEqual(candidate, r.binding.candidate) || !compatibilityJSONEqual(candidate.Validation, r.binding.candidate.Validation) {
		return ErrSelectedCandidateChanged
	}
	validator, err := adaptiveManagedValidatorLocked(m)
	if err != nil {
		return err
	}
	provider := validator.(CompatibleValidator).Provider.(*SupervisedCompatibilityProvider)
	if provider != r.provider || !compatibilityReviewsEqual(provider.review, r.review) {
		return ErrSelectedCandidateChanged
	}
	provider.mu.Lock()
	completed := !provider.running && !provider.unknown && provider.session != nil && compatibilityJSONEqual(provider.session, m.state.CompatibilitySession)
	provider.mu.Unlock()
	if !completed || selectedReviewCompatibility(m.state, candidate, r.selection, r.review) != nil {
		return ErrSelectedCandidateChanged
	}
	file, fileErr := os.Lstat(r.path)
	parent, parentErr := os.Lstat(filepath.Dir(r.path))
	if fileErr != nil || parentErr != nil || r.file == nil || r.parent == nil || !file.Mode().IsRegular() || !parent.IsDir() || !os.SameFile(file, r.file) || !os.SameFile(parent, r.parent) {
		return ErrSelectedCandidateChanged
	}
	image, err := restorejournal.ReadFileImage(ctx, r.path)
	if err != nil || !image.Exists || !bytes.Equal(image.Data, r.image.Data) || selectedReviewContext(ctx) != nil {
		return errors.Join(ErrSelectedCandidateChanged, err)
	}
	file, fileErr = os.Lstat(r.path)
	parent, parentErr = os.Lstat(filepath.Dir(r.path))
	if fileErr != nil || parentErr != nil || !os.SameFile(file, r.file) || !os.SameFile(parent, r.parent) {
		return ErrSelectedCandidateChanged
	}
	return nil
}

func selectedReviewCompatibility(state State, candidate Candidate, selection Selection, review compatibilityReview) error {
	session := state.CompatibilitySession
	v := candidate.Validation
	if selection.CandidateID != candidate.ID || !compatibilityHex(candidate.Incarnation, 32) || strings.HasPrefix(candidate.Origin, "pack:") || session == nil || state.CompatibilityFinalizing || compatibilitySessionUnknown(*session) || session.Active != "lua-init" || !compatibilityInvocationSucceeded(*session.LuaInit) || !compatibilityReviewsEqual(session.LuaInit.Command.Review, review) || v.QuiescenceUnknown || !v.OK || !v.Native || !v.LuaChecked || v.Code != "COMPATIBLE" {
		return ErrSelectedCandidateChanged
	}
	poolMatches := false
	for _, pool := range Pools {
		if pool.ID == candidate.PoolID && pool.Protocol == selection.Protocol {
			poolMatches = true
		}
	}
	arguments, err := parseArguments(candidate.Arguments)
	if !poolMatches || err != nil || ExportableArguments(candidate.Arguments) != nil || !slices.Equal(arguments, v.Arguments) {
		return ErrSelectedCandidateChanged
	}
	offset := 1 + len(review.BaseArguments)
	lua := session.LuaInit.Command.Args
	if len(lua) <= offset+1 || !slices.Equal(lua[offset:len(lua)-1], arguments) {
		return ErrSelectedCandidateChanged
	}
	// The finite deadline authorized the completed no-intercept invocation. It
	// is not an expiry for saved strategy bytes or a fresh runtime permission.
	return nil
}

func selectedReviewMaterial(review compatibilityReview, d components.NFQWSRuntimeDescriptor) error {
	if d.ReceiptID == "" || d.ManifestSHA256 == "" || len(d.Lua) != 3 || len(d.Blobs) != 2 || review.Binary.Path != d.Executable.Path || review.Binary.SHA256 != d.Executable.SHA256 || len(review.Assets) != 5 {
		return ErrSelectedCandidateChanged
	}
	base := make([]string, 0, 5)
	for i, asset := range d.Lua {
		if review.Assets[i].Path != asset.Path || review.Assets[i].SHA256 != asset.SHA256 {
			return ErrSelectedCandidateChanged
		}
		base = append(base, "--lua-init=@"+asset.Path)
	}
	for i, blob := range d.Blobs {
		if review.Assets[3+i].Path != blob.Path || review.Assets[3+i].SHA256 != blob.SHA256 {
			return ErrSelectedCandidateChanged
		}
		base = append(base, "--blob="+blob.Alias+":@"+blob.Path)
	}
	if !slices.Equal(review.BaseArguments, base) {
		return ErrSelectedCandidateChanged
	}
	return nil
}
