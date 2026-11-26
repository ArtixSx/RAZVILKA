package strategylab

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// Serialized comparison only. A decoded tag cannot construct a material,
// original selected source, component lease or native invocation owner.
type compatibilityDomainReview struct {
	Schema          int                      `json:"schema"`
	SourceSHA256    string                   `json:"source_sha256"`
	CandidateSHA256 string                   `json:"candidate_sha256"`
	Include         compatibilityFileBinding `json:"include"`
	Exclude         compatibilityFileBinding `json:"exclude"`
}

func validateCompatibilityDomain(d compatibilityDomainReview) error {
	parent := filepath.Dir(d.Include.Path)
	nonce := strings.TrimPrefix(filepath.Base(parent), "nfq-domain-")
	if d.Schema != 1 || !compatibilityHex(d.SourceSHA256, 64) || !compatibilityHex(d.CandidateSHA256, 64) || !compatibilityFileValid(d.Include, 128<<10) || !compatibilityFileValid(d.Exclude, 128<<10) || !compatibilityHex(nonce, 32) || filepath.Base(d.Include.Path) != "include.list" || filepath.Base(d.Exclude.Path) != "exclude.list" || filepath.Dir(d.Exclude.Path) != parent {
		return ErrNFQWSDomainMaterial
	}
	return nil
}

func compatibilityDomainFilesCurrent(d compatibilityDomainReview) error {
	if err := validateCompatibilityDomain(d); err != nil {
		return err
	}
	for i, binding := range []compatibilityFileBinding{d.Include, d.Exclude} {
		if err := compatibilityProtectedPath(binding.Path, false); err != nil {
			return err
		}
		root, err := ownedfs.Open(filepath.Dir(binding.Path))
		if err != nil {
			return err
		}
		file, err := root.OpenFile(filepath.Base(binding.Path), nfqDomainReadFlags(), 0)
		if err != nil {
			return errors.Join(err, root.Close())
		}
		before, statErr := file.Stat()
		if statErr != nil || !before.Mode().IsRegular() || before.Size() != binding.Size || before.Mode().Perm() != 0400 {
			return errors.Join(ErrNFQWSDomainMaterial, file.Close(), root.Close())
		}
		data, readErr := io.ReadAll(io.NewSectionReader(file, 0, binding.Size+1))
		after, pathErr := root.Stat(filepath.Base(binding.Path))
		hash, _ := nfqDomainHash(data)
		kind := "INCLUDE"
		if i == 1 {
			kind = "EXCLUDE"
		}
		header := "# RAZVILKA CORE NFQ " + kind + " V1\n"
		var canonical []string
		valid := bytes.HasPrefix(data, []byte(header)) && bytes.HasSuffix(data, []byte("\n"))
		if valid {
			body := strings.TrimSuffix(strings.TrimPrefix(string(data), header), "\n")
			var raw []string
			if body != "" {
				raw = strings.Split(body, "\n")
			}
			canonical, err = nfqDomainNames(raw, i == 1)
			valid = err == nil && bytes.Equal(nfqDomainImage(kind, canonical), data)
		}
		closeErr := errors.Join(file.Close(), root.Close())
		if readErr != nil || pathErr != nil || closeErr != nil || !valid || hash != binding.SHA256 || !os.SameFile(before, after) || after.Size() != before.Size() || after.Mode() != before.Mode() {
			return errors.Join(ErrNFQWSDomainMaterial, readErr, pathErr, closeErr)
		}
	}
	return nil
}

// The generic grammar remains unchanged. Only this separately tagged command
// may append the five exact CORE options after one frozen TCP443 profile.
func compatibilityReviewCommandPhase(review compatibilityReview, command []string) (string, error) {
	if review.Domain == nil {
		return compatibilityCommandPhase(review.BaseArguments, command)
	}
	d := *review.Domain
	if err := validateCompatibilityDomain(d); err != nil {
		return "", err
	}
	last := len(command)
	if len(command) == 0 {
		return "", ErrNFQWSDomainMaterial
	}
	lua := command[0] != "--dry-run"
	if lua {
		last--
	}
	suffix := nfqDomainArguments(d.Include.Path, d.Exclude.Path)
	if last < len(suffix) || !slices.Equal(command[last-len(suffix):last], suffix) {
		return "", ErrNFQWSDomainMaterial
	}
	stripped := append([]string(nil), command[:last-len(suffix)]...)
	if lua {
		stripped = append(stripped, command[len(command)-1])
	}
	phase, err := compatibilityCommandPhase(review.BaseArguments, stripped)
	if err != nil {
		return "", err
	}
	offset := 1 + len(review.BaseArguments)
	if phase == "dry-run" {
		offset++
	}
	end := last - len(suffix)
	if offset > end {
		return "", ErrNFQWSDomainMaterial
	}
	candidate := command[offset:end]
	digest, _ := selectedReferenceDigest(candidate)
	if digest != d.CandidateSHA256 || nfqDomainCandidate(candidate) != nil {
		return "", ErrNFQWSDomainMaterial
	}
	return phase, nil
}

// NFQWSDomainMaterial is compatibility-only material, not a domain execution
// issuer. No current CIDR/source builder accepts this type. COMPATIBLE proves
// parsing/Lua initialization only; service access and packet baseline remain
// unverified until a separate genuine packet oracle and issuer are accepted.
type NFQWSDomainMaterial struct {
	self                            *NFQWSDomainMaterial
	mu                              sync.Mutex
	source                          *SelectedCandidateReview
	reference                       SelectedCandidateReference
	runtime                         *components.ManagedNFQWSRuntimeLease
	control                         *operationgate.ControlEpochReview
	files                           *nfqDomainFiles
	review                          compatibilityDomainReview
	child                           *Manager
	provider                        *SupervisedCompatibilityProvider
	completion                      *ManagedCompatibilityCompletion
	pending, ready, closed, invalid bool
	validation                      Validation
	compatRoot                      *ownedfs.Root
	compatFile                      *os.File
	compatInfo, compatParent        os.FileInfo
	compatImage                     []byte
}

func (*NFQWSDomainMaterial) String() string {
	return "[original CORE NFQ domain compatibility material]"
}
func (*NFQWSDomainMaterial) GoString() string {
	return "[original CORE NFQ domain compatibility material]"
}

// validationRuntime must be a DISTINCT genuine lease. Its actual managed
// completion closes only that lease. The original selected source/runtime and
// caller's operation/control remain retained. On unknown, return this original
// material with the error: caller MUST retain it/admission and retire the same
// completion; a timeout/Close cannot release it or manufacture compatibility.
func ReviewManagedNFQWSDomainMaterial(ctx context.Context, source *SelectedCandidateReview, validationRuntime *components.ManagedNFQWSRuntimeLease, control *operationgate.ControlEpochReview, include, exclude []string) (*NFQWSDomainMaterial, error) {
	if selectedReviewContext(ctx) != nil || source == nil || source.self != source || validationRuntime == nil || control == nil || validationRuntime == source.runtime {
		return nil, ErrNFQWSDomainMaterial
	}
	if err := source.ManagedOwnersCurrent(ctx, source.runtime, control); err != nil {
		return nil, err
	}
	ref, err := source.Reference(ctx)
	if err != nil {
		return nil, err
	}
	selection := source.Selection()
	if selection.Mode != ModeManual || !selection.Frozen || selection.Protocol != "tcp" || selection.IPFamily != "ipv4" || nfqDomainCandidate(ref.Arguments) != nil {
		return nil, ErrNFQWSDomainMaterial
	}
	if err := validationRuntime.Check(ctx); err != nil || !compatibilityJSONEqual(validationRuntime.Descriptor(), source.descriptor) {
		return nil, errors.Join(ErrNFQWSDomainMaterial, err)
	}
	files, err := newNFQDomainFiles(filepath.Dir(source.path), include, exclude)
	if err != nil {
		return nil, err
	}
	r := &NFQWSDomainMaterial{source: source, reference: ref, runtime: source.runtime, control: control, files: files}
	r.self = r
	keep := false
	defer func() {
		if !keep {
			_ = r.Close()
		}
	}()
	sourceDigest, _ := selectedReferenceDigest(ref)
	candidateDigest, _ := selectedReferenceDigest(ref.Arguments)
	r.review = compatibilityDomainReview{1, sourceDigest, candidateDigest, files.include, files.exclude}
	// A separate private child-state prevents native session publication from
	// changing the existing frozen source image/selection/health history.
	childDir := files.path + "-compat"
	if err := os.Mkdir(childDir, 0700); err != nil {
		return nil, err
	}
	r.child, err = New(filepath.Join(childDir, "strategy.json"))
	if err != nil {
		return nil, err
	}
	candidate := source.Candidate()
	candidate.Validation = Validation{Code: "NATIVE_REQUIRED", Arguments: slices.Clone(ref.Arguments)}
	r.child.state.Candidates[candidate.ID] = candidate
	if err := control.WithRename(ctx, func() error { return r.child.saveLocked() }); err != nil {
		return nil, err
	}
	p, v, err := NewManagedSupervisedCompatibilityProvider(ctx, r.child, validationRuntime, control, source.provider.review.ControlPath)
	if err != nil {
		return nil, err
	}
	r.provider = p
	domain := r.review
	p.review.Domain = &domain
	p.domainMaterial = r
	v.domain = &domain
	r.child.Validator = v
	r.child.Executor = nil
	if err := r.forwardCurrent(ctx); err != nil {
		return nil, err
	}
	r.pending = true
	checked, completion, err := r.child.ValidateManagedCandidate(ctx, candidate.ID, validationRuntime)
	r.validation, r.completion = checked.Validation, completion
	if completion == nil {
		r.pending = false
		return nil, errors.Join(ErrNFQWSDomainMaterial, err)
	}
	keep = true // The actual completion, even on error, remains the only owner.
	retireCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), managedCompatibilityCleanupTimeout)
	defer cancel()
	retireErr := r.RetireCompatibility(retireCtx)
	if err != nil || retireErr != nil {
		return r, errors.Join(err, retireErr)
	}
	if !r.validation.OK || !r.validation.Native || !r.validation.LuaChecked || r.validation.QuiescenceUnknown {
		return r, ErrNFQWSDomainMaterial
	}
	if err := r.forwardCurrent(ctx); err != nil {
		return r, err
	}
	r.mu.Lock()
	r.ready = true
	r.mu.Unlock()
	return r, nil
}

// Static same-original comparison for cleanup. Forward source freshness is
// checked separately; Stop/source edits must not prevent joining owned helpers.
func (p *SupervisedCompatibilityProvider) managedReviewMaterial(ctx context.Context) error {
	base := p.review
	if base.Domain == nil {
		return selectedReviewMaterial(base, p.managedDescriptor)
	}
	r := p.domainMaterial
	if r == nil || r.self != r || r.provider != p || r.child != p.manager || r.source == nil || r.child == r.source.binding.manager || r.control != p.managedControl || !compatibilityJSONEqual(r.review, *base.Domain) {
		return ErrNFQWSDomainMaterial
	}
	base.Domain = nil
	return selectedReviewMaterial(base, p.managedDescriptor)
}

func (r *NFQWSDomainMaterial) forwardCurrent(ctx context.Context) error {
	if r == nil || r.self != r || selectedReviewContext(ctx) != nil {
		return ErrNFQWSDomainMaterial
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.files == nil || r.source == nil || r.runtime == nil || r.control == nil {
		return ErrNFQWSDomainMaterial
	}
	if err := r.source.ManagedOwnersCurrent(ctx, r.runtime, r.control); err != nil {
		return err
	}
	ref, err := r.source.Reference(ctx)
	if err != nil || !compatibilityJSONEqual(ref, r.reference) {
		return errors.Join(ErrNFQWSDomainMaterial, err)
	}
	if err := r.files.current(); err != nil {
		return err
	}
	if r.ready {
		if err := r.compatibilityCurrent(); err != nil {
			return err
		}
	}
	return r.source.ManagedOwnersCurrent(ctx, r.runtime, r.control)
}

func (r *NFQWSDomainMaterial) Current(ctx context.Context) error {
	if r == nil || r.self != r {
		return ErrNFQWSDomainMaterial
	}
	r.mu.Lock()
	ready := r.ready && !r.pending && !r.closed && !r.invalid
	r.mu.Unlock()
	if !ready {
		return ErrNFQWSDomainMaterial
	}
	err := r.forwardCurrent(ctx)
	if err != nil {
		r.mu.Lock()
		r.invalid = true
		r.mu.Unlock()
	}
	return err
}

// Command returns comparison data only: no --intercept/qnum/pidfile or queue,
// scope/activation capability. The ordinary candidate grammar rejects it.
func (r *NFQWSDomainMaterial) Command(ctx context.Context) (string, []string, error) {
	if err := r.Current(ctx); err != nil {
		return "", nil, err
	}
	args := append(slices.Clone(r.provider.review.BaseArguments), r.reference.Arguments...)
	args = append(args, nfqDomainArguments(r.review.Include.Path, r.review.Exclude.Path)...)
	return r.provider.review.Binary.Path, args, nil
}

func (r *NFQWSDomainMaterial) RetireCompatibility(ctx context.Context) error {
	if r == nil || r.self != r || selectedReviewContext(ctx) != nil {
		return ErrCompatibilityQuiescenceUnknown
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || !r.pending || r.completion == nil {
		return ErrCompatibilityQuiescenceUnknown
	}
	if err := r.completion.RetireKnown(ctx); err != nil {
		return err
	}
	r.pending = false
	return r.captureCompatibility()
}

func (r *NFQWSDomainMaterial) Close() error {
	if r == nil || r.self != r {
		return ErrNFQWSDomainMaterial
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending {
		return ErrCompatibilityQuiescenceUnknown
	}
	if r.closed {
		return nil
	}
	r.closed = true
	var err error
	if r.compatFile != nil {
		err = r.compatFile.Close()
	}
	if r.compatRoot != nil {
		err = errors.Join(err, r.compatRoot.Close())
	}
	if r.files != nil {
		err = errors.Join(err, r.files.close())
	}
	return err
}

// Retain the actual original managed completion's published image/identities,
// never a newly decoded or matching latest receipt. Caller holds r.mu.
func (r *NFQWSDomainMaterial) captureCompatibility() error {
	i := r.completion.invocation
	if r.completion.self != r.completion || !r.completion.retired || i == nil || !i.finished || !i.settled || !i.runtimeClosed || i.manager != r.child || i.provider != r.provider || i.file == nil || i.parent == nil || !i.image.Exists || len(i.image.Data) == 0 || len(i.image.Data) > 16<<20 {
		return ErrNFQWSDomainMaterial
	}
	root, err := ownedfs.Open(filepath.Dir(r.child.Path))
	if err != nil {
		return err
	}
	file, err := root.OpenFile(filepath.Base(r.child.Path), nfqDomainReadFlags(), 0)
	if err != nil {
		return errors.Join(err, root.Close())
	}
	r.compatRoot, r.compatFile = root, file
	r.compatInfo, r.compatParent = i.file, i.parent
	r.compatImage = slices.Clone(i.image.Data)
	return r.compatibilityCurrent()
}

func (r *NFQWSDomainMaterial) compatibilityCurrent() error {
	if r.compatRoot == nil || r.compatFile == nil || r.compatInfo == nil || r.compatParent == nil || r.provider == nil || r.provider.self != r.provider || r.provider.domainMaterial != r || r.provider.manager != r.child {
		return ErrNFQWSDomainMaterial
	}
	r.child.mu.RLock()
	imageEqual := bytes.Equal(r.child.image.Data, r.compatImage) && r.child.image.Exists && !r.child.nativeRunning && !r.child.writeBlocked && !r.child.compatibilityUnknownLocked()
	r.child.mu.RUnlock()
	r.provider.mu.Lock()
	complete := !r.provider.running && !r.provider.unknown && r.provider.managedInvocation == nil && r.provider.session != nil && r.provider.managedRetiredSession == r.provider.session && r.provider.session.Active == "lua-init" && r.provider.session.LuaInit != nil && !compatibilitySessionUnknown(*r.provider.session) && compatibilityInvocationSucceeded(*r.provider.session.LuaInit) && r.provider.review.Domain != nil && compatibilityJSONEqual(*r.provider.review.Domain, r.review) && compatibilityReviewsEqual(r.provider.session.LuaInit.Command.Review, r.provider.review)
	r.provider.mu.Unlock()
	if !imageEqual || !complete {
		return ErrNFQWSDomainMaterial
	}
	check := func() error {
		parent, err := os.Lstat(filepath.Dir(r.child.Path))
		held, heldErr := r.compatRoot.RootInfo()
		named, pathErr := r.compatRoot.Stat(filepath.Base(r.child.Path))
		file, fileErr := r.compatFile.Stat()
		if err != nil || heldErr != nil || pathErr != nil || fileErr != nil || !nfqDomainPrivateDirectory(parent) || !os.SameFile(parent, r.compatParent) || !os.SameFile(held, r.compatParent) || !named.Mode().IsRegular() || !os.SameFile(named, r.compatInfo) || !os.SameFile(file, r.compatInfo) || named.Size() != int64(len(r.compatImage)) || named.Mode() != r.compatInfo.Mode() {
			return ErrNFQWSDomainMaterial
		}
		return nil
	}
	if err := check(); err != nil {
		return err
	}
	image, err := io.ReadAll(io.NewSectionReader(r.compatFile, 0, int64(len(r.compatImage))+1))
	if err != nil || !bytes.Equal(image, r.compatImage) {
		return ErrNFQWSDomainMaterial
	}
	return check()
}
