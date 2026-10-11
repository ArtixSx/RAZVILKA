package dataplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

const xrayDomainTCPConfigName = "xray-domain-tcp.json"
const xrayDomainTCPExecutableLimit = 128 << 20

// The original scope will register this exact pointer and its typed immutable
// definition before exposing the resource. This lower file preparation does
// not publish an execution, create a launch capability or start a child.
type XrayDomainTCPExecutionResource struct {
	self              *XrayDomainTCPExecutionResource
	mu                sync.Mutex
	scope             *executionResourceScope
	material          *XrayDomainTCPOperationMaterial
	definition        ExecutionXrayDomainTCPDefinition
	id, relative      string
	rootPath          string
	root              *ownedfs.Root
	anchor            os.FileInfo
	config            *os.File
	configInfo        os.FileInfo
	executable        *xrayDomainTCPExecutable
	child             *xraySelectedTCPProcess
	descriptorsClosed atomic.Bool
	descriptorsErr    error
}

func (*XrayDomainTCPExecutionResource) String() string { return "[original domain Xray TCP resource]" }
func (*XrayDomainTCPExecutionResource) GoString() string {
	return "[original domain Xray TCP resource]"
}

// Called only by the upcoming original scope publisher, while that publisher
// still owns this resource on all success/failure paths. No public path or
// config input is accepted. Native Start must additionally require the actual
// scope map, authored journal FDs and durable planned registration.
func (s *executionResourceScope) prepareXrayDomainTCPResource(ctx context.Context, m *XrayDomainTCPOperationMaterial) (_ *XrayDomainTCPExecutionResource, resultErr error) {
	if s == nil || m == nil || m.self != m || xraySelectedTCPFinite(ctx) != nil || ctx.Value(syntheticExecutionRegistrarKey{}) != s || s.adapter != "xray" || s.adapterOwner != m.adapter || s.manager != m.manager || s.networkIdentity == nil || s.networkIdentity.provider == nil || !reflect.DeepEqual(s.plan, m.plan) {
		return nil, ErrXrayDomainTCPOriginal
	}
	s.startMu.RLock()
	defer s.startMu.RUnlock()
	if err := m.Current(ctx); err != nil {
		return nil, err
	}
	check := func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.resourceCount() >= maxExecutionResources {
			return ErrXrayDomainTCPOriginal
		}
		return s.checkOriginalOwner(ctx, nil, true, false)
	}
	if err := check(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.ctx.Err() != nil || m.resource != nil || len(m.config) == 0 || len(m.config) > 1<<20 {
		return nil, ErrXrayDomainTCPOriginal
	}
	image := slices.Clone(m.config)
	defer clear(image)
	d := ExecutionXrayDomainTCPDefinition{Schema: 1, PlanID: s.plan.PlanID, PlanDigest: s.plan.Digest, NetworkProfile: s.plan.NetworkProfileID,
		Domain: CloneDomainPolicyRuntimePlan(m.plan.DomainPolicy), Transport: CloneSyntheticDNSTransportPlan(m.plan.SyntheticDNS), Capture: m.spec,
		Service: cloneXraySelectedTCPService(m.service), Proof: m.proof.ref, Mapping: m.observation, PrivateEndpoint: m.private,
		ConfigSHA256: nodeDefaultSourceMaterialHash(image), NetworkIdentity: s.networkIdentity.value}
	if err := d.validate(); err != nil {
		return nil, err
	}
	if err := s.owned.MkdirAll("execution-resources", 0700); err != nil {
		return nil, executionJournalError(err)
	}
	relative, err := s.owned.MkdirTemp("execution-resources", "xd-")
	if err != nil {
		return nil, executionJournalError(err)
	}
	anchor, err := s.owned.Stat(relative)
	if err != nil || !networkPolicyPrivateDirectory(anchor) {
		return nil, executionJournalError(err)
	}
	r := &XrayDomainTCPExecutionResource{scope: s, material: m, definition: d.Clone(), relative: relative, id: filepath.Base(relative), rootPath: filepath.Join(s.root, relative), anchor: anchor}
	r.self = r
	m.resource = r
	keep := false
	defer func() {
		if !keep {
			resultErr = errors.Join(resultErr, r.closeUnpublishedFiles())
			m.resource = nil // No child/publication can exist in this lower constructor.
		}
	}()
	r.root, err = ownedfs.Open(r.rootPath)
	if err != nil {
		return nil, executionJournalError(err)
	}
	if err := r.directoryCurrent(); err != nil {
		return nil, err
	}
	// Retain the FD actually authored by the atomic writer; reopening matching
	// named bytes could adopt a same-byte replacement between write and open.
	r.config, err = r.root.WriteAtomicRetained(xrayDomainTCPConfigName, image, 0600)
	if err != nil {
		return nil, executionJournalError(err)
	}
	r.configInfo, err = r.config.Stat()
	if err != nil {
		return nil, executionJournalError(err)
	}
	r.executable, err = holdXrayDomainTCPExecutable(ctx, m)
	if err != nil {
		return nil, err
	}
	for _, path := range []string{r.rootPath, filepath.Dir(r.rootPath), s.root} {
		opened, err := openJournalDirectory(path)
		if err != nil {
			return nil, executionJournalError(err)
		}
		if err := errors.Join(syncDataplaneJournalDirectory(opened), opened.Close()); err != nil {
			return nil, executionJournalError(err)
		}
	}
	if err := errors.Join(r.filesCurrent(ctx), check()); err != nil {
		return nil, err
	}
	keep = true
	return r, nil // Still unregistered; this is NOT the public Acquire factory.
}

func (r *XrayDomainTCPExecutionResource) filesCurrent(ctx context.Context) error {
	if r == nil || r.self != r || r.descriptorsClosed.Load() || xraySelectedTCPFinite(ctx) != nil || r.root == nil || r.config == nil || r.configInfo == nil || r.executable == nil {
		return ErrXrayDomainTCPOriginal
	}
	check := func() error {
		if err := r.directoryCurrent(); err != nil {
			return err
		}
		held, heldErr := r.config.Stat()
		named, namedErr := r.root.Stat(xrayDomainTCPConfigName)
		if heldErr != nil || namedErr != nil ||
			!validNetworkPolicyReceiptFile(held) || !validNetworkPolicyReceiptFile(named) || !os.SameFile(r.configInfo, held) || !os.SameFile(held, named) ||
			held.Mode() != r.configInfo.Mode() || named.Mode() != held.Mode() || held.Size() != r.configInfo.Size() || named.Size() != held.Size() || held.Size() <= 0 || held.Size() > 1<<20 ||
			!held.ModTime().Equal(r.configInfo.ModTime()) || !named.ModTime().Equal(held.ModTime()) {
			return ErrXrayDomainTCPOriginal
		}
		return nil
	}
	if err := check(); err != nil {
		return err
	}
	data := make([]byte, int(r.configInfo.Size()))
	defer clear(data)
	if n, err := r.config.ReadAt(data, 0); err != nil || n != len(data) || nodeDefaultSourceMaterialHash(data) != r.definition.ConfigSHA256 {
		return ErrXrayDomainTCPOriginal
	}
	return errors.Join(check(), r.executable.current(ctx), ctx.Err())
}

// The held root must be the directory anchored before Open, as well as the
// directory currently named by rootPath. Matching config bytes/inodes inside
// a different held root cannot close an A->B(Open)->A directory replacement.
func (r *XrayDomainTCPExecutionResource) directoryCurrent() error {
	if r == nil || r.self != r || r.root == nil || r.anchor == nil || r.descriptorsClosed.Load() {
		return ErrXrayDomainTCPOriginal
	}
	held, heldErr := r.root.RootInfo()
	named, namedErr := os.Lstat(r.rootPath)
	if heldErr != nil || namedErr != nil || !networkPolicyPrivateDirectory(held) || !networkPolicyPrivateDirectory(named) ||
		!os.SameFile(r.anchor, held) || !os.SameFile(held, named) {
		return ErrXrayDomainTCPOriginal
	}
	return nil
}

// Private unpublished-constructor compensation ONLY. The eventual published
// Close must first join its original child/capture and journal protocol.
func (r *XrayDomainTCPExecutionResource) closeUnpublishedFiles() error {
	if r == nil || r.self != r || r.child != nil {
		return ErrXrayDomainTCPOriginal
	}
	if r.descriptorsClosed.Swap(true) {
		return r.descriptorsErr
	}
	if r.config != nil {
		r.descriptorsErr = errors.Join(r.descriptorsErr, r.config.Close())
	}
	if r.executable != nil {
		r.descriptorsErr = errors.Join(r.descriptorsErr, r.executable.file.Close())
	}
	if r.root != nil {
		r.descriptorsErr = errors.Join(r.descriptorsErr, r.root.Close())
	}
	return r.descriptorsErr
}

type xrayDomainTCPExecutable struct {
	file         *os.File
	info         os.FileInfo
	path, sha256 string
}

// Caller retains material.mu. This holds only the genuine dispatcher's
// resolved original ELF; it is not a launcher and grants no version/Start.
func holdXrayDomainTCPExecutable(ctx context.Context, m *XrayDomainTCPOperationMaterial) (_ *xrayDomainTCPExecutable, resultErr error) {
	if m == nil || m.self != m || xraySelectedTCPFinite(ctx) != nil {
		return nil, ErrXrayDomainTCPOriginal
	}
	named, err := os.Lstat(m.binary)
	if err != nil || !named.Mode().IsRegular() || named.Mode().Perm()&0022 != 0 || named.Mode().Perm()&0111 == 0 || named.Size() <= 0 || named.Size() > xrayDomainTCPExecutableLimit {
		return nil, ErrXrayDomainTCPOriginal
	}
	file, err := os.Open(m.binary)
	if err != nil {
		return nil, ErrXrayDomainTCPOriginal
	}
	keep := false
	defer func() {
		if !keep {
			resultErr = errors.Join(resultErr, file.Close())
		}
	}()
	info, err := file.Stat()
	if err != nil || !os.SameFile(named, info) || xraySelectedTCPELFHeader(file, info.Size()) != nil {
		return nil, ErrXrayDomainTCPOriginal
	}
	p := &xrayDomainTCPExecutable{file: file, info: info, path: m.binary}
	p.sha256, err = p.hash(ctx)
	if err != nil || p.current(ctx) != nil {
		return nil, ErrXrayDomainTCPOriginal
	}
	keep = true
	return p, nil
}

func (p *xrayDomainTCPExecutable) hash(ctx context.Context) (string, error) {
	if p == nil || p.file == nil || p.info == nil || xraySelectedTCPFinite(ctx) != nil || p.info.Size() <= 0 || p.info.Size() > xrayDomainTCPExecutableLimit {
		return "", ErrXrayDomainTCPOriginal
	}
	hash := sha256.New()
	var block [32 << 10]byte
	for offset := int64(0); offset < p.info.Size(); {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		want := min(int64(len(block)), p.info.Size()-offset)
		n, err := p.file.ReadAt(block[:want], offset)
		if int64(n) != want || err != nil && err != io.EOF {
			return "", ErrXrayDomainTCPOriginal
		}
		_, _ = hash.Write(block[:n])
		offset += int64(n)
	}
	return hex.EncodeToString(hash.Sum(nil)), ctx.Err()
}

func (p *xrayDomainTCPExecutable) current(ctx context.Context) error {
	if p == nil || p.file == nil || p.info == nil || xraySelectedTCPFinite(ctx) != nil {
		return ErrXrayDomainTCPOriginal
	}
	check := func() error {
		named, err := os.Lstat(p.path)
		held, heldErr := p.file.Stat()
		if err != nil || heldErr != nil || !named.Mode().IsRegular() || !os.SameFile(p.info, named) || !os.SameFile(p.info, held) ||
			named.Mode() != p.info.Mode() || held.Mode() != p.info.Mode() || named.Size() != p.info.Size() || held.Size() != p.info.Size() ||
			!named.ModTime().Equal(p.info.ModTime()) || !held.ModTime().Equal(p.info.ModTime()) {
			return ErrXrayDomainTCPOriginal
		}
		return nil
	}
	if err := check(); err != nil {
		return err
	}
	hash, err := p.hash(ctx)
	if err != nil || hash != p.sha256 {
		return ErrXrayDomainTCPOriginal
	}
	return errors.Join(check(), ctx.Err())
}
