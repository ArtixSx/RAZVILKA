package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
)

type mihomoSameBootPolicyKey struct{}

// The callback's original cursor retains the root, permanent writer marker
// and receipt FD through every session/retry. Parsed receipt bytes never
// construct it. Only save's actual authored descriptor advances the receipt.
type mihomoSameBootPolicy struct {
	self                     *mihomoSameBootPolicy
	owner                    *mihomoSameBootCleanup
	path                     string
	root                     *os.Root
	info                     os.FileInfo
	marker, record           *mihomoColdRecord
	candidatePins            []*mihomoColdRecord
	closed, pending, unknown bool
	closeErr                 error
	fault                    func() error // Private refusal-only cut after the actual writer ACK.
}

func holdMihomoSameBootPolicy(ctx context.Context, o *mihomoSameBootCleanup, generation string, original mihomoColdRuntimeArchive) (_ *mihomoSameBootPolicy, resultErr error) {
	if o == nil || o.self != o || o.inputs == nil || o.read == nil || o.read.proxy == nil {
		return nil, ErrPolicyAdditionUnknown
	}
	if err := o.inputs.current(o.inputs.ctx); err != nil {
		return nil, err
	}
	if o.policy != nil || validateMihomoColdRuntime(o.read.proxy, o.inputs.definition, original) != nil {
		return nil, ErrPolicyAdditionUnknown
	}
	path, err := o.read.proxy.policyGenerationRoot(generation)
	if err != nil {
		return nil, err
	}
	relative := filepath.Join("policy-generations", generation)
	expected := original.Files[filepath.Join(relative, policyAdditionFile)]
	if len(expected) == 0 || !bytes.Equal(original.Files[filepath.Join(relative, policyAdditionLock)], []byte(policyAdditionMarker)) {
		return nil, ErrPolicyAdditionUnknown
	}
	if err := validateBootRetirementReceipt(expected, path, o.inputs.definition.NetworkIdentity.BootID, &o.inputs.definition.Policy, false); err != nil {
		return nil, err
	}
	var initial policyAdditionDocument
	if json.Unmarshal(expected, &initial) != nil {
		return nil, ErrPolicyAdditionUnknown
	}
	for _, step := range initial.Steps {
		if step.State != "added" && step.State != "removed" {
			return nil, ErrPolicyAdditionUnknown
		}
	}
	c := &mihomoSameBootPolicy{owner: o, path: path}
	c.self = c
	keep := false
	defer func() {
		if !keep {
			resultErr = errors.Join(resultErr, c.close())
		}
	}()
	c.root, err = openBootRetirementRoot(path)
	if err != nil {
		return nil, err
	}
	c.info, err = c.root.Stat(".")
	if err != nil {
		return nil, err
	}
	if executionHistoryIdentity(c.info) != original.Directories[relative] {
		return nil, ErrPolicyAdditionUnknown
	}
	c.marker, err = openMihomoColdRecord(c.root, policyAdditionLock, []byte(policyAdditionMarker))
	if err != nil {
		return nil, err
	}
	c.record, err = openMihomoColdRecord(c.root, policyAdditionFile, expected)
	if err != nil {
		return nil, err
	}
	if mihomoColdFileIdentity(c.marker.info) != original.FileIdentities[filepath.Join(relative, policyAdditionLock)] || mihomoColdFileIdentity(c.record.info) != original.FileIdentities[filepath.Join(relative, policyAdditionFile)] {
		return nil, ErrPolicyAdditionUnknown
	}
	if err := errors.Join(sameBootPolicyRecordIdentity(c.marker), sameBootPolicyRecordIdentity(c.record), o.inputs.current(o.inputs.ctx)); err != nil {
		return nil, err
	}
	o.policy = c
	keep = true
	return c, nil
}

func (c *mihomoSameBootPolicy) currentRoot() error {
	if c == nil || c.self != c || c.closed || c.unknown || c.root == nil || c.owner == nil || c.owner.inputs == nil {
		return errors.Join(ErrPolicyAdditionUnknown, sameBootPolicyCloseError(c))
	}
	if err := c.owner.inputs.current(c.owner.inputs.ctx); err != nil {
		return err
	}
	named, e1 := os.Lstat(c.path)
	held, e2 := c.root.Stat(".")
	if e1 != nil || e2 != nil || !networkPolicyPrivateDirectory(named) || !networkPolicyPrivateDirectory(held) || !os.SameFile(c.info, named) || !os.SameFile(c.info, held) {
		return errors.Join(ErrPolicyAdditionUnknown, e1, e2)
	}
	for _, r := range append([]*mihomoColdRecord{c.marker, c.record}, c.candidatePins...) {
		if r == nil {
			return ErrPolicyAdditionUnknown
		}
		if err := errors.Join(r.current(), sameBootPolicyRecordIdentity(r)); err != nil {
			return err
		}
	}
	return c.closeErr
}

// No promoted path can be selected here: the parent is the ORIGINAL held
// transaction and the sole child name is compiled. The complete candidate ACK
// and every added step are retained before even the sidecar signal is issued.
func holdMihomoSameBootCandidatePolicy(ctx context.Context, o *mihomoSameBootCleanup) (_ *mihomoSameBootPolicy, resultErr error) {
	if o == nil || o.self != o || o.inputs == nil || !o.inputs.candidate || o.read == nil || o.read.proxy == nil || o.policy != nil {
		return nil, ErrPolicyAdditionUnknown
	}
	i := o.inputs
	if err := i.current(i.ctx); err != nil {
		return nil, err
	}
	for _, name := range []string{o.read.proxy.policyBindingPath(), o.read.proxy.policyPath()} {
		if _, err := os.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			return nil, errors.Join(ErrPolicyAdditionUnknown, err)
		}
	}
	c := &mihomoSameBootPolicy{owner: o, path: filepath.Join(i.statePath, "transactions", i.before.PlanID, "mihomo")}
	c.self = c
	keep := false
	defer func() {
		if !keep {
			resultErr = errors.Join(resultErr, c.close())
		}
	}()
	var err error
	c.root, err = openRetirementChild(i.roots[2], "mihomo")
	if err != nil {
		return nil, err
	}
	c.info, err = c.root.Stat(".")
	if err != nil {
		return nil, err
	}
	for _, name := range []string{"policy.staged.json", "policy-additions.json"} {
		r, err := openMihomoColdRecord(c.root, name, nil)
		if err != nil {
			return nil, err
		}
		c.candidatePins = append(c.candidatePins, r)
	}
	var staged PolicyState
	decoder := json.NewDecoder(bytes.NewReader(c.candidatePins[0].data))
	decoder.DisallowUnknownFields()
	if nfqws2ManagedUniqueJSON(c.candidatePins[0].data) != nil || decoder.Decode(&staged) != nil || decoder.Decode(new(any)) != io.EOF || !reflect.DeepEqual(staged, i.definition.Policy) {
		return nil, ErrPolicyAdditionUnknown
	}
	receipt, err := o.read.proxy.readCandidatePolicyReceipt(c.path, i.definition.Policy)
	if err != nil || receipt.Phase != "complete" || receipt.Generation != "" || receipt.RestorationGeneration != "" || receipt.NoAdditions || receipt.Boot != i.definition.NetworkIdentity.BootID {
		return nil, errors.Join(ErrPolicyAdditionUnknown, err)
	}
	c.marker, err = openMihomoColdRecord(c.root, policyAdditionLock, []byte(policyAdditionMarker))
	if err != nil {
		return nil, err
	}
	c.record, err = openMihomoColdRecord(c.root, policyAdditionFile, nil)
	if err != nil {
		return nil, err
	}
	if err := validateBootRetirementReceipt(c.record.data, c.path, i.definition.NetworkIdentity.BootID, &i.definition.Policy, false); err != nil {
		return nil, err
	}
	var doc policyAdditionDocument
	if json.Unmarshal(c.record.data, &doc) != nil {
		return nil, ErrPolicyAdditionUnknown
	}
	for _, step := range doc.Steps {
		if step.State != "added" {
			return nil, ErrPolicyAdditionUnknown
		}
	}
	if err := c.currentRoot(); err != nil {
		return nil, err
	}
	o.policy = c
	keep = true
	return c, nil
}

func (c *mihomoSameBootPolicy) check(ctx context.Context, s *policyAdditionSession) error {
	if c == nil || c.self != c || c.closed || c.unknown || c.root == nil || c.info == nil || c.marker == nil || c.record == nil || c.owner == nil || c.owner.self != c.owner || c.owner.inputs == nil || c.owner.policy != c || ctx == nil || ctx.Value(mihomoSameBootPolicyKey{}) != c || s == nil || s.self != s || s.sameBootClosed || s.root == nil || s.lock == nil || s.created || s.path != c.path || !reflect.DeepEqual(s.state, c.owner.inputs.definition.Policy) {
		return errors.Join(ErrPolicyAdditionUnknown, sameBootPolicyCloseError(c))
	}
	if err := c.owner.inputs.current(c.owner.inputs.ctx); err != nil {
		return err
	}
	if c.owner.control == nil || c.owner.cleanup == nil || !c.owner.control.MatchesControlRoot(c.owner.controlRoot) {
		return ErrPolicyAdditionUnknown
	}
	if err := c.owner.control.CurrentForCleanupOperation(ctx, c.owner.cleanup); err != nil {
		return err
	}
	named, e1 := os.Lstat(c.path)
	held, e2 := c.root.Stat(".")
	session, e3 := s.root.RootInfo()
	lock, e4 := s.lock.Stat()
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || !networkPolicyPrivateDirectory(named) || !networkPolicyPrivateDirectory(held) || !os.SameFile(c.info, named) || !os.SameFile(c.info, held) || !os.SameFile(c.info, session) || c.marker == nil || !os.SameFile(c.marker.info, lock) {
		return errors.Join(ErrPolicyAdditionUnknown, e1, e2, e3, e4)
	}
	if err := errors.Join(c.marker.current(), sameBootPolicyRecordIdentity(c.marker), c.record.current(), sameBootPolicyRecordIdentity(c.record)); err != nil {
		return err
	}
	if err := c.currentRoot(); err != nil {
		return err
	}
	if s.sameBoot != nil && s.sameBoot != c {
		return ErrPolicyAdditionUnknown
	}
	s.sameBoot = c
	return c.closeErr
}

func closeMihomoSameBootPolicySession(s *policyAdditionSession) {
	c := s.sameBoot
	if c == nil {
		return
	}
	if s.self != s || c.self != c {
		return
	}
	if !s.sameBootClosed {
		s.sameBootClosed = true
		// The original lock descriptor is not duplicated. Closing it releases
		// its flock and reports the real close result; avoid the legacy void
		// unlock/close closure which would discard that acknowledgment.
		c.closeErr = errors.Join(c.closeErr, s.lock.Close(), s.root.Close())
	}
}
func sameBootPolicyCloseError(c *mihomoSameBootPolicy) error {
	if c != nil {
		return c.closeErr
	}
	return nil
}

func mihomoSameBootPolicyCursor(ctx context.Context) (*mihomoSameBootPolicy, bool) {
	if ctx == nil {
		return nil, false
	}
	raw := ctx.Value(mihomoSameBootPolicyKey{})
	if raw == nil {
		return nil, false
	}
	c, _ := raw.(*mihomoSameBootPolicy)
	return c, true
}
func loadMihomoSameBootPolicy(ctx context.Context, s *policyAdditionSession) (bool, error) {
	c, present := mihomoSameBootPolicyCursor(ctx)
	if !present {
		return false, nil
	}
	if c == nil || ctx.Value(wgCommonWriterKey{}) != nil {
		return true, ErrPolicyAdditionUnknown
	}
	if err := c.check(ctx, s); err != nil {
		return true, err
	}
	if c.pending {
		if err := errors.Join(c.record.file.Sync(), s.root.Sync(), c.check(ctx, s)); err != nil {
			return true, err
		}
		c.pending = false
	}
	return true, s.decodeDocument(ctx, bytes.Clone(c.record.data))
}
func saveMihomoSameBootPolicy(ctx context.Context, s *policyAdditionSession) (bool, error) {
	c, present := mihomoSameBootPolicyCursor(ctx)
	if !present {
		return false, nil
	}
	if c == nil || ctx.Value(wgCommonWriterKey{}) != nil {
		return true, ErrPolicyAdditionUnknown
	}
	if err := c.check(ctx, s); err != nil {
		return true, err
	}
	if s.doc.Phase != "active" || s.doc.PromotionTarget != "" {
		return true, ErrPolicyAdditionUnknown
	}
	if err := s.validatePolicyDocument(ctx); err != nil {
		return true, errors.Join(ErrPolicyAdditionUnknown, err)
	}
	s.doc.Checksum = policyAdditionChecksum(s.doc)
	data, err := json.Marshal(s.doc)
	if err != nil || len(data) > policyAdditionMaxBytes {
		return true, errors.Join(ErrPolicyAdditionReceipt, err)
	}
	file, attempted, err := s.root.WriteAtomicRetainedAttempted(policyAdditionFile, data, 0600)
	if file == nil {
		if attempted {
			c.unknown = true
		}
		return true, errors.Join(ErrPolicyAdditionReceipt, err)
	}
	// Transfer custody BEFORE any directory sync/close/error. A later retry
	// uses this exact authored inode; it cannot reopen and adopt its pathname.
	old := c.record.file
	c.record.file, c.record.data = file, bytes.Clone(data)
	var statErr error
	c.record.info, statErr = file.Stat()
	c.pending = true
	c.closeErr = errors.Join(c.closeErr, old.Close())
	err = errors.Join(err, statErr, c.closeErr, s.root.Sync(), c.check(ctx, s))
	if err == nil {
		c.pending = false
		s.unsynced = false
	}
	if c.fault != nil {
		faultErr := c.fault()
		if faultErr != nil {
			c.pending = true
		}
		err = errors.Join(err, faultErr)
	}
	return true, err
}
func (c *mihomoSameBootPolicy) close() error {
	if c == nil || c.self != c {
		return ErrPolicyAdditionUnknown
	}
	if !c.closed {
		c.closed = true
		for _, r := range []*mihomoColdRecord{c.marker, c.record} {
			if r != nil {
				c.closeErr = errors.Join(c.closeErr, r.file.Close())
				clear(r.data)
			}
		}
		for _, r := range c.candidatePins {
			c.closeErr = errors.Join(c.closeErr, r.file.Close())
			clear(r.data)
		}
		if c.root != nil {
			c.closeErr = errors.Join(c.closeErr, c.root.Close())
		}
	}
	return c.closeErr
}
