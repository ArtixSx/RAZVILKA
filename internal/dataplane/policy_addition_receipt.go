package dataplane

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

var (
	ErrPolicyAdditionReceipt = errors.New("policy addition receipt unavailable or mismatched")
	ErrPolicyAdditionUnknown = errors.New("policy addition or cleanup result unknown; reconciliation required")
	ErrPolicyAdditionBusy    = errors.New("policy addition generation is busy")
	ErrPolicyAdditionExists  = errors.New("policy addition generation already exists; new generation required")
)

const policyAdditionFile = "policy-additions-v1.json"
const policyAdditionLock = ".policy-additions-v1.lock"
const policyAdditionMarker = "RAZVILKA policy addition lock v1\n"
const policyAdditionMaxBytes = 2 << 20

type policyAdditionStep struct {
	Add    []string `json:"add"`
	Delete []string `json:"delete"`
	State  string   `json:"state"`
	// Schema 2 only. Omitting these fields preserves schema 1 bytes/checksums.
	Tool  PolicyEffectTool `json:"tool,omitempty"`
	Needs []int            `json:"needs,omitempty"`
}
type policyAdditionDocument struct {
	Schema          int                  `json:"schema"`
	ID              string               `json:"id"`
	Boot            string               `json:"boot"`
	PolicyHash      string               `json:"policy_sha256"`
	RootHash        string               `json:"root_sha256"`
	Phase           string               `json:"phase"`
	PromotionTarget string               `json:"promotion_target,omitempty"`
	Steps           []policyAdditionStep `json:"steps"`
	Checksum        string               `json:"receipt_sha256,omitempty"`
	// Schema 2 only: this is the trusted complete mixed plan, never argv authority.
	Generation  string `json:"generation,omitempty"`
	EffectsHash string `json:"effects_sha256,omitempty"`
}

// Status is non-secret metadata, not new permission to apply/restore a route.
type PolicyAdditionStatus struct {
	ID                                   string
	Complete, Removed, Unknown, Promoted bool
	Added, Pending, Cleaned              int
}

type policyAdditionOptions struct {
	boot func() (string, error)
	// Test-only process/crash boundary injection. Production never sets it.
	fault func(string, int) error
}

type policyAdditionSession struct {
	root     *ownedfs.Root
	lock     *os.File // The actual still-held permanent writer marker.
	unlocked func()
	path     string
	state    PolicyState
	doc      policyAdditionDocument
	options  policyAdditionOptions
	// unsynced: the file holds a settled state not yet forced to disk.
	unsynced bool
	// created: this session's exclusive create made the lock file.
	created bool
}

func policyAdditionRootHash(path string) string {
	path = filepath.Clean(path)
	if runtime.GOOS == "windows" {
		path = strings.ToLower(path)
	}
	return routeidentity.Hash([]byte("policy-addition-root-v1\x00" + path))
}

func policyAdditionHash(state PolicyState) string {
	data, _ := json.Marshal(state)
	return routeidentity.Hash(data)
}
func policyAdditionChecksum(doc policyAdditionDocument) string {
	doc.Checksum = ""
	data, _ := json.Marshal(doc)
	return routeidentity.Hash(data)
}

func policyAdditionExpected(state PolicyState) ([]policyAdditionStep, error) {
	rules, err := kernelRulesForPolicy(state)
	if err != nil || len(rules) == 0 || !proxyFirewallInterface.MatchString(state.Interface) {
		return nil, ErrPolicyAdditionReceipt
	}
	var steps []policyAdditionStep
	for _, family := range []int{4, 6} {
		metric := "0"
		if family == 6 {
			metric = "1024"
		}
		add := []string{"route", "add", "default", "dev", state.Interface, "table", strconv.Itoa(state.Table), "proto", "boot", "metric", metric}
		del := slicesPolicyCommand(add, "del")
		if family == 6 {
			add = append([]string{"-6"}, add...)
			del = append([]string{"-6"}, del...)
		}
		steps = append(steps, policyAdditionStep{Add: add, Delete: del, State: "planned"})
	}
	for _, rule := range rules {
		steps = append(steps, policyAdditionStep{Add: kernelRuleArgs("add", rule), Delete: kernelRuleArgs("del", rule), State: "planned"})
	}
	return steps, nil
}

func slicesPolicyCommand(args []string, action string) []string {
	copy := append([]string{}, args...)
	offset := 1
	if len(copy) > 0 && copy[0] == "-6" {
		offset = 2
	}
	copy[offset] = action
	return copy
}

func openPolicyAdditionSession(ctx context.Context, state PolicyState, path string, options policyAdditionOptions) (*policyAdditionSession, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrPolicyAdditionReceipt
	}
	if _, err := policyAdditionExpected(state); err != nil {
		return nil, err
	}
	s, err := openPolicyAdditionRootSession(ctx, path, options)
	if err != nil {
		return nil, err
	}
	s.state = state
	return s, nil
}

// Both receipt modes use the same anchored root, permanent lock and boot source.
func openPolicyAdditionRootSession(ctx context.Context, path string, options policyAdditionOptions) (*policyAdditionSession, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrPolicyAdditionReceipt
	}
	// ownedfs deliberately rejects Stat("."): exported targets must be below
	// the root. Check root permissions before its anchored, SameFile open.
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return nil, ErrPolicyAdditionReceipt
	}
	root, err := ownedfs.Open(path)
	if err != nil {
		return nil, ErrPolicyAdditionReceipt
	}
	unlock, lock, created, err := lockPolicyAdditionRoot(root)
	if err != nil {
		root.Close()
		return nil, err
	}
	if options.boot == nil {
		options.boot = func() (string, error) { return (&ProxyTunnelAdapter{}).currentBootIdentity() }
	}
	return &policyAdditionSession{root: root, lock: lock, unlocked: unlock, path: path, options: options, created: created}, nil
}

func lockPolicyAdditionRoot(root *ownedfs.Root) (func(), *os.File, bool, error) {
	file, err := openNFQWS2LockFile(root, policyAdditionLock, true)
	created := err == nil
	if errors.Is(err, os.ErrExist) {
		file, err = openNFQWS2LockFile(root, policyAdditionLock, false)
	}
	if err != nil {
		return nil, nil, false, ErrPolicyAdditionReceipt
	}
	keep := false
	defer func() {
		if !keep {
			file.Close()
		}
	}()
	info, err := file.Stat()
	if err != nil || !validCloudflareScanLockFile(info) {
		return nil, nil, false, ErrPolicyAdditionReceipt
	}
	if err := lockCloudflareScanFile(file); err != nil {
		return nil, nil, false, ErrPolicyAdditionBusy
	}
	current, err := root.Stat(policyAdditionLock)
	if err != nil || !os.SameFile(info, current) {
		return nil, nil, false, ErrPolicyAdditionReceipt
	}
	if created {
		if info.Size() != 0 {
			return nil, nil, false, ErrPolicyAdditionReceipt
		}
		if n, err := file.WriteString(policyAdditionMarker); err != nil || n != len(policyAdditionMarker) || file.Sync() != nil {
			return nil, nil, false, ErrPolicyAdditionReceipt
		}
		if runtime.GOOS == "linux" && root.Sync() != nil {
			return nil, nil, false, ErrPolicyAdditionReceipt
		}
	} else {
		data, err := io.ReadAll(io.LimitReader(file, int64(len(policyAdditionMarker)+1)))
		if err != nil || string(data) != policyAdditionMarker {
			return nil, nil, false, ErrPolicyAdditionReceipt
		}
	}
	keep = true
	return func() { unlockCloudflareScanFile(file); file.Close() }, file, created, nil
}

func (s *policyAdditionSession) close() { s.unlocked(); s.root.Close() }
func (s *policyAdditionSession) fault(point string, index int) error {
	if s.options.fault != nil {
		return s.options.fault(point, index)
	}
	return nil
}
func (s *policyAdditionSession) save(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if ctx.Value(wgCommonWriterKey{}) != nil && ctx.Value(wgOperationOwnerKey{}) != nil {
		if err := checkWGCommonBeforePublication(ctx, s); err != nil {
			return err
		}
		s.doc.Checksum = policyAdditionChecksum(s.doc)
		data, err := json.Marshal(s.doc)
		if err != nil || len(data) > policyAdditionMaxBytes {
			return ErrPolicyAdditionReceipt
		}
		file, err := s.root.WriteAtomicRetained(policyAdditionFile, data, 0600)
		if err != nil {
			return err
		}
		defer file.Close()
		return saveWGCommonOriginal(ctx, s, file, nil)
	}
	s.doc.Checksum = policyAdditionChecksum(s.doc)
	data, err := json.Marshal(s.doc)
	if err != nil || len(data) > policyAdditionMaxBytes {
		return ErrPolicyAdditionReceipt
	}
	if err := s.root.WriteAtomic(policyAdditionFile, data, 0600); err != nil {
		return ErrPolicyAdditionReceipt
	}
	if runtime.GOOS == "linux" && s.root.Sync() != nil {
		return ErrPolicyAdditionReceipt
	}
	s.unsynced = false
	return ctx.Err()
}

// saveSettled records a state reached after the kernel confirmed a step
// ("added" or "removed"). Every save writes the whole document, so the next
// durable save carries it, and flush forces the last one. A crash before then
// leaves the previous intent, which recovery already treats as unknown. On a
// USB drive of a Keenetic each fsync costs about half a second, so halving
// them keeps a 60-selector policy inside its activation and rollback budgets.
func (s *policyAdditionSession) saveSettled(ctx context.Context) error {
	if runtime.GOOS != "linux" || ctx.Value(wgCommonWriterKey{}) != nil && ctx.Value(wgOperationOwnerKey{}) != nil {
		return s.save(ctx)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.doc.Checksum = policyAdditionChecksum(s.doc)
	data, err := json.Marshal(s.doc)
	if err != nil || len(data) > policyAdditionMaxBytes {
		return ErrPolicyAdditionReceipt
	}
	if err := s.root.WriteAtomicUnsynced(policyAdditionFile, data, 0600); err != nil {
		return ErrPolicyAdditionReceipt
	}
	s.unsynced = true
	return ctx.Err()
}

// flush makes a settled state durable before the session reports it. It runs
// even after the caller's context ended: the kernel state already changed.
const policyReceiptFlushBudget = 30 * time.Second

func (s *policyAdditionSession) flush(ctx context.Context) error {
	if !s.unsynced {
		return nil
	}
	flushCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), policyReceiptFlushBudget)
	defer cancel()
	return s.save(flushCtx)
}
func (s *policyAdditionSession) load(ctx context.Context) error {
	if err := s.loadDocument(ctx); err != nil {
		return err
	}
	return s.validatePolicyDocument(ctx)
}

// Pure comparison with the policy/owner already bound by this session.
func (s *policyAdditionSession) validatePolicyDocument(ctx context.Context) error {
	wanted, err := policyAdditionExpected(s.state)
	if err != nil {
		return err
	}
	if s.doc.Schema != 1 || s.doc.Generation != "" || s.doc.EffectsHash != "" || s.doc.PolicyHash != policyAdditionHash(s.state) || len(s.doc.Steps) != len(wanted) {
		return ErrPolicyAdditionReceipt
	}
	if err := s.validateIdentity(ctx); err != nil {
		return err
	}
	for i, step := range s.doc.Steps {
		if step.Tool != "" || len(step.Needs) != 0 || !reflect.DeepEqual(step.Add, wanted[i].Add) || !reflect.DeepEqual(step.Delete, wanted[i].Delete) || !validPolicyAdditionStepState(step.State) {
			return ErrPolicyAdditionReceipt
		}
	}
	return ctx.Err()
}

func (s *policyAdditionSession) loadDocument(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	info, err := s.root.Stat(policyAdditionFile)
	if errors.Is(err, os.ErrNotExist) {
		return os.ErrNotExist
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > policyAdditionMaxBytes || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return ErrPolicyAdditionReceipt
	}
	data, err := s.root.ReadLimited(policyAdditionFile, policyAdditionMaxBytes)
	if err != nil {
		return ErrPolicyAdditionReceipt
	}
	return s.decodeDocument(ctx, data)
}

// Pure decoder; retained observation supplies its own nonblocking held read.
func (s *policyAdditionSession) decodeDocument(ctx context.Context, data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&s.doc) != nil || d.Decode(new(any)) != io.EOF {
		return ErrPolicyAdditionReceipt
	}
	canonical, _ := json.Marshal(s.doc)
	var compact bytes.Buffer
	if json.Compact(&compact, data) != nil || !bytes.Equal(compact.Bytes(), canonical) || s.doc.Checksum != policyAdditionChecksum(s.doc) {
		return ErrPolicyAdditionReceipt
	}
	return ctx.Err()
}

func (s *policyAdditionSession) validateIdentity(ctx context.Context) error {
	if len(s.doc.ID) != 32 || s.doc.RootHash != policyAdditionRootHash(s.path) {
		return ErrPolicyAdditionReceipt
	}
	if _, err := hex.DecodeString(s.doc.ID); err != nil {
		return ErrPolicyAdditionReceipt
	}
	boot, err := s.options.boot()
	if err != nil || boot == "" || s.doc.Boot != boot {
		return ErrPolicyAdditionUnknown
	}
	switch s.doc.Phase {
	case "active":
		if s.doc.PromotionTarget != "" {
			return ErrPolicyAdditionReceipt
		}
	case "promotion-intent", "promoted":
		if len(s.doc.PromotionTarget) != 64 {
			return ErrPolicyAdditionReceipt
		}
	default:
		return ErrPolicyAdditionReceipt
	}
	return ctx.Err()
}

func validPolicyAdditionStepState(state string) bool {
	switch state {
	case "planned", "intent", "added", "cleanup-intent", "removed":
		return true
	}
	return false
}

func (s *policyAdditionSession) status() PolicyAdditionStatus {
	r := PolicyAdditionStatus{ID: s.doc.ID, Complete: s.doc.Phase == "active", Removed: true, Promoted: s.doc.Phase == "promoted"}
	for _, step := range s.doc.Steps {
		if step.State != "added" {
			r.Complete = false
		}
		switch step.State {
		case "added":
			r.Added++
			r.Removed = false
		case "intent", "cleanup-intent":
			r.Pending++
			r.Unknown = true
			r.Removed = false
		case "removed":
			r.Cleaned++
		}
	}
	if s.doc.Phase != "active" {
		r.Unknown = s.doc.Phase != "promoted"
		r.Complete = false
		r.Removed = false
	}
	return r
}

// applyPolicyWithReceipt uses CORE's single policy parser/primitive. The
// wrapper intercepts only argv derived by that primitive, never rewrites it.
// One root is one immutable generation; retry never overwrites old receipts.
func applyPolicyWithReceipt(ctx context.Context, runner NFQWS2Runner, ip string, state PolicyState, root string) error {
	return applyPolicyAddition(ctx, runner, ip, state, root, policyAdditionOptions{})
}
func applyPolicyAddition(ctx context.Context, runner NFQWS2Runner, ip string, state PolicyState, root string, options policyAdditionOptions) (result error) {
	if runner == nil || ip == "" {
		return ErrPolicyAdditionReceipt
	}
	s, err := openPolicyAdditionSession(ctx, state, root, options)
	if err != nil {
		return err
	}
	defer s.close()
	defer func() { result = errors.Join(result, s.flush(ctx)) }()
	if err := s.load(ctx); !errors.Is(err, os.ErrNotExist) {
		if err != nil {
			return err
		}
		return ErrPolicyAdditionExists
	}
	steps, err := policyAdditionExpected(state)
	if err != nil {
		return err
	}
	boot, err := s.options.boot()
	if err != nil || boot == "" {
		return ErrPolicyAdditionReceipt
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return ErrPolicyAdditionReceipt
	}
	s.doc = policyAdditionDocument{Schema: 1, ID: hex.EncodeToString(nonce[:]), Boot: boot, PolicyHash: policyAdditionHash(state), RootHash: policyAdditionRootHash(root), Phase: "active", Steps: steps}
	if err := s.save(ctx); err != nil {
		return err
	}
	wrapper := &policyAdditionRunner{base: runner, ip: ip, session: s}
	applyErr := applyRecordedPolicy(ctx, wrapper, ip, state)
	if applyErr != nil {
		return errors.Join(applyErr, wrapper.failure, func() error {
			if s.status().Unknown {
				return ErrPolicyAdditionUnknown
			}
			return nil
		}())
	}
	if err := errors.Join(wrapper.failure, ctx.Err()); err != nil {
		return err
	}
	if !s.status().Complete {
		return ErrPolicyAdditionUnknown
	}
	return nil
}

type policyAdditionRunner struct {
	base    NFQWS2Runner
	ip      string
	session *policyAdditionSession
	failure error
}

func (r *policyAdditionRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if name != r.ip {
		return r.base.Run(ctx, name, args...)
	}
	plain := args
	if len(plain) > 0 && plain[0] == "-6" {
		plain = plain[1:]
	}
	for i, step := range r.session.doc.Steps {
		if reflect.DeepEqual(args, step.Add) {
			return r.add(ctx, i, args)
		}
		if reflect.DeepEqual(args, step.Delete) {
			return r.remove(ctx, i, args)
		}
	}
	// CORE includes readback-derived scope attributes in default deletion.
	// Compare against CORE's reconstructed full selector; no second parser.
	if len(plain) > 2 && plain[0] == "route" && plain[1] == "del" && plain[2] == "default" {
		for i := 0; i < 2; i++ {
			if r.session.doc.Steps[i].State == "added" {
				family := 4
				if i == 1 {
					family = 6
				}
				derived, err := recordedDefaultRoute(ctx, r.base, r.ip, r.session.state, family)
				if err == nil && len(derived) > 0 && reflect.DeepEqual(args, derived) {
					return r.remove(ctx, i, args)
				}
			}
		}
	}
	if len(plain) > 1 && (plain[0] == "route" || plain[0] == "rule") && (plain[1] == "add" || plain[1] == "del" || plain[1] == "replace" || plain[1] == "flush") {
		return nil, ErrPolicyAdditionReceipt
	}
	return r.base.Run(ctx, name, args...)
}
func (r *policyAdditionRunner) add(ctx context.Context, index int, args []string) ([]byte, error) {
	s := r.session
	if s.doc.Steps[index].State != "planned" {
		return nil, ErrPolicyAdditionUnknown
	}
	present, err := policyAdditionPresence(ctx, r.base, r.ip, s.state, index)
	if err != nil || present != 0 {
		return nil, errors.Join(ErrPolicyAdditionReceipt, err)
	}
	s.doc.Steps[index].State = "intent"
	if err := s.save(ctx); err != nil {
		r.failure = err
		return nil, err
	}
	if err := s.fault("intent", index); err != nil {
		r.failure = err
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out, err := r.base.Run(ctx, r.ip, args...)
	if err != nil {
		r.failure = errors.Join(r.failure, ErrPolicyAdditionUnknown)
		return out, err
	}
	if err := s.fault("add", index); err != nil {
		r.failure = err
		return out, err
	}
	s.doc.Steps[index].State = "added"
	if err := s.saveSettled(ctx); err != nil {
		s.doc.Steps[index].State = "intent"
		r.failure = err
		return out, err
	}
	if err := s.fault("added", index); err != nil {
		r.failure = err
		return out, err
	}
	return out, nil
}
func (r *policyAdditionRunner) remove(ctx context.Context, index int, args []string) ([]byte, error) {
	s := r.session
	if s.doc.Steps[index].State != "added" {
		return nil, ErrPolicyAdditionUnknown
	}
	if index < 2 && s.hasUnsettledRules() {
		return nil, ErrPolicyAdditionUnknown
	}
	present, err := policyAdditionPresence(ctx, r.base, r.ip, s.state, index)
	if err != nil || present > 1 {
		return nil, errors.Join(ErrPolicyAdditionUnknown, err)
	}
	if index < 2 {
		if err := assertPolicyAdditionDefaultsUnreferenced(ctx, r.base, r.ip, s.state); err != nil {
			return nil, err
		}
	}
	if present == 0 {
		s.doc.Steps[index].State = "removed"
		return nil, s.saveSettled(ctx)
	}
	s.doc.Steps[index].State = "cleanup-intent"
	if err := s.save(ctx); err != nil {
		s.doc.Steps[index].State = "added"
		return nil, err
	}
	if err := s.fault("cleanup-intent", index); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if index < 2 {
		if err := assertPolicyAdditionDefaultsUnreferenced(ctx, r.base, r.ip, s.state); err != nil {
			// The delete has definitely not been invoked in this live call.
			// Restore only the original ACKed grant, never a readback grant.
			s.doc.Steps[index].State = "added"
			if saveErr := s.save(ctx); saveErr != nil {
				s.doc.Steps[index].State = "cleanup-intent"
				return nil, errors.Join(err, ErrPolicyAdditionUnknown, saveErr)
			}
			return nil, err
		}
	}
	out, err := r.base.Run(ctx, r.ip, args...)
	if err != nil {
		return out, errors.Join(err, ErrPolicyAdditionUnknown)
	}
	if err := s.fault("delete", index); err != nil {
		return out, err
	}
	present, err = policyAdditionPresence(ctx, r.base, r.ip, s.state, index)
	if err != nil || present != 0 {
		return out, errors.Join(ErrPolicyAdditionUnknown, err)
	}
	s.doc.Steps[index].State = "removed"
	if err := s.saveSettled(ctx); err != nil {
		s.doc.Steps[index].State = "cleanup-intent"
		return out, err
	}
	return out, s.fault("removed", index)
}

// Defaults are one receipt's prerequisites. Reverse cleanup starts with IPv6,
// so a foreign or unknown selector in either family must retain both defaults.
// CORE owns the numeric readback, bounded reader and sole selector parser.
func assertPolicyAdditionDefaultsUnreferenced(ctx context.Context, runner NFQWS2Runner, ip string, state PolicyState) error {
	for _, family := range []int{4, 6} {
		if err := AssertPolicyDefaultUnreferenced(ctx, runner, ip, state, family); err != nil {
			return errors.Join(ErrPolicyAdditionUnknown, err)
		}
	}
	return nil
}

func (s *policyAdditionSession) hasUnsettledRules() bool {
	for _, step := range s.doc.Steps[2:] {
		if step.State == "added" || step.State == "intent" || step.State == "cleanup-intent" {
			return true
		}
	}
	return false
}

func policyAdditionPresence(ctx context.Context, runner NFQWS2Runner, ip string, state PolicyState, index int) (int, error) {
	if index < 2 {
		family := 4
		if index == 1 {
			family = 6
		}
		args, err := recordedDefaultRoute(ctx, runner, ip, state, family)
		if err != nil {
			return 0, err
		}
		if len(args) > 0 {
			return 1, nil
		}
		return 0, nil
	}
	rules, err := kernelRulesForPolicy(state)
	if err != nil || index-2 >= len(rules) {
		return 0, ErrPolicyAdditionReceipt
	}
	wanted := rules[index-2]
	lines, err := readPolicyRules(ctx, runner, ip, wanted.family)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		priority, ok := policyLinePriority(line)
		if !ok {
			return 0, ErrPolicyAdditionReceipt
		}
		if priority != wanted.priority {
			continue
		}
		parsed, ok := parseKernelPolicyRule(wanted.family, line)
		if !ok {
			return 0, ErrPolicyAdditionReceipt
		}
		if parsed == wanted {
			count++
		}
	}
	return count, ctx.Err()
}

func removePolicyWithReceipt(ctx context.Context, runner NFQWS2Runner, ip string, state PolicyState, root string) error {
	return removePolicyAddition(ctx, runner, ip, state, root, policyAdditionOptions{})
}
func removePolicyAddition(ctx context.Context, runner NFQWS2Runner, ip string, state PolicyState, root string, options policyAdditionOptions) (result error) {
	if runner == nil || ip == "" {
		return ErrPolicyAdditionReceipt
	}
	s, err := openPolicyAdditionSession(ctx, state, root, options)
	if err != nil {
		return err
	}
	defer s.close()
	defer func() { result = errors.Join(result, s.flush(ctx)) }()
	if err := s.load(ctx); err != nil {
		return errors.Join(ErrPolicyAdditionReceipt, err)
	}
	if s.doc.Phase != "active" {
		return ErrPolicyAdditionUnknown
	}
	wrapper := &policyAdditionRunner{base: runner, ip: ip, session: s}
	for i := len(s.doc.Steps) - 1; i >= 0; i-- {
		if s.doc.Steps[i].State != "added" {
			continue
		}
		if i < 2 && s.hasUnsettledRules() {
			continue // Never open a DIRECT fallback under an unsettled selector.
		}
		args := s.doc.Steps[i].Delete
		if i < 2 {
			family := 4
			if i == 1 {
				family = 6
			}
			args, err = recordedDefaultRoute(ctx, runner, ip, state, family)
			if err != nil {
				return err
			}
			if len(args) == 0 {
				if err := assertPolicyAdditionDefaultsUnreferenced(ctx, runner, ip, state); err != nil {
					return err
				}
				s.doc.Steps[i].State = "removed"
				if err := s.save(ctx); err != nil {
					return err
				}
				continue
			}
		}
		if _, err := wrapper.remove(ctx, i, args); err != nil {
			return err
		}
	}
	if s.status().Unknown {
		return ErrPolicyAdditionUnknown
	}
	return nil
}

func inspectPolicyAdditionReceipt(ctx context.Context, state PolicyState, root string) (PolicyAdditionStatus, error) {
	s, err := openPolicyAdditionSession(ctx, state, root, policyAdditionOptions{})
	if err != nil {
		return PolicyAdditionStatus{}, err
	}
	defer s.close()
	if err := s.load(ctx); err != nil {
		return PolicyAdditionStatus{}, err
	}
	return s.status(), nil
}

// Promotion TRANSFERS a single cleanup grant. Source is fenced before the
// destination is written; copying an active receipt cannot create two owners.
// A crash in promotion requires matching reconciliation, never blind replay.
// Both roots are trusted existing generation directories, not JSON paths.
func promotePolicyAdditionReceipt(ctx context.Context, state PolicyState, source, destination string) error {
	return promotePolicyAddition(ctx, state, source, destination, policyAdditionOptions{})
}
func promotePolicyAddition(ctx context.Context, state PolicyState, source, destination string, options policyAdditionOptions) error {
	if policyAdditionRootHash(source) == policyAdditionRootHash(destination) {
		return ErrPolicyAdditionReceipt
	}
	s, err := openPolicyAdditionSession(ctx, state, source, options)
	if err != nil {
		return err
	}
	defer s.close()
	d, err := openPolicyAdditionSession(ctx, state, destination, options)
	if err != nil {
		return err
	}
	defer d.close()
	return promotePolicyAdditionSessions(ctx, s, d, s.load, d.load)
}

// Both modes transfer exactly one cleanup grant through the same durability
// boundaries. The supplied readers reconstruct the respective trusted plan.
func promotePolicyAdditionSessions(ctx context.Context, s, d *policyAdditionSession, loadSource, loadDestination func(context.Context) error) error {
	if err := loadSource(ctx); err != nil {
		return err
	}
	if s.doc.Phase == "promoted" && s.doc.PromotionTarget == policyAdditionRootHash(d.path) {
		if err := loadDestination(ctx); err != nil {
			return err
		}
		if d.doc.ID == s.doc.ID && d.status().Complete {
			return nil
		}
		return ErrPolicyAdditionUnknown
	}
	if !s.status().Complete {
		return ErrPolicyAdditionUnknown
	}
	if err := loadDestination(ctx); !errors.Is(err, os.ErrNotExist) {
		return ErrPolicyAdditionExists
	}
	s.doc.Phase, s.doc.PromotionTarget = "promotion-intent", policyAdditionRootHash(d.path)
	if err := s.save(ctx); err != nil {
		return err
	}
	if err := s.fault("promotion-intent", -1); err != nil {
		return err
	}
	d.doc = s.doc
	d.doc.Phase, d.doc.PromotionTarget, d.doc.RootHash = "active", "", policyAdditionRootHash(d.path)
	if err := d.save(ctx); err != nil {
		return err
	}
	if err := s.fault("promotion-copy", -1); err != nil {
		return err
	}
	s.doc.Phase = "promoted"
	return s.save(ctx)
}
