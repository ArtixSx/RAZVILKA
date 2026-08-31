// Package restorejournal records a bounded before/after plan before touching
// targets. It is not wired to the router's live stores yet: adapters must hold
// exclusive ownership and perform durable compare-and-swap before integration.
package restorejournal

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

const (
	MaxTargets      = 64
	MaxImageBytes   = 4 << 20
	MaxPlanBytes    = 8 << 20 // Both before and after images, combined.
	maxJournalBytes = 12 << 20
	journalFile     = "restore.private.json"
	journalKind     = "razvilka-private-restore"
)

var (
	ErrInvalid     = errors.New("invalid restore plan or journal")
	ErrUnavailable = errors.New("private restore journal unavailable")
	ErrBusy        = errors.New("private restore journal is locked")
	ErrPending     = errors.New("private restore recovery is required before a new import")
	ErrRecovery    = errors.New("private restore result requires recovery review")
	ErrAborted     = errors.New("private restore was not completed")
	idPattern      = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,47}$`)
)

// Image distinguishes an absent file from a present, empty file. Data is secret
// state, not an API/log DTO. It is never accepted as a destination path.
type Image struct {
	Exists bool   `json:"exists"`
	Data   []byte `json:"data"`
}

func (Image) String() string   { return "[private restore image]" }
func (Image) GoString() string { return "[private restore image]" }

// Target is supplied by trusted startup code, never by an imported archive.
// Read must be bounded. CompareAndSwap must atomically verify the whole image
// and persist replacement before returning success, including directory sync
// where supported. A failed write may have committed; recovery reads it back.
// Implementations must cooperate with every other writer, not only this journal.
// Neither method may retain/mutate arguments; they must honor cancellation.
type Target interface {
	Read(context.Context) (Image, error)
	CompareAndSwap(context.Context, Image, Image) error
}

type Outcome string

const (
	Clean      Outcome = "clean"
	Applied    Outcome = "applied"
	RolledBack Outcome = "rolled_back"
	Blocked    Outcome = "recovery_required"
)

type record struct {
	Target string `json:"target"`
	Before Image  `json:"before"`
	After  Image  `json:"after"`
}

type document struct {
	Kind    string   `json:"kind"`
	Schema  int      `json:"schema"`
	Scope   string   `json:"scope"`
	ID      string   `json:"id"`
	State   string   `json:"state"`
	Records []record `json:"records"`
	Digest  string   `json:"digest"`
}

// Journal holds a permanent protocol-marker lease until Close. Its directory
// must already exist and be private. scope is a SHA-256 of trusted deployment
// bindings (target IDs, roots, names, format versions), NOT archive input. A
// changed binding must not recover a journal against a different set of files.
// The lease coordinates journal users only; it does not lock live app stores.
type Journal struct {
	mu      sync.Mutex
	root    *ownedfs.Root
	scope   string
	targets map[string]Target
	release func()
	write   func([]byte) error
	closed  bool
}

func (*Journal) String() string   { return "[private restore journal]" }
func (*Journal) GoString() string { return "[private restore journal]" }

func Open(path, scope string, targets map[string]Target) (*Journal, error) {
	if !validHash(scope) || len(targets) == 0 || len(targets) > MaxTargets {
		return nil, ErrInvalid
	}
	copyTargets := make(map[string]Target, len(targets))
	for id, target := range targets {
		if !idPattern.MatchString(id) || target == nil {
			return nil, ErrInvalid
		}
		copyTargets[id] = target
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, ErrUnavailable
	}
	root, err := ownedfs.Open(path)
	if err != nil {
		return nil, ErrUnavailable
	}
	release, err := acquireLease(root)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	j := &Journal{root: root, scope: scope, targets: copyTargets, release: release}
	j.write = func(data []byte) error {
		if err := root.WriteAtomic(journalFile, data, 0o600); err != nil {
			return err
		}
		return syncJournalDir(root)
	}
	if _, err := j.load(); err != nil {
		_ = j.Close()
		return nil, err
	}
	return j, nil
}

func (j *Journal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return nil
	}
	j.closed = true
	j.release()
	if j.root.Close() != nil {
		return ErrUnavailable
	}
	return nil
}

// Execute refuses a pending journal, captures all before images and publishes
// the full plan before the first target write. This is a recovery protocol, not
// an isolation guarantee for readers of several target files.
func (j *Journal) Execute(ctx context.Context, changes map[string]Image) (Outcome, error) {
	if !j.mu.TryLock() {
		return Blocked, ErrBusy
	}
	defer j.mu.Unlock()
	if j.closed {
		return Blocked, ErrUnavailable
	}
	current, err := j.load()
	if err != nil {
		return Blocked, err
	}
	if current.State != "idle" {
		return Blocked, ErrPending
	}
	if err := ctx.Err(); err != nil {
		return Clean, ErrAborted
	}
	if len(changes) == 0 || len(changes) > MaxTargets {
		return Clean, ErrInvalid
	}
	ids := make([]string, 0, len(changes))
	for id, after := range changes {
		if j.targets[id] == nil || !validImage(after) {
			return Clean, ErrInvalid
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	doc := document{Kind: journalKind, Schema: 1, Scope: j.scope, State: "prepared", ID: hex.EncodeToString(randomID())}
	total := 0
	for _, id := range ids {
		if ctx.Err() != nil {
			return Clean, ErrAborted
		}
		before, err := j.targets[id].Read(ctx)
		if err != nil || !validImage(before) {
			return Clean, ErrAborted
		}
		after := changes[id]
		total += len(before.Data) + len(after.Data)
		if total > MaxPlanBytes {
			return Clean, ErrInvalid
		}
		if !equal(before, after) {
			doc.Records = append(doc.Records, record{Target: id, Before: clone(before), After: clone(after)})
		}
	}
	if len(doc.Records) == 0 {
		return Clean, nil
	}
	if ctx.Err() != nil {
		return Clean, ErrAborted
	}
	if err := j.save(doc); err != nil {
		return Blocked, ErrRecovery
	}
	for _, entry := range doc.Records {
		if ctx.Err() != nil {
			return j.abort()
		}
		if err := j.targets[entry.Target].CompareAndSwap(ctx, clone(entry.Before), clone(entry.After)); err != nil {
			return j.abort()
		}
	}
	// All target writes are complete. Publish the commit decision even if the
	// client disconnected just now. A failed journal write is ambiguous: NEVER
	// compensate based only on that error, since committed may already be durable.
	verifyCtx, cancelVerify := context.WithTimeout(context.Background(), 10*time.Second)
	err = j.checkTargets(verifyCtx, doc, true)
	cancelVerify()
	if err != nil {
		return Blocked, ErrRecovery
	}
	doc.State = "committed"
	if err := j.save(doc); err != nil {
		return Blocked, ErrRecovery
	}
	if err := j.save(j.idle()); err != nil {
		return Blocked, ErrRecovery
	}
	return Applied, nil
}

func (j *Journal) abort() (Outcome, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := j.recover(ctx)
	if err != nil {
		return Blocked, ErrRecovery
	}
	return result, ErrAborted
}

// Recover must run before opening mutating APIs/background writers. Prepared
// plans are rolled BACK; committed plans are only verified and finalized.
// Any third state blocks recovery without overwriting it. No paths, commands
// or targets are learned from the journal. Corrupt/unknown journals are kept.
func (j *Journal) Recover(ctx context.Context) (Outcome, error) {
	if !j.mu.TryLock() {
		return Blocked, ErrBusy
	}
	defer j.mu.Unlock()
	if j.closed {
		return Blocked, ErrUnavailable
	}
	return j.recover(ctx)
}

func (j *Journal) recover(ctx context.Context) (Outcome, error) {
	doc, err := j.load()
	if err != nil {
		return Blocked, err
	}
	if ctx.Err() != nil {
		return Blocked, ErrRecovery
	}
	if doc.State == "idle" {
		return Clean, nil
	}
	// Validate every target before undoing ANY of them. CAS rechecks each
	// individual image again, protecting edits made after this preflight.
	if err := j.checkTargets(ctx, doc, doc.State == "committed"); err != nil {
		return Blocked, ErrRecovery
	}
	result := Applied
	if doc.State == "prepared" {
		result = RolledBack
		for i := len(doc.Records) - 1; i >= 0; i-- {
			if ctx.Err() != nil {
				return Blocked, ErrRecovery
			}
			entry := doc.Records[i]
			current, err := j.targets[entry.Target].Read(ctx)
			if err != nil || !validImage(current) {
				return Blocked, ErrRecovery
			}
			if equal(current, entry.Before) {
				continue
			}
			if !equal(current, entry.After) {
				return Blocked, ErrRecovery
			}
			if err := j.targets[entry.Target].CompareAndSwap(ctx, clone(entry.After), clone(entry.Before)); err != nil {
				return Blocked, ErrRecovery
			}
		}
		// Do not clear the only recovery record if a later edit became visible
		// after an earlier target's undo. Exclusive adapters remain mandatory.
		for _, entry := range doc.Records {
			if ctx.Err() != nil {
				return Blocked, ErrRecovery
			}
			current, err := j.targets[entry.Target].Read(ctx)
			if err != nil || !equal(current, entry.Before) {
				return Blocked, ErrRecovery
			}
		}
	}
	if ctx.Err() != nil {
		return Blocked, ErrRecovery
	}
	if err := j.save(j.idle()); err != nil {
		return Blocked, ErrRecovery
	}
	return result, nil
}

func (j *Journal) checkTargets(ctx context.Context, doc document, committed bool) error {
	for _, entry := range doc.Records {
		if ctx.Err() != nil {
			return ErrRecovery
		}
		current, err := j.targets[entry.Target].Read(ctx)
		if err != nil || !validImage(current) {
			return ErrRecovery
		}
		if equal(current, entry.After) || !committed && equal(current, entry.Before) {
			continue
		}
		return ErrRecovery
	}
	return nil
}

func (j *Journal) idle() document {
	return document{Kind: journalKind, Schema: 1, Scope: j.scope, State: "idle"}
}

func (j *Journal) load() (document, error) {
	info, err := j.root.Stat(journalFile)
	if errors.Is(err, os.ErrNotExist) {
		return j.idle(), nil
	}
	if err != nil || !privateFile(info) || info.Size() > maxJournalBytes {
		return document{}, ErrInvalid
	}
	f, err := openPrivate(j.root, journalFile, false)
	if err != nil {
		return document{}, ErrUnavailable
	}
	defer f.Close()
	actual, err := f.Stat()
	if err != nil || !privateFile(actual) || !os.SameFile(info, actual) {
		return document{}, ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxJournalBytes+1))
	if err != nil || len(raw) > maxJournalBytes {
		return document{}, ErrInvalid
	}
	var doc document
	if json.Unmarshal(raw, &doc) != nil {
		return document{}, ErrInvalid
	}
	canonical, err := json.Marshal(doc)
	// Our internal format is canonical: reject duplicates, unknown/case-folded
	// fields, alternate encodings and extra JSON before using any record.
	if err != nil || !bytes.Equal(raw, canonical) {
		return document{}, ErrInvalid
	}
	if doc.Kind != journalKind || doc.Schema != 1 || doc.Scope != j.scope || !validHash(doc.Digest) {
		return document{}, ErrInvalid
	}
	digest := doc.Digest
	doc.Digest = ""
	unsigned, _ := json.Marshal(doc)
	if sum(unsigned) != digest {
		return document{}, ErrInvalid
	}
	if doc.State == "idle" {
		if doc.ID != "" || len(doc.Records) != 0 {
			return document{}, ErrInvalid
		}
		return doc, nil
	}
	id, err := hex.DecodeString(doc.ID)
	if err != nil || len(id) != 16 || hex.EncodeToString(id) != doc.ID || (doc.State != "prepared" && doc.State != "committed") || len(doc.Records) == 0 || len(doc.Records) > MaxTargets {
		return document{}, ErrInvalid
	}
	total, last := 0, ""
	for _, entry := range doc.Records {
		if entry.Target <= last || j.targets[entry.Target] == nil || !validImage(entry.Before) || !validImage(entry.After) || equal(entry.Before, entry.After) {
			return document{}, ErrInvalid
		}
		last = entry.Target
		total += len(entry.Before.Data) + len(entry.After.Data)
		if total > MaxPlanBytes {
			return document{}, ErrInvalid
		}
	}
	return doc, nil
}

func (j *Journal) save(doc document) error {
	doc.Digest = ""
	unsigned, err := json.Marshal(doc)
	if err != nil {
		return ErrInvalid
	}
	doc.Digest = sum(unsigned)
	raw, err := json.Marshal(doc)
	if err != nil || len(raw) > maxJournalBytes {
		return ErrInvalid
	}
	if j.write(raw) != nil {
		return ErrUnavailable
	}
	return nil
}

func validHash(value string) bool {
	b, err := hex.DecodeString(value)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == value
}

func sum(data []byte) string { hash := sha256.Sum256(data); return hex.EncodeToString(hash[:]) }
func validImage(image Image) bool {
	return len(image.Data) <= MaxImageBytes && (image.Exists || len(image.Data) == 0)
}
func equal(a, b Image) bool { return a.Exists == b.Exists && bytes.Equal(a.Data, b.Data) }
func clone(image Image) Image {
	return Image{Exists: image.Exists, Data: append([]byte(nil), image.Data...)}
}
func randomID() []byte { data := make([]byte, 16); _, _ = rand.Read(data); return data }

func privateFile(info os.FileInfo) bool {
	return info.Mode().IsRegular() && (runtime.GOOS == "windows" || info.Mode().Perm()&0o077 == 0)
}
