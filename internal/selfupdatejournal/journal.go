// Package selfupdatejournal journals application file replacement independently
// of opkg/component transactions. It never executes recovery commands itself.
package selfupdatejournal

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

const Schema = 1
const maxFileBytes = 256 << 20

var (
	ErrPending     = errors.New("self update pending")
	ErrUnknown     = errors.New("self update command outcome unknown; do not replay")
	ErrMismatch    = errors.New("self update identity or file mismatch")
	idPattern      = regexp.MustCompile(`^[a-f0-9]{32}$`)
	commandPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
)

// Authority must re-read current CAS/Stop/SafeMode before each write/effect.
// Quiescence is a trusted process check, never an HTTP-provided boolean.
type Check func(context.Context) error

type File struct {
	Target    string // Fixed relative application path; see allowedTarget.
	Candidate string // Absolute regular file; copied before Prepared is durable.
	SHA256    string // Digest from the independently verified release manifest.
}

type image struct {
	Target     string `json:"target"`
	OldPresent bool   `json:"old_present"`
	OldHash    string `json:"old_sha256,omitempty"`
	OldMode    uint32 `json:"old_mode,omitempty"`
	NewHash    string `json:"new_sha256"`
}

type Receipt struct {
	Schema   int      `json:"schema"`
	ID       string   `json:"id"`
	Phase    string   `json:"phase"`
	Index    int      `json:"index"`
	Command  string   `json:"command,omitempty"`
	Commands []string `json:"commands,omitempty"`
	Rollback bool     `json:"rollback,omitempty"`
	Files    []image  `json:"files"`
}

func (r Receipt) Pending() bool { return r.Phase != "accepted" && r.Phase != "rolled-back" }

// Store uses pre-existing directories. The caller must establish ownership and
// durably create the private journal directory before opening it. Receipts and
// LKG images are retained; there is deliberately no prune/delete API.
type Store struct {
	installation *ownedfs.Root
	journal      *ownedfs.Root
	files        *os.Root
	journalFiles *os.Root
	fault        func(string) error
}

func Open(installation, journal string) (*Store, error) {
	s := &Store{}
	var err error
	installInfo, err := os.Lstat(installation)
	if err != nil {
		return nil, err
	}
	journalInfo, err := os.Lstat(journal)
	if err != nil {
		return nil, err
	}
	if s.installation, err = ownedfs.Open(installation); err != nil {
		return nil, err
	}
	if s.journal, err = ownedfs.Open(journal); err != nil {
		s.Close()
		return nil, err
	}
	info, err := os.Lstat(journal)
	if err != nil || (runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0) {
		s.Close()
		return nil, errors.New("private self update journal required")
	}
	if s.files, err = os.OpenRoot(installation); err != nil {
		s.Close()
		return nil, err
	}
	if s.journalFiles, err = os.OpenRoot(journal); err != nil {
		s.Close()
		return nil, err
	}
	actualInstall, err := s.files.Stat(".")
	if err != nil || !os.SameFile(installInfo, actualInstall) {
		s.Close()
		return nil, ErrMismatch
	}
	actualJournal, err := s.journalFiles.Stat(".")
	if err != nil || !os.SameFile(journalInfo, actualJournal) {
		s.Close()
		return nil, ErrMismatch
	}
	return s, nil
}

func (s *Store) Close() {
	if s.installation != nil {
		_ = s.installation.Close()
	}
	if s.journal != nil {
		_ = s.journal.Close()
	}
	if s.files != nil {
		_ = s.files.Close()
	}
	if s.journalFiles != nil {
		_ = s.journalFiles.Close()
	}
}

func allowedTarget(name string) bool {
	switch name {
	case "bin/razvilka", "etc/init.d/S99razvilka", "etc/razvilka/config.json", "etc/razvilka/service-catalog.json", "etc/razvilka/community-catalog.json", "etc/razvilka/sources.json":
		return true
	}
	return false
}

func checks(ctx context.Context, authority, quiescence Check) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if authority == nil || quiescence == nil {
		return errors.New("trusted authority and quiescence checks required")
	}
	if err := authority(ctx); err != nil {
		return err
	}
	return quiescence(ctx)
}

func (s *Store) boundary(point string) error {
	if s.fault != nil {
		return s.fault(point)
	}
	return nil
}

func (s *Store) writeReceipt(r Receipt) error {
	if err := s.boundary("before:receipt:" + r.Phase); err != nil {
		return err
	}
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if err := s.journal.WriteAtomic(r.ID+"/receipt.json", data, 0600); err != nil {
		return err
	}
	if err := syncDirectory(s.journalFiles, r.ID); err != nil {
		return err
	}
	return s.boundary("after:receipt:" + r.Phase)
}

func valid(r Receipt) bool {
	if r.Schema != Schema || !idPattern.MatchString(r.ID) || len(r.Files) == 0 || len(r.Files) > 6 || r.Index < 0 || r.Index > len(r.Files) {
		return false
	}
	switch r.Phase {
	case "prepared":
		if r.Index != 0 || r.Command != "" || len(r.Commands) != 0 {
			return false
		}
	case "installing", "restoring":
		if r.Command != "" {
			return false
		}
	case "installed", "restored", "accepted", "rolled-back":
		if r.Index != len(r.Files) || r.Command != "" {
			return false
		}
	case "command-started", "command-finished":
		if r.Index != len(r.Files) || !commandPattern.MatchString(r.Command) {
			return false
		}
	default:
		return false
	}
	if len(r.Commands) > 16 {
		return false
	}
	commands := map[string]bool{}
	for _, command := range r.Commands {
		if !commandPattern.MatchString(command) || commands[command] {
			return false
		}
		commands[command] = true
	}
	if r.Command != "" && !commands[r.Command] {
		return false
	}
	if r.Command != "" && r.Commands[len(r.Commands)-1] != r.Command {
		return false
	}
	if (r.Phase == "restoring" || r.Phase == "restored" || r.Phase == "rolled-back") && !r.Rollback {
		return false
	}
	if (r.Phase == "prepared" || r.Phase == "installing" || r.Phase == "installed" || r.Phase == "accepted") && r.Rollback {
		return false
	}
	seen := map[string]bool{}
	for _, f := range r.Files {
		if !allowedTarget(f.Target) || seen[f.Target] || !digest(f.NewHash) {
			return false
		}
		seen[f.Target] = true
		if f.OldPresent {
			if !digest(f.OldHash) || f.OldMode > 0777 {
				return false
			}
		} else if f.OldHash != "" || f.OldMode != 0 {
			return false
		}
	}
	return true
}

func digest(value string) bool {
	data, err := hex.DecodeString(value)
	return err == nil && len(data) == sha256.Size && strings.ToLower(value) == value
}

func decode(data []byte, out any) error {
	d := json.NewDecoder(strings.NewReader(string(data)))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if d.Decode(&struct{}{}) != io.EOF {
		return errors.New("trailing receipt data")
	}
	return nil
}

// Current is read-only. Missing current means no transaction; every other
// error (including corrupt terminal receipts) is a fence, not an empty state.
func (s *Store) Current() (Receipt, bool, error) {
	data, err := s.journal.ReadLimited("current.json", 1024)
	if errors.Is(err, os.ErrNotExist) {
		return Receipt{}, false, nil
	}
	if err != nil {
		return Receipt{}, false, err
	}
	var pointer struct {
		Schema int    `json:"schema"`
		ID     string `json:"id"`
	}
	if decode(data, &pointer) != nil || pointer.Schema != Schema || !idPattern.MatchString(pointer.ID) {
		return Receipt{}, false, ErrMismatch
	}
	data, err = s.journal.ReadLimited(pointer.ID+"/receipt.json", 16<<10)
	if err != nil {
		return Receipt{}, false, err
	}
	var r Receipt
	if decode(data, &r) != nil || !valid(r) || r.ID != pointer.ID {
		return Receipt{}, false, ErrMismatch
	}
	return r, true, nil
}

func (s *Store) matching(id string) (Receipt, error) {
	r, present, err := s.Current()
	if err != nil {
		return r, err
	}
	if !present || r.ID != id {
		return r, ErrMismatch
	}
	return r, nil
}

// Prepare freezes both old and candidate images before publishing current.
// An interrupted preparation can leave an unreferenced directory; it cannot
// authorize file mutation, overwrite a receipt, or discard the previous LKG.
func (s *Store) Prepare(ctx context.Context, id string, files []File, authority, quiescence Check) error {
	unlock, err := lockWriter(s.journal)
	if err != nil {
		return err
	}
	defer unlock()
	if !idPattern.MatchString(id) || len(files) == 0 || len(files) > 6 {
		return ErrMismatch
	}
	current, present, err := s.Current()
	if err != nil {
		return err
	}
	if present && current.Pending() {
		return ErrPending
	}
	if present {
		if err := s.verifyImages(current); err != nil {
			return err
		}
	}
	seen := map[string]bool{}
	for _, f := range files {
		if !allowedTarget(f.Target) || seen[f.Target] || !filepath.IsAbs(f.Candidate) || !digest(f.SHA256) {
			return ErrMismatch
		}
		seen[f.Target] = true
	}
	if err := checks(ctx, authority, quiescence); err != nil {
		return err
	}
	if err := s.journalFiles.Mkdir(id, 0700); err != nil {
		return err
	}
	if err := syncDirectory(s.journalFiles, "."); err != nil {
		return err
	}
	r := Receipt{Schema: Schema, ID: id, Phase: "prepared"}
	for index, f := range files {
		if err := checks(ctx, authority, quiescence); err != nil {
			return err
		}
		if err := s.installation.Check(f.Target); err != nil {
			return err
		}
		entry := image{Target: f.Target}
		old, err := s.installation.OpenFile(f.Target, os.O_RDONLY|fileFlags(), 0)
		if err == nil {
			info, statErr := old.Stat()
			if statErr != nil || !info.Mode().IsRegular() {
				old.Close()
				return ErrMismatch
			}
			entry.OldMode = uint32(info.Mode().Perm())
			entry.OldPresent = true
			entry.OldHash, err = s.snapshot(old, id+"/old-"+strconv.Itoa(index))
			old.Close()
			if err != nil {
				return err
			}
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		candidateInfo, err := os.Lstat(f.Candidate)
		if err != nil || !candidateInfo.Mode().IsRegular() {
			return ErrMismatch
		}
		candidate, err := os.OpenFile(f.Candidate, os.O_RDONLY|fileFlags(), 0)
		if err != nil {
			return err
		}
		opened, statErr := candidate.Stat()
		if statErr != nil || !os.SameFile(candidateInfo, opened) {
			candidate.Close()
			return ErrMismatch
		}
		entry.NewHash, err = s.snapshot(candidate, id+"/new-"+strconv.Itoa(index))
		candidate.Close()
		if err != nil {
			return err
		}
		if entry.NewHash != f.SHA256 {
			return ErrMismatch
		}
		r.Files = append(r.Files, entry)
	}
	if err := syncDirectory(s.journalFiles, id); err != nil {
		return err
	}
	if err := s.writeReceipt(r); err != nil {
		return err
	}
	if err := checks(ctx, authority, quiescence); err != nil {
		return err
	}
	data, _ := json.Marshal(struct {
		Schema int    `json:"schema"`
		ID     string `json:"id"`
	}{Schema, id})
	if err := s.boundary("before:current"); err != nil {
		return err
	}
	if err := s.journal.WriteAtomic("current.json", data, 0600); err != nil {
		return err
	}
	if err := syncDirectory(s.journalFiles, "."); err != nil {
		return err
	}
	return s.boundary("after:current")
}

func (s *Store) snapshot(src *os.File, name string) (string, error) {
	if err := s.boundary("before:snapshot:" + name[strings.IndexByte(name, '/')+1:]); err != nil {
		return "", err
	}
	info, err := src.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxFileBytes {
		return "", ErrMismatch
	}
	out, err := s.journal.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", err
	}
	defer out.Close()
	hash := sha256.New()
	count, err := io.Copy(io.MultiWriter(out, hash), io.LimitReader(src, maxFileBytes+1))
	if err != nil {
		return "", err
	}
	if count > maxFileBytes {
		return "", ErrMismatch
	}
	if err := out.Sync(); err != nil {
		return "", err
	}
	if err := out.Close(); err != nil {
		return "", err
	}
	if err := s.boundary("after:snapshot:" + name[strings.IndexByte(name, '/')+1:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func hashFile(root *ownedfs.Root, name string) (string, bool, error) {
	f, err := root.OpenFile(name, os.O_RDONLY|fileFlags(), 0)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxFileBytes {
		return "", false, ErrMismatch
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, maxFileBytes+1))
	if err != nil || n > maxFileBytes {
		return "", false, ErrMismatch
	}
	return hex.EncodeToString(h.Sum(nil)), true, nil
}

func (s *Store) verifyImages(r Receipt) error {
	for index, f := range r.Files {
		for _, version := range []struct {
			prefix, hash string
			present      bool
		}{{"new-", f.NewHash, true}, {"old-", f.OldHash, f.OldPresent}} {
			if !version.present {
				continue
			}
			actual, present, err := hashFile(s.journal, r.ID+"/"+version.prefix+strconv.Itoa(index))
			if err != nil || !present || actual != version.hash {
				return ErrMismatch
			}
		}
	}
	return nil
}

// Install/Restore resume only known file writes. A target must still equal
// its frozen old/new digest. Foreign edits stop recovery. Neither method
// replays commands or accepts a live process; callers must prove quiescence.
func (s *Store) Install(ctx context.Context, id string, authority, quiescence Check) error {
	return s.replace(ctx, id, false, authority, quiescence)
}
func (s *Store) Restore(ctx context.Context, id string, authority, quiescence Check) error {
	return s.replace(ctx, id, true, authority, quiescence)
}

func (s *Store) replace(ctx context.Context, id string, rollback bool, authority, quiescence Check) error {
	unlock, err := lockWriter(s.journal)
	if err != nil {
		return err
	}
	defer unlock()
	r, err := s.matching(id)
	if err != nil {
		return err
	}
	if r.Phase == "command-started" {
		return ErrUnknown
	}
	if !r.Pending() {
		return ErrPending
	}
	if err := s.verifyImages(r); err != nil {
		return err
	}
	phase, finished := "installing", "installed"
	if rollback {
		phase, finished = "restoring", "restored"
	} else if (r.Phase != "prepared" && r.Phase != "installing") || r.Rollback {
		return ErrPending
	}
	if r.Phase == finished {
		return nil
	}
	if err := checks(ctx, authority, quiescence); err != nil {
		return err
	}
	if r.Phase != phase {
		r.Phase, r.Index, r.Command, r.Rollback = phase, 0, "", rollback
		if err := s.writeReceipt(r); err != nil {
			return err
		}
	}
	for ; r.Index < len(r.Files); r.Index++ {
		if err := checks(ctx, authority, quiescence); err != nil {
			return err
		}
		if err := s.writeReceipt(r); err != nil {
			return err
		}
		if err := s.replaceFile(ctx, r, rollback, authority, quiescence); err != nil {
			return err
		}
		checkpoint := r
		checkpoint.Index++
		if err := s.writeReceipt(checkpoint); err != nil {
			return err
		}
	}
	r.Phase = finished
	return s.writeReceipt(r)
}

func (s *Store) replaceFile(ctx context.Context, r Receipt, rollback bool, authority, quiescence Check) error {
	entry := r.Files[r.Index]
	actual, present, err := hashFile(s.installation, entry.Target)
	if err != nil {
		return err
	}
	old := present == entry.OldPresent && actual == entry.OldHash
	new := present && actual == entry.NewHash
	if !old && !new {
		return ErrMismatch
	}
	name, expected, mode := r.ID+"/new-"+strconv.Itoa(r.Index), entry.NewHash, os.FileMode(0600)
	if entry.Target == "bin/razvilka" || entry.Target == "etc/init.d/S99razvilka" {
		mode = 0755
	}
	if rollback {
		name, expected, mode = r.ID+"/old-"+strconv.Itoa(r.Index), entry.OldHash, os.FileMode(entry.OldMode)
	}
	if !rollback || entry.OldPresent {
		hash, present, err := hashFile(s.journal, name)
		if err != nil || !present || hash != expected {
			return ErrMismatch
		}
	}
	point := fmt.Sprintf("file:%d", r.Index)
	if err := s.boundary("before:" + point); err != nil {
		return err
	}
	if rollback && !entry.OldPresent {
		if err := checks(ctx, authority, quiescence); err != nil {
			return err
		}
		if present {
			if err := s.installation.Remove(entry.Target); err != nil {
				return err
			}
		}
	} else {
		// The temp stays beside the target for a same-filesystem atomic rename.
		// Unique names avoid overwriting files left by a killed older process.
		dir := filepath.Dir(entry.Target)
		var nonce [16]byte
		_, _ = rand.Read(nonce[:])
		tmpName := filepath.Join(dir, ".self-update-"+hex.EncodeToString(nonce[:]))
		tmp, err := s.installation.OpenFile(tmpName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		defer func() { _ = tmp.Close(); _ = s.files.Remove(tmpName) }()
		src, err := s.journal.OpenFile(name, os.O_RDONLY|fileFlags(), 0)
		if err != nil {
			return err
		}
		defer src.Close()
		h := sha256.New()
		n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(src, maxFileBytes+1))
		if err != nil {
			return err
		}
		if n > maxFileBytes || hex.EncodeToString(h.Sum(nil)) != expected {
			return ErrMismatch
		}
		if err := s.boundary("after:copy:" + point); err != nil {
			return err
		}
		if err := tmp.Chmod(mode); err != nil {
			return err
		}
		if err := tmp.Sync(); err != nil {
			return err
		}
		if err := tmp.Close(); err != nil {
			return err
		}
		if err := s.boundary("after:sync:" + point); err != nil {
			return err
		}
		if err := s.installation.Check(entry.Target); err != nil {
			return err
		}
		if err := s.boundary("before:rename:" + point); err != nil {
			return err
		}
		if err := checks(ctx, authority, quiescence); err != nil {
			return err
		}
		if err := s.files.Rename(tmpName, entry.Target); err != nil {
			return err
		}
		if err := s.boundary("after:rename:" + point); err != nil {
			return err
		}
	}
	if err := syncDirectory(s.files, filepath.Dir(entry.Target)); err != nil {
		return err
	}
	return s.boundary("after:" + point)
}

// Execute records intent before calling an installer effect exactly once.
// Any error/crash before command-finished stays unknown and prohibits replay.
// Even a successful callback is not evidence of live acceptance.
func (s *Store) Execute(ctx context.Context, id, command string, authority Check, run Check) error {
	unlock, err := lockWriter(s.journal)
	if err != nil {
		return err
	}
	defer unlock()
	r, err := s.matching(id)
	if err != nil {
		return err
	}
	if r.Phase == "command-started" {
		return ErrUnknown
	}
	if err := s.verifyImages(r); err != nil {
		return err
	}
	if (r.Phase != "installed" && r.Phase != "restored" && r.Phase != "command-finished") || !commandPattern.MatchString(command) || run == nil || authority == nil || len(r.Commands) >= 16 {
		return ErrPending
	}
	// A command name is a monotonically single-use step, including after restart.
	for _, done := range r.Commands {
		if done == command {
			return ErrPending
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := authority(ctx); err != nil {
		return err
	}
	r.Phase, r.Command = "command-started", command
	r.Commands = append(r.Commands, command)
	if err := s.writeReceipt(r); err != nil {
		return err
	}
	if err := s.boundary("before:command"); err != nil {
		return err
	}
	if err := authority(ctx); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := run(ctx); err != nil {
		return err
	}
	if err := s.boundary("after:command"); err != nil {
		return err
	}
	r.Phase = "command-finished"
	return s.writeReceipt(r)
}

// ResolveUnknown observes an externally repaired/quiescent installation; it
// never executes the saved command. Only a trusted observation can clear the
// unknown boundary. HTTP must not supply either check as a claimed result.
func (s *Store) ResolveUnknown(ctx context.Context, id string, authority, quiescence, observe Check) error {
	unlock, err := lockWriter(s.journal)
	if err != nil {
		return err
	}
	defer unlock()
	r, err := s.matching(id)
	if err != nil {
		return err
	}
	if r.Phase != "command-started" {
		return ErrPending
	}
	if err := s.verifyImages(r); err != nil {
		return err
	}
	if err := checks(ctx, authority, quiescence); err != nil {
		return err
	}
	if observe == nil {
		return ErrUnknown
	}
	if err := observe(ctx); err != nil {
		return err
	}
	if err := checks(ctx, authority, quiescence); err != nil {
		return err
	}
	r.Phase = "command-finished"
	return s.writeReceipt(r)
}

// Accept requires independent live evidence and exact transaction matching.
// The successful receipt and both file images remain after acceptance.
func (s *Store) Accept(ctx context.Context, id string, rollback bool, authority, live Check) error {
	unlock, err := lockWriter(s.journal)
	if err != nil {
		return err
	}
	defer unlock()
	r, err := s.matching(id)
	if err != nil {
		return err
	}
	if r.Phase == "command-started" {
		return ErrUnknown
	}
	if err := s.verifyImages(r); err != nil {
		return err
	}
	if rollback != r.Rollback {
		return ErrPending
	}
	if rollback {
		if r.Phase != "restored" && r.Phase != "command-finished" {
			return ErrPending
		}
	} else if r.Phase != "installed" && r.Phase != "command-finished" {
		return ErrPending
	}
	if authority == nil || live == nil {
		return ErrPending
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := authority(ctx); err != nil {
		return err
	}
	if err := live(ctx); err != nil {
		return err
	}
	if err := authority(ctx); err != nil {
		return err
	}
	for _, f := range r.Files {
		expected, wanted := f.NewHash, true
		if rollback {
			expected, wanted = f.OldHash, f.OldPresent
		}
		actual, present, err := hashFile(s.installation, f.Target)
		if err != nil || present != wanted || actual != expected {
			return ErrMismatch
		}
		if present {
			info, err := s.installation.Stat(f.Target)
			if err != nil {
				return err
			}
			mode := os.FileMode(0600)
			if f.Target == "bin/razvilka" || f.Target == "etc/init.d/S99razvilka" {
				mode = 0755
			}
			if rollback {
				mode = os.FileMode(f.OldMode)
			}
			if runtime.GOOS != "windows" && info.Mode().Perm() != mode {
				return ErrMismatch
			}
		}
	}
	r.Command = ""
	r.Phase = "accepted"
	if rollback {
		r.Phase = "rolled-back"
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := authority(ctx); err != nil {
		return err
	}
	return s.writeReceipt(r)
}
