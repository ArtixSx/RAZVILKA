package components

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type mihomoReleaseFile interface {
	restorejournal.Target
	Close() error
	CompareAndSwapWithRenameAdmission(context.Context, restorejournal.Image, restorejournal.Image, func(context.Context, func() error) error) error
}

type mihomoSmallFile struct{ *restorejournal.FileTarget }

func (f *mihomoSmallFile) CompareAndSwapWithRenameAdmission(ctx context.Context, before, after restorejournal.Image, admit func(context.Context, func() error) error) error {
	return f.FileTarget.CompareAndSwapWithRenameAdmission(ctx, before, after, admit)
}

// Reached only with an authenticated immutable artifact. It cannot replace a
// different running image: initial install and identical pinned reinstall are
// supported here; changed-version transitions require the runtime owner.
func (m *Manager) installMihomoImage(ctx context.Context, info releaseInfo, image restorejournal.Image, guard, rename func(context.Context, func() error) error) (result Result, err error) {
	return m.installMihomoImageWithReplacement(ctx, info, image, guard, rename, nil)
}

func (m *Manager) installMihomoImageWithReplacement(ctx context.Context, info releaseInfo, image restorejournal.Image, guard, rename func(context.Context, func() error) error, inactive func(context.Context, *MihomoReplacementReview) error) (result Result, err error) {
	result = Result{Component: "mihomo", Action: "install"}
	ref, err := mihomoArtifactReferenceOf(image)
	if err != nil || guard == nil || rename == nil {
		return result, errors.Join(err, ErrRecoveryAuthority)
	}
	var s *mihomoReleaseSession
	err = guard(ctx, func() error { s, err = m.openMihomoRelease(true); return err })
	if err != nil {
		if s != nil {
			err = errors.Join(err, s.close())
		}
		return result, err
	}
	defer func() { err = errors.Join(err, s.close()) }()
	// Interrupted operations are recovered only through explicit startup/review,
	// never as a side effect of a new installation request.
	if err := s.j.RequireIdle(ctx); err != nil {
		return result, err
	}
	before, err := s.files["a_binary"].Read(ctx)
	if err != nil {
		return result, err
	}
	receiptBefore, err := s.files["b_receipt"].Read(ctx)
	if err != nil {
		return result, err
	}
	oldVersion := ""
	if before.Exists {
		oldRef, e := mihomoArtifactReferenceOf(before)
		var receipt externalReceipt
		if e != nil || !receiptBefore.Exists || json.Unmarshal(receiptBefore.Data, &receipt) != nil || !externalVersionValuePattern.MatchString(receipt.Version) || receipt.SHA256 != oldRef.SHA256 {
			return result, errors.New("existing Mihomo has no valid original ownership receipt")
		}
		if !bytes.Equal(before.Data, image.Data) {
			if inactive == nil {
				return result, errors.New("Mihomo version replacement requires original runtime inactivity admission")
			}
			s.replacement, err = newMihomoReplacementReview(ctx, m, s, before)
			if err != nil {
				return result, err
			}
			s.inactive = inactive
			if err := inactive(ctx, s.replacement); err != nil {
				return result, err
			}
		}
		oldVersion, result.Action = receipt.Version, "update"
	} else if receiptBefore.Exists {
		return result, errors.New("orphan Mihomo receipt requires recovery")
	}
	receipt, _ := json.Marshal(externalReceipt{Version: info.Version, SHA256: ref.SHA256})
	lifecycle, _ := json.Marshal(lifecycleReceipt{SchemaVersion: 1, Component: "mihomo", Provider: "github-release", Action: result.Action, BeforeVersion: oldVersion, AfterVersion: info.Version, CompletedAt: time.Now().UTC().Format(time.RFC3339Nano)})
	s.admission = map[string]restorejournal.Image{"a_binary": before, "b_receipt": receiptBefore}
	changes := map[string]restorejournal.Image{"a_binary": image, "b_receipt": {Exists: true, Data: append(receipt, '\n')}, "c_lifecycle": {Exists: true, Data: append(lifecycle, '\n')}}
	s.guard, s.renameAdmission, s.forwardImages = guard, rename, changes
	if _, err = s.j.Execute(ctx, changes); err != nil {
		return result, errors.Join(err, errors.Join(s.failures...))
	}
	if m.external == nil {
		m.external = map[string]releaseInfo{}
	}
	m.external["mihomo"] = info
	result.OK, result.InstalledIdleAccepted = true, true
	result.Output = "installed pinned Mihomo " + info.Version + "; runtime remains stopped"
	return result, nil
}

type mihomoReleaseSession struct {
	replacement     *MihomoReplacementReview
	inactive        func(context.Context, *MihomoReplacementReview) error
	j               *restorejournal.Journal
	files           map[string]mihomoReleaseFile
	paths           map[string]string
	failures        []error
	admission       map[string]restorejournal.Image
	guard           func(context.Context, func() error) error
	forwardImages   map[string]restorejournal.Image
	renameAdmission func(context.Context, func() error) error
}

func (s *mihomoReleaseSession) close() error {
	var errs []error
	if s.replacement != nil {
		errs = append(errs, s.replacement.close())
	}
	if s.j != nil {
		errs = append(errs, s.j.Close())
	}
	for _, f := range s.files {
		errs = append(errs, f.Close())
	}
	return errors.Join(errs...)
}

type mihomoReleaseTarget struct {
	restorejournal.Target
	session *mihomoReleaseSession
	manager *Manager
	id      string
}

func (t *mihomoReleaseTarget) Read(ctx context.Context) (restorejournal.Image, error) {
	image, err := t.Target.Read(ctx)
	if expected, ok := t.session.admission[t.id]; ok {
		if err == nil && (image.Exists != expected.Exists || !bytes.Equal(image.Data, expected.Data)) {
			err = restorejournal.ErrConflict
		}
		if err != nil {
			t.session.failures = append(t.session.failures, err)
		}
		delete(t.session.admission, t.id)
	}
	return image, err
}

func (t *mihomoReleaseTarget) CompareAndSwap(ctx context.Context, before, after restorejournal.Image) error {
	desired, forward := t.session.forwardImages[t.id]
	forward = forward && after.Exists == desired.Exists && bytes.Equal(after.Data, desired.Data)
	mutate := func() error { return t.compareAndSwap(ctx, before, after, forward) }
	if t.session.guard != nil && forward {
		err := t.session.guard(ctx, func() error {
			if t.session.replacement != nil {
				if err := t.session.inactive(ctx, t.session.replacement); err != nil {
					return err
				}
			}
			if err := mutate(); err != nil {
				return err
			}
			if t.session.replacement != nil {
				return t.session.inactive(ctx, t.session.replacement)
			}
			return nil
		})
		if err != nil {
			t.session.failures = append(t.session.failures, err)
		}
		return err
	}
	// Compensation remains on the original CAS/lease path with the journal's
	// bounded background context, even after forward admission/caller expired.
	return mutate()
}
func (t *mihomoReleaseTarget) compareAndSwap(ctx context.Context, before, after restorejournal.Image, forward bool) error {
	if t.manager.updateFault != nil {
		if err := t.manager.updateFault("mihomo:before:" + t.id); err != nil {
			t.session.failures = append(t.session.failures, err)
			return err
		}
	}
	var err error
	if forward && t.session.renameAdmission != nil {
		err = t.session.files[t.id].CompareAndSwapWithRenameAdmission(ctx, before, after, t.session.renameAdmission)
	} else {
		err = t.Target.CompareAndSwap(ctx, before, after)
	}
	if forward && t.session.replacement != nil {
		err = errors.Join(err, t.session.replacement.acknowledge(t.id, before, after, err))
	}
	if err == nil && t.manager.updateFault != nil {
		err = t.manager.updateFault("mihomo:after:" + t.id)
	}
	if err != nil {
		t.session.failures = append(t.session.failures, err)
	}
	return err
}

// The scope binds trusted configured paths and the explicit executable mode.
func (m *Manager) mihomoReleaseLayout() (string, string, string, map[string]string, error) {
	if strings.TrimSpace(m.StateDir) == "" {
		return "", "", "", nil, errors.New("Mihomo durable component state directory is required")
	}
	binary, err := filepath.Abs(filepath.Join(defaultValue(m.BinDir, "/opt/bin"), "mihomo"))
	if err != nil {
		return "", "", "", nil, err
	}
	state, err := filepath.Abs(m.StateDir)
	if err != nil {
		return "", "", "", nil, err
	}
	artifacts := filepath.Join(state, "mihomo-artifacts-v1")
	paths := map[string]string{"a_binary": binary, "b_receipt": externalReceiptPath(binary), "c_lifecycle": filepath.Join(state, "receipts", "mihomo.json")}
	binding := "mihomo-release-files-v1:artifact-ref-v1:binary0755:state0600\nartifacts:" + artifacts
	for _, id := range []string{"a_binary", "b_receipt", "c_lifecycle"} {
		v, err := restorejournal.FileBinding(paths[id])
		if err != nil {
			return "", "", "", nil, err
		}
		binding += "\n" + id + ":" + v
	}
	digest := sha256.Sum256([]byte(binding))
	return filepath.Join(state, "mihomo-release-v1"), hex.EncodeToString(digest[:]), artifacts, paths, nil
}
func (m *Manager) openMihomoRelease(create bool) (*mihomoReleaseSession, error) {
	root, scope, artifacts, paths, err := m.mihomoReleaseLayout()
	if err != nil {
		return nil, err
	}
	if create {
		for _, dir := range []string{root, artifacts, filepath.Dir(paths["a_binary"]), filepath.Dir(paths["c_lifecycle"])} {
			if err := os.MkdirAll(dir, 0700); err != nil {
				return nil, err
			}
		}
	}
	s := &mihomoReleaseSession{files: map[string]mihomoReleaseFile{}, paths: paths}
	targets := map[string]restorejournal.Target{}
	for _, id := range []string{"a_binary", "b_receipt", "c_lifecycle"} {
		var f mihomoReleaseFile
		if !create && id == "a_binary" {
			f, err = restorejournal.OpenExistingArtifactExecutableTarget(paths[id], artifacts)
		} else if !create {
			var small *restorejournal.FileTarget
			small, err = restorejournal.OpenExistingFileTarget(paths[id])
			if err == nil {
				f = &mihomoSmallFile{small}
			}
		} else if id == "a_binary" {
			f, err = restorejournal.OpenArtifactExecutableTarget(paths[id], artifacts)
		} else {
			var small *restorejournal.FileTarget
			small, err = restorejournal.OpenFileTarget(paths[id])
			if err == nil {
				f = &mihomoSmallFile{small}
			}
		}
		if err != nil {
			return nil, errors.Join(err, s.close())
		}
		s.files[id] = f
		targets[id] = &mihomoReleaseTarget{Target: f, session: s, manager: m, id: id}
	}
	if create {
		s.j, err = restorejournal.Open(root, scope, targets)
	} else {
		s.j, err = restorejournal.OpenExisting(root, scope, targets)
	}
	if err != nil {
		return nil, errors.Join(err, s.close())
	}
	return s, nil
}

// RecoverMihomoRelease is explicit startup/offline recovery, before admitting a
// sidecar consumer. Missing journal is inert; malformed/foreign state is fenced.
func (m *Manager) RecoverMihomoRelease(ctx context.Context) (out restorejournal.Outcome, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	root, _, _, _, err := m.mihomoReleaseLayout()
	if err != nil {
		return restorejournal.Blocked, err
	}
	if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
		return restorejournal.Clean, nil
	}
	s, err := m.openMihomoRelease(false)
	if err != nil {
		return restorejournal.Blocked, err
	}
	defer func() { err = errors.Join(err, s.close()) }()
	out, err = s.j.Recover(ctx)
	return out, errors.Join(err, errors.Join(s.failures...))
}

// RequireIdle is read-only: it uses the existing protocol marker, opens no
// target, creates no directory and never silently replays an interrupted install.
func (m *Manager) mihomoReleaseIdle() (err error) {
	return m.checkMihomoReleaseIdle(context.Background())
}

func (m *Manager) CheckMihomoReleaseIdle(ctx context.Context) error {
	if m == nil {
		return restorejournal.ErrUnavailable
	}
	return m.checkMihomoReleaseIdle(ctx)
}
func (m *Manager) checkMihomoReleaseIdle(ctx context.Context) (err error) {
	if ctx == nil {
		return errors.New("Mihomo observation context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	root, scope, _, paths, err := m.mihomoReleaseLayout()
	if err != nil {
		return err
	}
	if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	targets := map[string]restorejournal.Target{}
	for id := range paths {
		targets[id] = mihomoIdleTarget{}
	}
	j, err := restorejournal.OpenExisting(root, scope, targets)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, j.Close()) }()
	return j.RequireIdle(ctx)
}

type mihomoIdleTarget struct{}

func (mihomoIdleTarget) Read(context.Context) (restorejournal.Image, error) {
	return restorejournal.Image{}, errors.New("Mihomo passive target is unavailable")
}
func (mihomoIdleTarget) CompareAndSwap(context.Context, restorejournal.Image, restorejournal.Image) error {
	return errors.New("Mihomo passive target is unavailable")
}
