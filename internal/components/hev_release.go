package components

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/backendprofile"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// The reviewed dialect/lifecycle is deliberately independent of upstream latest.
// Digests are from the official 2.17.1 release asset metadata, not a mirror.
func hevPinnedRelease(spec Spec, arch string) (releaseInfo, error) {
	if spec.Binary != "hev-socks5-tunnel" || spec.Repository != "https://github.com/heiher/hev-socks5-tunnel" {
		return releaseInfo{}, errors.New("invalid HEV release binding")
	}
	var asset, digest string
	switch arch {
	case "amd64":
		asset = "hev-socks5-tunnel-linux-x86_64"
		digest = "a98763f18b0ad1f72a903221008488275f2bf60be00028886f9fa41622df6a03"
	case "arm64":
		asset = "hev-socks5-tunnel-linux-arm64"
		digest = "958206dcebcdc390cdc4d5b88c8504ec81483e2a04b46d37c835a179830c86ba"
	default:
		return releaseInfo{}, fmt.Errorf("HEV has no reviewed Linux asset for %s", arch)
	}
	return releaseInfo{Version: backendprofile.ReviewedHEVVersion, Asset: releaseAsset{Name: asset, URL: spec.Repository + "/releases/download/" + backendprofile.ReviewedHEVVersion + "/" + asset}, PinnedSHA256: digest}, nil
}

var hevReleaseVersionLine = regexp.MustCompile(`(?m)^Version: ([0-9]+\.[0-9]+\.[0-9]+)(?: [A-Za-z0-9._-]+)?\r?$`)

// This only executes the reviewed version command, never a config or TUN.
func verifyHEVRelease(parent context.Context, path string) error {
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "--version").CombinedOutput()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		var exited *exec.ExitError
		if !errors.As(err, &exited) || exited.ExitCode() != 255 {
			return fmt.Errorf("HEV version command: %w", err)
		}
	}
	matches := hevReleaseVersionLine.FindAllStringSubmatch(string(out), -1)
	if len(matches) != 1 || matches[0][1] != backendprofile.ReviewedHEVVersion {
		return errors.New("HEV version does not match reviewed release")
	}
	return nil
}

func (m *Manager) installHEVRelease(ctx context.Context, spec Spec) (Result, error) {
	result := Result{Component: spec.ID, Action: "install"}
	info, err := hevPinnedRelease(spec, m.Arch)
	if err != nil {
		return result, err
	}
	binary, err := m.download(ctx, info.Asset.URL, restorejournal.MaxImageBytes)
	if err != nil {
		return result, err
	}
	digest := sha256.Sum256(binary)
	if len(binary) == 0 || hex.EncodeToString(digest[:]) != info.PinnedSHA256 {
		return result, errors.New("HEV official pinned SHA-256 mismatch")
	}
	// Execute only digest-verified bytes, outside the installed path. A failed
	// version observation cannot mutate the installed binary or its receipts.
	if err := os.MkdirAll(defaultValue(m.BinDir, "/opt/bin"), 0755); err != nil {
		return result, err
	}
	staged, err := os.CreateTemp(defaultValue(m.BinDir, "/opt/bin"), ".hev-verified-*")
	if err != nil {
		return result, err
	}
	path := staged.Name()
	defer os.Remove(path)
	_, writeErr := staged.Write(binary)
	chmodErr := staged.Chmod(0755)
	syncErr := staged.Sync()
	closeErr := staged.Close()
	if err := errors.Join(writeErr, chmodErr, syncErr, closeErr); err != nil {
		return result, err
	}
	if err := verifyHEVRelease(ctx, path); err != nil {
		return result, err
	}
	return m.installHEVImage(ctx, spec, info, binary)
}

// installHEVImage is reached only after pinned digest + version verification.
// It never starts a service. Recovery is run before inspecting pair ownership,
// since a prepared transaction may legitimately contain a half-written pair.
func (m *Manager) installHEVImage(ctx context.Context, spec Spec, info releaseInfo, binary []byte) (result Result, err error) {
	result = Result{Component: spec.ID, Action: "install"}
	session, err := m.openHEVRelease(true)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, session.close()) }()
	if _, err = session.j.Recover(ctx); err != nil {
		return result, err
	}
	before, err := session.files["a_binary"].Read(ctx)
	if err != nil {
		return result, err
	}
	receiptBefore, err := session.files["b_receipt"].Read(ctx)
	if err != nil {
		return result, err
	}
	beforeVersion := ""
	if before.Exists {
		var ownership externalReceipt
		digest := sha256.Sum256(before.Data)
		if receiptBefore.Exists && json.Unmarshal(receiptBefore.Data, &ownership) == nil && externalVersionValuePattern.MatchString(ownership.Version) && ownership.SHA256 == hex.EncodeToString(digest[:]) {
			beforeVersion = ownership.Version
		}
		if beforeVersion == "" {
			return result, errors.New("existing HEV has no valid RAZVILKA ownership receipt")
		}
		if !bytes.Equal(before.Data, binary) {
			return result, errors.New("HEV binary replacement requires original sidecar inactivity admission; only identical pinned bytes can be reinstalled")
		}
		result.Action = "update"
	} else if receiptBefore.Exists {
		return result, errors.New("orphan HEV ownership receipt requires review")
	}
	digest := sha256.Sum256(binary)
	receipt, _ := json.Marshal(externalReceipt{Version: info.Version, SHA256: hex.EncodeToString(digest[:])})
	lifecycle, _ := json.MarshalIndent(lifecycleReceipt{SchemaVersion: 1, Component: spec.ID, Provider: spec.Provider, Action: result.Action, BeforeVersion: beforeVersion, AfterVersion: info.Version, CompletedAt: time.Now().UTC().Format(time.RFC3339Nano)}, "", "  ")
	// Journal snapshot admission must use the same ownership-reviewed pair,
	// rather than adopting an intervening foreign edit as its new before image.
	session.admission = map[string]restorejournal.Image{"a_binary": before, "b_receipt": receiptBefore}
	_, err = session.j.Execute(ctx, map[string]restorejournal.Image{"a_binary": {Exists: true, Data: binary}, "b_receipt": {Exists: true, Data: append(receipt, '\n')}, "c_lifecycle": {Exists: true, Data: append(lifecycle, '\n')}})
	if err != nil {
		return result, errors.Join(err, errors.Join(session.failures...))
	}
	if m.external == nil {
		m.external = map[string]releaseInfo{}
	}
	m.external[spec.ID] = info
	result.OK = true
	result.Output = "installed pinned HEV " + info.Version + "; no service or route started"
	return result, nil
}

type hevReleaseSession struct {
	j         *restorejournal.Journal
	files     map[string]*restorejournal.FileTarget
	paths     map[string]string
	failures  []error
	admission map[string]restorejournal.Image
}

func (s *hevReleaseSession) close() error {
	var errs []error
	if s.j != nil {
		errs = append(errs, s.j.Close())
	}
	for _, f := range s.files {
		errs = append(errs, f.Close())
	}
	return errors.Join(errs...)
}

type hevReleaseTarget struct {
	restorejournal.Target
	session *hevReleaseSession
	manager *Manager
	id      string
}

func (t *hevReleaseTarget) Read(ctx context.Context) (restorejournal.Image, error) {
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

func (t *hevReleaseTarget) CompareAndSwap(ctx context.Context, before, after restorejournal.Image) error {
	if t.manager.updateFault != nil {
		if err := t.manager.updateFault("hev:before:" + t.id); err != nil {
			t.session.failures = append(t.session.failures, err)
			return err
		}
	}
	err := t.Target.CompareAndSwap(ctx, before, after)
	if err == nil && t.manager.updateFault != nil {
		err = t.manager.updateFault("hev:after:" + t.id)
	}
	if err != nil {
		t.session.failures = append(t.session.failures, err)
	}
	return err
}

// The scope binds trusted configured paths and the explicit executable mode.
func (m *Manager) hevReleaseLayout() (string, string, map[string]string, error) {
	if strings.TrimSpace(m.StateDir) == "" {
		return "", "", nil, errors.New("HEV durable component state directory is required")
	}
	binary, err := filepath.Abs(filepath.Join(defaultValue(m.BinDir, "/opt/bin"), "hev-socks5-tunnel"))
	if err != nil {
		return "", "", nil, err
	}
	state, err := filepath.Abs(m.StateDir)
	if err != nil {
		return "", "", nil, err
	}
	paths := map[string]string{"a_binary": binary, "b_receipt": externalReceiptPath(binary), "c_lifecycle": filepath.Join(state, "receipts", "hev-socks5-tunnel.json")}
	binding := "hev-release-files-v1:binary0755:state0600"
	for _, id := range []string{"a_binary", "b_receipt", "c_lifecycle"} {
		v, err := restorejournal.FileBinding(paths[id])
		if err != nil {
			return "", "", nil, err
		}
		binding += "\n" + id + ":" + v
	}
	digest := sha256.Sum256([]byte(binding))
	return filepath.Join(state, "hev-release-v1"), hex.EncodeToString(digest[:]), paths, nil
}
func (m *Manager) openHEVRelease(create bool) (*hevReleaseSession, error) {
	root, scope, paths, err := m.hevReleaseLayout()
	if err != nil {
		return nil, err
	}
	if create {
		for _, dir := range []string{root, filepath.Dir(paths["a_binary"]), filepath.Dir(paths["c_lifecycle"])} {
			if err := os.MkdirAll(dir, 0700); err != nil {
				return nil, err
			}
		}
	}
	s := &hevReleaseSession{files: map[string]*restorejournal.FileTarget{}, paths: paths}
	targets := map[string]restorejournal.Target{}
	for _, id := range []string{"a_binary", "b_receipt", "c_lifecycle"} {
		var f *restorejournal.FileTarget
		if !create && id == "a_binary" {
			f, err = restorejournal.OpenExistingExecutableFileTarget(paths[id])
		} else if !create {
			f, err = restorejournal.OpenExistingFileTarget(paths[id])
		} else if id == "a_binary" {
			f, err = restorejournal.OpenExecutableFileTarget(paths[id])
		} else {
			f, err = restorejournal.OpenFileTarget(paths[id])
		}
		if err != nil {
			return nil, errors.Join(err, s.close())
		}
		s.files[id] = f
		targets[id] = &hevReleaseTarget{Target: f, session: s, manager: m, id: id}
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

// RecoverHEVRelease is explicit startup/offline recovery, before admitting a
// sidecar consumer. Missing journal is inert; malformed/foreign state is fenced.
func (m *Manager) RecoverHEVRelease(ctx context.Context) (out restorejournal.Outcome, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	root, _, _, err := m.hevReleaseLayout()
	if err != nil {
		return restorejournal.Blocked, err
	}
	if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
		return restorejournal.Clean, nil
	}
	s, err := m.openHEVRelease(false)
	if err != nil {
		return restorejournal.Blocked, err
	}
	defer func() { err = errors.Join(err, s.close()) }()
	out, err = s.j.Recover(ctx)
	return out, errors.Join(err, errors.Join(s.failures...))
}

// RequireIdle is read-only: it uses the existing protocol marker, opens no
// target, creates no directory and never silently replays an interrupted install.
func (m *Manager) hevReleaseIdle() (err error) {
	root, scope, paths, err := m.hevReleaseLayout()
	if err != nil {
		return err
	}
	if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	targets := map[string]restorejournal.Target{}
	for id := range paths {
		targets[id] = hevIdleTarget{}
	}
	j, err := restorejournal.OpenExisting(root, scope, targets)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, j.Close()) }()
	return j.RequireIdle(context.Background())
}

type hevIdleTarget struct{}

func (hevIdleTarget) Read(context.Context) (restorejournal.Image, error) {
	return restorejournal.Image{}, errors.New("HEV passive target is unavailable")
}
func (hevIdleTarget) CompareAndSwap(context.Context, restorejournal.Image, restorejournal.Image) error {
	return errors.New("HEV passive target is unavailable")
}
