package usquediag

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

const (
	RepairConfirmation = "REPAIR_USQUE_NDMC"
	repairLimit        = 1 << 20
)

var (
	ErrRepairBlocked      = errors.New("USQUE ndmc repair is blocked")
	ErrRepairConfirmation = errors.New("USQUE ndmc repair confirmation is required")
)

type RepairResult struct {
	OK         bool                   `json:"ok"`
	Status     string                 `json:"status"`
	Changed    bool                   `json:"changed"`
	RolledBack bool                   `json:"rolled_back"`
	Outcome    restorejournal.Outcome `json:"outcome"`
	BackupID   string                 `json:"backup_id,omitempty"`
	Message    string                 `json:"message"`
}

type ndmcInitTarget struct {
	root     *ownedfs.Root
	name     string
	path     string
	mode     os.FileMode
	runner   Runner
	shell    string
	ndmcPath string
}

type unavailableNDMCTarget struct{}

func (unavailableNDMCTarget) Read(context.Context) (restorejournal.Image, error) {
	return restorejournal.Image{}, restorejournal.ErrRecovery
}
func (unavailableNDMCTarget) CompareAndSwap(context.Context, restorejournal.Image, restorejournal.Image) error {
	return restorejournal.ErrRecovery
}

func openNDMCInitTarget(path, shell, ndmcPath string, runner Runner) (*ndmcInitTarget, error) {
	if !filepath.IsAbs(path) || filepath.Base(path) == "." || shell == "" || ndmcPath == "" || runner == nil {
		return nil, ErrRepairBlocked
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > repairLimit || runtime.GOOS != "windows" && info.Mode().Perm()&0o022 != 0 {
		return nil, ErrRepairBlocked
	}
	root, err := ownedfs.Open(filepath.Dir(path))
	if err != nil {
		return nil, ErrRepairBlocked
	}
	return &ndmcInitTarget{root: root, name: filepath.Base(path), path: path, mode: info.Mode().Perm(), runner: runner, shell: shell, ndmcPath: ndmcPath}, nil
}

func (t *ndmcInitTarget) Close() error   { return t.root.Close() }
func (*ndmcInitTarget) String() string   { return "[USQUE init repair target]" }
func (*ndmcInitTarget) GoString() string { return "[USQUE init repair target]" }

func (t *ndmcInitTarget) Read(ctx context.Context) (restorejournal.Image, error) {
	if ctx.Err() != nil {
		return restorejournal.Image{}, restorejournal.ErrAborted
	}
	data, err := t.root.ReadLimited(t.name, repairLimit)
	if err != nil || len(data) == 0 {
		return restorejournal.Image{}, restorejournal.ErrInvalid
	}
	return restorejournal.Image{Exists: true, Data: data}, nil
}

func (t *ndmcInitTarget) CompareAndSwap(ctx context.Context, before, after restorejournal.Image) error {
	if !before.Exists || !after.Exists || len(before.Data) == 0 || len(after.Data) == 0 || len(before.Data) > repairLimit || len(after.Data) > repairLimit || ctx.Err() != nil {
		return restorejournal.ErrInvalid
	}
	current, err := t.Read(ctx)
	if err != nil || !bytes.Equal(current.Data, before.Data) {
		return restorejournal.ErrConflict
	}
	if bytes.Equal(before.Data, after.Data) {
		return nil
	}
	if err := t.root.WriteAtomic(t.name, after.Data, t.mode); err != nil {
		return restorejournal.ErrRecovery
	}
	if runtime.GOOS != "windows" && t.root.Sync() != nil {
		return restorejournal.ErrRecovery
	}
	if _, err := t.runner.Run(ctx, Command{Name: t.shell, Args: []string{"-n", t.path}}); err != nil {
		return restorejournal.ErrRecovery
	}
	if _, err := t.runner.Run(ctx, Command{Name: t.ndmcPath, Args: []string{"-c", "show version"}, Env: []string{"LD_LIBRARY_PATH=/lib:/usr/lib"}}); err != nil {
		return restorejournal.ErrRecovery
	}
	return nil
}

func patchNDMCInit(input []byte) ([]byte, int, error) {
	lines := strings.Split(string(input), "\n")
	changed := 0
	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "ndmc") {
			continue
		}
		if strings.Contains(line, "NDMC=") || strings.Contains(line, "$NDMC") {
			return nil, 0, ErrRepairBlocked
		}
		if strings.Contains(line, "LD_LIBRARY_PATH=") {
			if !strings.Contains(line, "LD_LIBRARY_PATH=/lib:/usr/lib") {
				return nil, 0, ErrRepairBlocked
			}
			continue
		}
		count := strings.Count(raw, "/bin/ndmc")
		if count != 1 || !directNDMCInvocation(raw) {
			return nil, 0, ErrRepairBlocked
		}
		lines[i] = strings.Replace(raw, "/bin/ndmc", "LD_LIBRARY_PATH=/lib:/usr/lib /bin/ndmc", 1)
		changed++
	}
	if changed == 0 {
		return nil, 0, ErrRepairBlocked
	}
	return []byte(strings.Join(lines, "\n")), changed, nil
}

// directNDMCInvocation accepts only the two forms used by the supported USQUE
// init script: a command on its own line or a command substitution. Merely
// mentioning /bin/ndmc in echo, tests, assignments or shell control flow must
// never become an executable command after an automated rewrite.
func directNDMCInvocation(raw string) bool {
	index := strings.Index(raw, "/bin/ndmc")
	if index < 0 || strings.Count(raw, "/bin/ndmc") != 1 {
		return false
	}
	prefix := strings.TrimSpace(raw[:index])
	if prefix != "" && !strings.HasSuffix(prefix, "$(") {
		return false
	}
	suffix := raw[index+len("/bin/ndmc"):]
	return suffix == "" || suffix[0] == ' ' || suffix[0] == '\t'
}

func repairScope(path string) string {
	value := path
	if runtime.GOOS == "windows" {
		value = strings.ToLower(value)
	}
	return fmt.Sprintf("%x", sha256.Sum256([]byte("usque-ndmc-init-v1\x00"+value)))
}

func ensurePrivateRoot(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) == filepath.VolumeName(path)+string(filepath.Separator) {
		return ErrRepairBlocked
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return ErrRepairBlocked
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return ErrRepairBlocked
	}
	return nil
}

func (m *Manager) repairPaths() (root, shell string) {
	root, shell = m.RepairRoot, m.ShellPath
	if root == "" {
		root = "/opt/var/lib/razvilka/usque-repair"
	}
	if shell == "" {
		shell = "/bin/sh"
	}
	return
}

func (m *Manager) openRepairJournal() (*restorejournal.Journal, *ndmcInitTarget, error) {
	rootPath, shell := m.repairPaths()
	if err := ensurePrivateRoot(rootPath); err != nil {
		return nil, nil, err
	}
	target, err := openNDMCInitTarget(m.InitPath, shell, m.NDMCPath, m.Runner)
	if err != nil {
		return nil, nil, err
	}
	journal, err := restorejournal.Open(rootPath, repairScope(m.InitPath), map[string]restorejournal.Target{"usque_init": target})
	if err != nil {
		_ = target.Close()
		return nil, nil, err
	}
	return journal, target, nil
}

// RecoverNDMCRepair is idempotent and must run before the HTTP mutation is
// exposed. It creates nothing when the repair protocol has never been used.
func (m *Manager) RecoverNDMCRepair(ctx context.Context) (restorejournal.Outcome, error) {
	root, _ := m.repairPaths()
	if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
		return restorejournal.Clean, nil
	}
	m.repairMu.Lock()
	defer m.repairMu.Unlock()
	journal, target, err := m.openRepairJournal()
	if err != nil {
		// A clean journal does not need its former target. This permits an
		// explicitly uninstalled USQUE package to coexist with old backups, while
		// a pending/corrupt record still fails closed until the init target exists.
		if ensurePrivateRoot(root) != nil {
			return restorejournal.Blocked, err
		}
		journal, openErr := restorejournal.Open(root, repairScope(m.InitPath), map[string]restorejournal.Target{"usque_init": unavailableNDMCTarget{}})
		if openErr != nil {
			return restorejournal.Blocked, err
		}
		defer journal.Close()
		return journal.Recover(ctx)
	}
	defer journal.Close()
	defer target.Close()
	return journal.Recover(ctx)
}

// RepairNDMC performs one bounded, journaled init-script change. It never
// starts/stops USQUE and never changes global process environment or DNS.
func (m *Manager) RepairNDMC(ctx context.Context, confirmation string) (RepairResult, error) {
	if confirmation != RepairConfirmation {
		return RepairResult{}, ErrRepairConfirmation
	}
	m.repairMu.Lock()
	defer m.repairMu.Unlock()
	journal, target, err := m.openRepairJournal()
	if err != nil {
		return RepairResult{}, ErrRepairBlocked
	}
	defer journal.Close()
	defer target.Close()
	if outcome, err := journal.Recover(ctx); err != nil || outcome != restorejournal.Clean {
		return RepairResult{OK: err == nil, Status: "recovered", RolledBack: outcome == restorejournal.RolledBack, Outcome: outcome, Message: "Предыдущая операция ремонта завершена; повторите проверку USQUE."}, err
	}

	_, normalErr := m.Runner.Run(ctx, Command{Name: m.NDMCPath, Args: []string{"-c", "show version"}})
	_, cleanErr := m.Runner.Run(ctx, Command{Name: m.NDMCPath, Args: []string{"-c", "show version"}, Env: []string{"LD_LIBRARY_PATH=/lib:/usr/lib"}})
	mode := "unavailable"
	if normalErr == nil {
		mode = "current-environment"
	} else if cleanErr == nil {
		mode = "system-libraries-only"
	}
	preview := previewNDMCRepair(m.InitPath, mode)
	if preview.Status == "protected" || preview.Status == "not-needed" {
		return RepairResult{OK: true, Status: "not_needed", Outcome: restorejournal.Clean, Message: preview.Summary}, nil
	}
	if !preview.Eligible || !preview.Needed {
		return RepairResult{}, ErrRepairBlocked
	}
	before, err := target.Read(ctx)
	if err != nil {
		return RepairResult{}, ErrRepairBlocked
	}
	patched, changed, err := patchNDMCInit(before.Data)
	if err != nil || changed != preview.NDMCInvocations-preview.ScopedInvocations {
		return RepairResult{}, ErrRepairBlocked
	}
	rootPath, _ := m.repairPaths()
	backupRoot, err := ownedfs.Open(rootPath)
	if err != nil {
		return RepairResult{}, ErrRepairBlocked
	}
	defer backupRoot.Close()
	backupID, err := backupRoot.MkdirTemp(".", "backup-")
	if err != nil || backupRoot.WriteAtomic(filepath.Join(backupID, "S51usque.before"), before.Data, 0o600) != nil {
		return RepairResult{}, ErrRepairBlocked
	}
	if runtime.GOOS != "windows" && backupRoot.Sync() != nil {
		return RepairResult{}, ErrRepairBlocked
	}
	outcome, executeErr := journal.Execute(ctx, map[string]restorejournal.Image{"usque_init": {Exists: true, Data: patched}})
	if executeErr != nil {
		return RepairResult{Status: "failed", RolledBack: outcome == restorejournal.RolledBack, Outcome: outcome, BackupID: filepath.Base(backupID), Message: "Проверка ремонта не прошла; исходный init-скрипт восстановлен или оставлен для recovery."}, executeErr
	}
	return RepairResult{OK: true, Status: "applied", Changed: true, Outcome: outcome, BackupID: filepath.Base(backupID), Message: fmt.Sprintf("Точечно защищено вызовов ndmc: %d. USQUE не перезапускался.", changed)}, nil
}
