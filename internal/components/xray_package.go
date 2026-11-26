package components

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// Older readers reject unknown top-level files in update-journal. The marker
// also covers fresh installs and removals, which only write a lifecycle receipt.
const XrayCorePackageReadVersion = 7
const xrayCoreMarkerFile = "xray-core-package.v7"
const xrayCoreMarker = "RAZVILKA xray-core package history v7\n"

func (m *Manager) xrayWriteAdmission(ctx context.Context) (context.Context, func(), error) {
	if m.Opkg == "" {
		return nil, nil, errors.New("opkg is not available")
	}
	if m.StateDir == "" || m.AdmitXrayCoreWrite == nil {
		return nil, nil, ErrRecoveryAuthority
	}
	held, release, err := m.AdmitXrayCoreWrite(ctx)
	if err != nil {
		return nil, nil, err
	}
	if err := m.xrayHistoryPreflight(); err != nil {
		release()
		return nil, nil, err
	}
	return held, release, nil
}

func (m *Manager) xrayPackageConflict(id string, installed map[string]string) error {
	if id != "xray" {
		return nil
	}
	if installed["xray"] != "" {
		return errors.New("Установлен метапакет Entware xray со своим автозапуском. Управление пакетом остаётся за Entware.")
	}
	_, err := os.Lstat(filepath.Join(defaultValue(m.InitDir, "/opt/etc/init.d"), "S24xray"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return errors.New("Обнаружен скрипт автозапуска Entware S24xray. Владельца процесса должен проверить администратор.")
}

// Check existing storage before recursively installing the shared Sing-box
// dependency. Creating the actual marker remains inside the package lease.
func (m *Manager) xrayHistoryPreflight() error {
	for _, name := range []string{"receipts", "update-journal"} {
		root, err := ownedfs.Open(filepath.Join(m.StateDir, name))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		err = xrayHistoryDirectory(root)
		if err == nil && name == "update-journal" {
			data, readErr := readXrayHistoryFile(root, xrayCoreMarkerFile, 128)
			if !errors.Is(readErr, os.ErrNotExist) && (readErr != nil || string(data) != xrayCoreMarker) {
				err = ErrRetainedManagedUpdate
			}
		}
		if err == nil && name == "receipts" {
			_, readErr := readXrayHistoryFile(root, "xray.json", 16<<10)
			if !errors.Is(readErr, os.ErrNotExist) {
				err = readErr
			}
		}
		err = errors.Join(err, root.Close())
		if err != nil {
			return err
		}
	}
	return nil
}

// markXrayCoreHistory runs under the package writer lease. Publish and sync
// the compatibility boundary before opkg can change any Xray package bytes.
func (m *Manager) markXrayCoreHistory() error {
	root, err := openUpdateRoot(m.updateJournalDir(), false)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := xrayHistoryDirectory(root); err != nil {
		return err
	}
	if err := m.prepareReceiptDir(); err != nil {
		return err
	}
	receipts, err := ownedfs.Open(filepath.Join(m.StateDir, "receipts"))
	if err != nil {
		return err
	}
	defer receipts.Close()
	if err := xrayHistoryDirectory(receipts); err != nil {
		return err
	}
	data, err := readXrayHistoryFile(root, xrayCoreMarkerFile, 128)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := root.WriteAtomic(xrayCoreMarkerFile, []byte(xrayCoreMarker), 0600); err != nil {
			return err
		}
	case err != nil:
		return err
	case string(data) != xrayCoreMarker:
		return ErrRetainedManagedUpdate
	}
	return syncUpdateDirectory(root)
}

// A missing directory may only describe absent history. On Linux use the
// descriptor-bound reader also used by managed HEV and Mihomo history.
func readXrayHistoryFile(root *ownedfs.Root, name string, limit int64) ([]byte, error) {
	info, err := root.Stat(name)
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(name)
	before, err := root.RootInfo()
	if dir != "." {
		before, err = root.Stat(dir)
	}
	if err != nil {
		return nil, err
	}
	if runtime.GOOS == "linux" {
		if _, ok := hevRetainedOwner(before, true); !ok {
			return nil, ErrRetainedManagedUpdate
		}
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, ErrRetainedManagedUpdate
	}
	if runtime.GOOS != "linux" {
		return root.ReadLimited(name, limit)
	}
	owner, ok := hevRetainedOwner(info, false)
	if !ok {
		return nil, ErrRetainedManagedUpdate
	}
	data, err := readHEVRetainedFile(root, name, limit, info)
	if err != nil {
		return nil, err
	}
	after, err := root.Stat(name)
	endOwner, ok := hevRetainedOwner(after, false)
	if err != nil || !ok || owner != endOwner || info.Mode() != after.Mode() || info.Size() != after.Size() || !info.ModTime().Equal(after.ModTime()) {
		return nil, ErrRetainedManagedUpdate
	}
	endDir, err := root.RootInfo()
	if dir != "." {
		endDir, err = root.Stat(dir)
	}
	if _, ok := hevRetainedOwner(endDir, true); err != nil || !ok || !os.SameFile(before, endDir) {
		return nil, ErrRetainedManagedUpdate
	}
	return data, nil
}

func xrayHistoryDirectory(root *ownedfs.Root) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	dir, err := root.RootInfo()
	if _, ok := hevRetainedOwner(dir, true); err != nil || !ok {
		return ErrRetainedManagedUpdate
	}
	return nil
}
