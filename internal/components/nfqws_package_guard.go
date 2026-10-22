package components

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

var ErrNFQWSOwnedPackageMutation = errors.New("Изменение пакета NFQWS2 для этого управляемого профиля пока не поддерживается: оно может сбросить ограничения выбранных сайтов.")
var ErrNFQWSPackageOwnershipUnknown = errors.New("Не удалось проверить сохранённое управление NFQWS2; изменение пакета заблокировано")

// NFQWSOwnedPackageInit is read-only recognition, never an ownership or start
// grant. The dataplane additionally checks its durable lease before app actions.
// This component boundary also protects CLI InstallRecommended and recovery.
func (m *Manager) NFQWSOwnedPackageInit() (bool, error) {
	if m == nil {
		return false, ErrNFQWSPackageOwnershipUnknown
	}
	dir := defaultValue(m.InitDir, "/opt/etc/init.d")
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	root, err := ownedfs.Open(dir)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrNFQWSPackageOwnershipUnknown, err)
	}
	defer root.Close()
	data, err := root.ReadLimited("S51nfqws2", 1<<20)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrNFQWSPackageOwnershipUnknown, err)
	}
	if _, err := engineconfig.NFQWSFirstStartInitOwner(data); err == nil {
		return true, nil
	}
	if bytes.Contains(data, []byte("RAZVILKA NFQWS2")) || bytes.Contains(data, []byte("# RAZVILKA INSTANCE ")) {
		return false, ErrNFQWSPackageOwnershipUnknown
	}
	return false, nil
}

func (m *Manager) nfqwsPackageMutationGuard(id string) error {
	if id != "nfqws2" {
		return nil
	}
	blocked, err := m.NFQWSOwnedPackageInit()
	if err != nil {
		return err
	}
	if blocked {
		return ErrNFQWSOwnedPackageMutation
	}
	return nil
}

// Resolve only actual package commands, not list/update/download observations.
// Journal rollback uses an ipk path, so its component is checked separately.
func (m *Manager) nfqwsPackageArgumentsGuard(args []string) error {
	if len(args) == 0 || (args[0] != "install" && args[0] != "upgrade" && args[0] != "remove") {
		return nil
	}
	for _, arg := range args[1:] {
		if arg == "nfqws2-keenetic" || (filepath.Ext(arg) == ".ipk" && bytes.HasPrefix([]byte(filepath.Base(arg)), []byte("nfqws2-keenetic_"))) {
			return m.nfqwsPackageMutationGuard("nfqws2")
		}
	}
	return nil
}
