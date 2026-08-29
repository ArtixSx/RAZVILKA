package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEntwareUpgradeDoesNotRequireArchiveScriptModeBits(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	upgrade, err := os.ReadFile(filepath.Join(root, "scripts", "upgrade-entware.sh"))
	if err != nil {
		t.Fatal(err)
	}
	install, err := os.ReadFile(filepath.Join(root, "scripts", "install-entware.sh"))
	if err != nil {
		t.Fatal(err)
	}
	upgradeText := string(upgrade)
	for _, required := range []string{
		`[ -r "$BIN_SOURCE" ]`,
		`if [ ! -x "$BIN_SOURCE" ]; then`,
		`chmod 755 "$BIN_SOURCE"`,
		`[ -r "$INIT_SOURCE" ]`,
		`[ -r "$ROLLBACK" ]`,
		`sh "$ROLLBACK" "$BACKUP" --auto`,
		`install_atomic "$INIT_SOURCE" "$RAZ_INIT" 755`,
		`stage 1 "Останавливаем текущую версию`,
		`stage 4 "Сохраняем и отключаем только принадлежащий RAZVILKA dataplane`,
		`stage 6 "Запускаем новую версию и ждём восстановления маршрутов`,
		`stage 7 "Проверяем процесс, HTTP и восстановленный dataplane`,
	} {
		if !strings.Contains(upgradeText, required) {
			t.Fatalf("upgrade script lost archive-mode safeguard %q", required)
		}
	}
	for _, forbidden := range []string{`[ -x "$BIN_SOURCE" ] ||`, `[ -x "$INIT_SOURCE" ]`, `[ -x "$ROLLBACK" ]`} {
		if strings.Contains(upgradeText, forbidden) {
			t.Fatalf("upgrade script still requires preserved executable bits: %q", forbidden)
		}
	}
	if !strings.Contains(string(install), `exec sh "$HERE/upgrade-entware.sh"`) {
		t.Fatal("install wrapper must work when an archive did not preserve executable bits")
	}
}
