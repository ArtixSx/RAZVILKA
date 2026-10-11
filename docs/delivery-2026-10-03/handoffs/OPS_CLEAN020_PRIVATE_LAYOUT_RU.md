# OPS: защищённые пути чистой 0.20.0

11.10.2026. Root подтвердил реальный shared `/opt/var` с UID1001, а `/`, `/opt`, `/opt/etc` — root0/0755. Guard `checkOwnedAncestors` остаётся строгим: все предки доверенной записи должны быть root-owned, без ссылок и group/other write. Общие Entware права не переписываются.

Единственный модуль — `internal/installpath`, finished dependency `24df9620e41544b417871670e889bc442062e6bd`. Экспорты Root/State/Run/Cache/Log/Config. Итоговые пути:

| Назначение | Путь |
|---|---|
| Приватный корень | `/opt/razvilka` |
| State | `/opt/razvilka/state` |
| PID | `/opt/razvilka/run/razvilka.pid` |
| Cache | `/opt/razvilka/cache` |
| Log | `/opt/razvilka/log/server.log` |
| Config, ключи, nodes/private feeds | `/opt/etc/razvilka` и прежние дочерние имена |
| Journal/control | `state/self-update`, `state/self-update-files`, `state/self-update-stop` |
| Components | `state/components`, включая update-journal/operations/rollback-packages |
| Runtime | `state/dataplane`, `state/dns/state.json`, `state/staging`, `state/backups`, `state/warp` |
| Install snapshots | `state/update-backups`, `state/current-backup` |
| Candidate | `/opt/razvilka/candidate/{state,run,cache,log}`, config `/opt/etc/razvilka-candidate` |
| Offline archive | `/opt/razvilka/state-offline-recovery` — отдельный sibling state |

Controller `/opt/bin/razvilka` и init `/opt/etc/init.d/S99razvilka` сохраняются. Новые каталоги init/install создают с umask077 (0700) действующего root; журналы/credential files остаются приватными. Lab scripts также выставляют umask077. Нет chown/chmod shared `/opt/var`, автоматического переноса старых данных, symlink, fallback или ослабления ownership guards. Повторная установка/rollback/uninstall проверяют все реальные новые предки; uninstall сохраняет новый state и settings.

Изменены только OPS scripts/tests, `internal/updatecheck` и пять назначенных Root файлов `internal/components/{components,lifecycle,managed_update,package_supervision,update_journal}.go`. Updatecheck использует общие константы для production root/defaults, PID checks и retained NodeHistory/component readers; relative snapshot/restore inventory и bounded fixtures согласованы с новым деревом. Entware-owned sing-box init string `/opt/var/lib/$PROCS` не является state RAZVILKA и не изменён. Main/App/DP/default flags подключает CORE отдельным pin; CLI/UI/native helper paths подключает UI. Этот source pin требует согласованной интеграции, отдельно старый Main с новым install layout использовать нельзя.

Проверки Windows: полный updatecheck PASS 59.112s; components PASS14.442s; vet обоих пакетов PASS. Shell syntax, actual-entrypoint path refusal, uninstall, bootstrap, candidate isolation PASS через Windows Git Bash PE. Symlink cases там явно SKIP; architecture suite требует Linux из-за `ulimit -f 128` RC125 в Windows. Linux AMD64/ARM64 vet+test-c обоих Go пакетов RC0; ELF не запускались OPS.

Новые fixtures создают чужой shared var и проверяют неизменность его bytes/metadata. Native root ownership test проверяет настоящую UID1001 на отдельном TempDir: новый private ancestor проходит, старый foreign ancestor отказывает. Root запускает `TestNativePrivateLayoutDoesNotTrustOrChangeForeignSharedVar`, реальную shell transaction/architecture/bootstrap/remove и будущий manual/automatic update после полной интеграции. Старый private old193 harness не менялся (SHA256 cb882927d56d84f739bc7d9c33e1bb582fe42cfd243da9e1b4ee3281c4fc828f) и не является текущей приёмкой.
