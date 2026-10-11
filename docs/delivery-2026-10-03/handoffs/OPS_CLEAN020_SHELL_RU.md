# OPS: shell для чистой 0.20.0 и будущих обновлений

11.10.2026. По прямому уточнению владельца 0.20.0 устанавливается начисто; приёмка миграции 0.19.3 и ниже больше не требуется. Существующие запреты raw replacement при retained self-update protocol, Stop и проверки recovery сохранены.

Исправления в принадлежащих OPS скриптах:

- Bootstrap добавляет фиксированный Entware пакет `coreutils-timeout`, если текущий `timeout` не принимает обязательный `-k`. После `opkg install` обновляет поиск команд и повторно проверяет поддержку до загрузок. PATH по-прежнему начинается с физических Entware каталогов; глобальный upgrade не добавлен.
- Install/rollback проверяют каждый используемый родительский каталог ниже явно разрешённого физического BASE: ссылка, включая broken link, или другой тип приводят к отказу до candidate/snapshot. Проверки повторяются перед файловыми изменениями. Uninstall дополнительно проверяет BASE и var/run. Ссылку самого пользовательского BASE по-прежнему разрешено канонизировать.
- Три запуска candidate в command substitution используют кавычки. Fixture архитектурной suite теперь содержит пробелы в пути пакета.
- Новый `test-entware-path-safety.sh` вызывает настоящие upgrade/rollback/uninstall entrypoints, проверяет конкретный отказ и неизменность чужих Entware файлов. Он подключён в `test-entware-transaction.sh`, общий check.sh не изменён.

Windows Git Bash PE: `test-bootstrap.sh`, `test-entware-path-safety.sh`, `test-uninstall-entware.sh` PASS; shell syntax и git diff --check PASS. В Windows Git Bash production `ulimit -f 128` возвращает RC125 (Invalid argument), поэтому architecture suite здесь не подтверждена. Ограничение production probe не ослаблялось. Native Linux, включая реальные symlink случаи и путь candidate с пробелами, проверяет только Root:

```sh
sh scripts/test-bootstrap.sh
sh scripts/test-installer-architecture.sh
sh scripts/test-entware-path-safety.sh
sh scripts/test-uninstall-entware.sh
# В штатном Linux check также запускается test-entware-transaction.sh.
```

Официальные Entware MIPS/MIPSel каталоги содержат coreutils-timeout; ARM64 каталог при read-only проверке не ответил. Три целевые платформы фактически не проверены. Native clean install, будущий journaled update/rollback и часовой Telegram/VLESS тест остаются отдельной приёмкой Root. Скрипты не удаляют retained настройки, ключи, компоненты или чужие Entware файлы. VERSION/README, Main/DP, публикация и роутер не затронуты.
