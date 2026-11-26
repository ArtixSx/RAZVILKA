# Пассивный platform fingerprint

Collector читает локальные выбранные сведения и пишет только в stdout. Он не
запускает engines, не делает сетевых запросов, не меняет сервисы, firewall,
routes, sysctl или конфигурацию. Перенаправление stdout выполняет оператор:

```sh
sh scripts/diagnostics/collect-platform-fingerprint.sh \
  --model KN-1812 --firmware 'observed version' \
  --binary /opt/bin/xray --binary /opt/bin/nfqws2 > router-fingerprint.txt
python3 scripts/diagnostics/compare-platforms.py router-fingerprint.txt
python3 scripts/diagnostics/compare-platforms.py host-fingerprint.txt router-fingerprint.txt
```

`--model` и `--firmware` — непроверенные объявления оператора. Максимум 12
явных `--binary`, пути должны быть абсолютными. Автоматически читается только
первый ELF header текущего shell. Каждый header ограничен 64 bytes через
`dd bs=64 count=1`; `od -b -v` использует короткие опции BusyBox/GNU. Parser
получает decimal bytes после проверки octal offsets, byte range и обоих
reader exit codes. Полный SHA256 читается только для явно переданного binary;
hash shell по умолчанию не вычисляется. Программы из этих путей не исполняются.

Прочие сведения ограничены выбранными CPU/memory/credentials fields,
mountpoints `/`, `/opt`, `/tmp`, `/run`, space `/opt` и `/tmp`, именами loaded
modules, kernel config subset, presence `/dev/net/tun`/namespace/BTF, явным
набором sysctl и feed family без URL пользовательских feeds. Tool inventory
использует `command -v`; отдельные fixed metadata команды: `uname`, `date`,
`df -Pk`, `opkg print-architecture`, `ip -V`, `iptables --version`,
`ip6tables --version`, `nft --version`, `curl --version`, `getconf GNU_LIBC_VERSION`.
Нет глобальных NDM/status/configuration dumps и активных capability probes.

Отсутствующий `od`/`dd`/command, ошибка чтения, malformed/truncated header дают
UNKNOWN. Из `uname`, feed name или наличия tools порядок байтов MIPS не
выводится. Lane основан только на валидном ELF class/data/machine/version/size;
даже observed ELF header не определяет полный ABI, float ABI, ISA или loader.
Все functional support fields остаются `UNKNOWN_NOT_TESTED`. Результат не
является platform PASS или допуском production install/bootstrap.

Офлайн parser использует Python 3 standard library, проверяет framing и exit
codes, ограничивает вход 1 MiB. `--output result.json` создаёт только явный
новый output и отказывает при уже существующем файле, включая symlink/hardlink
на input. Формат `KAFINGERPRINT|1` сохранён;
старые inventories с `NOT_COLLECTED` также читаются.

## Происхождение

Адаптация двух tools из предоставленного пакета
`RAZVILKA_KEENETIC_CODEX_2026_10_12`:

- SHA256 исходного архива:
  `456c9dc1d8df604b9b978205fc3fc0bba3d5da1eac1cc2ef9a050385f05d202d`.
- `tools/collect_platform_fingerprint.sh`:
  `18fd527a1755d654336e7536886bfa093db7a78561551ea8aa125ee0f5c08884`.
- `tools/compare_platforms.py`:
  `5381115d07ac290b1e44a60c310ab55f739d0d93f9e17e05788b301ec7b334d1`.

Исправлен реальный отказ compact BusyBox `od` на `-A/-t/-N`. Переносимый
`dd | od -b` уже используется в `scripts/upgrade-entware.sh`; production
script здесь не меняется. Добавлены независимый dd status, отключение подавления
повторяющихся octal rows, validation и read-only bounds. Collector/parser
не устанавливаются и не вызываются автоматически приложением.

## Регрессии

```sh
python3 scripts/diagnostics/test-platform-fingerprint.py
```

Suite запускает настоящий collector в temporary mock PATH и настоящий офлайн
parser. GNU `od` читает реальные fixture bytes; short-option BusyBox profile
отвергает опции кроме `-b -v`, затем использует этот byte reader. Это модель
portability contract, не запуск настоящего router BusyBox. Проверяются GNU,
repeat-zero rows, ≤64-byte read, producer failure, missing od/dd/hash utility,
truncated/malformed ELF/framing и обе MIPS byte orders. Другие utilities в PATH
моделируются; fixture files и audit log создаёт suite, collector файлов не пишет.
На Windows используется Git for Windows `sh.exe` и GNU utilities (PE), без WSL
или Linux ELF. Можно явно указать shell через `RAZVILKA_DIAG_TEST_SH`.
Native запуск на роутере остаётся отдельной проверкой владельца устройства.
